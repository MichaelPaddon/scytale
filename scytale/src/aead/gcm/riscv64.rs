//! AES-GCM as one loop, for the RISC-V vector cryptography extension.
//!
//! Counter mode and GHASH are independent of each other and run on
//! different instructions: `vaesem` does the cipher and `vgmul` the
//! field multiplication. Called one after the other, each waits while
//! the other's pipe stands idle, and the data is read and written
//! twice. Written as one loop, the hash costs little beyond the cipher
//! it rides along with: four blocks are multiplied by four powers of
//! the subkey in a single `vgmul`, and two slides and two exclusive
//! ors add the results together.
//!
//! # Four blocks to a pass
//!
//! The vector length is fixed at sixteen 32-bit elements, which is
//! four blocks, rather than taken from the hardware as the counter
//! loop does. Two things ask for that. The powers of the subkey have
//! to match the blocks one for one, and there are only so many of
//! them; and the tree that adds the four products together is two
//! steps, which a length that varied would make a loop. On a machine
//! with wider registers this uses the low part of each.
//!
//! # What is in which register
//!
//! Thirty-two registers, and at `LMUL=4` only eight groups, so the
//! budget decides the shape:
//!
//! ```text
//! v0      the powers H^4 H^3 H^2 H, one to an element group
//! v4      the data on its way past, and the adder's scratch
//! v8      the running counters, as plain numbers
//! v12     the pass being worked on
//! v16-v30 the fifteen round keys, one register each
//! v31     the running hash
//! ```
//!
//! The round keys take four of the eight groups, which is why the
//! counters advance by a step vector loaded from memory rather than by
//! a masked add: a mask has to live in `v0`, and `v0` holds the
//! powers. During setup, before the powers are loaded, `v0` is the
//! mask that builds the first four counters.
//!
//! # The one-group lag when encrypting
//!
//! GHASH covers the ciphertext, so when encrypting the hash follows
//! the cipher within the pass: the keystream is XORed over the
//! plaintext, the result stored, and that same register hashed. When
//! decrypting the ciphertext is what arrived, so it is hashed from the
//! register it was loaded into, after the plaintext has been stored
//! out of the way.
//!
//! # Availability
//!
//! [`supported`] asks for the vector AES instructions, a byte reverse,
//! and `vgmul`. The other two carry-less multiplies RISC-V offers
//! would each need a reduction written out, which does not fit beside
//! the round keys; a processor with one of those runs GCM as the
//! portable mode over its own accelerated hash.

#![allow(unsafe_code)]

use super::super::ghash;
use super::{BLOCK, Direction};
use crate::cipher::mode::{ByteOrder, add_counter};
// Re-exported so that GCM-SIV, which runs the same counter
// under a different byte order, can name one path whatever the
// architecture is.
use crate::align::At16;
use crate::cipher::BlockCipher;
pub(crate) use crate::cipher::aes::riscv64::{Keys, keys};
use crate::cipher::aes::riscv64::{Schedule, has_vrev8, has_zvkned};

/// Blocks the loop takes at once, which is also how many powers of
/// the subkey it holds.
const GROUP: usize = 4;

/// Bytes in one group.
const SPAN: usize = GROUP * BLOCK;

static STEP: At16<[u32; 4 * GROUP]> = {
    let mut w = [0u32; 4 * GROUP];
    let mut i = 0;
    while i < GROUP {
        w[4 * i + 3] = GROUP as u32;
        i += 1;
    }
    At16(w)
};

/// Whether the loops here can run.
pub(crate) fn supported() -> bool {
    has_zvkned() && has_vrev8() && ghash::riscv64::has_vector_ghash()
}

/// Everything the hash works out from the subkey and never changes.
#[derive(Clone, Copy)]
pub(crate) struct Subkey {
    /// The subkey prepared for the multiply, for a block at a time.
    h: [u64; 2],
    /// Its first [`GROUP`] powers, highest first, which is the order
    /// the blocks of a pass meet them in.
    powers: [[u64; 2]; GROUP],
}

impl Subkey {
    /// The powers of hash subkey `h`, or `None` where this processor
    /// has not the instructions to use them.
    fn new(h: &[u8; BLOCK]) -> Option<Self> {
        if !supported() {
            return None;
        }
        let h = ghash::riscv64::zvkg::prepare(&[
            ghash::halve(&h[..8]),
            ghash::halve(&h[8..]),
        ]);
        // The powers are built with the instruction rather than the
        // portable multiply: this runs once for the key, and the
        // portable one would cost more than the first message saves.
        let mut powers = [[0u64; 2]; GROUP];
        let mut power = [1u64 << 63, 0];
        for slot in powers.iter_mut().rev() {
            // SAFETY: `supported` has just confirmed the instruction.
            unsafe { ghash::riscv64::zvkg::multiply(&mut power, &h) };
            *slot = ghash::riscv64::zvkg::prepare(&power);
        }
        Some(Subkey { h, powers })
    }
}

/// GCM's bulk work and its hash, for one key.
pub(crate) struct Engine<C> {
    keys: Keys<C>,
    subkey: Subkey,
}

/// By hand rather than derived: nothing here is a cipher, only a
/// pointer to the way to reach one's round keys, so this clones
/// whatever `C` is.
impl<C> Clone for Engine<C> {
    fn clone(&self) -> Self {
        Engine {
            keys: self.keys,
            subkey: self.subkey,
        }
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Engine<C> {
    /// The engine under hash subkey `h`, or `None` where this
    /// processor lacks the instructions or `C` is not a cipher this is
    /// written for.
    ///
    /// The loop works at one fixed width, so there is no second one to
    /// ask for: `wide` is answered with nothing.
    pub(crate) fn at_width(h: &[u8; BLOCK], wide: bool) -> Option<Self> {
        if wide {
            return None;
        }
        Some(Engine {
            keys: keys::<C>()?,
            subkey: Subkey::new(h)?,
        })
    }
}

/// One message going by: what the hash has taken in so far.
///
/// Everything else it needs it borrows from the engine, which belongs
/// to the key, so starting a message costs a pointer and nothing more.
pub(crate) struct Hasher<'a, C> {
    engine: &'a Engine<C>,
    /// The running hash, most significant word first, as
    /// [`finish`](Hasher::finish) writes it out.
    y: [u64; 2],
    /// A hash block not yet complete.
    block: [u8; BLOCK],
    used: usize,
}

impl<'a, C: BlockCipher<Block = [u8; BLOCK]>> Hasher<'a, C> {
    pub(crate) fn new(engine: &'a Engine<C>) -> Self {
        Hasher {
            engine,
            y: [0, 0],
            block: [0; BLOCK],
            used: 0,
        }
    }

    /// Adds more of the current field to the hash.
    ///
    /// A block at a time: `vgmul` does the whole multiplication,
    /// reduction included, so there is no reduction for a group to
    /// amortise and nothing for the aggregated form to save here. The
    /// powers earn their keep in the loop below, where they break the
    /// chain of dependent multiplies rather than share a reduction.
    pub(crate) fn hash(&mut self, mut data: &[u8]) {
        // Finish a block a previous call left part way through.
        if self.used > 0 {
            let take = data.len().min(BLOCK - self.used);
            self.block[self.used..self.used + take]
                .copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used < BLOCK {
                return;
            }
            let block = self.block;
            self.absorb(&block);
            self.used = 0;
        }
        let mut blocks = data.chunks_exact(BLOCK);
        for block in &mut blocks {
            self.absorb(block);
        }
        let rest = blocks.remainder();
        self.block[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
    }

    /// Ends the current field, padding it with zeros to a block.
    pub(crate) fn pad(&mut self) {
        if self.used > 0 {
            let mut block = self.block;
            block[self.used..].fill(0);
            self.absorb(&block);
            self.used = 0;
        }
    }

    /// The hash so far. Every field must have been padded first.
    pub(crate) fn finish(&self) -> [u8; BLOCK] {
        debug_assert_eq!(self.used, 0);
        let mut out = [0u8; BLOCK];
        out[..8].copy_from_slice(&self.y[0].to_be_bytes());
        out[8..].copy_from_slice(&self.y[1].to_be_bytes());
        out
    }

    /// Adds one whole block.
    fn absorb(&mut self, block: &[u8]) {
        self.y[0] ^= ghash::halve(&block[..8]);
        self.y[1] ^= ghash::halve(&block[8..BLOCK]);
        // SAFETY: the instruction was confirmed at construction.
        unsafe {
            ghash::riscv64::zvkg::multiply(&mut self.y, &self.engine.subkey.h)
        };
    }

    /// The counter over `data`, which is a whole number of blocks, and
    /// the hash of it, in one pass.
    pub(crate) fn bulk(
        &mut self,
        cipher: &C,
        counter: &mut [u8; BLOCK],
        direction: Direction,
        data: &mut [u8],
    ) {
        debug_assert_eq!(data.len() % BLOCK, 0);
        let Some(schedule) = (self.engine.keys)(cipher) else {
            debug_assert!(false, "the cipher changed under the mode");
            return;
        };
        let groups = data.len() / SPAN;
        let (whole, rest) = data.split_at_mut(groups * SPAN);
        if groups > 0 {
            let run = match (direction, schedule.rounds()) {
                (Direction::Encrypt, 10) => encrypt10,
                (Direction::Encrypt, 12) => encrypt12,
                (Direction::Encrypt, _) => encrypt14,
                (Direction::Decrypt, 10) => decrypt10,
                (Direction::Decrypt, 12) => decrypt12,
                (Direction::Decrypt, _) => decrypt14,
            };
            // The hash rides through the loop in a register, in the
            // byte order the instruction wants rather than the one the
            // digest is written in.
            let mut y = ghash::riscv64::zvkg::prepare(&self.y);
            // The block as four big-endian words: the first three are
            // fixed and the last is the counter.
            let word = |i: usize| {
                u32::from_be_bytes([
                    counter[i],
                    counter[i + 1],
                    counter[i + 2],
                    counter[i + 3],
                ])
            };
            // SAFETY: the instructions were confirmed at construction,
            // the schedule points at the whole round key array,
            // `whole` is `groups` whole groups with at least one, and
            // the powers are the ones this engine built.
            unsafe {
                run(
                    schedule.keys(),
                    word(12),
                    word(0),
                    word(4),
                    word(8),
                    whole.as_mut_ptr(),
                    groups,
                    y.as_mut_ptr(),
                    self.engine.subkey.powers.as_ptr().cast::<u32>(),
                );
            }
            self.y = ghash::riscv64::zvkg::prepare(&y);
            add_counter(counter, ByteOrder::Big, (groups * GROUP) as u32);
        }

        // Fewer than a group is left, if anything. There is not enough
        // of it to be worth running the two together, so they go in
        // turn.
        if !rest.is_empty() {
            if direction == Direction::Decrypt {
                self.hash(rest);
            }
            counter_tail(schedule, counter, rest);
            if direction == Direction::Encrypt {
                self.hash(rest);
            }
        }
    }
}

/// Counter mode over fewer than a group of blocks, a block at a time:
/// there is not enough of it for the interleaving to pay.
fn counter_tail(
    schedule: Schedule<'_>,
    counter: &mut [u8; BLOCK],
    data: &mut [u8],
) {
    for block in data.chunks_mut(BLOCK) {
        let mut keystream = *counter;
        // SAFETY: the instructions were confirmed at construction, and
        // the schedule points at the whole round key array.
        unsafe {
            encrypt_one(
                schedule.keys(),
                schedule.rounds(),
                keystream.as_mut_ptr(),
            )
        };
        for (byte, key) in block.iter_mut().zip(&keystream) {
            *byte ^= key;
        }
        add_counter(counter, ByteOrder::Big, 1);
    }
}

/// Counter mode over `data` with GCM-SIV's counter, which is the first
/// four bytes of the block, least significant first, and nothing
/// hashed beside it.
///
/// Encrypting, GCM-SIV cannot run the two together: the tag covers the
/// plaintext and the counter comes from the tag, so the hash has to
/// finish before the cipher starts. This is the cipher on its own for
/// that case, and for the tail of the other.
///
/// `data` is a whole number of blocks.
pub(crate) fn siv_counter(
    schedule: Schedule<'_>,
    counter: &mut [u8; BLOCK],
    data: &mut [u8],
) {
    debug_assert_eq!(data.len() % BLOCK, 0);
    if data.is_empty() {
        return;
    }
    let blocks = data.len() / BLOCK;
    // The block as four little-endian words, the first being the
    // counter; see the note on the loop below.
    let word = |i: usize| {
        u32::from_le_bytes([
            counter[i],
            counter[i + 1],
            counter[i + 2],
            counter[i + 3],
        ])
    };
    let run = match schedule.rounds() {
        10 => siv_counter10,
        12 => siv_counter12,
        _ => siv_counter14,
    };
    // SAFETY: the instructions were confirmed when the mode was built,
    // the schedule points at the whole round key array, and `data`
    // holds `blocks` whole blocks with at least one.
    unsafe {
        run(
            schedule.keys(),
            word(0),
            word(4),
            word(8),
            word(12),
            data.as_mut_ptr(),
            blocks,
        );
    }
    add_counter(counter, ByteOrder::Little, blocks as u32);
}

/// Defines `fn $name(rk, n, c0, c1, c2, data, blocks)`: counter mode
/// over `blocks` blocks with no hash beside it, for GCM-SIV.
///
/// GCM-SIV counts in the first word, least significant byte first,
/// which is the order the vector holds it in already: nothing to
/// reverse, and the fixed words are the other three. One call covers a
/// run of any length, because `vsetvli` takes the length from what is
/// left.
macro_rules! siv_body {
    ($name:ident, $first:literal, [$($mid:literal),*], $last:literal) => {
        /// # Safety
        /// Requires the vector AES instructions with VLEN >= 128; `rk`
        /// must point at 15 round keys and `data` at `blocks`
        /// writable blocks, `blocks >= 1`.
        unsafe fn $name(
            rk: *const u32,
            n: u32,
            c0: u32,
            c1: u32,
            c2: u32,
            data: *mut u8,
            blocks: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    ".option push",
                    ".option arch, +v, +zvkned",
                    "vsetivli zero, 4, e32, m1, ta, ma",
                    "vle32.v v16, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v17, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v18, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v19, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v20, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v21, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v22, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v23, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v24, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v25, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v26, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v27, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v28, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v29, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v30, ({rk})",
                    // Element `i` is word `i & 3` of block `i >> 2`,
                    // and word 0 is the counter.
                    "vsetvli {vl}, {avl}, e32, m4, ta, ma",
                    "vid.v v8",
                    "vand.vi v12, v8, 3",
                    "vsrl.vi v8, v8, 2",
                    "vadd.vx v8, v8, {n}",
                    "vmseq.vi v0, v12, 1",
                    "vmerge.vxm v8, v8, {c0}, v0",
                    "vmseq.vi v0, v12, 2",
                    "vmerge.vxm v8, v8, {c1}, v0",
                    "vmseq.vi v0, v12, 3",
                    "vmerge.vxm v8, v8, {c2}, v0",
                    "srli {t}, {vl}, 2",
                    "vmv.v.i v4, 0",
                    "vmseq.vi v0, v12, 0",
                    "vmerge.vxm v4, v4, {t}, v0",
                    "2:",
                    "vsetvli {vl}, {avl}, e32, m4, ta, ma",
                    "vmv.v.v v12, v8",
                    concat!("vaesz.vs v12, ", $first),
                    $(concat!("vaesem.vs v12, ", $mid),)*
                    concat!("vaesef.vs v12, ", $last),
                    "vle32.v v0, ({data})",
                    "vxor.vv v12, v12, v0",
                    "vse32.v v12, ({data})",
                    "slli {t}, {vl}, 2",
                    "add {data}, {data}, {t}",
                    "vadd.vv v8, v8, v4",
                    "sub {avl}, {avl}, {vl}",
                    "bnez {avl}, 2b",
                    ".option pop",
                    rk = inout(reg) rk => _,
                    c0 = in(reg) c0,
                    c1 = in(reg) c1,
                    c2 = in(reg) c2,
                    n = in(reg) n,
                    data = inout(reg) data => _,
                    avl = inout(reg) 4 * blocks => _,
                    vl = out(reg) _,
                    t = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                    out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                    out("v28") _, out("v29") _, out("v30") _,
                    options(nostack),
                );
            }
        }
    };
}

siv_body!(
    siv_counter10,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25"
    ],
    "v26"
);
siv_body!(
    siv_counter12,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27"
    ],
    "v28"
);
siv_body!(
    siv_counter14,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27", "v28", "v29"
    ],
    "v30"
);

/// One block through the cipher, in place, for the tail.
///
/// # Safety
/// Requires the vector AES instructions and a byte reverse; `rk` must
/// point at 15 round keys and `block` at a writable block.
unsafe fn encrypt_one(rk: *const u32, rounds: usize, block: *mut u8) {
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v, +zvkned",
            "vsetivli zero, 4, e32, m1, ta, ma",
            "vle32.v v1, ({block})",
            "vle32.v v2, ({rk})",
            "vaesz.vs v1, v2",
            "addi {k}, {rk}, 16",
            "addi {n}, {nr}, -1",
            "2:",
            "vle32.v v2, ({k})",
            "vaesem.vs v1, v2",
            "addi {k}, {k}, 16",
            "addi {n}, {n}, -1",
            "bnez {n}, 2b",
            "vle32.v v2, ({k})",
            "vaesef.vs v1, v2",
            "vse32.v v1, ({block})",
            ".option pop",
            rk = in(reg) rk,
            nr = in(reg) rounds,
            block = in(reg) block,
            k = out(reg) _,
            n = out(reg) _,
            out("v1") _, out("v2") _,
            options(nostack),
        );
    }
}

/// Defines the fused loop for one direction and one key size.
///
/// `$hash` is the register the hash takes its blocks from and `$temp`
/// the one the adding tree uses; encrypting hashes what it produced
/// and decrypting what arrived, which is the only difference between
/// the two directions.
macro_rules! body {
    ($name:ident, $first:literal, [$($mid:literal),*], $last:literal,
     $hash:literal, $temp:literal, $store:literal) => {
        /// # Safety
        /// Requires the vector AES instructions, a byte reverse and
        /// `vgmul`, with VLEN >= 128; `rk` must point at 15 round
        /// keys, `data` at `groups * 64` writable bytes with
        /// `groups >= 1`, `y` at a block and `powers` at [`GROUP`]
        /// prepared powers of the subkey, highest first.
        #[allow(clippy::too_many_arguments)]
        unsafe fn $name(
            rk: *const u32,
            n: u32,
            c0: u32,
            c1: u32,
            c2: u32,
            data: *mut u8,
            groups: usize,
            y: *mut u64,
            powers: *const u32,
        ) {
            unsafe {
                core::arch::asm!(
                    ".option push",
                    ".option arch, +v, +zvkned, +zvkb, +zvkg",
                    // The round keys, one to a register.
                    "vsetivli zero, 4, e32, m1, ta, ma",
                    "vle32.v v16, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v17, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v18, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v19, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v20, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v21, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v22, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v23, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v24, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v25, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v26, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v27, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v28, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v29, ({k})",
                    "addi {k}, {k}, 16",
                    "vle32.v v30, ({k})",
                    // The running hash, in the order the instruction
                    // wants it.
                    "vle32.v v31, ({y})",

                    // The four counters, built once. Element `i` is
                    // word `i & 3` of block `i >> 2`, and word 3 is
                    // the counter, which starts at `n` and goes up by
                    // one a block. v0 is the mask that puts the three
                    // fixed words in; the powers take it afterwards.
                    "vsetivli zero, 16, e32, m4, ta, ma",
                    "vid.v v8",
                    "vand.vi v12, v8, 3",
                    "vsrl.vi v8, v8, 2",
                    "vadd.vx v8, v8, {n}",
                    "vmseq.vi v0, v12, 0",
                    "vmerge.vxm v8, v8, {c0}, v0",
                    "vmseq.vi v0, v12, 1",
                    "vmerge.vxm v8, v8, {c1}, v0",
                    "vmseq.vi v0, v12, 2",
                    "vmerge.vxm v8, v8, {c2}, v0",
                    "vle32.v v0, ({powers})",

                    "3:",
                    // The counters through the cipher. They are held
                    // as plain numbers, so one reverse puts a whole
                    // pass into block order.
                    "vmv.v.v v12, v8",
                    "vrev8.v v12, v12",
                    concat!("vaesz.vs v12, ", $first),
                    $(concat!("vaesem.vs v12, ", $mid),)*
                    concat!("vaesef.vs v12, ", $last),
                    // The keystream never reaches memory: it is XORed
                    // over the data on the way to the one store.
                    "vle32.v v4, ({data})",
                    "vxor.vv v12, v12, v4",
                    concat!("vse32.v ", $store, ", ({data})"),

                    // The hash takes the ciphertext, whichever
                    // register that is. The running hash joins the
                    // first block of the pass and nothing after it, so
                    // only the first element group is touched.
                    "vsetivli zero, 4, e32, m1, tu, ma",
                    concat!("vxor.vv ", $hash, ", ", $hash, ", v31"),
                    "vsetivli zero, 16, e32, m4, ta, ma",
                    // Every block by its own power of the subkey, and
                    // then the four products added together: each is
                    // a term of the same sum, so the tree is two
                    // slides and two exclusive ors.
                    concat!("vgmul.vv ", $hash, ", v0"),
                    concat!("vslidedown.vi ", $temp, ", ", $hash, ", 8"),
                    concat!("vxor.vv ", $hash, ", ", $hash, ", ", $temp),
                    concat!("vslidedown.vi ", $temp, ", ", $hash, ", 4"),
                    concat!("vxor.vv ", $hash, ", ", $hash, ", ", $temp),
                    "vsetivli zero, 4, e32, m1, tu, ma",
                    concat!("vmv.v.v v31, ", $hash),

                    // On to the next four blocks.
                    "vsetivli zero, 16, e32, m4, ta, ma",
                    "vle32.v v4, ({step})",
                    "vadd.vv v8, v8, v4",
                    "addi {data}, {data}, 64",
                    "addi {groups}, {groups}, -1",
                    "bnez {groups}, 3b",

                    "vsetivli zero, 4, e32, m1, ta, ma",
                    "vse32.v v31, ({y})",
                    ".option pop",
                    k = inout(reg) rk => _,
                    n = in(reg) n,
                    c0 = in(reg) c0,
                    c1 = in(reg) c1,
                    c2 = in(reg) c2,
                    data = inout(reg) data => _,
                    groups = inout(reg) groups => _,
                    y = in(reg) y,
                    powers = in(reg) powers,
                    step = in(reg) STEP.0.as_ptr(),
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                    out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                    out("v28") _, out("v29") _, out("v30") _, out("v31") _,
                    options(nostack),
                );
            }
        }
    };
}

/// The rounds for each key size, as the key registers they run under.
macro_rules! directions {
    ($enc:ident, $dec:ident, $first:literal, [$($mid:literal),*],
     $last:literal) => {
        // Encrypting hashes what it produced, which is in v12 after
        // the exclusive or, and stores the same register.
        body!($enc, $first, [$($mid),*], $last, "v12", "v4", "v12");
        // Decrypting hashes what arrived, which is still in v4 once
        // the plaintext in v12 has been stored.
        body!($dec, $first, [$($mid),*], $last, "v4", "v12", "v12");
    };
}

directions!(
    encrypt10,
    decrypt10,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25"
    ],
    "v26"
);
directions!(
    encrypt12,
    decrypt12,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27"
    ],
    "v28"
);
directions!(
    encrypt14,
    decrypt14,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27", "v28", "v29"
    ],
    "v30"
);
