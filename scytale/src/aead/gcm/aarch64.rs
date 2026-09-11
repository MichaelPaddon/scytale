//! AES-GCM as one loop, for the ARMv8 cryptography extension.
//!
//! Counter mode and GHASH are independent of each other, and the
//! extension runs them on different pipes: `aese` and `aesmc` on the
//! one that does the cipher, `pmull` on the one that does polynomial
//! multiplication. Called one after the other, each waits while the
//! other's pipe stands idle, and the data is read and written twice.
//! Written as one loop, the hash costs little beyond the cipher it
//! rides along with.
//!
//! So this is a single loop over a group of eight blocks: the eight
//! counter blocks go through the rounds while the multiplications for
//! eight message blocks are issued between them, one to a round.
//!
//! There are thirty-two vector registers, so the blocks, the counter
//! constants, the hash's three running sums and its working pair all
//! stay in registers for the whole loop.
//!
//! # The one-group lag when encrypting
//!
//! GHASH covers the ciphertext, so when encrypting there is nothing
//! to hash until the cipher has produced it. The loop therefore
//! hashes the group before the one it is encrypting, and carries that
//! itself: it encrypts the first group with nothing beside it, runs
//! the interleaved loop over the rest, and hashes the last group on
//! the way out.
//!
//! Decrypting has no such problem, since the ciphertext is what
//! arrived, so there each group is hashed as it is decrypted.
//!
//! # Availability
//!
//! [`supported`] asks for the AES instructions and the 64-bit
//! polynomial multiply, which arrive together as the cryptography
//! extension. Without them GCM uses the generic wrapper.

#![allow(unsafe_code)]

use super::super::ghash;
use super::{BLOCK, Direction};
use crate::cipher::mode::{ByteOrder, add_counter};
// Re-exported so that GCM-SIV, which runs the same counter
// under a different byte order, can name one path whatever the
// architecture is.
use crate::align::At16;
use crate::cipher::BlockCipher;
pub(crate) use crate::cipher::aes::aarch64::{Keys, keys};
use crate::cipher::aes::aarch64::{Schedule, armv8::has_aes};

/// Blocks the loop takes at once, which is also how many powers of
/// the subkey the hash keeps.
const GROUP: usize = ghash::MAX_GROUP;

/// Bytes in one group.
const SPAN: usize = GROUP * BLOCK;

/// The field polynomial's low half in GHASH's reversed bit order.
const POLYNOMIAL: u64 = 0xc200_0000_0000_0000;

static OFFSETS: At16<[u32; 4 * GROUP + 4]> = {
    let mut w = [0u32; 4 * GROUP + 4];
    let mut i = 0;
    while i < GROUP {
        w[4 * i] = i as u32;
        i += 1;
    }
    w[4 * GROUP] = GROUP as u32;
    At16(w)
};

static BSWAP: At16<[u8; BLOCK]> =
    At16([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

/// Whether the loops here can run.
pub(crate) fn supported() -> bool {
    has_aes() && ghash::aarch64::has_carryless_multiply()
}

/// Everything the hash works out from the subkey and never changes.
#[derive(Clone, Copy)]
pub(crate) struct Subkey {
    /// The subkey prepared for the multiply, for a block at a time.
    h: [u64; 2],
    /// Its powers, `H` first, for a whole group at once.
    powers: [[u64; 2]; GROUP],
}

impl Subkey {
    /// The powers of hash subkey `h`, or `None` where this processor
    /// has not the instructions to use them.
    fn new(h: &[u8; BLOCK]) -> Option<Self> {
        if !supported() {
            return None;
        }
        let h = ghash::aarch64::prepare(&[
            ghash::halve(&h[..8]),
            ghash::halve(&h[8..]),
        ]);
        // SAFETY: `supported` has just confirmed the instructions.
        let powers = unsafe { ghash::powers_of(&h) };
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
    /// The extension works on a register of one block, so unlike
    /// x86-64 there is no wider form: `wide` is answered with
    /// nothing.
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
        let mut groups = data.chunks_exact(SPAN);
        for group in &mut groups {
            // SAFETY: confirmed at construction; a whole group.
            unsafe {
                ghash::aarch64::multiply_group(
                    &mut self.y,
                    &self.engine.subkey.powers,
                    group,
                )
            };
        }
        let mut blocks = groups.remainder().chunks_exact(BLOCK);
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
        unsafe { ghash::aarch64::multiply(&mut self.y, &self.engine.subkey.h) };
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
            let run = match direction {
                Direction::Encrypt => encrypt_groups,
                Direction::Decrypt => decrypt_groups,
            };
            // SAFETY: the instructions were confirmed at
            // construction, the schedule holds `rounds + 1` round
            // keys, `whole` is `groups` whole groups with at least
            // one, and the powers are the ones this engine built.
            unsafe {
                run(
                    schedule.keys(),
                    schedule.rounds(),
                    counter.as_mut_ptr(),
                    whole.as_mut_ptr(),
                    groups,
                    self.y.as_mut_ptr(),
                    self.engine.subkey.powers.as_ptr().cast::<u8>(),
                );
            }
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

/// Counter mode over `data` with GCM-SIV's counter, which is the first
/// four bytes of the block, least significant first, and nothing
/// hashed beside it.
///
/// Encrypting, GCM-SIV cannot run the two together: the tag covers the
/// plaintext and the counter comes from the tag, so the hash has to
/// finish before the cipher starts. This is the cipher on its own for
/// that case, and for the tail of the other.
///
/// It is simpler than GCM's own counter: that one counts in the last
/// four bytes, most significant first, and has to reverse the register
/// to put the field where a word add reaches it. GCM-SIV's field is
/// already the low word, so there is nothing to turn round either way.
///
/// `data` is a whole number of blocks.
pub(crate) fn siv_counter(
    schedule: Schedule<'_>,
    counter: &mut [u8; BLOCK],
    data: &mut [u8],
) {
    debug_assert_eq!(data.len() % BLOCK, 0);
    let (rk, rounds) = (schedule.keys(), schedule.rounds());
    let mut data = data;
    let groups = data.len() / SPAN;
    if groups > 0 {
        let (whole, rest) = data.split_at_mut(groups * SPAN);
        // SAFETY: the instructions were confirmed at construction, the
        // schedule holds `rounds + 1` round keys, and `whole` is
        // `groups` whole groups with at least one. The loop leaves
        // `counter` on the block after the last.
        unsafe {
            siv_counter_groups(
                rk,
                rounds,
                counter.as_mut_ptr(),
                whole.as_mut_ptr(),
                groups,
            );
        }
        data = rest;
    }
    // At most seven blocks are left; one at a time is enough for that.
    for block in data.chunks_mut(BLOCK) {
        let mut keystream = *counter;
        // SAFETY: as above.
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
        add_counter(counter, ByteOrder::Little, 1);
    }
}

/// Runs whole groups of GCM-SIV's counter blocks through the cipher
/// and XORs them over `data`, leaving `counter` on the block after the
/// last.
///
/// # Safety
/// Requires the AES instructions; `rk` must point at `rounds + 1`
/// round keys, `counter` at a block, and `data` at `groups * 128`
/// writable bytes, with `groups >= 1`.
#[target_feature(enable = "aes")]
unsafe fn siv_counter_groups(
    rk: *const u32,
    rounds: usize,
    counter: *mut u8,
    data: *mut u8,
    groups: usize,
) {
    unsafe {
        core::arch::asm!(
            "ld1 {{v16.16b, v17.16b, v18.16b, v19.16b}}, [{offs}], #64",
            "ld1 {{v20.16b, v21.16b, v22.16b, v23.16b}}, [{offs}], #64",
            "ld1 {{v12.16b}}, [{offs}]",
            // The base counter, as it stands: the field is already the
            // low word.
            "ld1 {{v11.16b}}, [{counter}]",
            "3:",
            "add v0.4s, v11.4s, v16.4s",
            "add v1.4s, v11.4s, v17.4s",
            "add v2.4s, v11.4s, v18.4s",
            "add v3.4s, v11.4s, v19.4s",
            "add v4.4s, v11.4s, v20.4s",
            "add v5.4s, v11.4s, v21.4s",
            "add v6.4s, v11.4s, v22.4s",
            "add v7.4s, v11.4s, v23.4s",
            "add v11.4s, v11.4s, v12.4s",
            "mov {k}, {rk}",
            "mov {n}, {nr}",
            "2:",
            "ld1 {{v8.16b}}, [{k}], #16",
            "aese v0.16b, v8.16b",
            "aesmc v0.16b, v0.16b",
            "aese v1.16b, v8.16b",
            "aesmc v1.16b, v1.16b",
            "aese v2.16b, v8.16b",
            "aesmc v2.16b, v2.16b",
            "aese v3.16b, v8.16b",
            "aesmc v3.16b, v3.16b",
            "aese v4.16b, v8.16b",
            "aesmc v4.16b, v4.16b",
            "aese v5.16b, v8.16b",
            "aesmc v5.16b, v5.16b",
            "aese v6.16b, v8.16b",
            "aesmc v6.16b, v6.16b",
            "aese v7.16b, v8.16b",
            "aesmc v7.16b, v7.16b",
            "subs {n}, {n}, #1",
            "b.ne 2b",
            "ld1 {{v8.16b, v9.16b}}, [{k}]",
            "aese v0.16b, v8.16b",
            "eor v0.16b, v0.16b, v9.16b",
            "aese v1.16b, v8.16b",
            "eor v1.16b, v1.16b, v9.16b",
            "aese v2.16b, v8.16b",
            "eor v2.16b, v2.16b, v9.16b",
            "aese v3.16b, v8.16b",
            "eor v3.16b, v3.16b, v9.16b",
            "aese v4.16b, v8.16b",
            "eor v4.16b, v4.16b, v9.16b",
            "aese v5.16b, v8.16b",
            "eor v5.16b, v5.16b, v9.16b",
            "aese v6.16b, v8.16b",
            "eor v6.16b, v6.16b, v9.16b",
            "aese v7.16b, v8.16b",
            "eor v7.16b, v7.16b, v9.16b",
            // The keystream never reaches memory: it is XORed over the
            // data on the way to the one store.
            "add {p}, {data}, #64",
            "ld1 {{v24.16b, v25.16b, v26.16b, v27.16b}}, [{data}]",
            "ld1 {{v28.16b, v29.16b, v30.16b, v31.16b}}, [{p}]",
            "eor v0.16b, v0.16b, v24.16b",
            "eor v1.16b, v1.16b, v25.16b",
            "eor v2.16b, v2.16b, v26.16b",
            "eor v3.16b, v3.16b, v27.16b",
            "eor v4.16b, v4.16b, v28.16b",
            "eor v5.16b, v5.16b, v29.16b",
            "eor v6.16b, v6.16b, v30.16b",
            "eor v7.16b, v7.16b, v31.16b",
            "st1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{data}], #64",
            "st1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{data}], #64",
            "subs {groups}, {groups}, #1",
            "b.ne 3b",
            "st1 {{v11.16b}}, [{counter}]",
            rk = in(reg) rk,
            nr = in(reg) rounds - 1,
            counter = in(reg) counter,
            data = inout(reg) data => _,
            groups = inout(reg) groups => _,
            offs = inout(reg) OFFSETS.0.as_ptr() => _,
            p = out(reg) _,
            k = out(reg) _,
            n = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v11") _, out("v12") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            out("v24") _, out("v25") _, out("v26") _, out("v27") _,
            out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            options(nostack),
        );
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
        // SAFETY: the instructions were confirmed at construction,
        // and the schedule holds `rounds + 1` round keys.
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

/// One block through the cipher, for the tail.
///
/// # Safety
/// Requires the AES instructions; `rk` must point at `rounds + 1`
/// round keys and `block` at a block.
#[target_feature(enable = "aes")]
unsafe fn encrypt_one(rk: *const u32, rounds: usize, block: *mut u8) {
    unsafe {
        core::arch::asm!(
            "ldr q0, [{block}]",
            "mov {k}, {rk}",
            "mov {n}, {nr}",
            "2:",
            "ld1 {{v1.16b}}, [{k}], #16",
            "aese v0.16b, v1.16b",
            "aesmc v0.16b, v0.16b",
            "subs {n}, {n}, #1",
            "b.ne 2b",
            "ld1 {{v1.16b, v2.16b}}, [{k}]",
            "aese v0.16b, v1.16b",
            "eor v0.16b, v0.16b, v2.16b",
            "str q0, [{block}]",
            rk = in(reg) rk,
            nr = in(reg) rounds - 1,
            block = in(reg) block,
            k = out(reg) _,
            n = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _,
            options(nostack),
        );
    }
}

// The sequences below are written once and used by both directions.
// Blocks live in v0 to v7 and round keys stream through v8 and v9;
// v10 holds the byte reversal, v11 the base counter and v12 the group
// advance, with the lane offsets in v16 to v23. The hash keeps its
// three running sums in v24, v25 and v26, the running value in v27,
// and works in v28 to v31 and v15.

/// The eight counter blocks from the base, turned back into block
/// order. `aese` takes the first round key itself, so there is no
/// exclusive or before the rounds.
macro_rules! counters {
    () => {
        concat!(
            "add v0.4s, v11.4s, v16.4s\n",
            "add v1.4s, v11.4s, v17.4s\n",
            "add v2.4s, v11.4s, v18.4s\n",
            "add v3.4s, v11.4s, v19.4s\n",
            "add v4.4s, v11.4s, v20.4s\n",
            "add v5.4s, v11.4s, v21.4s\n",
            "add v6.4s, v11.4s, v22.4s\n",
            "add v7.4s, v11.4s, v23.4s\n",
            "add v11.4s, v11.4s, v12.4s\n",
            "tbl v0.16b, {{v0.16b}}, v10.16b\n",
            "tbl v1.16b, {{v1.16b}}, v10.16b\n",
            "tbl v2.16b, {{v2.16b}}, v10.16b\n",
            "tbl v3.16b, {{v3.16b}}, v10.16b\n",
            "tbl v4.16b, {{v4.16b}}, v10.16b\n",
            "tbl v5.16b, {{v5.16b}}, v10.16b\n",
            "tbl v6.16b, {{v6.16b}}, v10.16b\n",
            "tbl v7.16b, {{v7.16b}}, v10.16b\n",
            "mov {k}, {rk}\n",
        )
    };
}

/// One round on all eight blocks.
macro_rules! round {
    () => {
        concat!(
            "ld1 {{v8.16b}}, [{k}], #16\n",
            "aese v0.16b, v8.16b\n",
            "aesmc v0.16b, v0.16b\n",
            "aese v1.16b, v8.16b\n",
            "aesmc v1.16b, v1.16b\n",
            "aese v2.16b, v8.16b\n",
            "aesmc v2.16b, v2.16b\n",
            "aese v3.16b, v8.16b\n",
            "aesmc v3.16b, v3.16b\n",
            "aese v4.16b, v8.16b\n",
            "aesmc v4.16b, v4.16b\n",
            "aese v5.16b, v8.16b\n",
            "aesmc v5.16b, v5.16b\n",
            "aese v6.16b, v8.16b\n",
            "aesmc v6.16b, v6.16b\n",
            "aese v7.16b, v8.16b\n",
            "aesmc v7.16b, v7.16b\n",
        )
    };
}

/// `$n` middle rounds and nothing else, at local label `$at`.
macro_rules! rounds {
    ($at:literal, $n:literal) => {
        concat!(
            "mov {n}, ",
            $n,
            "\n",
            $at,
            ":\n",
            round!(),
            "subs {n}, {n}, #1\n",
            "b.ne ",
            $at,
            "b\n",
        )
    };
}

/// One block of the hash.
///
/// The running value joins the first block of a group and is cleared
/// straight after, so every later block finds it zero. The powers are
/// walked backwards, so the first block meets the highest.
///
/// Three multiplications rather than four: the two middle products are
/// only wanted added together, and Karatsuba's identity gets that sum
/// from one multiplication of the operands' folded halves. The two
/// corrections are products already being accumulated, so they are
/// applied once at the reduction.
macro_rules! hash_block {
    () => {
        concat!(
            "ld1 {{v28.16b}}, [{hash}], #16\n",
            // GHASH numbers its bits backwards, so a block reversed is
            // the order the arithmetic wants.
            "rev64 v28.16b, v28.16b\n",
            "ext v28.16b, v28.16b, v28.16b, #8\n",
            "eor v28.16b, v28.16b, v27.16b\n",
            "movi v27.16b, #0\n",
            "ldr q29, [{pw}]\n",
            "sub {pw}, {pw}, #16\n",
            "ext v30.16b, v28.16b, v28.16b, #8\n",
            "eor v30.16b, v30.16b, v28.16b\n",
            "ext v31.16b, v29.16b, v29.16b, #8\n",
            "eor v31.16b, v31.16b, v29.16b\n",
            "pmull v15.1q, v28.1d, v29.1d\n",
            "eor v24.16b, v24.16b, v15.16b\n",
            "pmull2 v15.1q, v28.2d, v29.2d\n",
            "eor v26.16b, v26.16b, v15.16b\n",
            "pmull v15.1q, v30.1d, v31.1d\n",
            "eor v25.16b, v25.16b, v15.16b\n",
        )
    };
}

/// The sums cleared, ready for a group.
macro_rules! clear_sums {
    () => {
        concat!(
            "movi v24.16b, #0\n",
            "movi v25.16b, #0\n",
            "movi v26.16b, #0\n",
        )
    };
}

/// Seven rounds with seven blocks of the hash beside them, at local
/// label `$at`.
///
/// Seven because the eighth block of the group is hashed before the
/// rounds begin, and because the shortest key width has that many
/// middle rounds to spare.
macro_rules! rounds_and_hash {
    ($at:literal) => {
        concat!(
            "mov {n}, 7\n",
            $at,
            ":\n",
            round!(),
            hash_block!(),
            "subs {n}, {n}, #1\n",
            "b.ne ",
            $at,
            "b\n",
        )
    };
}

/// The rest of a group's hash and nothing else, at local label `$at`:
/// seven blocks, for the last group of an encryption.
macro_rules! hash_rest {
    ($at:literal) => {
        concat!(
            "mov {n}, 7\n",
            $at,
            ":\n",
            hash_block!(),
            "subs {n}, {n}, #1\n",
            "b.ne ",
            $at,
            "b\n",
        )
    };
}

/// The last round, and the keystream XORed over the data on the way to
/// a single store, so it never reaches memory.
macro_rules! finish_group {
    () => {
        concat!(
            "ld1 {{v8.16b, v9.16b}}, [{k}]\n",
            "aese v0.16b, v8.16b\n",
            "eor v0.16b, v0.16b, v9.16b\n",
            "aese v1.16b, v8.16b\n",
            "eor v1.16b, v1.16b, v9.16b\n",
            "aese v2.16b, v8.16b\n",
            "eor v2.16b, v2.16b, v9.16b\n",
            "aese v3.16b, v8.16b\n",
            "eor v3.16b, v3.16b, v9.16b\n",
            "aese v4.16b, v8.16b\n",
            "eor v4.16b, v4.16b, v9.16b\n",
            "aese v5.16b, v8.16b\n",
            "eor v5.16b, v5.16b, v9.16b\n",
            "aese v6.16b, v8.16b\n",
            "eor v6.16b, v6.16b, v9.16b\n",
            "aese v7.16b, v8.16b\n",
            "eor v7.16b, v7.16b, v9.16b\n",
            "ldr q13, [{data}]\n",
            "ldr q14, [{data}, #16]\n",
            "eor v0.16b, v0.16b, v13.16b\n",
            "eor v1.16b, v1.16b, v14.16b\n",
            "ldr q13, [{data}, #32]\n",
            "ldr q14, [{data}, #48]\n",
            "eor v2.16b, v2.16b, v13.16b\n",
            "eor v3.16b, v3.16b, v14.16b\n",
            "ldr q13, [{data}, #64]\n",
            "ldr q14, [{data}, #80]\n",
            "eor v4.16b, v4.16b, v13.16b\n",
            "eor v5.16b, v5.16b, v14.16b\n",
            "ldr q13, [{data}, #96]\n",
            "ldr q14, [{data}, #112]\n",
            "eor v6.16b, v6.16b, v13.16b\n",
            "eor v7.16b, v7.16b, v14.16b\n",
            "st1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{data}], #64\n",
            "st1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{data}], #64\n",
        )
    };
}

/// One reduction for the whole group, and the table of powers wound
/// back to where the next group's first block will find it.
macro_rules! reduce {
    () => {
        concat!(
            // The middle sum wants the other two products added in.
            "eor v25.16b, v25.16b, v24.16b\n",
            "eor v25.16b, v25.16b, v26.16b\n",
            // It belongs half in each of the other two.
            "movi v15.16b, #0\n",
            "ext v30.16b, v15.16b, v25.16b, #8\n",
            "ext v31.16b, v25.16b, v15.16b, #8\n",
            "eor v24.16b, v24.16b, v30.16b\n",
            "eor v26.16b, v26.16b, v31.16b\n",
            // Fold the excess down in two halves.
            "fmov d28, {poly}\n",
            "pmull v30.1q, v28.1d, v24.1d\n",
            "ext v31.16b, v24.16b, v24.16b, #8\n",
            "eor v31.16b, v31.16b, v30.16b\n",
            "pmull v30.1q, v28.1d, v31.1d\n",
            "ext v24.16b, v31.16b, v31.16b, #8\n",
            "eor v24.16b, v24.16b, v30.16b\n",
            "eor v26.16b, v26.16b, v24.16b\n",
            // The running value, ready for the next group.
            "mov v27.16b, v26.16b\n",
            "add {pw}, {pw}, #128\n",
        )
    };
}

/// Loads the constants, the base counter and the running value, and
/// points the table of powers at the one a group's first block meets.
macro_rules! prologue {
    () => {
        concat!(
            "ld1 {{v16.16b, v17.16b, v18.16b, v19.16b}}, [{offs}], #64\n",
            "ld1 {{v20.16b, v21.16b, v22.16b, v23.16b}}, [{offs}], #64\n",
            "ld1 {{v12.16b}}, [{offs}]\n",
            "ld1 {{v10.16b}}, [{bswap}]\n",
            // The base counter, byte-reversed so the field adds.
            "ld1 {{v11.16b}}, [{counter}]\n",
            "tbl v11.16b, {{v11.16b}}, v10.16b\n",
            "ld1 {{v27.2d}}, [{y}]\n",
            "ext v27.16b, v27.16b, v27.16b, #8\n",
            "add {pw}, {pw}, #112\n",
        )
    };
}

/// Hands the counter and the running value back the way they arrived.
macro_rules! epilogue {
    () => {
        concat!(
            "ext v27.16b, v27.16b, v27.16b, #8\n",
            "st1 {{v27.2d}}, [{y}]\n",
            "tbl v11.16b, {{v11.16b}}, v10.16b\n",
            "st1 {{v11.16b}}, [{counter}]\n",
        )
    };
}

/// Decrypts `groups` groups in place and hashes them as it goes.
///
/// # Safety
/// Requires the AES instructions and the polynomial multiply. `rk`
/// must point at `rounds + 1` round keys and `counter` at a block.
/// `data` must be `groups * 128` writable bytes with `groups >= 1`.
/// `y` is the running hash and `powers` the eight prepared powers of
/// the subkey, `H` first.
#[target_feature(enable = "aes")]
unsafe fn decrypt_groups(
    rk: *const u32,
    rounds: usize,
    counter: *mut u8,
    data: *mut u8,
    groups: usize,
    y: *mut u64,
    powers: *const u8,
) {
    unsafe {
        core::arch::asm!(
            prologue!(),
            "3:",
            clear_sums!(),
            // The ciphertext is what arrived, so the group is hashed
            // where it lies, before the store below overwrites it.
            hash_block!(),
            counters!(),
            rounds_and_hash!("2"),
            rounds!("4", "{nr}"),
            finish_group!(),
            reduce!(),
            "subs {groups}, {groups}, #1",
            "b.ne 3b",
            epilogue!(),
            rk = in(reg) rk,
            nr = in(reg) rounds - 8,
            counter = in(reg) counter,
            data = inout(reg) data => _,
            hash = inout(reg) data => _,
            groups = inout(reg) groups => _,
            y = in(reg) y,
            pw = inout(reg) powers => _,
            k = out(reg) _,
            n = out(reg) _,
            offs = inout(reg) OFFSETS.0.as_ptr() => _,
            bswap = in(reg) BSWAP.0.as_ptr(),
            poly = in(reg) POLYNOMIAL,
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

/// Encrypts `groups` groups in place and hashes them as it goes, a
/// group behind.
///
/// # Safety
/// As [`decrypt_groups`].
#[target_feature(enable = "aes")]
unsafe fn encrypt_groups(
    rk: *const u32,
    rounds: usize,
    counter: *mut u8,
    data: *mut u8,
    groups: usize,
    y: *mut u64,
    powers: *const u8,
) {
    unsafe {
        core::arch::asm!(
            prologue!(),
            // The first group has nothing to hash alongside it, so it
            // goes through the rounds on its own.
            counters!(),
            "mov {n}, {nr}",
            "add {n}, {n}, #7",
            "5:",
            round!(),
            "subs {n}, {n}, #1",
            "b.ne 5b",
            finish_group!(),
            "subs {groups}, {groups}, #1",
            "b.eq 6f",

            // Every group after it is encrypted while the one before
            // it is hashed.
            "3:",
            clear_sums!(),
            hash_block!(),
            counters!(),
            rounds_and_hash!("2"),
            rounds!("4", "{nr}"),
            finish_group!(),
            reduce!(),
            "subs {groups}, {groups}, #1",
            "b.ne 3b",

            // Which leaves the last group unhashed.
            "6:",
            clear_sums!(),
            hash_block!(),
            hash_rest!("7"),
            reduce!(),
            epilogue!(),
            rk = in(reg) rk,
            nr = in(reg) rounds - 8,
            counter = in(reg) counter,
            data = inout(reg) data => _,
            hash = inout(reg) data => _,
            groups = inout(reg) groups => _,
            y = in(reg) y,
            pw = inout(reg) powers => _,
            k = out(reg) _,
            n = out(reg) _,
            offs = inout(reg) OFFSETS.0.as_ptr() => _,
            bswap = in(reg) BSWAP.0.as_ptr(),
            poly = in(reg) POLYNOMIAL,
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
