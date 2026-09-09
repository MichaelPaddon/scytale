//! AES-GCM as one implementation, for processors that have both the
//! AES instructions and the carry-less multiply.
//!
//! Counter mode and GHASH are independent of each other, and on this
//! processor they are not even served by the same execution ports:
//! `aesenc` issues on the vector ports that do shuffles and integer
//! multiplies, `pclmulqdq` on the one that does carry-less
//! multiplication. Called one after the other, each waits while the
//! other's port stands idle. Written as one loop, the hash costs very
//! little beyond the cipher it rides along with.
//!
//! So this is not the two called in turn. It is a single loop over a
//! group of eight blocks: eight counter blocks go through the rounds
//! while the multiplications for eight message blocks are issued
//! between them, one to a round.
//!
//! Everything the loop needs it owns: the running hash, the powers of
//! the subkey, and the block a short piece left part way through.
//! Nothing here reaches into the portable hash, and nothing there
//! reaches in here.
//!
//! # The one-group lag when encrypting
//!
//! GHASH covers the ciphertext, so when encrypting there is nothing
//! to hash until the cipher has produced it. The loop therefore hashes
//! the group before the one it is encrypting, and the assembly carries
//! that itself: it encrypts the first group with nothing beside it,
//! runs the interleaved loop over the rest, and hashes the last group
//! on the way out.
//!
//! Decrypting has no such problem, since the ciphertext is what
//! arrived, so there each group is hashed as it is decrypted.
//!
//! # Availability
//!
//! [`supported`] asks for AES-NI, SSSE3 and `pclmulqdq`. Without them
//! there is no engine here and GCM uses the generic wrapper, which
//! reaches the same answer with the counter loop and the group hash
//! this processor does have.

#![allow(unsafe_code)]

use core::any::Any;
use core::sync::atomic::{AtomicU8, Ordering};

use super::{BLOCK, Direction};
use crate::cipher::aes::x86_64::{Keyed, Schedule, has_aesni};
use crate::cipher::aes::{Aes, Aes128, Aes192, Aes256};
use crate::cipher::{BlockCipher, is};

/// Blocks the loop takes at once, which is also how many powers of
/// the subkey it keeps.
const GROUP: usize = 8;

/// Bytes in one group.
const SPAN: usize = GROUP * BLOCK;

/// Blocks the wider loop takes at once: the same eight registers,
/// two blocks in each.
const WIDE_GROUP: usize = 2 * GROUP;

/// Bytes in one of its groups.
const WIDE_SPAN: usize = WIDE_GROUP * BLOCK;

/// The field polynomial's low half in GHASH's reversed bit order,
/// where the reduction can reach it without a register to hold it.
static POLYNOMIAL: u64 = 0xc200_0000_0000_0000;

/// Constants the loops read, at the width they load them. Their
/// contents are named only by the assembly, which reaches them by
/// symbol rather than through a pointer the compiler can follow.
#[repr(align(16))]
struct Mask(#[allow(dead_code)] [u8; BLOCK]);

#[repr(align(16))]
struct Words<const N: usize>(#[allow(dead_code)] [u32; N]);

/// Reverses the bytes of a register.
///
/// One mask for two jobs. GCM's counter is the last four bytes of a
/// block, most significant first; reversed, it is the low doubleword,
/// where a doubleword add can reach it. And GHASH numbers its bits
/// backwards, so a block reversed is a block in the order the
/// multiplication below wants.
static BSWAP: Mask =
    Mask([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

/// What each register adds to the base counter to make its block,
/// and after those, in the ninth place, what the base itself moves on
/// by once a group is made: one group's worth.
static OFFSETS: Words<{ 4 * (GROUP + 1) }> = {
    let mut w = [0u32; 4 * (GROUP + 1)];
    let mut i = 0;
    while i <= GROUP {
        w[4 * i] = i as u32;
        i += 1;
    }
    Words(w)
};

/// The wider width takes two blocks to a register, so the counters
/// come in pairs and the base moves on by sixteen blocks at a time.
static WIDE_OFFSETS: Words<{ 8 * (WIDE_GROUP / 2 + 1) }> = {
    let mut w = [0u32; 8 * (WIDE_GROUP / 2 + 1)];
    let mut i = 0;
    while i < WIDE_GROUP / 2 {
        w[8 * i] = 2 * i as u32;
        w[8 * i + 4] = 2 * i as u32 + 1;
        i += 1;
    }
    w[8 * (WIDE_GROUP / 2)] = WIDE_GROUP as u32;
    w[8 * (WIDE_GROUP / 2) + 4] = WIDE_GROUP as u32;
    Words(w)
};

/// The powers of the subkey, `H` first.
///
/// Aligned because the loops name them as memory operands rather than
/// loading each into a register first, and the older vector
/// instructions require a sixteen byte boundary of an operand they
/// read from memory.
#[repr(align(16))]
#[derive(Clone, Copy)]
struct Powers([[u64; 2]; GROUP]);

/// The powers the wider loop wants, which is twice as many and in the
/// order its lanes meet them.
///
/// A register there holds two blocks, the earlier of the two in the
/// low half, and the earlier block meets the higher power. So each
/// entry is a pair, the higher power below the lower, and the table
/// is walked backwards exactly as the narrower one is.
#[repr(align(32))]
#[derive(Clone, Copy)]
struct WidePowers([[u64; 2]; WIDE_GROUP]);

/// Reads eight bytes as a big-endian word, which is how GHASH's bit
/// order maps onto integers.
fn halve(bytes: &[u8]) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    u64::from_be_bytes(word)
}

/// Divides the subkey by `x` and puts its halves in the order a
/// register wants them, least significant first.
///
/// GHASH's bit order makes a block held as two big-endian words the
/// reversal of the natural integer, and reversing turns a product
/// into the reversal of the product shifted up one place, because a
/// product of two degree-127 polynomials has degree 254 rather than
/// 255. That leftover place would cost a 256-bit shift on every
/// block; dividing the subkey by `x` once, here, brings every product
/// out already in place.
///
/// Division by `x` is the reverse of multiplication by it: the top
/// bit says whether the polynomial was folded in on the way, so it
/// both selects the term to undo and supplies the bit that comes back
/// at the bottom. A mask rather than a branch, because the subkey is
/// secret.
fn prepare(h: &[u64; 2]) -> [u64; 2] {
    let bit = h[0] >> 63;
    let mask = 0u64.wrapping_sub(bit);
    let high = h[0] ^ (mask & (0xe1 << 56));
    let low = h[1];
    [(low << 1) | bit, (high << 1) | (low >> 63)]
}

/// The first [`GROUP`] powers of the subkey, each prepared, given the
/// subkey already prepared.
///
/// Worked out once for the key rather than once for the message: the
/// mode keeps an engine and clones it, so this is paid for at
/// [`Gcm::new`](super::Gcm::new).
///
/// # Safety
/// Requires `pclmulqdq` and SSSE3.
unsafe fn powers_of(h: &[u64; 2]) -> Powers {
    let mut powers = Powers([[0u64; 2]; GROUP]);
    let mut power = [1u64 << 63, 0];
    for slot in powers.0.iter_mut() {
        // SAFETY: the caller has confirmed the instructions.
        unsafe { multiply(&mut power, h) };
        *slot = prepare(&power);
    }
    powers
}

/// The [`WIDE_GROUP`] powers, in the order the pairs of lanes meet
/// them.
///
/// # Safety
/// Requires `pclmulqdq` and AVX.
unsafe fn wide_powers_of(h: &[u64; 2]) -> WidePowers {
    let mut ascending = [[0u64; 2]; WIDE_GROUP];
    let mut power = [1u64 << 63, 0];
    for slot in ascending.iter_mut() {
        // SAFETY: the caller has confirmed the instructions.
        unsafe { multiply(&mut power, h) };
        *slot = prepare(&power);
    }
    let mut wide = WidePowers([[0u64; 2]; WIDE_GROUP]);
    for (j, pair) in wide.0.chunks_exact_mut(2).enumerate() {
        pair[0] = ascending[2 * j + 1];
        pair[1] = ascending[2 * j];
    }
    wide
}

/// Whether this processor has everything the loop below uses. Probed
/// once: 0 unknown, 1 no, 2 yes.
static PROBED: AtomicU8 = AtomicU8::new(0);

/// Whether the processor has `pclmulqdq` (CPUID leaf 1, ECX bit 1),
/// AVX (bit 28), and an operating system that has turned the wider
/// register state on (bit 27, then XCR0 bits 1 and 2).
///
/// AVX is asked for not to work on wider registers but for the way
/// the instructions are written down. The VEX encoding of the same
/// 128-bit instructions takes three operands where the original takes
/// two, so a product can be written somewhere other than over one of
/// its own inputs. Without it every multiplication needs a copy of
/// its operand first, and those copies contend for the very ports the
/// cipher is trying to use. It is a separate question from VAES, and
/// answered yes by every processor built since about 2011.
fn has_vex_and_carryless_multiply() -> bool {
    use core::arch::x86_64::{__cpuid, _xgetbv};
    let leaf1 = __cpuid(1);
    let wanted = (1 << 1) | (1 << 27) | (1 << 28);
    if leaf1.ecx & wanted != wanted {
        return false;
    }
    // SAFETY: OSXSAVE was just confirmed, so XGETBV is available.
    let xcr0 = unsafe { _xgetbv(0) };
    xcr0 & 0b110 == 0b110
}

/// Whether the wider loop can run here as well: VAES and
/// VPCLMULQDQ, which have shipped together on every processor that
/// has either (leaf 7, ECX bits 9 and 10), AVX2 (leaf 7, EBX bit 5),
/// and the operating system saving the upper halves.
///
/// Asked separately from [`supported`], and only ever narrowing what
/// that allows: a processor with these runs the wider loop over as
/// much of a message as it covers and the narrower one over the rest.
fn wide_supported() -> bool {
    use core::arch::x86_64::__cpuid_count;
    if !supported() {
        return false;
    }
    let leaf7 = __cpuid_count(7, 0);
    let wanted = (1 << 9) | (1 << 10);
    leaf7.ecx & wanted == wanted && leaf7.ebx & (1 << 5) != 0
}

/// Whether the loops here can run: AES-NI and SSSE3, which
/// [`has_aesni`] asks for together, and `pclmulqdq` with AVX.
pub(crate) fn supported() -> bool {
    match PROBED.load(Ordering::Relaxed) {
        0 => {
            let yes = has_aesni() && has_vex_and_carryless_multiply();
            PROBED.store(1 + u8::from(yes), Ordering::Relaxed);
            yes
        }
        n => n == 2,
    }
}

/// How to reach the round keys of the cipher the mode was built over.
///
/// Settled when the mode is built, because which implementation
/// expanded the key is the processor's to decide and only the object
/// knows.
type Keys<C> = for<'a> fn(&'a C) -> Option<Schedule<'a>>;

/// What AES-GCM's bulk work needs and what it does not change: the
/// way to the round keys, and the powers of the hash subkey.
///
/// This belongs to the key, so the mode holds one and every message
/// borrows it. The powers are worked out once here rather than once
/// per message, and a message short enough never to reach a group
/// copies none of them.
pub(crate) struct Engine<C> {
    keys: Keys<C>,
    /// The subkey prepared for the multiply, for a block at a time.
    h: [u64; 2],
    /// Its powers, `H` first, for a whole group at once.
    powers: Powers,
    /// Twice as many, in the order the wider loop's lanes meet them,
    /// where this processor has the wider instructions.
    wide: Option<WidePowers>,
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Engine<C> {
    /// The engine under hash subkey `h`, or `None` where this
    /// processor lacks the instructions or `C` is not a cipher this
    /// is written for.
    pub(crate) fn new(h: &[u8; BLOCK]) -> Option<Self> {
        if !supported() {
            return None;
        }
        let h = prepare(&[halve(&h[..8]), halve(&h[8..])]);
        // SAFETY: `supported` has just confirmed the instructions.
        let powers = unsafe { powers_of(&h) };
        // SAFETY: as above.
        let wide = wide_supported().then(|| unsafe { wide_powers_of(&h) });
        Some(Engine {
            keys: keys::<C>()?,
            h,
            powers,
            wide,
        })
    }
}

/// By hand rather than derived: nothing here is a cipher, only a
/// pointer to the way to reach one's round keys, so this clones
/// whatever `C` is.
impl<C> Clone for Engine<C> {
    fn clone(&self) -> Self {
        Engine {
            keys: self.keys,
            h: self.h,
            powers: self.powers,
            wide: self.wide,
        }
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
            self.absorb(&block, 1);
            self.used = 0;
        }
        let mut runs = data.chunks_exact(SPAN);
        for run in &mut runs {
            self.absorb(run, GROUP);
        }
        let data = runs.remainder();
        let blocks = data.len() / BLOCK;
        if blocks > 0 {
            self.absorb(&data[..blocks * BLOCK], blocks);
        }
        let rest = &data[blocks * BLOCK..];
        self.block[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
    }

    /// Ends the current field, padding it with zeros to a block.
    pub(crate) fn pad(&mut self) {
        if self.used > 0 {
            let mut block = self.block;
            block[self.used..].fill(0);
            self.absorb(&block, 1);
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

    /// Adds a run of `blocks` whole blocks, one to a group's worth,
    /// with a single reduction at the end.
    fn absorb(&mut self, data: &[u8], blocks: usize) {
        debug_assert_eq!(data.len(), blocks * BLOCK);
        debug_assert!((1..=GROUP).contains(&blocks));
        // The first block of a run meets the highest power it needs,
        // and the last meets `H`.
        let pw = &self.engine.powers.0[blocks - 1];
        // SAFETY: the instructions were confirmed at construction,
        // `data` is `blocks` blocks and `blocks` is within the table.
        unsafe {
            hash_blocks(
                self.y.as_mut_ptr(),
                (pw as *const [u64; 2]).cast::<u8>(),
                data.as_ptr(),
                blocks,
            )
        };
    }

    /// The counter over `data` and the hash of it, in one pass.
    ///
    /// `data` is a whole number of blocks. Whole groups go through
    /// the loop below; what is left over, always fewer than eight
    /// blocks, goes through the counter loop and the hash in turn,
    /// which for a tail that size is no slower.
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
        // The widest loop this processor has, then the narrower one
        // for what a group of that width could not cover, then the
        // odd blocks. Each loop leaves the counter and the running
        // hash finished with what it took, so they follow one another
        // with nothing to arrange in between.
        let mut rest = data;
        let wide = self.engine.wide.as_ref().map(|w| w.0.as_ptr().cast::<u8>());
        if let Some(powers) = wide {
            let groups = rest.len() / WIDE_SPAN;
            if groups > 0 {
                let (whole, after) = rest.split_at_mut(groups * WIDE_SPAN);
                let run = match direction {
                    Direction::Encrypt => wide_encrypt_groups,
                    Direction::Decrypt => wide_decrypt_groups,
                };
                // SAFETY: the instructions were confirmed at
                // construction, the schedule holds `rounds + 1` round
                // keys, `whole` is `groups` whole groups with at
                // least one, and the powers are the ones this engine
                // built for that width.
                unsafe {
                    run(
                        schedule.keys(),
                        schedule.rounds(),
                        counter.as_mut_ptr(),
                        whole.as_mut_ptr(),
                        groups,
                        self.y.as_mut_ptr(),
                        powers,
                    );
                }
                rest = after;
            }
        }

        let groups = rest.len() / SPAN;
        if groups > 0 {
            let (whole, after) = rest.split_at_mut(groups * SPAN);
            let run = match direction {
                Direction::Encrypt => encrypt_groups,
                Direction::Decrypt => decrypt_groups,
            };
            // SAFETY: as above, at the narrower width.
            unsafe {
                run(
                    schedule.keys(),
                    schedule.rounds(),
                    counter.as_mut_ptr(),
                    whole.as_mut_ptr(),
                    groups,
                    self.y.as_mut_ptr(),
                    self.engine.powers.0.as_ptr().cast::<u8>(),
                );
            }
            rest = after;
        }
        // Fewer than a group is left, if anything. There is not
        // enough of it to be worth interleaving, so it goes through
        // one pass of exactly its width and is hashed either side.
        if !rest.is_empty() {
            let blocks = rest.len() / BLOCK;
            if direction == Direction::Decrypt {
                self.hash(rest);
            }
            // SAFETY: as above, and `blocks` is 1 to 7, which indexes
            // the table, with `rest` exactly that many blocks.
            unsafe {
                TAILS[blocks - 1](
                    schedule.keys(),
                    schedule.rounds(),
                    counter.as_ptr(),
                    rest.as_mut_ptr(),
                );
            }
            advance(counter, blocks as u32);
            if direction == Direction::Encrypt {
                self.hash(rest);
            }
        }
    }
}

/// Answers [`keys`] for one group of types.
macro_rules! arms {
    ($($ty:ty),* $(,)?) => {
        $(
            if is::<$ty, C>() {
                return Some(|cipher| {
                    let any = cipher as &dyn Any;
                    any.downcast_ref::<$ty>().and_then(Keyed::schedule)
                });
            }
        )*
    };
}

/// How to reach `C`'s round keys, or `None` if `C` is not a cipher
/// whose keys these instructions could read.
///
/// Asked once, when the mode is built. `C` is a type parameter, so
/// every comparison is a constant and all but one folds away.
fn keys<C: BlockCipher<Block = [u8; BLOCK]>>() -> Option<Keys<C>> {
    arms!(
        Aes128,
        Aes192,
        Aes256,
        Aes<16>,
        Aes<24>,
        Aes<32>,
        crate::cipher::aes::x86_64::aesni::Aes<16>,
        crate::cipher::aes::x86_64::aesni::Aes<24>,
        crate::cipher::aes::x86_64::aesni::Aes<32>,
        crate::cipher::aes::x86_64::vaes::Aes<16>,
        crate::cipher::aes::x86_64::vaes::Aes<24>,
        crate::cipher::aes::x86_64::vaes::Aes<32>,
    );
    None
}

// The assembly below is built out of the pieces that follow, so that
// each is written once and the three sequences that use them - encrypt
// only, encrypt and hash together, hash only - read as what they are.
// Blocks live in xmm0..xmm7 and round keys stream through xmm8; xmm9
// holds the base counter and xmm10 the byte reversal; xmm11, xmm12 and
// xmm13 hold the low, middle and high thirds of the group's unreduced
// sum; xmm14 and xmm15 are the hash's working pair, and between groups
// xmm15 carries the running hash.

// Every sequence below is written once and used at both widths. The
// register prefix `$p` is "xmm" or "ymm" and `$w` is how many bytes
// one of them holds, so the same text names one block or two; `$bc`
// is how a 128-bit constant is brought in, which at the wider width
// means broadcasting it into both halves. Eight registers hold the
// group either way, so the shape of the loop, the number of hash
// steps and the rounds they sit beside are the same at both.
//
// Blocks live in registers 0 to 7 and round keys stream through 8;
// 9 holds the base counter and 10 the byte reversal; 11, 12 and 13
// hold the low, middle and high thirds of the group's unreduced sum;
// 14 and 15 are the hash's working pair, and between groups 15
// carries the running hash.

/// The eight counter registers from the base, and the round key they
/// start with. Leaves the base on the block after the last.
macro_rules! counters {
    ($p:literal, $w:literal, $bc:literal) => {
        concat!(
            "vpaddd ",
            $p,
            "0, ",
            $p,
            "9, [rip + {offs} + 0*",
            $w,
            "]\n",
            "vpaddd ",
            $p,
            "1, ",
            $p,
            "9, [rip + {offs} + 1*",
            $w,
            "]\n",
            "vpaddd ",
            $p,
            "2, ",
            $p,
            "9, [rip + {offs} + 2*",
            $w,
            "]\n",
            "vpaddd ",
            $p,
            "3, ",
            $p,
            "9, [rip + {offs} + 3*",
            $w,
            "]\n",
            "vpaddd ",
            $p,
            "4, ",
            $p,
            "9, [rip + {offs} + 4*",
            $w,
            "]\n",
            "vpaddd ",
            $p,
            "5, ",
            $p,
            "9, [rip + {offs} + 5*",
            $w,
            "]\n",
            "vpaddd ",
            $p,
            "6, ",
            $p,
            "9, [rip + {offs} + 6*",
            $w,
            "]\n",
            "vpaddd ",
            $p,
            "7, ",
            $p,
            "9, [rip + {offs} + 7*",
            $w,
            "]\n",
            "vpaddd ",
            $p,
            "9, ",
            $p,
            "9, [rip + {offs} + 8*",
            $w,
            "]\n",
            "vpshufb ",
            $p,
            "0, ",
            $p,
            "0, ",
            $p,
            "10\n",
            "vpshufb ",
            $p,
            "1, ",
            $p,
            "1, ",
            $p,
            "10\n",
            "vpshufb ",
            $p,
            "2, ",
            $p,
            "2, ",
            $p,
            "10\n",
            "vpshufb ",
            $p,
            "3, ",
            $p,
            "3, ",
            $p,
            "10\n",
            "vpshufb ",
            $p,
            "4, ",
            $p,
            "4, ",
            $p,
            "10\n",
            "vpshufb ",
            $p,
            "5, ",
            $p,
            "5, ",
            $p,
            "10\n",
            "vpshufb ",
            $p,
            "6, ",
            $p,
            "6, ",
            $p,
            "10\n",
            "vpshufb ",
            $p,
            "7, ",
            $p,
            "7, ",
            $p,
            "10\n",
            $bc,
            " ",
            $p,
            "8, [{rk}]\n",
            "vpxor ",
            $p,
            "0, ",
            $p,
            "0, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "1, ",
            $p,
            "1, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "2, ",
            $p,
            "2, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "3, ",
            $p,
            "3, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "4, ",
            $p,
            "4, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "5, ",
            $p,
            "5, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "6, ",
            $p,
            "6, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "7, ",
            $p,
            "7, ",
            $p,
            "8\n",
            "lea {k}, [{rk} + 16]\n",
        )
    };
}

/// One round on every block in the group.
macro_rules! round {
    ($p:literal, $bc:literal) => {
        concat!(
            $bc,
            " ",
            $p,
            "8, [{k}]\n",
            "vaesenc ",
            $p,
            "0, ",
            $p,
            "0, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "1, ",
            $p,
            "1, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "2, ",
            $p,
            "2, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "3, ",
            $p,
            "3, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "4, ",
            $p,
            "4, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "5, ",
            $p,
            "5, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "6, ",
            $p,
            "6, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "7, ",
            $p,
            "7, ",
            $p,
            "8\n",
            "add {k}, 16\n",
        )
    };
}

/// `$n` middle rounds and nothing else, at local label `$at`.
macro_rules! rounds {
    ($at:literal, $n:literal, $p:literal, $bc:literal) => {
        concat!(
            "mov {n}, ",
            $n,
            "\n",
            $at,
            ":\n",
            round!($p, $bc),
            "dec {n}\n",
            "jnz ",
            $at,
            "b\n",
        )
    };
}

/// The group's first hash step: the one the running hash joins, and
/// the one that starts the sums rather than adding to them.
///
/// The powers are walked backwards, so this meets the highest of them
/// and the last step of the group meets `H` itself. At the wider
/// width each step covers two blocks in two lanes, and the running
/// hash, which sits alone in the low one, joins only the first.
macro_rules! ghash_first {
    ($p:literal, $w:literal) => {
        concat!(
            "vmovdqu ",
            $p,
            "14, [{hash}]\n",
            "vpshufb ",
            $p,
            "14, ",
            $p,
            "14, ",
            $p,
            "10\n",
            "vpxor ",
            $p,
            "14, ",
            $p,
            "14, ",
            $p,
            "15\n",
            "vpclmulqdq ",
            $p,
            "11, ",
            $p,
            "14, [{pw}], 0x00\n",
            "vpclmulqdq ",
            $p,
            "13, ",
            $p,
            "14, [{pw}], 0x11\n",
            "vpclmulqdq ",
            $p,
            "12, ",
            $p,
            "14, [{pw}], 0x10\n",
            "vpclmulqdq ",
            $p,
            "14, ",
            $p,
            "14, [{pw}], 0x01\n",
            "vpxor ",
            $p,
            "12, ",
            $p,
            "12, ",
            $p,
            "14\n",
            "add {hash}, ",
            $w,
            "\n",
            "sub {pw}, ",
            $w,
            "\n",
        )
    };
}

/// Any later step of the group, which adds to the sums.
macro_rules! ghash_next {
    ($p:literal, $w:literal) => {
        concat!(
            "vmovdqu ",
            $p,
            "14, [{hash}]\n",
            "vpshufb ",
            $p,
            "14, ",
            $p,
            "14, ",
            $p,
            "10\n",
            "vpclmulqdq ",
            $p,
            "15, ",
            $p,
            "14, [{pw}], 0x00\n",
            "vpxor ",
            $p,
            "11, ",
            $p,
            "11, ",
            $p,
            "15\n",
            "vpclmulqdq ",
            $p,
            "15, ",
            $p,
            "14, [{pw}], 0x11\n",
            "vpxor ",
            $p,
            "13, ",
            $p,
            "13, ",
            $p,
            "15\n",
            "vpclmulqdq ",
            $p,
            "15, ",
            $p,
            "14, [{pw}], 0x10\n",
            "vpxor ",
            $p,
            "12, ",
            $p,
            "12, ",
            $p,
            "15\n",
            "vpclmulqdq ",
            $p,
            "14, ",
            $p,
            "14, [{pw}], 0x01\n",
            "vpxor ",
            $p,
            "12, ",
            $p,
            "12, ",
            $p,
            "14\n",
            "add {hash}, ",
            $w,
            "\n",
            "sub {pw}, ",
            $w,
            "\n",
        )
    };
}

/// The rest of a group's hash and nothing else, at local label `$at`:
/// seven steps, for the last group of an encryption, which the loop
/// was always a group behind.
macro_rules! hash_rest {
    ($at:literal, $p:literal, $w:literal) => {
        concat!(
            "mov {n}, 7\n",
            $at,
            ":\n",
            ghash_next!($p, $w),
            "dec {n}\n",
            "jnz ",
            $at,
            "b\n",
        )
    };
}

/// Seven rounds with seven steps of the hash beside them, at local
/// label `$at`.
///
/// Seven because the eighth step of the group is taken before the
/// rounds begin, and because the shortest key width has seven middle
/// rounds to spare after the ones the group needs on its own.
macro_rules! rounds_and_hash {
    ($at:literal, $p:literal, $w:literal, $bc:literal) => {
        concat!(
            "mov {n}, 7\n",
            $at,
            ":\n",
            round!($p, $bc),
            ghash_next!($p, $w),
            "dec {n}\n",
            "jnz ",
            $at,
            "b\n",
        )
    };
}

/// The last round, and the keystream XORed over the data on the way
/// to a single store, so it never reaches memory.
macro_rules! finish_group {
    ($p:literal, $w:literal, $span:literal, $bc:literal) => {
        concat!(
            $bc,
            " ",
            $p,
            "8, [{k}]\n",
            "vaesenclast ",
            $p,
            "0, ",
            $p,
            "0, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "1, ",
            $p,
            "1, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "2, ",
            $p,
            "2, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "3, ",
            $p,
            "3, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "4, ",
            $p,
            "4, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "5, ",
            $p,
            "5, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "6, ",
            $p,
            "6, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "7, ",
            $p,
            "7, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "0, ",
            $p,
            "0, [{data} + 0*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "1, ",
            $p,
            "1, [{data} + 1*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "2, ",
            $p,
            "2, [{data} + 2*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "3, ",
            $p,
            "3, [{data} + 3*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "4, ",
            $p,
            "4, [{data} + 4*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "5, ",
            $p,
            "5, [{data} + 5*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "6, ",
            $p,
            "6, [{data} + 6*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "7, ",
            $p,
            "7, [{data} + 7*",
            $w,
            "]\n",
            "vmovdqu [{data} + 0*",
            $w,
            "], ",
            $p,
            "0\n",
            "vmovdqu [{data} + 1*",
            $w,
            "], ",
            $p,
            "1\n",
            "vmovdqu [{data} + 2*",
            $w,
            "], ",
            $p,
            "2\n",
            "vmovdqu [{data} + 3*",
            $w,
            "], ",
            $p,
            "3\n",
            "vmovdqu [{data} + 4*",
            $w,
            "], ",
            $p,
            "4\n",
            "vmovdqu [{data} + 5*",
            $w,
            "], ",
            $p,
            "5\n",
            "vmovdqu [{data} + 6*",
            $w,
            "], ",
            $p,
            "6\n",
            "vmovdqu [{data} + 7*",
            $w,
            "], ",
            $p,
            "7\n",
            "add {data}, ",
            $span,
            "\n",
        )
    };
}

/// One reduction for the whole group.
///
/// At the wider width the two lanes hold two independent sums, so
/// `$fold` brings them together first; at the narrower one there is
/// nothing to fold and it is empty. After that the work is the same:
/// the middle third of the 256-bit sum belongs half in each of the
/// other two, and then the excess is folded down in two halves, each
/// a multiplication by the polynomial's low half. What comes out is
/// the running hash the next group's first step will join, in the low
/// half of a register whose high half these instructions have
/// cleared, which is what leaves it joining that step alone.
macro_rules! reduce {
    (narrow) => {
        reduce!(@rest "")
    };
    (wide) => {
        reduce!(@rest fold_lanes!())
    };
    (@rest $fold:expr) => {
        concat!(
            $fold,
            "vpslldq xmm14, xmm12, 8\n",
            "vpsrldq xmm12, xmm12, 8\n",
            "vpxor xmm11, xmm11, xmm14\n",
            "vpxor xmm13, xmm13, xmm12\n",
            "vmovq xmm15, [rip + {poly}]\n",
            "vpclmulqdq xmm14, xmm15, xmm11, 0x00\n",
            "vpshufd xmm12, xmm11, 0x4e\n",
            "vpxor xmm12, xmm12, xmm14\n",
            "vpclmulqdq xmm14, xmm15, xmm12, 0x00\n",
            "vpshufd xmm11, xmm12, 0x4e\n",
            "vpxor xmm11, xmm11, xmm14\n",
            "vpxor xmm15, xmm13, xmm11\n",
        )
    };
}

/// The two lanes of each sum brought together, for the wider width.
macro_rules! fold_lanes {
    () => {
        concat!(
            "vextracti128 xmm14, ymm11, 1\n",
            "vpxor xmm11, xmm11, xmm14\n",
            "vextracti128 xmm14, ymm12, 1\n",
            "vpxor xmm12, xmm12, xmm14\n",
            "vextracti128 xmm14, ymm13, 1\n",
            "vpxor xmm13, xmm13, xmm14\n",
        )
    };
}

/// Loads the base counter and the running hash, and points the table
/// of powers at the one the first step of a group meets.
macro_rules! prologue {
    ($p:literal, $top:literal, $bc:literal) => {
        concat!(
            $bc,
            " ",
            $p,
            "10, [rip + {bswap}]\n",
            $bc,
            " ",
            $p,
            "9, [{counter}]\n",
            "vpshufb ",
            $p,
            "9, ",
            $p,
            "9, ",
            $p,
            "10\n",
            "vmovdqu xmm15, [{y}]\n",
            "vpshufd xmm15, xmm15, 0x4e\n",
            "add {pw}, ",
            $top,
            "\n",
        )
    };
}

/// Hands the counter and the running hash back the way they arrived.
/// At the wider width every lane of the base holds the same counter,
/// so the low one is the block after the last either way.
macro_rules! epilogue {
    ($p:literal) => {
        concat!(
            "vpshufd xmm15, xmm15, 0x4e\n",
            "vmovdqu [{y}], xmm15\n",
            "vpshufb ",
            $p,
            "9, ",
            $p,
            "9, ",
            $p,
            "10\n",
            "vmovdqu [{counter}], xmm9\n",
        )
    };
}

/// Adds `count` to GCM's counter field, the last four bytes of the
/// block, most significant first, wrapping inside them rather than
/// carrying out.
fn advance(counter: &mut [u8; BLOCK], count: u32) {
    let field = &mut counter[BLOCK - 4..];
    let n = u32::from_be_bytes([field[0], field[1], field[2], field[3]]);
    field.copy_from_slice(&n.wrapping_add(count).to_be_bytes());
}

/// Multiplies `value` by the prepared subkey `h`, in place.
///
/// One block, for the additional data and for anything else that does
/// not come in runs.
///
/// # Safety
/// Requires `pclmulqdq` and SSSE3.
unsafe fn multiply(value: &mut [u64; 2], h: &[u64; 2]) {
    unsafe {
        core::arch::asm!(
            "vmovdqu xmm15, [{y}]",
            "vpshufd xmm15, xmm15, 0x4e",
            "vmovdqu xmm14, [{pw}]",
            // The value is already in register order, so it needs no
            // reversal; the sums start from it directly.
            "vpclmulqdq xmm11, xmm15, xmm14, 0x00",
            "vpclmulqdq xmm13, xmm15, xmm14, 0x11",
            "vpclmulqdq xmm12, xmm15, xmm14, 0x10",
            "vpclmulqdq xmm15, xmm15, xmm14, 0x01",
            "vpxor xmm12, xmm12, xmm15",
            reduce!(narrow),
            "vpshufd xmm15, xmm15, 0x4e",
            "vmovdqu [{y}], xmm15",
            y = in(reg) value.as_mut_ptr(),
            pw = in(reg) h.as_ptr(),
            poly = sym POLYNOMIAL,
            out("xmm11") _, out("xmm12") _,
            out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack),
        );
    }
}

/// Hashes `blocks` blocks at `data`, which is one to [`GROUP`] of
/// them, with one reduction at the end.
///
/// Nothing in the loop depends on the iteration before it, so the
/// multiplier stays busy; only the reduction is serial.
///
/// # Safety
/// Requires `pclmulqdq` and SSSE3. `data` must be `blocks` blocks,
/// with `1 <= blocks <= GROUP`, and `pw` must point at the power the
/// first of them meets, which is `powers + 16 * (blocks - 1)`.
unsafe fn hash_blocks(y: *mut u64, pw: *const u8, data: *const u8, n: usize) {
    unsafe {
        core::arch::asm!(
            "vmovdqa xmm10, [rip + {bswap}]",
            "vmovdqu xmm15, [{y}]",
            "vpshufd xmm15, xmm15, 0x4e",
            ghash_first!("xmm", "16"),
            "dec {n}",
            "jz 8f",
            "9:",
            ghash_next!("xmm", "16"),
            "dec {n}",
            "jnz 9b",
            "8:",
            reduce!(narrow),
            "vpshufd xmm15, xmm15, 0x4e",
            "vmovdqu [{y}], xmm15",
            y = in(reg) y,
            pw = inout(reg) pw => _,
            hash = inout(reg) data => _,
            n = inout(reg) n => _,
            bswap = sym BSWAP,
            poly = sym POLYNOMIAL,
            out("xmm10") _, out("xmm11") _, out("xmm12") _,
            out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack),
        );
    }
}

/// Defines the counter body for a tail of exactly the listed
/// registers: fewer blocks than a group, so there is nothing to hash
/// alongside them and they are simply encrypted and XORed over the
/// data.
///
/// Advancing the counter is left to the caller, which knows the
/// width.
macro_rules! tail {
    ($name:ident, [$(($r:literal, $off:literal)),+]) => {
        /// # Safety
        /// Requires AES-NI and SSSE3; `rk` must point at `rounds + 1`
        /// round keys, `counter` at a block, and `data` at the blocks
        /// this body handles.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            counter: *const u8,
            data: *mut u8,
        ) {
            unsafe {
                core::arch::asm!(
                    "vmovdqa xmm10, [rip + {bswap}]",
                    "vmovdqu xmm9, [{counter}]",
                    "vpshufb xmm9, xmm9, xmm10",
                    $(concat!(
                        "vpaddd ", $r, ", xmm9, [rip + {offs} + ",
                        $off, "]"),)+
                    $(concat!("vpshufb ", $r, ", ", $r, ", xmm10"),)+
                    "vmovdqu xmm8, [{rk}]",
                    $(concat!("vpxor ", $r, ", ", $r, ", xmm8"),)+
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "vmovdqu xmm8, [{k}]",
                    $(concat!("vaesenc ", $r, ", ", $r, ", xmm8"),)+
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "vmovdqu xmm8, [{k}]",
                    $(concat!("vaesenclast ", $r, ", ", $r, ", xmm8"),)+
                    $(concat!(
                        "vpxor ", $r, ", ", $r, ", [{data} + ", $off, "]\n",
                        "vmovdqu [{data} + ", $off, "], ", $r),)+
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    counter = in(reg) counter,
                    data = in(reg) data,
                    k = out(reg) _,
                    n = out(reg) _,
                    bswap = sym BSWAP,
                    offs = sym OFFSETS,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm8") _, out("xmm9") _,
                    out("xmm10") _,
                    options(nostack),
                );
            }
        }
    };
}

tail!(tail1, [("xmm0", "0")]);
tail!(tail2, [("xmm0", "0"), ("xmm1", "16")]);
tail!(tail3, [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]);
tail!(
    tail4,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48")
    ]
);
tail!(
    tail5,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
tail!(
    tail6,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80")
    ]
);
tail!(
    tail7,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80"),
        ("xmm6", "96")
    ]
);

/// The bodies by block count, so a tail of `n` blocks is one pass.
static TAILS: [unsafe fn(*const u32, usize, *const u8, *mut u8); 7] =
    [tail1, tail2, tail3, tail4, tail5, tail6, tail7];

/// Defines the pair of group loops at one width.
///
/// The two directions differ only in what they hash while they work.
/// Decrypting, the ciphertext is what arrived, so each group is
/// hashed where it lies before the store overwrites it. Encrypting,
/// there is nothing to hash until the cipher has produced it, so the
/// first group goes through the rounds with nothing beside it, every
/// group after it is encrypted while its predecessor is hashed, and
/// the last is hashed on the way out.
macro_rules! groups {
    ($decrypt:ident, $encrypt:ident, $offs:ident, $p:literal, $w:literal,
     $span:literal, $top:literal, $bc:literal, $fold:ident,
     $zero:literal) => {
        /// Decrypts `groups` groups in place and hashes them as it
        /// goes.
        ///
        /// # Safety
        /// Requires the instructions [`supported`] asks for. `rk`
        /// must point at `rounds + 1` round keys and `counter` at a
        /// block. `data` must be `groups` groups of writable bytes
        /// with `groups >= 1`. `y` is the running hash and `powers`
        /// the prepared powers of the subkey this width wants.
        unsafe fn $decrypt(
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
                    prologue!($p, $top, $bc),
                    "3:",
                    ghash_first!($p, $w),
                    counters!($p, $w, $bc),
                    rounds_and_hash!("2", $p, $w, $bc),
                    rounds!("4", "{nr}", $p, $bc),
                    finish_group!($p, $w, $span, $bc),
                    reduce!($fold),
                    concat!("add {pw}, ", $span),
                    "dec {groups}",
                    "jnz 3b",
                    epilogue!($p),
                    $zero,
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
                    bswap = sym BSWAP,
                    offs = sym $offs,
                    poly = sym POLYNOMIAL,
                    out("ymm0") _, out("ymm1") _, out("ymm2") _,
                    out("ymm3") _, out("ymm4") _, out("ymm5") _,
                    out("ymm6") _, out("ymm7") _, out("ymm8") _,
                    out("ymm9") _, out("ymm10") _, out("ymm11") _,
                    out("ymm12") _, out("ymm13") _, out("ymm14") _,
                    out("ymm15") _,
                    options(nostack),
                );
            }
        }

        /// Encrypts `groups` groups in place and hashes them as it
        /// goes, a group behind.
        ///
        /// # Safety
        /// As the decrypting loop above.
        unsafe fn $encrypt(
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
                    prologue!($p, $top, $bc),
                    // The first group has nothing to hash alongside
                    // it, so it goes through the rounds on its own.
                    counters!($p, $w, $bc),
                    "mov {n}, {nr}",
                    "add {n}, 7",
                    "5:",
                    round!($p, $bc),
                    "dec {n}",
                    "jnz 5b",
                    finish_group!($p, $w, $span, $bc),
                    "dec {groups}",
                    "jz 6f",

                    // Every group after it is encrypted while the one
                    // before it is hashed.
                    "3:",
                    ghash_first!($p, $w),
                    counters!($p, $w, $bc),
                    rounds_and_hash!("2", $p, $w, $bc),
                    rounds!("4", "{nr}", $p, $bc),
                    finish_group!($p, $w, $span, $bc),
                    reduce!($fold),
                    concat!("add {pw}, ", $span),
                    "dec {groups}",
                    "jnz 3b",

                    // Which leaves the last group unhashed.
                    "6:",
                    ghash_first!($p, $w),
                    hash_rest!("7", $p, $w),
                    reduce!($fold),
                    epilogue!($p),
                    $zero,
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
                    bswap = sym BSWAP,
                    offs = sym $offs,
                    poly = sym POLYNOMIAL,
                    out("ymm0") _, out("ymm1") _, out("ymm2") _,
                    out("ymm3") _, out("ymm4") _, out("ymm5") _,
                    out("ymm6") _, out("ymm7") _, out("ymm8") _,
                    out("ymm9") _, out("ymm10") _, out("ymm11") _,
                    out("ymm12") _, out("ymm13") _, out("ymm14") _,
                    out("ymm15") _,
                    options(nostack),
                );
            }
        }
    };
}

groups!(
    decrypt_groups,
    encrypt_groups,
    OFFSETS,
    "xmm",
    "16",
    "128",
    "112",
    "vmovdqu",
    narrow,
    ""
);

groups!(
    wide_decrypt_groups,
    wide_encrypt_groups,
    WIDE_OFFSETS,
    "ymm",
    "32",
    "256",
    "224",
    "vbroadcasti128",
    wide,
    // Leaving the upper halves dirty would slow down whatever plain
    // SSE code runs next, so they are cleared on the way out.
    "vzeroupper"
);
