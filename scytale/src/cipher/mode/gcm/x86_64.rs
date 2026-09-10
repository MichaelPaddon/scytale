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

use super::{BLOCK, Direction};
// Re-exported so that GCM-SIV, which runs the same counter
// under a different byte order, can name one path whatever the
// architecture is.
use super::super::{ByteOrder, add_counter};
use crate::align::{At16, At32};
use crate::cipher::BlockCipher;
pub(crate) use crate::cipher::aes::x86_64::{Keys, keys};
use crate::cipher::aes::x86_64::{Schedule, has_aesni};
use crate::probe::Probe;

/// Blocks the loop takes at once, which is also how many powers of
/// the subkey it keeps.
const GROUP: usize = 8;

/// Bytes in one group.
const SPAN: usize = GROUP * BLOCK;

/// Blocks the wider loop takes at once: the same eight registers,
/// two blocks in each.
const WIDE_GROUP: usize = 2 * GROUP;

/// Bytes in one group at the wider width.
const WIDE_SPAN: usize = WIDE_GROUP * BLOCK;

/// Blocks the wider loop hashes between reductions: two groups.
///
/// The reduction is a chain of dependent multiplications and shifts
/// that the next group's hash waits on, and nothing in it can be
/// spread across the ports the way the rest of the work can. Halving
/// how often it falls due halves what that wait costs a byte, at the
/// price of twice as many powers of the subkey, which are worked out
/// once for the key.
const WIDE_AGGREGATE: usize = 2 * WIDE_GROUP;

/// Bytes hashed between reductions at the wider width.
const WIDE_AGGREGATE_SPAN: usize = WIDE_AGGREGATE * BLOCK;

/// The field polynomial's low half in GHASH's reversed bit order,
/// where the reduction can reach it without a register to hold it.
static POLYNOMIAL: u64 = 0xc200_0000_0000_0000;

/// Reverses the bytes of a register.
///
/// One mask for two jobs. GCM's counter is the last four bytes of a
/// block, most significant first; reversed, it is the low doubleword,
/// where a doubleword add can reach it. And GHASH numbers its bits
/// backwards, so a block reversed is a block in the order the
/// multiplication below wants.
static BSWAP: At16<[u8; BLOCK]> =
    At16([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

/// What each register adds to the base counter to make its block,
/// and after those, in the ninth place, what the base itself moves on
/// by once a group is made: one group's worth.
/// # Why these are added a byte at a time
///
/// The counter is the last four bytes of the block, most significant
/// first, so the byte these change is the last byte of all, and a
/// byte-wise add reaches it where it lies. That is one instruction
/// per register and no more: the block is already in the order the
/// cipher wants it, so nothing has to be turned round on the way in
/// or on the way out, which leaves the shuffle port for the hash.
///
/// The catch is that a byte-wise add does not carry into the byte
/// above, so it is right only while that last byte does not overflow.
/// [`Hasher::bulk`] keeps every run short enough that it cannot, and
/// does the carrying itself between runs, which falls due once in
/// every 256 blocks.
static OFFSETS: At16<[u8; BLOCK * (GROUP + 1)]> = {
    let mut b = [0u8; BLOCK * (GROUP + 1)];
    let mut i = 0;
    while i < GROUP {
        b[BLOCK * i + BLOCK - 1] = i as u8;
        i += 1;
    }
    b[BLOCK * GROUP + BLOCK - 1] = GROUP as u8;
    At16(b)
};

/// The wider width takes two blocks to a register, so the counters
/// come in pairs and the base moves on by sixteen blocks at a time.
static WIDE_OFFSETS: At16<[u8; 2 * BLOCK * (GROUP + 1)]> = {
    let mut b = [0u8; 2 * BLOCK * (GROUP + 1)];
    let mut i = 0;
    while i < GROUP {
        b[2 * BLOCK * i + BLOCK - 1] = 2 * i as u8;
        b[2 * BLOCK * i + 2 * BLOCK - 1] = 2 * i as u8 + 1;
        i += 1;
    }
    b[2 * BLOCK * GROUP + BLOCK - 1] = WIDE_GROUP as u8;
    b[2 * BLOCK * GROUP + 2 * BLOCK - 1] = WIDE_GROUP as u8;
    At16(b)
};

/// The same for GCM-SIV, which counts in the first four bytes of the
/// block read the little-endian way round, so the byte a byte-wise
/// add must reach is the first of all rather than the last.
static SIV_OFFSETS: At16<[u8; BLOCK * (GROUP + 1)]> = {
    let mut b = [0u8; BLOCK * (GROUP + 1)];
    let mut i = 0;
    while i < GROUP {
        b[BLOCK * i] = i as u8;
        i += 1;
    }
    b[BLOCK * GROUP] = GROUP as u8;
    At16(b)
};

/// The same again at the wider width.
static SIV_WIDE_OFFSETS: At16<[u8; 2 * BLOCK * (GROUP + 1)]> = {
    let mut b = [0u8; 2 * BLOCK * (GROUP + 1)];
    let mut i = 0;
    while i < GROUP {
        b[2 * BLOCK * i] = 2 * i as u8;
        b[2 * BLOCK * i + BLOCK] = 2 * i as u8 + 1;
        i += 1;
    }
    b[2 * BLOCK * GROUP] = WIDE_GROUP as u8;
    b[2 * BLOCK * GROUP + BLOCK] = WIDE_GROUP as u8;
    At16(b)
};

/// The powers of the subkey the narrower loop wants, aligned so the
/// older vector instructions can read them from memory.
type Powers = At16<[[u64; 2]; 2 * GROUP]>;

/// The powers the wider loop wants, which is twice as many and in the
/// order its lanes meet them.
///
/// A register there holds two blocks, the earlier of the two in the
/// low half, and the earlier block meets the higher power. So each
/// entry is a pair, the higher power below the lower, and the table is
/// walked backwards exactly as the narrower one is.
type WidePowers = At32<[[u64; 2]; 2 * WIDE_AGGREGATE]>;

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
    let mut powers = At16([[0u64; 2]; 2 * GROUP]);
    let mut power = [1u64 << 63, 0];
    for slot in powers.0.chunks_exact_mut(2) {
        // SAFETY: the caller has confirmed the instructions.
        unsafe { multiply(&mut power, h) };
        slot[0] = prepare(&power);
        slot[1] = folded(&slot[0]);
    }
    powers
}

/// A power's halves added together, which is the operand Karatsuba's
/// middle product takes.
///
/// Only the low half of what this returns is read; the other is the
/// same value, so that either half of a register may name it.
fn folded(power: &[u64; 2]) -> [u64; 2] {
    let both = power[0] ^ power[1];
    [both, both]
}

/// The [`WIDE_GROUP`] powers, in the order the pairs of lanes meet
/// them.
///
/// # Safety
/// Requires `pclmulqdq` and AVX.
unsafe fn wide_powers_of(h: &[u64; 2]) -> At32<[[u64; 2]; 2 * WIDE_AGGREGATE]> {
    let mut ascending = [[0u64; 2]; WIDE_AGGREGATE];
    let mut power = [1u64 << 63, 0];
    for slot in ascending.iter_mut() {
        // SAFETY: the caller has confirmed the instructions.
        unsafe { multiply(&mut power, h) };
        *slot = prepare(&power);
    }
    // Each entry is a register of two powers followed by a register
    // of the same two folded, so one pointer walks both.
    let mut wide = At32([[0u64; 2]; 2 * WIDE_AGGREGATE]);
    for (j, entry) in wide.0.chunks_exact_mut(4).enumerate() {
        entry[0] = ascending[2 * j + 1];
        entry[1] = ascending[2 * j];
        entry[2] = folded(&entry[0]);
        entry[3] = folded(&entry[1]);
    }
    wide
}

/// Whether this processor has everything the loop below uses, asked
/// once; see [`crate::probe`].
static PROBED: Probe = Probe::new();

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
    WIDE_PROBED.yes(ask_wide)
}

/// Whether this processor has the wider loop's instructions, asked
/// once.
///
/// Kept because `cpuid` serialises the processor, and a mode that
/// derives a key for every message would otherwise ask once a
/// message.
static WIDE_PROBED: Probe = Probe::new();

fn ask_wide() -> bool {
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
    PROBED.yes(|| has_aesni() && has_vex_and_carryless_multiply())
}

/// What AES-GCM's bulk work needs and what it does not change: the
/// way to the round keys, and the powers of the hash subkey.
///
/// This belongs to the key, so the mode holds one and every message
/// borrows it. The powers are worked out once here rather than once
/// per message, and a message short enough never to reach a group
/// copies none of them.
pub(crate) struct Engine<C> {
    keys: Keys<C>,
    subkey: Subkey,
}

/// Everything the hash works out from the subkey and never changes.
///
/// Held apart from the cipher because the same arithmetic serves
/// POLYVAL, which has no cipher of its own and differs only in the
/// order it reads a block's bytes.
#[derive(Clone, Copy)]
pub(crate) struct Subkey {
    /// The powers of the subkey, `H` first. A run of one block meets
    /// the first of them, so there is no separate single multiply.
    powers: Powers,
    /// Twice as many, in the order the wider loop's lanes meet them,
    /// where this processor has the wider instructions and the caller
    /// wants them.
    wide: Option<WidePowers>,
}

impl Subkey {
    /// The powers of hash subkey `h`, at the width asked for, or
    /// `None` where this processor has not the instructions for it.
    ///
    /// The wider table is four times the work to build: worth it for
    /// a key that many messages go under, not for one derived per
    /// message as GCM-SIV derives its own.
    pub(crate) fn at_width(h: &[u8; BLOCK], wide: bool) -> Option<Self> {
        if !supported() || (wide && !wide_supported()) {
            return None;
        }
        let h = prepare(&[halve(&h[..8]), halve(&h[8..])]);
        // SAFETY: `supported` has just confirmed the instructions.
        let powers = unsafe { powers_of(&h) };
        // SAFETY: as above.
        let wide = wide.then(|| unsafe { wide_powers_of(&h) });
        Some(Subkey { powers, wide })
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Engine<C> {
    /// The engine under hash subkey `h` at the width asked for, or
    /// `None` where this processor lacks the instructions for it or
    /// `C` is not a cipher this is written for.
    pub(crate) fn at_width(h: &[u8; BLOCK], wide: bool) -> Option<Self> {
        Some(Engine {
            keys: keys::<C>()?,
            subkey: Subkey::at_width(h, wide)?,
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
            subkey: self.subkey,
        }
    }
}

/// One message going by: what the hash has taken in so far.
///
/// Everything else it needs it borrows from the engine, which belongs
/// to the key, so starting a message costs a pointer and nothing more.
pub(crate) struct Hasher<'a, C> {
    engine: &'a Engine<C>,
    digest: Digest,
}

/// The hash's running state, with the subkey handed in rather than
/// held: GCM borrows one that belongs to the key, POLYVAL owns its
/// own, and neither should pay to copy the powers.
#[derive(Clone)]
struct Digest {
    /// The running hash, most significant word first, as
    /// [`finish`](Digest::finish) writes it out.
    y: [u64; 2],
    /// A hash block not yet complete.
    block: [u8; BLOCK],
    used: usize,
    /// Whether a block's bytes are reversed on the way in. GHASH
    /// reads them that way round; POLYVAL, which is the same
    /// arithmetic over the same field, does not.
    reverse: bool,
}

impl Digest {
    fn new(reverse: bool) -> Self {
        Digest {
            y: [0, 0],
            block: [0; BLOCK],
            used: 0,
            reverse,
        }
    }

    /// Adds more of the current field to the hash.
    fn hash(&mut self, subkey: &Subkey, mut data: &[u8]) {
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
            self.absorb(subkey, &block, 1);
            self.used = 0;
        }
        let mut data = data;
        if subkey.wide.is_some() {
            let mut runs = data.chunks_exact(WIDE_AGGREGATE_SPAN);
            for run in &mut runs {
                self.absorb_wide(subkey, run);
            }
            data = runs.remainder();
        }
        let mut runs = data.chunks_exact(SPAN);
        for run in &mut runs {
            self.absorb(subkey, run, GROUP);
        }
        let data = runs.remainder();
        let blocks = data.len() / BLOCK;
        if blocks > 0 {
            self.absorb(subkey, &data[..blocks * BLOCK], blocks);
        }
        let rest = &data[blocks * BLOCK..];
        self.block[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
    }

    /// Ends the current field, padding it with zeros to a block.
    fn pad(&mut self, subkey: &Subkey) {
        if self.used > 0 {
            let mut block = self.block;
            block[self.used..].fill(0);
            self.absorb(subkey, &block, 1);
            self.used = 0;
        }
    }

    /// The hash so far. Every field must have been padded first.
    fn finish(&self) -> [u8; BLOCK] {
        debug_assert_eq!(self.used, 0);
        let mut out = [0u8; BLOCK];
        out[..8].copy_from_slice(&self.y[0].to_be_bytes());
        out[8..].copy_from_slice(&self.y[1].to_be_bytes());
        out
    }

    /// Adds a whole run at the wider width: thirty-two blocks through
    /// eight registers twice, with one reduction.
    fn absorb_wide(&mut self, subkey: &Subkey, data: &[u8]) {
        debug_assert_eq!(data.len(), WIDE_AGGREGATE_SPAN);
        debug_assert!(self.reverse, "no wider loop for POLYVAL");
        let Some(wide) = subkey.wide.as_ref() else {
            debug_assert!(false, "no wider powers");
            return;
        };
        // The first register of the run meets the highest pair of
        // powers, and the table is walked backwards from there.
        let pw = wide.0.as_ptr().cast::<u8>();
        // SAFETY: the instructions were confirmed at construction,
        // `data` is a whole run, and the table has sixteen entries.
        unsafe {
            wide_hash_blocks(
                self.y.as_mut_ptr(),
                pw.add(15 * 64),
                data.as_ptr(),
                2 * GROUP,
            )
        };
    }

    /// Adds a run of `blocks` whole blocks, one to a group's worth,
    /// with a single reduction at the end.
    fn absorb(&mut self, subkey: &Subkey, data: &[u8], blocks: usize) {
        debug_assert_eq!(data.len(), blocks * BLOCK);
        debug_assert!((1..=GROUP).contains(&blocks));
        // The first block of a run meets the highest power it needs,
        // and the last meets `H`.
        let pw = &subkey.powers.0[2 * (blocks - 1)];
        let run = if self.reverse {
            hash_blocks
        } else {
            kept_blocks
        };
        // SAFETY: the instructions were confirmed at construction,
        // `data` is `blocks` blocks and `blocks` is within the table.
        unsafe {
            run(
                self.y.as_mut_ptr(),
                (pw as *const [u64; 2]).cast::<u8>(),
                data.as_ptr(),
                blocks,
            )
        };
    }
}

/// POLYVAL: the same arithmetic with a block's bytes left as they
/// lie, and no cipher behind it.
///
/// RFC 8452 defines POLYVAL as GHASH over reversed blocks under a
/// converted key. Reversing every block on the way in, only for the
/// loop to reverse it back, is what the portable construction spends
/// most of its time on; here the reversal is simply left out.
///
/// Only the narrower width: GCM-SIV derives a hash key for every
/// message, and the wider table is four times the work to build,
/// which a single message cannot earn back.
#[derive(Clone)]
pub(crate) struct Polyval {
    subkey: Subkey,
    digest: Digest,
}

impl Polyval {
    /// The hash under converted key `key`, or `None` where this
    /// processor has not the instructions for it.
    pub(crate) fn new(key: &[u8; BLOCK]) -> Option<Self> {
        Some(Polyval {
            subkey: Subkey::at_width(key, false)?,
            digest: Digest::new(false),
        })
    }

    pub(crate) fn hash(&mut self, data: &[u8]) {
        self.digest.hash(&self.subkey, data)
    }

    pub(crate) fn finish(&self) -> [u8; BLOCK] {
        self.digest.finish()
    }

    /// GCM-SIV's counter over `data` and the hash of the plaintext it
    /// produces, in one pass.
    ///
    /// `data` is a whole number of blocks. GCM-SIV counts in the
    /// first four bytes of the block, the little-endian way round, so
    /// the byte the loop adds to is the first of all; the runs are cut
    /// where it would carry, as in GCM.
    pub(crate) fn bulk(
        &mut self,
        schedule: Schedule<'_>,
        counter: &mut [u8; BLOCK],
        data: &mut [u8],
    ) {
        debug_assert_eq!(data.len() % BLOCK, 0);
        let mut data = data;
        while !data.is_empty() {
            let room = (256 - counter[0] as usize) * BLOCK;
            let take = data.len().min(room);
            let (mut rest, after) = data.split_at_mut(take);
            data = after;

            let groups = rest.len() / SPAN;
            if groups > 0 {
                let (whole, tail) = rest.split_at_mut(groups * SPAN);
                // SAFETY: the instructions were confirmed at
                // construction, the schedule holds `rounds + 1` round
                // keys, `whole` is `groups` whole groups with at least
                // one, the powers are the ones this hash built, and
                // the run was cut so that no counter in it carries.
                unsafe {
                    siv_decrypt_groups(
                        schedule.keys(),
                        schedule.rounds(),
                        counter.as_ptr(),
                        whole.as_mut_ptr(),
                        groups,
                        self.digest.y.as_mut_ptr(),
                        self.subkey.powers.0.as_ptr().cast::<u8>(),
                    );
                }
                add_counter(
                    counter,
                    ByteOrder::Little,
                    (groups * GROUP) as u32,
                );
                rest = tail;
            }

            // Fewer than a group is left, if anything: not enough to
            // be worth running the two together, so they go in turn.
            if !rest.is_empty() {
                siv_counter(schedule, counter, rest);
                self.hash(rest);
            }
        }
    }
}

/// GCM-SIV's counter over `data`, with nothing hashed beside it: the
/// direction where the tag must be known before the cipher may start.
///
/// `data` is a whole number of blocks, and `counter` is left on the
/// block after the last.
pub(crate) fn siv_counter(
    schedule: Schedule<'_>,
    counter: &mut [u8; BLOCK],
    data: &mut [u8],
) {
    debug_assert_eq!(data.len() % BLOCK, 0);
    let (rk, rounds) = (schedule.keys(), schedule.rounds());
    let wide = wide_supported();
    let mut data = data;
    while !data.is_empty() {
        let room = (256 - counter[0] as usize) * BLOCK;
        let take = data.len().min(room);
        let (mut rest, after) = data.split_at_mut(take);
        data = after;

        if wide {
            let groups = rest.len() / WIDE_SPAN;
            if groups > 0 {
                let (whole, tail) = rest.split_at_mut(groups * WIDE_SPAN);
                // SAFETY: as in `bulk`, at the wider width.
                unsafe {
                    siv_wide_counter_groups(
                        rk,
                        rounds,
                        counter.as_ptr(),
                        whole.as_mut_ptr(),
                        groups,
                    );
                }
                add_counter(
                    counter,
                    ByteOrder::Little,
                    (groups * WIDE_GROUP) as u32,
                );
                rest = tail;
            }
        }

        let groups = rest.len() / SPAN;
        if groups > 0 {
            let (whole, tail) = rest.split_at_mut(groups * SPAN);
            // SAFETY: as above, at the narrower width.
            unsafe {
                siv_counter_groups(
                    rk,
                    rounds,
                    counter.as_ptr(),
                    whole.as_mut_ptr(),
                    groups,
                );
            }
            add_counter(counter, ByteOrder::Little, (groups * GROUP) as u32);
            rest = tail;
        }

        if !rest.is_empty() {
            let blocks = rest.len() / BLOCK;
            // SAFETY: as above, and `blocks` is 1 to 7, which indexes
            // the table, with `rest` exactly that many blocks.
            unsafe {
                SIV_TAILS[blocks - 1](
                    rk,
                    rounds,
                    counter.as_ptr(),
                    rest.as_mut_ptr(),
                );
            }
            add_counter(counter, ByteOrder::Little, blocks as u32);
        }
    }
}

impl<'a, C: BlockCipher<Block = [u8; BLOCK]>> Hasher<'a, C> {
    /// A hash at the start of a message, over the cipher this engine
    /// was built for.
    pub(crate) fn new(engine: &'a Engine<C>) -> Self {
        Hasher {
            engine,
            digest: Digest::new(true),
        }
    }

    /// Adds more of the current field to the hash.
    pub(crate) fn hash(&mut self, data: &[u8]) {
        self.digest.hash(&self.engine.subkey, data)
    }

    /// Ends the current field, padding it with zeros to a block.
    pub(crate) fn pad(&mut self) {
        self.digest.pad(&self.engine.subkey)
    }

    /// The hash so far. Every field must have been padded first.
    pub(crate) fn finish(&self) -> [u8; BLOCK] {
        self.digest.finish()
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
        // The loops add to the last byte of the block and do not
        // carry out of it, so a run stops where that byte would
        // overflow and the carrying is done here, in full. It falls
        // due once in every 256 blocks.
        //
        // Within a run: the widest loop this processor has, then the
        // narrower one for what a group of that width could not
        // cover, then the odd blocks. Each leaves the running hash
        // finished with what it took.
        let wide = self
            .engine
            .subkey
            .wide
            .as_ref()
            .map(|w| w.0.as_ptr().cast::<u8>());
        let mut data = data;
        while !data.is_empty() {
            let room = (256 - counter[BLOCK - 1] as usize) * BLOCK;
            let take = data.len().min(room);
            let (mut rest, after) = data.split_at_mut(take);
            data = after;

            if let Some(powers) = wide {
                let groups = rest.len() / WIDE_AGGREGATE_SPAN;
                if groups > 0 {
                    let (whole, tail) =
                        rest.split_at_mut(groups * WIDE_AGGREGATE_SPAN);
                    let run = match direction {
                        Direction::Encrypt => wide_encrypt_groups,
                        Direction::Decrypt => wide_decrypt_groups,
                    };
                    // SAFETY: the instructions were confirmed at
                    // construction, the schedule holds `rounds + 1`
                    // round keys, `whole` is `groups` whole groups
                    // with at least one, the powers are the ones this
                    // engine built for that width, and the run was
                    // cut so that no counter in it carries.
                    unsafe {
                        run(
                            schedule.keys(),
                            schedule.rounds(),
                            counter.as_ptr(),
                            whole.as_mut_ptr(),
                            groups,
                            self.digest.y.as_mut_ptr(),
                            powers,
                        );
                    }
                    add_counter(
                        counter,
                        ByteOrder::Big,
                        (groups * WIDE_AGGREGATE) as u32,
                    );
                    rest = tail;
                }
            }

            let groups = rest.len() / SPAN;
            if groups > 0 {
                let (whole, tail) = rest.split_at_mut(groups * SPAN);
                let run = match direction {
                    Direction::Encrypt => encrypt_groups,
                    Direction::Decrypt => decrypt_groups,
                };
                // SAFETY: as above, at the narrower width.
                unsafe {
                    run(
                        schedule.keys(),
                        schedule.rounds(),
                        counter.as_ptr(),
                        whole.as_mut_ptr(),
                        groups,
                        self.digest.y.as_mut_ptr(),
                        self.engine.subkey.powers.0.as_ptr().cast::<u8>(),
                    );
                }
                add_counter(counter, ByteOrder::Big, (groups * GROUP) as u32);
                rest = tail;
            }

            self.tail(schedule, counter, direction, rest);
        }
    }

    /// Fewer than a group of blocks: not enough to be worth running
    /// the cipher and the hash together, so they go in turn.
    fn tail(
        &mut self,
        schedule: Schedule<'_>,
        counter: &mut [u8; BLOCK],
        direction: Direction,
        rest: &mut [u8],
    ) {
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
            add_counter(counter, ByteOrder::Big, blocks as u32);
            if direction == Direction::Encrypt {
                self.hash(rest);
            }
        }
    }
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
            "vpaddb ",
            $p,
            "0, ",
            $p,
            "9, [rip + {offs} + 0*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "1, ",
            $p,
            "9, [rip + {offs} + 1*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "2, ",
            $p,
            "9, [rip + {offs} + 2*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "3, ",
            $p,
            "9, [rip + {offs} + 3*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "4, ",
            $p,
            "9, [rip + {offs} + 4*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "5, ",
            $p,
            "9, [rip + {offs} + 5*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "6, ",
            $p,
            "9, [rip + {offs} + 6*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "7, ",
            $p,
            "9, [rip + {offs} + 7*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "9, ",
            $p,
            "9, [rip + {offs} + 8*",
            $w,
            "]\n",
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
///
/// # Three multiplications rather than four
///
/// The product of two 128-bit values needs the four products of
/// their halves, but the two middle ones are only ever wanted added
/// together, and Karatsuba's identity gets that sum from one more
/// multiplication instead of two:
///
/// ```text
/// X.hi H.lo + X.lo H.hi = (X.lo + X.hi)(H.lo + H.hi) + X.lo H.lo
///                         + X.hi H.hi
/// ```
///
/// The two corrections are the products already being accumulated, so
/// they are applied once at the reduction rather than once a step.
/// Each power is stored with its own halves already added, in the
/// register after it, so only the block's have to be added here.
///
/// It trades a carry-less multiply for a shuffle and an exclusive or,
/// which matters because the multiplier is the one port the cipher
/// alongside is not competing for.
macro_rules! ghash_first {
    ($p:literal, $w:literal, $s:literal) => {
        ghash_first!($p, $w, $s, reversed)
    };
    ($p:literal, $w:literal, $s:literal, reversed) => {
        ghash_first!(@body $p, $w, $s,
            concat!("vpshufb ", $p, "14, ", $p, "14, ", $p, "10
"))
    };
    ($p:literal, $w:literal, $s:literal, kept) => {
        ghash_first!(@body $p, $w, $s, "")
    };
    (@body $p:literal, $w:literal, $s:literal, $rev:expr) => {
        concat!(
            "vmovdqu ",
            $p,
            "14, [{hash}]\n",
            $rev,
            "vpxor ",
            $p,
            "14, ",
            $p,
            "14, ",
            $p,
            "15\n",
            "vpshufd ",
            $p,
            "15, ",
            $p,
            "14, 0x4e\n",
            "vpxor ",
            $p,
            "15, ",
            $p,
            "15, ",
            $p,
            "14\n",
            "vpclmulqdq ",
            $p,
            "12, ",
            $p,
            "15, [{pw} + ",
            $w,
            "], 0x00\n",
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
            "add {hash}, ",
            $w,
            "\n",
            "sub {pw}, ",
            $s,
            "\n",
        )
    };
}

/// Any later step of the group, which adds to the sums.
macro_rules! ghash_next {
    ($p:literal, $w:literal, $s:literal) => {
        ghash_next!($p, $w, $s, reversed)
    };
    ($p:literal, $w:literal, $s:literal, reversed) => {
        ghash_next!(@body $p, $w, $s,
            concat!("vpshufb ", $p, "14, ", $p, "14, ", $p, "10
"))
    };
    ($p:literal, $w:literal, $s:literal, kept) => {
        ghash_next!(@body $p, $w, $s, "")
    };
    (@body $p:literal, $w:literal, $s:literal, $rev:expr) => {
        concat!(
            "vmovdqu ",
            $p,
            "14, [{hash}]\n",
            $rev,
            "vpshufd ",
            $p,
            "15, ",
            $p,
            "14, 0x4e\n",
            "vpxor ",
            $p,
            "15, ",
            $p,
            "15, ",
            $p,
            "14\n",
            "vpclmulqdq ",
            $p,
            "15, ",
            $p,
            "15, [{pw} + ",
            $w,
            "], 0x00\n",
            "vpxor ",
            $p,
            "12, ",
            $p,
            "12, ",
            $p,
            "15\n",
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
            "14, ",
            $p,
            "14, [{pw}], 0x11\n",
            "vpxor ",
            $p,
            "13, ",
            $p,
            "13, ",
            $p,
            "14\n",
            "add {hash}, ",
            $w,
            "\n",
            "sub {pw}, ",
            $s,
            "\n",
        )
    };
}

/// The rest of a group's hash and nothing else, at local label `$at`:
/// seven steps, for the last group of an encryption, which the loop
/// was always a group behind.
macro_rules! hash_rest {
    ($at:literal, $n:literal, $p:literal, $w:literal, $s:literal,
     $rev:ident) => {
        concat!(
            "mov {n}, ",
            $n,
            "\n",
            $at,
            ":\n",
            ghash_next!($p, $w, $s, $rev),
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
    ($at:literal, $p:literal, $w:literal, $s:literal, $bc:literal,
     $rev:ident) => {
        concat!(
            "mov {n}, 7\n",
            $at,
            ":\n",
            round!($p, $bc),
            ghash_next!($p, $w, $s, $rev),
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
            // The middle sum wants the other two products added in;
            // both are accumulated, so this is done once here rather
            // than once a step.
            "vpxor xmm12, xmm12, xmm11\n",
            "vpxor xmm12, xmm12, xmm13\n",
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
/// Hands the running hash back the way it arrived. The counter is
/// the caller's to move on, since it is the caller that cut the run
/// where the byte-wise add would have carried.
macro_rules! epilogue {
    () => {
        concat!("vpshufd xmm15, xmm15, 0x4e\n", "vmovdqu [{y}], xmm15\n",)
    };
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
            // reversal; the sums start from it directly. Karatsuba as
            // in the loops, since the reduction below expects the
            // middle sum to want its corrections. Neither operand has
            // its halves added in advance here, so both are folded on
            // the spot; this runs once for each power of the subkey
            // and never in a message.
            "vpshufd xmm13, xmm15, 0x4e",
            "vpxor xmm13, xmm13, xmm15",
            "vpshufd xmm12, xmm14, 0x4e",
            "vpxor xmm12, xmm12, xmm14",
            "vpclmulqdq xmm12, xmm13, xmm12, 0x00",
            "vpclmulqdq xmm11, xmm15, xmm14, 0x00",
            "vpclmulqdq xmm13, xmm15, xmm14, 0x11",
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

/// Defines the hash of a run of blocks with nothing else beside it,
/// at one width: for the additional data, and for whatever a message
/// has left over after the loops that run the cipher alongside.
///
/// `steps` is how many registers of blocks there are, one to eight,
/// with a single reduction at the end. Nothing in the loop depends on
/// the iteration before it, so the multiplier stays busy; only the
/// reduction is serial.
macro_rules! hash_run {
    ($name:ident, $p:literal, $w:literal, $s:literal, $bc:literal,
     $fold:ident, $rev:ident, $zero:literal) => {
        /// # Safety
        /// Requires the instructions [`supported`] asks for, and for
        /// the wider width those [`wide_supported`] asks for. `data`
        /// must be `steps` registers of blocks, `1 <= steps <= 8`,
        /// and `pw` must point at the entry the first of them meets.
        unsafe fn $name(
            y: *mut u64,
            pw: *const u8,
            data: *const u8,
            steps: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    concat!($bc, " ", $p, "10, [rip + {bswap}]"),
                    "vmovdqu xmm15, [{y}]",
                    "vpshufd xmm15, xmm15, 0x4e",
                    ghash_first!($p, $w, $s, $rev),
                    "dec {n}",
                    "jz 8f",
                    "9:",
                    ghash_next!($p, $w, $s, $rev),
                    "dec {n}",
                    "jnz 9b",
                    "8:",
                    reduce!($fold),
                    "vpshufd xmm15, xmm15, 0x4e",
                    "vmovdqu [{y}], xmm15",
                    $zero,
                    y = in(reg) y,
                    pw = inout(reg) pw => _,
                    hash = inout(reg) data => _,
                    n = inout(reg) steps => _,
                    bswap = sym BSWAP,
                    poly = sym POLYNOMIAL,
                    out("ymm10") _, out("ymm11") _, out("ymm12") _,
                    out("ymm13") _, out("ymm14") _, out("ymm15") _,
                    options(nostack),
                );
            }
        }
    };
}

hash_run!(
    hash_blocks,
    "xmm",
    "16",
    "32",
    "vmovdqu",
    narrow,
    reversed,
    ""
);
hash_run!(kept_blocks, "xmm", "16", "32", "vmovdqu", narrow, kept, "");
hash_run!(
    wide_hash_blocks,
    "ymm",
    "32",
    "64",
    "vbroadcasti128",
    wide,
    reversed,
    "vzeroupper"
);

/// Defines the counter body for a tail of exactly the listed
/// registers: fewer blocks than a group, so there is nothing to hash
/// alongside them and they are simply encrypted and XORed over the
/// data.
///
/// Advancing the counter is left to the caller, which knows the
/// width.
macro_rules! tail {
    ($name:ident, [$(($r:literal, $off:literal)),+]) => {
        tail!($name, OFFSETS, [$(($r, $off)),+]);
    };
    ($name:ident, $offs:ident, [$(($r:literal, $off:literal)),+]) => {
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
                    "vmovdqu xmm9, [{counter}]",
                    $(concat!(
                        "vpaddb ", $r, ", xmm9, [rip + {offs} + ",
                        $off, "]"),)+
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
                    offs = sym $offs,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm8") _, out("xmm9") _,
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

tail!(siv_tail1, SIV_OFFSETS, [("xmm0", "0")]);
tail!(siv_tail2, SIV_OFFSETS, [("xmm0", "0"), ("xmm1", "16")]);
tail!(
    siv_tail3,
    SIV_OFFSETS,
    [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]
);
tail!(
    siv_tail4,
    SIV_OFFSETS,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48")
    ]
);
tail!(
    siv_tail5,
    SIV_OFFSETS,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
tail!(
    siv_tail6,
    SIV_OFFSETS,
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
    siv_tail7,
    SIV_OFFSETS,
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

/// The same for GCM-SIV, which counts in the other end of the block.
static SIV_TAILS: [unsafe fn(*const u32, usize, *const u8, *mut u8); 7] = [
    siv_tail1, siv_tail2, siv_tail3, siv_tail4, siv_tail5, siv_tail6, siv_tail7,
];

/// One group: a step of the hash, then eight registers of counter
/// blocks through the rounds with seven more steps beside them.
///
/// `single` is one group between reductions, `double` two. The
/// second group's step adds to the sums the first started, so the
/// two share one reduction and the chain it costs is paid once for
/// twice the data.
macro_rules! passes {
    (single, $p:literal, $w:literal, $s:literal, $span:literal,
     $bc:literal, $rev:ident) => {
        concat!(
            ghash_first!($p, $w, $s, $rev),
            counters!($p, $w, $bc),
            rounds_and_hash!("2", $p, $w, $s, $bc, $rev),
            rounds!("4", "{nr}", $p, $bc),
            finish_group!($p, $w, $span, $bc),
        )
    };
    (double, $p:literal, $w:literal, $s:literal, $span:literal,
     $bc:literal, $rev:ident) => {
        concat!(
            passes!(single, $p, $w, $s, $span, $bc, $rev),
            ghash_next!($p, $w, $s, $rev),
            counters!($p, $w, $bc),
            rounds_and_hash!("2", $p, $w, $s, $bc, $rev),
            rounds!("4", "{nr}", $p, $bc),
            finish_group!($p, $w, $span, $bc),
        )
    };
}

/// The same groups with nothing hashed beside them, for the first
/// run of an encryption, which has no ciphertext behind it yet.
macro_rules! cipher_only {
    (@one, $p:literal, $w:literal, $span:literal, $bc:literal) => {
        concat!(
            counters!($p, $w, $bc),
            "mov {n}, {nr}\n",
            "add {n}, 7\n",
            "5:\n",
            round!($p, $bc),
            "dec {n}\n",
            "jnz 5b\n",
            finish_group!($p, $w, $span, $bc),
        )
    };
    (single, $p:literal, $w:literal, $span:literal, $bc:literal) => {
        cipher_only!(@one, $p, $w, $span, $bc)
    };
    (double, $p:literal, $w:literal, $span:literal, $bc:literal) => {
        concat!(
            cipher_only!(@one, $p, $w, $span, $bc),
            cipher_only!(@one, $p, $w, $span, $bc),
        )
    };
}

/// Defines a loop that runs the counter and nothing else, for the
/// direction of GCM-SIV that cannot hash as it goes: encrypting, the
/// tag covers the plaintext and the counter comes from the tag, so the
/// hash has to finish before the cipher may start.
macro_rules! counter_groups {
    ($name:ident, $offs:ident, $p:literal, $w:literal, $span:literal,
     $bc:literal, $zero:literal) => {
        /// # Safety
        /// Requires the instructions [`supported`] asks for. `rk`
        /// must point at `rounds + 1` round keys and `counter` at a
        /// block; `data` must be `groups` groups of writable bytes
        /// with `groups >= 1`. The counter is left to the caller,
        /// which cut the run so that the byte-wise add cannot carry.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            counter: *const u8,
            data: *mut u8,
            groups: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    concat!($bc, " ", $p, "9, [{counter}]"),
                    "3:",
                    cipher_only!(single, $p, $w, $span, $bc),
                    "dec {groups}",
                    "jnz 3b",
                    $zero,
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 8,
                    counter = in(reg) counter,
                    data = inout(reg) data => _,
                    groups = inout(reg) groups => _,
                    k = out(reg) _,
                    n = out(reg) _,
                    offs = sym $offs,
                    out("ymm0") _, out("ymm1") _, out("ymm2") _,
                    out("ymm3") _, out("ymm4") _, out("ymm5") _,
                    out("ymm6") _, out("ymm7") _, out("ymm8") _,
                    out("ymm9") _,
                    options(nostack),
                );
            }
        }
    };
}

counter_groups!(
    siv_counter_groups,
    SIV_OFFSETS,
    "xmm",
    "16",
    "128",
    "vmovdqu",
    ""
);

counter_groups!(
    siv_wide_counter_groups,
    SIV_WIDE_OFFSETS,
    "ymm",
    "32",
    "256",
    "vbroadcasti128",
    // Leaving the upper halves dirty would slow down whatever plain
    // SSE code runs next, so they are cleared on the way out.
    "vzeroupper"
);

/// Defines a loop that hashes each run where it lies, before the
/// cipher overwrites it.
///
/// What decrypting GCM wants: the ciphertext the hash covers is what
/// arrived, so there is nothing to wait for.
macro_rules! immediate_groups {
    ($name:ident, $offs:ident, $p:literal, $w:literal,
     $span:literal, $s:literal, $top:literal, $back:literal,
     $bc:literal, $fold:ident, $passes:ident, $rev:ident,
     $zero:literal) => {
        /// Decrypts `runs` runs in place and hashes them as it goes.
        ///
        /// # Safety
        /// Requires the instructions [`supported`] asks for. `rk`
        /// must point at `rounds + 1` round keys and `counter` at a
        /// block. `data` must be `runs` runs of writable bytes with
        /// `runs >= 1`. `y` is the running hash and `powers` the
        /// prepared powers of the subkey this width wants. The
        /// counter is left to the caller, which cut the run so that
        /// the byte-wise add in it cannot carry.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            counter: *const u8,
            data: *mut u8,
            groups: usize,
            y: *mut u64,
            powers: *const u8,
        ) {
            unsafe {
                core::arch::asm!(
                    prologue!($p, $top, $bc),
                    "3:",
                    passes!($passes, $p, $w, $s, $span, $bc, $rev),
                    reduce!($fold),
                    concat!("add {pw}, ", $back),
                    "dec {groups}",
                    "jnz 3b",
                    epilogue!(),
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

/// Defines a loop that hashes the run before the one it is working
/// on, because what the hash covers is what the cipher produces.
///
/// What encrypting GCM wants, and what decrypting GCM-SIV wants: in
/// both the hash covers the side of the message the cipher is about
/// to write. The first run goes through the rounds with nothing
/// beside it, every run after it is run while its predecessor is
/// hashed, and the last is hashed on the way out.
macro_rules! lagging_groups {
    ($name:ident, $offs:ident, $p:literal, $w:literal,
     $span:literal, $s:literal, $top:literal, $back:literal,
     $bc:literal, $fold:ident, $passes:ident, $rest:literal,
     $rev:ident, $zero:literal) => {
        /// Encrypts `runs` runs in place and hashes them as it goes,
        /// a run behind.
        ///
        /// # Safety
        /// As the decrypting loop above.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            counter: *const u8,
            data: *mut u8,
            groups: usize,
            y: *mut u64,
            powers: *const u8,
        ) {
            unsafe {
                core::arch::asm!(
                    prologue!($p, $top, $bc),
                    cipher_only!($passes, $p, $w, $span, $bc),
                    "dec {groups}",
                    "jz 6f",
                    "3:",
                    passes!($passes, $p, $w, $s, $span, $bc, $rev),
                    reduce!($fold),
                    concat!("add {pw}, ", $back),
                    "dec {groups}",
                    "jnz 3b",
                    // Which leaves the last run unhashed.
                    "6:",
                    ghash_first!($p, $w, $s, $rev),
                    hash_rest!("7", $rest, $p, $w, $s, $rev),
                    reduce!($fold),
                    epilogue!(),
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

/// Defines both shapes at one width, which is what GCM needs.
macro_rules! groups {
    ($decrypt:ident, $encrypt:ident, $offs:ident, $p:literal,
     $w:literal, $span:literal, $s:literal, $top:literal,
     $back:literal, $bc:literal, $fold:ident, $passes:ident,
     $rest:literal, $rev:ident, $zero:literal) => {
        immediate_groups!(
            $decrypt, $offs, $p, $w, $span, $s, $top, $back, $bc, $fold,
            $passes, $rev, $zero
        );
        lagging_groups!(
            $encrypt, $offs, $p, $w, $span, $s, $top, $back, $bc, $fold,
            $passes, $rest, $rev, $zero
        );
    };
}

groups!(
    decrypt_groups,
    encrypt_groups,
    OFFSETS,
    "xmm",
    "16",
    "128",
    "32",
    "224",
    "256",
    "vmovdqu",
    narrow,
    single,
    "7",
    reversed,
    ""
);

groups!(
    wide_decrypt_groups,
    wide_encrypt_groups,
    WIDE_OFFSETS,
    "ymm",
    "32",
    "256",
    "64",
    "960",
    "1024",
    "vbroadcasti128",
    wide,
    double,
    "15",
    reversed,
    // Leaving the upper halves dirty would slow down whatever plain
    // SSE code runs next, so they are cleared on the way out.
    "vzeroupper"
);

lagging_groups!(
    siv_decrypt_groups,
    SIV_OFFSETS,
    "xmm",
    "16",
    "128",
    "32",
    "224",
    "256",
    "vmovdqu",
    narrow,
    single,
    "7",
    // POLYVAL reads a block's bytes as they lie. The narrower width
    // only: GCM-SIV derives a hash key for every message, so the
    // wider table of powers cannot earn back the building.
    kept,
    ""
);
