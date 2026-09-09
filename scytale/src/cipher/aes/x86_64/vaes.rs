//! AES using the VAES instructions on 256-bit registers, with the
//! block loops in hand-written assembly.
//!
//! Each 256-bit register holds two blocks, and the loops keep eight
//! registers in flight, so sixteen blocks go through each round
//! together; a tail of fewer pairs goes through one pass of exactly
//! its width. A block left over after the pairs is handled with plain
//! AES-NI.
//!
//! # Availability
//!
//! [`Aes::new`] checks at run time for VAES, AVX2 and operating
//! system support for 256-bit registers, and returns
//! [`Error::NotSupported`] otherwise.
//!

use core::fmt;

use super::{RoundKeys, aesni, expand, has_vaes256};
use crate::cipher::aes::{BLOCK_SIZE, KeySize};
use crate::cipher::mode::xor;
use crate::cipher::{BlockCipher, ByteOrder, add_counter};
use crate::{BlockType, Key, KeyType};
use zeroize::ZeroizeOnDrop;

/// Bytes in one 256-bit register: two blocks.
const PAIR: usize = 2 * BLOCK_SIZE;

/// An AES cipher with an expanded key, using VAES.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::new`]; the key is wiped on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes<const K: usize> {
    /// 128-bit keys; the loops broadcast each into both halves of a
    /// 256-bit register as they load it.
    keys: RoundKeys,
}

impl<const K: usize> fmt::Debug for Aes<K> {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes")
            .field("rounds", &self.rounds())
            .finish()
    }
}

impl<const K: usize> Aes<K> {
    /// Whether this processor can run this implementation.
    pub(crate) fn supported() -> bool {
        has_vaes256()
    }

    /// Expands `key`.
    ///
    /// # Panics
    /// If the processor lacks VAES. The type is private and
    /// is named only after the probe has confirmed them, so the
    /// panic is unreachable from outside this crate.
    pub(crate) fn new(key: &[u8; K]) -> Self {
        const {
            assert!(
                K == 16 || K == 24 || K == 32,
                "AES keys are 16, 24 or 32 bytes"
            )
        };
        assert!(Self::supported(), "VAES not available");
        // SAFETY: just confirmed present.
        unsafe { Self::new_unchecked(key) }
    }

    /// Expands `key` without checking for VAES.
    ///
    /// # Safety
    /// The caller must have confirmed that VAES, AVX2 and operating
    /// system support for 256-bit registers are available.
    pub(crate) unsafe fn new_unchecked(key: &[u8; K]) -> Self {
        unsafe {
            let size = KeySize::for_key(key);
            let keys = expand(key, size);
            Aes { keys }
        }
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.keys.size.rounds()
    }

    /// Encrypts every block in place, independently (ECB).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = blocks.as_flattened_mut();
        let (pairs, odd) = data.split_at_mut(data.len() / PAIR * PAIR);
        // SAFETY: the struct only exists if try_new confirmed VAES;
        // `pairs` is a whole number of pairs.
        unsafe {
            encrypt_pairs(&self.keys, pairs);
            aesni::encrypt_blocks(&self.keys, odd);
        }
    }

    /// Decrypts every block in place, independently (ECB).
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = blocks.as_flattened_mut();
        let (pairs, odd) = data.split_at_mut(data.len() / PAIR * PAIR);
        // SAFETY: as in encrypt_blocks.
        unsafe {
            decrypt_pairs(&self.keys, pairs);
            aesni::decrypt_blocks(&self.keys, odd);
        }
    }

    /// Counter mode's inner loop; see
    /// [`BlockCipher::xor_counter_blocks`].
    ///
    /// The counters are made in registers and encrypted where they
    /// lie, then XORed over the data on the way to a single store,
    /// so a block is read once and written once, which is what plain
    /// ECB costs. Whole groups go first, then one pass of exactly the
    /// pairs left over, then a last odd block.
    pub fn xor_counter_blocks(
        &self,
        counter: &mut [u8; BLOCK_SIZE],
        order: ByteOrder,
        data: &mut [u8],
    ) {
        debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
        let shuffle = shuffle_for(order);
        let rk = self.keys.enc.as_ptr();
        let rounds = self.keys.size.rounds();
        let mut data = data;

        let groups = data.len() / (GROUP * BLOCK_SIZE);
        if groups > 0 {
            let (whole, rest) = data.split_at_mut(groups * GROUP * BLOCK_SIZE);
            // SAFETY: the struct only exists if try_new confirmed
            // VAES; `whole` is `groups` whole groups, at least one.
            // The loop leaves `counter` on the block after the last.
            unsafe {
                counter_groups(
                    rk,
                    rounds,
                    counter.as_mut_ptr(),
                    whole.as_mut_ptr(),
                    groups,
                    shuffle,
                );
            }
            data = rest;
        }

        // At most seven pairs are left, each with a body of its own
        // width so that the tail costs one pass and not a group.
        let pairs = data.len() / PAIR;
        if pairs > 0 {
            let (whole, rest) = data.split_at_mut(pairs * PAIR);
            // SAFETY: as above, and `pairs` is 1 to 7, which indexes
            // the table, with `whole` exactly that many pairs.
            unsafe {
                PAIRS[pairs - 1](
                    rk,
                    rounds,
                    counter.as_ptr(),
                    whole.as_mut_ptr(),
                    shuffle,
                );
            }
            add_counter(counter, order, 2 * pairs as u32);
            data = rest;
        }

        if !data.is_empty() {
            let mut block = [*counter];
            self.encrypt_blocks(&mut block);
            let block = block[0];
            xor(data, &block);
            add_counter(counter, order, 1);
        }
    }
}

/// Blocks the counter loop puts through the cipher at once: eight
/// 256-bit registers, two blocks in each.
const GROUP: usize = 16;

impl<const K: usize> super::Keyed for Aes<K> {
    /// Always: this implementation exists only where they do.
    fn schedule(&self) -> Option<super::Schedule<'_>> {
        Some(super::Schedule::new(&self.keys))
    }
}

impl<const K: usize> BlockType for Aes<K> {
    type Block = [u8; BLOCK_SIZE];

    fn zero_block() -> Self::Block {
        [0; BLOCK_SIZE]
    }
}

impl<const K: usize> KeyType for Aes<K> {
    type Key = Key<[u8; K]>;

    fn zero_key() -> Self::Key {
        Key::zeroed()
    }
}

impl<const K: usize> BlockCipher for Aes<K> {
    fn new(key: &Self::Key) -> Self {
        Aes::new(key.array())
    }

    fn encrypt(&self, blocks: &mut [Self::Block]) {
        Aes::encrypt_blocks(self, blocks)
    }

    fn decrypt(&self, blocks: &mut [Self::Block]) {
        Aes::decrypt_blocks(self, blocks)
    }
}

/// Encrypts a whole number of block pairs.
///
/// # Safety
/// Requires VAES and AVX2; `data.len()` must be a multiple of 32.
unsafe fn encrypt_pairs(keys: &RoundKeys, data: &mut [u8]) {
    unsafe {
        run(
            keys.enc.as_ptr(),
            keys.size.rounds(),
            data,
            encrypt8,
            [
                encrypt1, encrypt2, encrypt3, encrypt4, encrypt5, encrypt6,
                encrypt7,
            ],
        )
    }
}

/// Decrypts a whole number of block pairs.
///
/// # Safety
/// Requires VAES and AVX2; `data.len()` must be a multiple of 32.
unsafe fn decrypt_pairs(keys: &RoundKeys, data: &mut [u8]) {
    unsafe {
        run(
            keys.dec.as_ptr(),
            keys.size.rounds(),
            data,
            decrypt8,
            [
                decrypt1, decrypt2, decrypt3, decrypt4, decrypt5, decrypt6,
                decrypt7,
            ],
        )
    }
}

/// A body that processes `n` register pairs at `data`.
type Body = unsafe fn(*const u32, usize, *mut u8);

/// Whole groups of eight pairs through `groups`, then the 1 to 7
/// leftover pairs through the body of exactly that width, so the tail
/// is one interleaved pass rather than a sequence of single pairs.
///
/// # Safety
/// Requires VAES and AVX2; `data.len()` must be a multiple of 32.
unsafe fn run(
    rk: *const u32,
    rounds: usize,
    data: &mut [u8],
    groups: unsafe fn(*const u32, usize, *mut u8, usize),
    tails: [Body; 7],
) {
    unsafe {
        let pairs = data.len() / PAIR;
        let full = pairs / 8;
        let mut p = data.as_mut_ptr();
        if full > 0 {
            groups(rk, rounds, p, full);
            p = p.add(full * 8 * PAIR);
        }
        if let Some(tail) = (pairs % 8).checked_sub(1) {
            tails[tail](rk, rounds, p);
        }
    }
}

// The bodies below are hand-written so the instruction order can be
// tuned. Block pairs live in ymm0..ymm7; round keys are broadcast
// into ymm8 straight from the 128-bit key array. The middle rounds
// loop over the key pointer, so one body serves all key sizes.
// `vzeroupper` at the end of each avoids the SSE/AVX transition
// penalty for whatever runs next.

/// Defines a body that runs the listed registers, loaded from the
/// listed byte offsets, through the cipher once.
macro_rules! body {
    ($name:ident, $mid:literal, $last:literal,
     [$(($r:literal, $off:literal)),+]) => {
        /// # Safety
        /// Requires VAES and AVX2; `rk` must point at `rounds + 1`
        /// round keys and `data` at the pairs this body handles.
        unsafe fn $name(rk: *const u32, rounds: usize, data: *mut u8) {
            unsafe {
                core::arch::asm!(
                    "vbroadcasti128 ymm8, [{rk}]",
                    $(concat!("vmovdqu ", $r, ", [{data} + ", $off, "]"),)+
                    $(concat!("vpxor ", $r, ", ", $r, ", ymm8"),)+
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "vbroadcasti128 ymm8, [{k}]",
                    $(concat!($mid, " ", $r, ", ", $r, ", ymm8"),)+
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "vbroadcasti128 ymm8, [{k}]",
                    $(concat!($last, " ", $r, ", ", $r, ", ymm8"),)+
                    $(concat!("vmovdqu [{data} + ", $off, "], ", $r),)+
                    "vzeroupper",
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    data = in(reg) data,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
                    out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
                    out("ymm8") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Defines the loop over whole groups of eight pairs.
macro_rules! groups {
    ($name:ident, $mid:literal, $last:literal) => {
        /// # Safety
        /// Requires VAES and AVX2; `rk` must point at `rounds + 1`
        /// round keys and `data` at `groups * 256` writable bytes,
        /// `groups >= 1`.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            data: *mut u8,
            groups: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    "3:",
                    "vbroadcasti128 ymm8, [{rk}]",
                    "vmovdqu ymm0, [{data}]",
                    "vmovdqu ymm1, [{data} + 32]",
                    "vmovdqu ymm2, [{data} + 64]",
                    "vmovdqu ymm3, [{data} + 96]",
                    "vmovdqu ymm4, [{data} + 128]",
                    "vmovdqu ymm5, [{data} + 160]",
                    "vmovdqu ymm6, [{data} + 192]",
                    "vmovdqu ymm7, [{data} + 224]",
                    "vpxor ymm0, ymm0, ymm8",
                    "vpxor ymm1, ymm1, ymm8",
                    "vpxor ymm2, ymm2, ymm8",
                    "vpxor ymm3, ymm3, ymm8",
                    "vpxor ymm4, ymm4, ymm8",
                    "vpxor ymm5, ymm5, ymm8",
                    "vpxor ymm6, ymm6, ymm8",
                    "vpxor ymm7, ymm7, ymm8",
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "vbroadcasti128 ymm8, [{k}]",
                    concat!($mid, " ymm0, ymm0, ymm8"),
                    concat!($mid, " ymm1, ymm1, ymm8"),
                    concat!($mid, " ymm2, ymm2, ymm8"),
                    concat!($mid, " ymm3, ymm3, ymm8"),
                    concat!($mid, " ymm4, ymm4, ymm8"),
                    concat!($mid, " ymm5, ymm5, ymm8"),
                    concat!($mid, " ymm6, ymm6, ymm8"),
                    concat!($mid, " ymm7, ymm7, ymm8"),
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "vbroadcasti128 ymm8, [{k}]",
                    concat!($last, " ymm0, ymm0, ymm8"),
                    concat!($last, " ymm1, ymm1, ymm8"),
                    concat!($last, " ymm2, ymm2, ymm8"),
                    concat!($last, " ymm3, ymm3, ymm8"),
                    concat!($last, " ymm4, ymm4, ymm8"),
                    concat!($last, " ymm5, ymm5, ymm8"),
                    concat!($last, " ymm6, ymm6, ymm8"),
                    concat!($last, " ymm7, ymm7, ymm8"),
                    "vmovdqu [{data}], ymm0",
                    "vmovdqu [{data} + 32], ymm1",
                    "vmovdqu [{data} + 64], ymm2",
                    "vmovdqu [{data} + 96], ymm3",
                    "vmovdqu [{data} + 128], ymm4",
                    "vmovdqu [{data} + 160], ymm5",
                    "vmovdqu [{data} + 192], ymm6",
                    "vmovdqu [{data} + 224], ymm7",
                    "add {data}, 256",
                    "dec {groups}",
                    "jnz 3b",
                    "vzeroupper",
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    data = inout(reg) data => _,
                    groups = inout(reg) groups => _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
                    out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
                    out("ymm8") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Constants the counter loop reads, kept at the width it loads them.
#[repr(align(32))]
struct Mask([u8; 32]);

#[repr(align(32))]
struct Words<const N: usize>([u32; N]);

/// Reverses the bytes of each 128-bit lane. The counter is the last
/// four bytes of a block, most significant first; reversed, it is the
/// low doubleword of the lane, least significant first, which is
/// where a doubleword add can reach it.
static BSWAP: Mask = Mask([
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11,
    10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
]);

/// Leaves a register alone. A counter in the first four bytes, least
/// significant first, is already the low doubleword, so the same loop
/// serves it with nothing to reverse.
static KEEP: Mask = Mask([
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6,
    7, 8, 9, 10, 11, 12, 13, 14, 15,
]);

/// The shuffle that puts a block's counter field in the low
/// doubleword, and afterwards puts it back.
fn shuffle_for(order: ByteOrder) -> *const u8 {
    match order {
        ByteOrder::Big => BSWAP.0.as_ptr(),
        ByteOrder::Little => KEEP.0.as_ptr(),
    }
}

/// What each register adds to the base counter: register `i` carries
/// blocks `2i` and `2i + 1`, one in each lane.
static OFFSETS: Words<64> = {
    let mut w = [0u32; 64];
    let mut i = 0;
    while i < 8 {
        w[8 * i] = 2 * i as u32;
        w[8 * i + 4] = 2 * i as u32 + 1;
        i += 1;
    }
    Words(w)
};

/// One group's worth, added to the base after each pass.
static ADVANCE: Words<8> =
    Words([GROUP as u32, 0, 0, 0, GROUP as u32, 0, 0, 0]);

/// Runs whole groups of counter blocks through the cipher and XORs
/// them over `data`, leaving `counter` on the block after the last.
///
/// The counters are made in registers from a single base rather than
/// read from memory, and the result is XORed against the data on its
/// way out, so a block is read once and written once. Only the low
/// doubleword is added to, so a carry out of the counter field would
/// be lost; the caller splits its run at that boundary.
///
/// # Safety
/// Requires VAES and AVX2; `rk` must point at `rounds + 1` round
/// keys, `counter` at a block, and `data` at `groups * 256` writable
/// bytes, with `groups >= 1`.
unsafe fn counter_groups(
    rk: *const u32,
    rounds: usize,
    counter: *mut u8,
    data: *mut u8,
    groups: usize,
    shuffle: *const u8,
) {
    unsafe {
        core::arch::asm!(
            "vmovdqa ymm10, [{shuffle}]",
            "vmovdqa ymm11, [{advance}]",
            // The base counter, a copy in each lane, byte-reversed.
            "vbroadcasti128 ymm9, [{counter}]",
            "vpshufb ymm9, ymm9, ymm10",
            "3:",
            // Eight registers of counters from the one base, then
            // the base moved on while they are turned back into
            // blocks: the add and the shuffles do not depend on each
            // other and fill the slots the cipher leaves idle.
            "vpaddd ymm0, ymm9, [{offs}]",
            "vpaddd ymm1, ymm9, [{offs} + 32]",
            "vpaddd ymm2, ymm9, [{offs} + 64]",
            "vpaddd ymm3, ymm9, [{offs} + 96]",
            "vpaddd ymm4, ymm9, [{offs} + 128]",
            "vpaddd ymm5, ymm9, [{offs} + 160]",
            "vpaddd ymm6, ymm9, [{offs} + 192]",
            "vpaddd ymm7, ymm9, [{offs} + 224]",
            "vpaddd ymm9, ymm9, ymm11",
            "vpshufb ymm0, ymm0, ymm10",
            "vpshufb ymm1, ymm1, ymm10",
            "vpshufb ymm2, ymm2, ymm10",
            "vpshufb ymm3, ymm3, ymm10",
            "vpshufb ymm4, ymm4, ymm10",
            "vpshufb ymm5, ymm5, ymm10",
            "vpshufb ymm6, ymm6, ymm10",
            "vpshufb ymm7, ymm7, ymm10",
            "vbroadcasti128 ymm8, [{rk}]",
            "vpxor ymm0, ymm0, ymm8",
            "vpxor ymm1, ymm1, ymm8",
            "vpxor ymm2, ymm2, ymm8",
            "vpxor ymm3, ymm3, ymm8",
            "vpxor ymm4, ymm4, ymm8",
            "vpxor ymm5, ymm5, ymm8",
            "vpxor ymm6, ymm6, ymm8",
            "vpxor ymm7, ymm7, ymm8",
            "lea {k}, [{rk} + 16]",
            "mov {n}, {nr}",
            "2:",
            "vbroadcasti128 ymm8, [{k}]",
            "vaesenc ymm0, ymm0, ymm8",
            "vaesenc ymm1, ymm1, ymm8",
            "vaesenc ymm2, ymm2, ymm8",
            "vaesenc ymm3, ymm3, ymm8",
            "vaesenc ymm4, ymm4, ymm8",
            "vaesenc ymm5, ymm5, ymm8",
            "vaesenc ymm6, ymm6, ymm8",
            "vaesenc ymm7, ymm7, ymm8",
            "add {k}, 16",
            "dec {n}",
            "jnz 2b",
            "vbroadcasti128 ymm8, [{k}]",
            "vaesenclast ymm0, ymm0, ymm8",
            "vaesenclast ymm1, ymm1, ymm8",
            "vaesenclast ymm2, ymm2, ymm8",
            "vaesenclast ymm3, ymm3, ymm8",
            "vaesenclast ymm4, ymm4, ymm8",
            "vaesenclast ymm5, ymm5, ymm8",
            "vaesenclast ymm6, ymm6, ymm8",
            "vaesenclast ymm7, ymm7, ymm8",
            // The keystream never reaches memory: it is XORed over
            // the data on the way to the one store.
            "vpxor ymm0, ymm0, [{data}]",
            "vpxor ymm1, ymm1, [{data} + 32]",
            "vpxor ymm2, ymm2, [{data} + 64]",
            "vpxor ymm3, ymm3, [{data} + 96]",
            "vpxor ymm4, ymm4, [{data} + 128]",
            "vpxor ymm5, ymm5, [{data} + 160]",
            "vpxor ymm6, ymm6, [{data} + 192]",
            "vpxor ymm7, ymm7, [{data} + 224]",
            "vmovdqu [{data}], ymm0",
            "vmovdqu [{data} + 32], ymm1",
            "vmovdqu [{data} + 64], ymm2",
            "vmovdqu [{data} + 96], ymm3",
            "vmovdqu [{data} + 128], ymm4",
            "vmovdqu [{data} + 160], ymm5",
            "vmovdqu [{data} + 192], ymm6",
            "vmovdqu [{data} + 224], ymm7",
            "add {data}, 256",
            "dec {groups}",
            "jnz 3b",
            // Hand the counter back in block order.
            "vpshufb ymm9, ymm9, ymm10",
            "vmovdqu [{counter}], xmm9",
            "vzeroupper",
            rk = in(reg) rk,
            nr = in(reg) rounds - 1,
            counter = in(reg) counter,
            data = inout(reg) data => _,
            groups = inout(reg) groups => _,
            offs = in(reg) OFFSETS.0.as_ptr(),
            shuffle = in(reg) shuffle,
            advance = in(reg) ADVANCE.0.as_ptr(),
            k = out(reg) _,
            n = out(reg) _,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
            options(nostack),
        );
    }
}

/// Defines a counter body for a fixed number of pairs: it makes its
/// counters from `counter`, encrypts them and XORs them over `data`.
/// Advancing `counter` is left to the caller, which knows the width.
macro_rules! counter_body {
    ($name:ident, [$(($r:literal, $off:literal)),+]) => {
        /// # Safety
        /// Requires VAES and AVX2; `rk` must point at `rounds + 1`
        /// round keys, `counter` at a block, and `data` at the pairs
        /// this body handles.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            counter: *const u8,
            data: *mut u8,
            shuffle: *const u8,
        ) {
            unsafe {
                core::arch::asm!(
                    "vmovdqa ymm10, [{shuffle}]",
                    "vbroadcasti128 ymm9, [{counter}]",
                    "vpshufb ymm9, ymm9, ymm10",
                    $(concat!(
                        "vpaddd ", $r, ", ymm9, [{offs} + ", $off, "]"),)+
                    $(concat!("vpshufb ", $r, ", ", $r, ", ymm10"),)+
                    "vbroadcasti128 ymm8, [{rk}]",
                    $(concat!("vpxor ", $r, ", ", $r, ", ymm8"),)+
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "vbroadcasti128 ymm8, [{k}]",
                    $(concat!("vaesenc ", $r, ", ", $r, ", ymm8"),)+
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "vbroadcasti128 ymm8, [{k}]",
                    $(concat!("vaesenclast ", $r, ", ", $r, ", ymm8"),)+
                    $(concat!(
                        "vpxor ", $r, ", ", $r, ", [{data} + ", $off, "]"),)+
                    $(concat!("vmovdqu [{data} + ", $off, "], ", $r),)+
                    "vzeroupper",
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    counter = in(reg) counter,
                    data = in(reg) data,
                    offs = in(reg) OFFSETS.0.as_ptr(),
                    shuffle = in(reg) shuffle,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
                    out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm8") _,
                    out("ymm9") _, out("ymm10") _,
                    options(nostack),
                );
            }
        }
    };
}

counter_body!(counter1, [("ymm0", "0")]);
counter_body!(counter2, [("ymm0", "0"), ("ymm1", "32")]);
counter_body!(counter3, [("ymm0", "0"), ("ymm1", "32"), ("ymm2", "64")]);
counter_body!(
    counter4,
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96")
    ]
);
counter_body!(
    counter5,
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96"),
        ("ymm4", "128")
    ]
);
counter_body!(
    counter6,
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96"),
        ("ymm4", "128"),
        ("ymm5", "160")
    ]
);
counter_body!(
    counter7,
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96"),
        ("ymm4", "128"),
        ("ymm5", "160"),
        ("ymm6", "192")
    ]
);

/// A counter body: the round keys, the round count, the counter
/// block, the data, and the shuffle that puts the counter field
/// where an add can reach it.
type CounterBody = unsafe fn(*const u32, usize, *const u8, *mut u8, *const u8);

/// The bodies by pair count, so that a tail of `n` pairs is one call.
static PAIRS: [CounterBody; 7] = [
    counter1, counter2, counter3, counter4, counter5, counter6, counter7,
];

groups!(encrypt8, "vaesenc", "vaesenclast");
groups!(decrypt8, "vaesdec", "vaesdeclast");

body!(encrypt1, "vaesenc", "vaesenclast", [("ymm0", "0")]);
body!(
    encrypt2,
    "vaesenc",
    "vaesenclast",
    [("ymm0", "0"), ("ymm1", "32")]
);
body!(
    encrypt3,
    "vaesenc",
    "vaesenclast",
    [("ymm0", "0"), ("ymm1", "32"), ("ymm2", "64")]
);
body!(
    encrypt4,
    "vaesenc",
    "vaesenclast",
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96")
    ]
);
body!(
    encrypt5,
    "vaesenc",
    "vaesenclast",
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96"),
        ("ymm4", "128")
    ]
);
body!(
    encrypt6,
    "vaesenc",
    "vaesenclast",
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96"),
        ("ymm4", "128"),
        ("ymm5", "160")
    ]
);
body!(
    encrypt7,
    "vaesenc",
    "vaesenclast",
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96"),
        ("ymm4", "128"),
        ("ymm5", "160"),
        ("ymm6", "192")
    ]
);

body!(decrypt1, "vaesdec", "vaesdeclast", [("ymm0", "0")]);
body!(
    decrypt2,
    "vaesdec",
    "vaesdeclast",
    [("ymm0", "0"), ("ymm1", "32")]
);
body!(
    decrypt3,
    "vaesdec",
    "vaesdeclast",
    [("ymm0", "0"), ("ymm1", "32"), ("ymm2", "64")]
);
body!(
    decrypt4,
    "vaesdec",
    "vaesdeclast",
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96")
    ]
);
body!(
    decrypt5,
    "vaesdec",
    "vaesdeclast",
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96"),
        ("ymm4", "128")
    ]
);
body!(
    decrypt6,
    "vaesdec",
    "vaesdeclast",
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96"),
        ("ymm4", "128"),
        ("ymm5", "160")
    ]
);
body!(
    decrypt7,
    "vaesdec",
    "vaesdeclast",
    [
        ("ymm0", "0"),
        ("ymm1", "32"),
        ("ymm2", "64"),
        ("ymm3", "96"),
        ("ymm4", "128"),
        ("ymm5", "160"),
        ("ymm6", "192")
    ]
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::portable;

    /// Returns the cipher, or `None` (skipping the test) without VAES.
    fn aes<const K: usize>(key: &[u8; K]) -> Option<Aes<K>> {
        Aes::<K>::supported().then(|| Aes::new(key))
    }

    /// The counter loop against a block at a time, at every length
    /// across a group, its tail widths and the block after it.
    ///
    /// Round-tripping would not catch a wrong keystream, since the
    /// same wrong keystream undoes itself.
    #[test]
    fn counter_blocks_match_a_block_at_a_time() {
        let Some(aes) = aes(&[0x5au8; 16]) else {
            return;
        };
        // Both conventions: GCM's last four bytes and GCM-SIV's
        // first four, which is the same loop with nothing to
        // reverse.
        for order in [ByteOrder::Big, ByteOrder::Little] {
            counter_blocks_match(&aes, order);
        }
    }

    fn counter_blocks_match<const K: usize>(aes: &Aes<K>, order: ByteOrder) {
        const N: usize = (2 * GROUP + 5) * BLOCK_SIZE;
        let start = [0x77u8; BLOCK_SIZE];

        let mut want = [0u8; N];
        let mut counter = start;
        for chunk in want.chunks_mut(BLOCK_SIZE) {
            let mut block = counter;
            aes.encrypt_blocks(core::slice::from_mut(&mut block));
            chunk.copy_from_slice(&block);
            add_counter(&mut counter, order, 1);
        }

        for blocks in 0..=N / BLOCK_SIZE {
            let n = blocks * BLOCK_SIZE;
            let mut got = [0u8; N];
            let mut counter = start;
            aes.xor_counter_blocks(&mut counter, order, &mut got[..n]);
            assert_eq!(got[..n], want[..n], "{blocks} blocks");
            // And the counter is left on the block after the last.
            let mut want_counter = start;
            add_counter(&mut want_counter, order, blocks as u32);
            assert_eq!(counter, want_counter, "{blocks} blocks, counter");
        }
    }

    fn unhex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            let hex = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(hex, 16).unwrap();
        }
        out
    }

    fn check<const K: usize>(key: &str, plain: &str, cipher: &str) {
        let key: [u8; K] = unhex(key)[..K].try_into().unwrap();
        let plain: [u8; 16] = unhex(plain)[..16].try_into().unwrap();
        let cipher: [u8; 16] = unhex(cipher)[..16].try_into().unwrap();
        let Some(aes) = aes(&key) else { return };

        let mut block = plain;
        aes.encrypt_blocks(core::slice::from_mut(&mut block));
        assert_eq!(block, cipher, "encrypt");
        aes.decrypt_blocks(core::slice::from_mut(&mut block));
        assert_eq!(block, plain, "decrypt");

        // Same vector through the 256-bit path: two copies.
        let mut pair = [plain, plain];
        aes.encrypt_blocks(&mut pair);
        assert_eq!(pair, [cipher, cipher]);
        aes.decrypt_blocks(&mut pair);
        assert_eq!(pair, [plain, plain]);
    }

    // FIPS 197 Appendix C.
    #[test]
    fn fips197_aes128() {
        check::<16>(
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        );
    }

    #[test]
    fn fips197_aes192() {
        check::<24>(
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        );
    }

    #[test]
    fn fips197_aes256() {
        check::<32>(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        );
    }

    #[test]
    fn matches_ttable() {
        matches_ttable_for::<16>();
        matches_ttable_for::<24>();
        matches_ttable_for::<32>();
    }

    fn matches_ttable_for<const K: usize>() {
        const MAX: usize = 40;
        let klen = K;
        {
            let mut key = [0u8; K];
            for (i, k) in key.iter_mut().enumerate() {
                *k = (i * 37 + klen) as u8;
            }
            let Some(hw) = aes(&key) else { return };
            let sw = portable::ttable::Aes::new(&key);
            // Every pair-tail width and odd block, with and without
            // full groups before it.
            for nblocks in 0..40 {
                let mut data = [[0u8; BLOCK_SIZE]; MAX];
                for (i, b) in data.as_flattened_mut().iter_mut().enumerate() {
                    *b = (i * 13 + klen) as u8;
                }
                let data = &mut data[..nblocks];
                let mut expected = [[0u8; BLOCK_SIZE]; MAX];
                let expected = &mut expected[..data.len()];
                expected.copy_from_slice(data);
                let mut orig = [[0u8; BLOCK_SIZE]; MAX];
                orig[..data.len()].copy_from_slice(data);

                sw.encrypt_blocks(expected);
                hw.encrypt_blocks(data);
                assert_eq!(data, expected, "encrypt {klen} {nblocks}");
                hw.decrypt_blocks(data);
                assert_eq!(data, &orig[..data.len()], "decrypt {klen}");
            }
        }
    }

    #[test]
    fn round_counts() {
        let Some(a) = aes(&[0; 16]) else { return };
        assert_eq!(a.rounds(), 10);
        assert_eq!(aes(&[0; 24]).unwrap().rounds(), 12);
        assert_eq!(aes(&[0; 32]).unwrap().rounds(), 14);
    }
}
