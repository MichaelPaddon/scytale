//! AES using the ARMv8 cryptography extension, with the round loops
//! in hand-written assembly.
//!
//! `aese` does AddRoundKey, SubBytes and ShiftRows in one instruction
//! and `aesmc` does MixColumns; `aesd` and `aesimc` are the inverses.
//! The multi-block methods feed eight blocks through each round
//! together so the pipelined AES unit stays busy; a tail of fewer
//! blocks goes through one pass of exactly its width.
//!
//! The S-box lives in hardware, so this implementation does not leak
//! key material through cache timing.
//!
//! # Availability
//!
//! There is no user-space CPUID on aarch64. [`Aes::new`] accepts
//! when the crate was compiled with the `aes` target feature, or, on
//! Linux, when the kernel's emulated `ID_AA64ISAR0_EL1` register
//! reports the instructions. Otherwise it returns
//! [`Error::NotSupported`].
//!

#![allow(unsafe_code)]

use core::arch::aarch64::{
    vaeseq_u8, vaesimcq_u8, vdupq_n_u8, vdupq_n_u32, vgetq_lane_u32, vld1q_u8,
    vreinterpretq_u8_u32, vreinterpretq_u32_u8, vst1q_u8,
};
use core::fmt;

use crate::cipher::aes::{BLOCK_SIZE, KeySize, MAX_WORDS, expand_words};
use crate::cipher::{BlockCipher, ByteOrder, add_counter};
use crate::{BlockType, Key, KeyType};
use zeroize::ZeroizeOnDrop;

/// An AES cipher with an expanded key, using the ARMv8 instructions.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::new`]; the key is wiped on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes<const K: usize> {
    /// Round keys as words in memory order; the loops load them
    /// straight from memory.
    enc: [u32; MAX_WORDS],
    dec: [u32; MAX_WORDS],
    #[zeroize(skip)]
    size: KeySize,
}

impl<const K: usize> fmt::Debug for Aes<K> {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes")
            .field("rounds", &self.rounds())
            .finish()
    }
}

/// Whether the AES instructions are available.
pub(crate) fn has_aes() -> bool {
    cfg!(target_feature = "aes") || id_register_reports_aes()
}

/// Linux traps and emulates reads of the ID registers from user space
/// (since 4.11). Bits 7:4 of ID_AA64ISAR0_EL1 are nonzero when
/// AESE/AESD are implemented.
#[cfg(target_os = "linux")]
fn id_register_reports_aes() -> bool {
    let isar0: u64;
    // SAFETY: reads a register the kernel exposes to user space; no
    // memory is touched.
    unsafe {
        core::arch::asm!(
            "mrs {}, ID_AA64ISAR0_EL1",
            out(reg) isar0,
            options(nomem, nostack, preserves_flags),
        );
    }
    (isar0 >> 4) & 0xf != 0
}

/// Without an operating system that exposes the ID registers there is
/// no safe way to ask, so only the compile-time feature counts.
#[cfg(not(target_os = "linux"))]
fn id_register_reports_aes() -> bool {
    false
}

impl<const K: usize> Aes<K> {
    /// Whether this processor can run this implementation.
    pub(crate) fn supported() -> bool {
        has_aes()
    }

    /// Expands `key`.
    ///
    /// # Panics
    /// If the processor lacks the AES instructions. The type is private and
    /// is named only after the probe has confirmed them, so the
    /// panic is unreachable from outside this crate.
    pub(crate) fn new(key: &[u8; K]) -> Self {
        const {
            assert!(
                K == 16 || K == 24 || K == 32,
                "AES keys are 16, 24 or 32 bytes"
            )
        };
        assert!(Self::supported(), "the AES instructions not available");
        // SAFETY: just confirmed present.
        unsafe { Self::new_unchecked(key) }
    }

    /// Expands `key` without checking for the AES instructions.
    ///
    /// # Safety
    /// The caller must have confirmed that the AES instructions are
    /// available.
    pub(crate) unsafe fn new_unchecked(key: &[u8; K]) -> Self {
        unsafe {
            let size = KeySize::for_key(key);
            expand(key, size)
        }
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.size.rounds()
    }

    /// Encrypts every block in place, independently (ECB).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = blocks.as_flattened_mut();
        // SAFETY: the struct only exists if try_new confirmed support.
        // SAFETY: the struct only exists if try_new confirmed support;
        // the length is a whole number of blocks.
        unsafe { encrypt_blocks(&self.enc, self.rounds(), data) }
    }

    /// Decrypts every block in place, independently (ECB).
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = blocks.as_flattened_mut();
        // SAFETY: the struct only exists if try_new confirmed support.
        // SAFETY: the struct only exists if try_new confirmed support;
        // the length is a whole number of blocks.
        unsafe { decrypt_blocks(&self.dec, self.rounds(), data) }
    }

    /// Counter mode's inner loop; see
    /// [`BlockCipher::xor_counter_blocks`].
    ///
    /// The counters are made in registers and encrypted where they
    /// lie, then XORed over the data on the way to a single store, so
    /// a block is read once and written once, which is what plain ECB
    /// costs. Whole groups go first, then one pass of exactly the
    /// blocks left over.
    pub fn xor_counter_blocks(
        &self,
        counter: &mut [u8; BLOCK_SIZE],
        order: ByteOrder,
        data: &mut [u8],
    ) {
        debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
        let shuffle = shuffle_for(order);
        let rk = self.enc.as_ptr();
        let rounds = self.rounds();
        let mut data = data;

        let groups = data.len() / (GROUP * BLOCK_SIZE);
        if groups > 0 {
            let (whole, rest) = data.split_at_mut(groups * GROUP * BLOCK_SIZE);
            // SAFETY: the struct only exists if try_new confirmed the
            // AES instructions; `whole` is `groups` whole groups, at
            // least one. The loop leaves `counter` on the block after
            // the last.
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

        if !data.is_empty() {
            let blocks = data.len() / BLOCK_SIZE;
            // SAFETY: as above, and `blocks` is 1 to 7, which indexes
            // the table, with `data` exactly that many blocks.
            unsafe {
                TAILS[blocks - 1](
                    rk,
                    rounds,
                    counter.as_ptr(),
                    data.as_mut_ptr(),
                    shuffle,
                );
            }
            add_counter(counter, order, blocks as u32);
        }
    }
}

/// Blocks the counter loop puts through the cipher at once.
const GROUP: usize = 8;

/// Constants the counter loop reads.
#[repr(align(16))]
struct Mask([u8; BLOCK_SIZE]);

#[repr(align(16))]
struct Words<const N: usize>([u32; N]);

/// Reverses the bytes of a register, as `tbl` indices. The counter is
/// the last four bytes of a block, most significant first; reversed,
/// it is the low word, least significant first, where a word add can
/// reach it.
static BSWAP: Mask =
    Mask([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

/// Leaves a register alone. A counter in the first four bytes, least
/// significant first, is already the low word, so the same loop
/// serves it with nothing to reverse.
static KEEP: Mask =
    Mask([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

/// The table that puts a block's counter field in the low word, and
/// afterwards puts it back.
fn shuffle_for(order: ByteOrder) -> *const u8 {
    match order {
        ByteOrder::Big => BSWAP.0.as_ptr(),
        ByteOrder::Little => KEEP.0.as_ptr(),
    }
}

/// What each register adds to the base counter to make its block,
/// then one group's worth to move the base on.
static OFFSETS: Words<{ 4 * GROUP + 4 }> = {
    let mut w = [0u32; 4 * GROUP + 4];
    let mut i = 0;
    while i < GROUP {
        w[4 * i] = i as u32;
        i += 1;
    }
    w[4 * GROUP] = GROUP as u32;
    Words(w)
};

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

/// `SubWord` via `aese` with a zero key: that applies SubBytes then
/// ShiftRows, and with the word copied into every column ShiftRows
/// only moves equal bytes around.
///
/// # Safety
/// Requires the AES instructions.
#[target_feature(enable = "aes")]
unsafe fn sub_word(w: u32) -> u32 {
    let v = vreinterpretq_u8_u32(vdupq_n_u32(w));
    let s = vaeseq_u8(v, vdupq_n_u8(0));
    vgetq_lane_u32::<0>(vreinterpretq_u32_u8(s))
}

/// The shared key expansion with the hardware S-box, then the inverse
/// keys for the equivalent inverse cipher.
///
/// # Safety
/// Requires the AES instructions.
#[target_feature(enable = "aes")]
unsafe fn expand<const K: usize>(key: &[u8; K], size: KeySize) -> Aes<K> {
    unsafe {
        let rounds = size.rounds();
        let enc = expand_words(key, size, |w| sub_word(w));

        // Decryption runs the round keys backwards, with the inner ones
        // passed through InvMixColumns so `aesd`/`aesimc` can use them
        // directly.
        let mut dec = [0u32; MAX_WORDS];
        dec[..4].copy_from_slice(&enc[4 * rounds..4 * rounds + 4]);
        for r in 1..rounds {
            let src = 4 * (rounds - r);
            // SAFETY: both slices are four words; vld1q/vst1q have no
            // alignment demand.
            let k = vld1q_u8(enc[src..].as_ptr() as *const u8);
            vst1q_u8(dec[4 * r..].as_mut_ptr() as *mut u8, vaesimcq_u8(k));
        }
        dec[4 * rounds..4 * rounds + 4].copy_from_slice(&enc[..4]);

        Aes { enc, dec, size }
    }
}

/// Encrypts a whole number of blocks.
///
/// # Safety
/// Requires the AES instructions; `data.len()` must be a multiple of
/// 16.
unsafe fn encrypt_blocks(
    rk: &[u32; MAX_WORDS],
    rounds: usize,
    data: &mut [u8],
) {
    unsafe {
        run(
            rk.as_ptr(),
            rounds,
            data,
            encrypt8,
            [
                encrypt1, encrypt2, encrypt3, encrypt4, encrypt5, encrypt6,
                encrypt7,
            ],
        )
    }
}

/// Decrypts a whole number of blocks.
///
/// # Safety
/// Requires the AES instructions; `data.len()` must be a multiple of
/// 16.
unsafe fn decrypt_blocks(
    rk: &[u32; MAX_WORDS],
    rounds: usize,
    data: &mut [u8],
) {
    unsafe {
        run(
            rk.as_ptr(),
            rounds,
            data,
            decrypt8,
            [
                decrypt1, decrypt2, decrypt3, decrypt4, decrypt5, decrypt6,
                decrypt7,
            ],
        )
    }
}

/// A body that processes `n` blocks at `data`.
type Body = unsafe fn(*const u32, usize, *mut u8);

/// Whole groups of eight through `groups`, then the 1 to 7 leftover
/// blocks through the body of exactly that width, so the tail is one
/// interleaved pass rather than a sequence of single blocks.
///
/// # Safety
/// Requires the AES instructions; `data.len()` must be a multiple of
/// 16.
unsafe fn run(
    rk: *const u32,
    rounds: usize,
    data: &mut [u8],
    groups: unsafe fn(*const u32, usize, *mut u8, usize),
    tails: [Body; 7],
) {
    unsafe {
        let blocks = data.len() / BLOCK_SIZE;
        let full = blocks / 8;
        let mut p = data.as_mut_ptr();
        if full > 0 {
            groups(rk, rounds, p, full);
            p = p.add(full * 8 * BLOCK_SIZE);
        }
        if let Some(tail) = (blocks % 8).checked_sub(1) {
            tails[tail](rk, rounds, p);
        }
    }
}

// The bodies below are hand-written so the instruction order can be
// tuned. Blocks live in v0..v7; round keys stream through v8 (and v9
// for the last one) from memory. `aese` xors the key in before
// SubBytes, so the middle-round loop covers keys 0 to `rounds - 2`
// with `aesmc`, then the last `aese` and a plain `eor` of the final
// key. The pairing of `aese` with the `aesmc` on the same register
// matters: cores fuse the two. The `target_feature` attribute only
// tells the assembler the instructions are allowed.

/// Defines a body that runs the listed registers through the cipher
/// once; blocks are loaded and stored in order from `data`.
macro_rules! body {
    ($name:ident, $mid:literal, $mix:literal, [$($r:literal),+]) => {
        /// # Safety
        /// Requires the AES instructions; `rk` must point at
        /// `rounds + 1` round keys and `data` at the blocks this body
        /// handles.
        #[target_feature(enable = "aes")]
        unsafe fn $name(rk: *const u32, rounds: usize, data: *mut u8) {
            unsafe {
                core::arch::asm!(
                    "mov {p}, {data}",
                    $(concat!("ld1 {{", $r, ".16b}}, [{p}], #16"),)+
                    "mov {k}, {rk}",
                    "mov {n}, {nr}",
                    "2:",
                    "ld1 {{v8.16b}}, [{k}], #16",
                    $(concat!($mid, " ", $r, ".16b, v8.16b"),
                      concat!($mix, " ", $r, ".16b, ", $r, ".16b"),)+
                    "subs {n}, {n}, #1",
                    "b.ne 2b",
                    "ld1 {{v8.16b, v9.16b}}, [{k}]",
                    $(concat!($mid, " ", $r, ".16b, v8.16b"),
                      concat!("eor ", $r, ".16b, ", $r, ".16b, v9.16b"),)+
                    "mov {p}, {data}",
                    $(concat!("st1 {{", $r, ".16b}}, [{p}], #16"),)+
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    data = in(reg) data,
                    p = out(reg) _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Defines the loop over whole groups of eight blocks.
macro_rules! groups {
    ($name:ident, $mid:literal, $mix:literal) => {
        /// # Safety
        /// Requires the AES instructions; `rk` must point at
        /// `rounds + 1` round keys and `data` at `groups * 128`
        /// writable bytes, `groups >= 1`.
        #[target_feature(enable = "aes")]
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            data: *mut u8,
            groups: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    "3:",
                    "add {p}, {data}, #64",
                    "ld1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{data}]",
                    "ld1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{p}]",
                    "mov {k}, {rk}",
                    "mov {n}, {nr}",
                    "2:",
                    "ld1 {{v8.16b}}, [{k}], #16",
                    concat!($mid, " v0.16b, v8.16b"),
                    concat!($mix, " v0.16b, v0.16b"),
                    concat!($mid, " v1.16b, v8.16b"),
                    concat!($mix, " v1.16b, v1.16b"),
                    concat!($mid, " v2.16b, v8.16b"),
                    concat!($mix, " v2.16b, v2.16b"),
                    concat!($mid, " v3.16b, v8.16b"),
                    concat!($mix, " v3.16b, v3.16b"),
                    concat!($mid, " v4.16b, v8.16b"),
                    concat!($mix, " v4.16b, v4.16b"),
                    concat!($mid, " v5.16b, v8.16b"),
                    concat!($mix, " v5.16b, v5.16b"),
                    concat!($mid, " v6.16b, v8.16b"),
                    concat!($mix, " v6.16b, v6.16b"),
                    concat!($mid, " v7.16b, v8.16b"),
                    concat!($mix, " v7.16b, v7.16b"),
                    "subs {n}, {n}, #1",
                    "b.ne 2b",
                    "ld1 {{v8.16b, v9.16b}}, [{k}]",
                    concat!($mid, " v0.16b, v8.16b"),
                    "eor v0.16b, v0.16b, v9.16b",
                    concat!($mid, " v1.16b, v8.16b"),
                    "eor v1.16b, v1.16b, v9.16b",
                    concat!($mid, " v2.16b, v8.16b"),
                    "eor v2.16b, v2.16b, v9.16b",
                    concat!($mid, " v3.16b, v8.16b"),
                    "eor v3.16b, v3.16b, v9.16b",
                    concat!($mid, " v4.16b, v8.16b"),
                    "eor v4.16b, v4.16b, v9.16b",
                    concat!($mid, " v5.16b, v8.16b"),
                    "eor v5.16b, v5.16b, v9.16b",
                    concat!($mid, " v6.16b, v8.16b"),
                    "eor v6.16b, v6.16b, v9.16b",
                    concat!($mid, " v7.16b, v8.16b"),
                    "eor v7.16b, v7.16b, v9.16b",
                    "st1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{data}], #64",
                    "st1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{data}], #64",
                    "subs {groups}, {groups}, #1",
                    "b.ne 3b",
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    data = inout(reg) data => _,
                    groups = inout(reg) groups => _,
                    p = out(reg) _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Runs whole groups of counter blocks through the cipher and XORs
/// them over `data`, leaving `counter` on the block after the last.
///
/// Only the low word is added to, so a carry out of the counter field
/// would be lost; the caller splits its run at that boundary.
///
/// # Safety
/// Requires the AES instructions; `rk` must point at `rounds + 1`
/// round keys, `counter` at a block, and `data` at `groups * 128`
/// writable bytes, with `groups >= 1`.
#[target_feature(enable = "aes")]
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
            // The lane offsets and the group advance stay in
            // registers: there are enough to hold them all.
            "ld1 {{v16.16b, v17.16b, v18.16b, v19.16b}}, [{offs}], #64",
            "ld1 {{v20.16b, v21.16b, v22.16b, v23.16b}}, [{offs}], #64",
            "ld1 {{v12.16b}}, [{offs}]",
            "ld1 {{v10.16b}}, [{shuffle}]",
            // The base counter, byte-reversed so the field adds.
            "ld1 {{v11.16b}}, [{counter}]",
            "tbl v11.16b, {{v11.16b}}, v10.16b",
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
            "tbl v0.16b, {{v0.16b}}, v10.16b",
            "tbl v1.16b, {{v1.16b}}, v10.16b",
            "tbl v2.16b, {{v2.16b}}, v10.16b",
            "tbl v3.16b, {{v3.16b}}, v10.16b",
            "tbl v4.16b, {{v4.16b}}, v10.16b",
            "tbl v5.16b, {{v5.16b}}, v10.16b",
            "tbl v6.16b, {{v6.16b}}, v10.16b",
            "tbl v7.16b, {{v7.16b}}, v10.16b",
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
            // The keystream never reaches memory: it is XORed over
            // the data on the way to the one store.
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
            // Hand the counter back in block order.
            "tbl v11.16b, {{v11.16b}}, v10.16b",
            "st1 {{v11.16b}}, [{counter}]",
            rk = in(reg) rk,
            nr = in(reg) rounds - 1,
            counter = in(reg) counter,
            data = inout(reg) data => _,
            groups = inout(reg) groups => _,
            offs = inout(reg) OFFSETS.0.as_ptr() => _,
            shuffle = in(reg) shuffle,
            p = out(reg) _,
            k = out(reg) _,
            n = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v16") _, out("v17") _, out("v18") _,
            out("v19") _, out("v20") _, out("v21") _, out("v22") _,
            out("v23") _, out("v24") _, out("v25") _, out("v26") _,
            out("v27") _, out("v28") _, out("v29") _, out("v30") _,
            out("v31") _,
            options(nostack),
        );
    }
}

/// Defines a counter body for a fixed number of blocks: it makes its
/// counters from `counter`, encrypts them and XORs them over `data`.
/// Advancing `counter` is left to the caller, which knows the width.
macro_rules! counter_body {
    ($name:ident, [$(($r:literal, $o:literal, $d:literal)),+]) => {
        /// # Safety
        /// Requires the AES instructions; `rk` must point at
        /// `rounds + 1` round keys, `counter` at a block, and `data`
        /// at the blocks this body handles.
        #[target_feature(enable = "aes")]
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            counter: *const u8,
            data: *mut u8,
            shuffle: *const u8,
        ) {
            unsafe {
                core::arch::asm!(
                    "ld1 {{v10.16b}}, [{shuffle}]",
                    "ld1 {{v11.16b}}, [{counter}]",
                    "tbl v11.16b, {{v11.16b}}, v10.16b",
                    "mov {p}, {offs}",
                    $(concat!(
                        "ld1 {{v12.16b}}, [{p}], #16\n",
                        "add ", $r, ".4s, v11.4s, v12.4s\n",
                        "tbl ", $r, ".16b, {{", $r, ".16b}}, v10.16b"),)+
                    "mov {k}, {rk}",
                    "mov {n}, {nr}",
                    "2:",
                    "ld1 {{v8.16b}}, [{k}], #16",
                    $(concat!(
                        "aese ", $r, ".16b, v8.16b\n",
                        "aesmc ", $r, ".16b, ", $r, ".16b"),)+
                    "subs {n}, {n}, #1",
                    "b.ne 2b",
                    "ld1 {{v8.16b, v9.16b}}, [{k}]",
                    $(concat!(
                        "aese ", $r, ".16b, v8.16b\n",
                        "eor ", $r, ".16b, ", $r, ".16b, v9.16b"),)+
                    "mov {p}, {data}",
                    $(concat!(
                        "ld1 {{v13.16b}}, [{p}]\n",
                        "eor ", $r, ".16b, ", $r, ".16b, v13.16b\n",
                        "st1 {{", $r, ".16b}}, [{p}], #16",
                        $d),)+
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    counter = in(reg) counter,
                    data = in(reg) data,
                    offs = in(reg) OFFSETS.0.as_ptr(),
                    shuffle = in(reg) shuffle,
                    p = out(reg) _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v8") _,
                    out("v9") _, out("v10") _, out("v11") _, out("v12") _,
                    out("v13") _,
                    options(nostack),
                );
            }
        }
    };
}

counter_body!(counter1, [("v0", "0", "")]);
counter_body!(counter2, [("v0", "0", ""), ("v1", "16", "")]);
counter_body!(
    counter3,
    [("v0", "0", ""), ("v1", "16", ""), ("v2", "32", "")]
);
counter_body!(
    counter4,
    [
        ("v0", "0", ""),
        ("v1", "16", ""),
        ("v2", "32", ""),
        ("v3", "48", "")
    ]
);
counter_body!(
    counter5,
    [
        ("v0", "0", ""),
        ("v1", "16", ""),
        ("v2", "32", ""),
        ("v3", "48", ""),
        ("v4", "64", "")
    ]
);
counter_body!(
    counter6,
    [
        ("v0", "0", ""),
        ("v1", "16", ""),
        ("v2", "32", ""),
        ("v3", "48", ""),
        ("v4", "64", ""),
        ("v5", "80", "")
    ]
);
counter_body!(
    counter7,
    [
        ("v0", "0", ""),
        ("v1", "16", ""),
        ("v2", "32", ""),
        ("v3", "48", ""),
        ("v4", "64", ""),
        ("v5", "80", ""),
        ("v6", "96", "")
    ]
);

/// A counter body: the round keys, the round count, the counter
/// block, the data, and the shuffle that puts the counter field
/// where an add can reach it.
type CounterBody = unsafe fn(*const u32, usize, *const u8, *mut u8, *const u8);

/// The bodies by block count, so that a tail of `n` blocks is one
/// call.
static TAILS: [CounterBody; 7] = [
    counter1, counter2, counter3, counter4, counter5, counter6, counter7,
];

groups!(encrypt8, "aese", "aesmc");
groups!(decrypt8, "aesd", "aesimc");

body!(encrypt1, "aese", "aesmc", ["v0"]);
body!(encrypt2, "aese", "aesmc", ["v0", "v1"]);
body!(encrypt3, "aese", "aesmc", ["v0", "v1", "v2"]);
body!(encrypt4, "aese", "aesmc", ["v0", "v1", "v2", "v3"]);
body!(encrypt5, "aese", "aesmc", ["v0", "v1", "v2", "v3", "v4"]);
body!(
    encrypt6,
    "aese",
    "aesmc",
    ["v0", "v1", "v2", "v3", "v4", "v5"]
);
body!(
    encrypt7,
    "aese",
    "aesmc",
    ["v0", "v1", "v2", "v3", "v4", "v5", "v6"]
);

body!(decrypt1, "aesd", "aesimc", ["v0"]);
body!(decrypt2, "aesd", "aesimc", ["v0", "v1"]);
body!(decrypt3, "aesd", "aesimc", ["v0", "v1", "v2"]);
body!(decrypt4, "aesd", "aesimc", ["v0", "v1", "v2", "v3"]);
body!(decrypt5, "aesd", "aesimc", ["v0", "v1", "v2", "v3", "v4"]);
body!(
    decrypt6,
    "aesd",
    "aesimc",
    ["v0", "v1", "v2", "v3", "v4", "v5"]
);
body!(
    decrypt7,
    "aesd",
    "aesimc",
    ["v0", "v1", "v2", "v3", "v4", "v5", "v6"]
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::portable;

    /// Returns the cipher, or `None` (skipping the test) without the
    /// AES instructions.
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
        let klen = K;
        {
            let mut key = [0u8; K];
            for (i, k) in key.iter_mut().enumerate() {
                *k = (i * 37 + klen) as u8;
            }
            let Some(hw) = aes(&key) else { return };
            let sw = portable::ttable::Aes::new(&key);
            // Every tail width, with and without full groups before it.
            for nblocks in 0..26 {
                let mut data = [[0u8; BLOCK_SIZE]; 25];
                for (i, b) in data.as_flattened_mut().iter_mut().enumerate() {
                    *b = (i * 13 + klen) as u8;
                }
                let data = &mut data[..nblocks];
                let mut expected = [[0u8; BLOCK_SIZE]; 25];
                let expected = &mut expected[..data.len()];
                expected.copy_from_slice(data);
                let mut orig = [[0u8; BLOCK_SIZE]; 25];
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
