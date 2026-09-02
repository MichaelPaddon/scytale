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
//! There is no user-space CPUID on aarch64. [`Aes::try_new`] accepts
//! when the crate was compiled with the `aes` target feature, or, on
//! Linux, when the kernel's emulated `ID_AA64ISAR0_EL1` register
//! reports the instructions. Otherwise it returns
//! [`Error::NotSupported`].
//!
//! # Example
//!
//! ```
//! use scytale::cipher::aes::aarch64::armv8::Aes;
//! use scytale::Error;
//!
//! # fn main() -> Result<(), Error> {
//! match Aes::try_new(&[0u8; 16]) {
//!     Ok(aes) => {
//!         let mut block = [0u8; 16];
//!         aes.encrypt_block(&mut block);
//!         aes.decrypt_block(&mut block);
//!         assert_eq!(block, [0u8; 16]);
//!     }
//!     Err(Error::NotSupported) => {} // no AES instructions here
//!     Err(e) => return Err(e),
//! }
//! # Ok(())
//! # }
//! ```

#![allow(unsafe_code)]

use core::arch::aarch64::{
    vaeseq_u8, vaesimcq_u8, vdupq_n_u32, vdupq_n_u8, vgetq_lane_u32, vld1q_u8,
    vreinterpretq_u32_u8, vreinterpretq_u8_u32, vst1q_u8,
};
use core::fmt;

use crate::cipher::aes::{expand_words, KeySize, BLOCK_SIZE, MAX_WORDS};
use crate::cipher::{Block, BlockCipher};
use crate::Error;
use zeroize::ZeroizeOnDrop;

/// An AES cipher with an expanded key, using the ARMv8 instructions.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::try_new`]; the key is wiped on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes {
    /// Round keys as words in memory order; the loops load them
    /// straight from memory.
    enc: [u32; MAX_WORDS],
    dec: [u32; MAX_WORDS],
    #[zeroize(skip)]
    size: KeySize,
}

impl fmt::Debug for Aes {
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

impl Aes {
    /// Expands `key`, which must be 16, 24 or 32 bytes long.
    ///
    /// Returns [`Error::NotSupported`] if the AES instructions cannot
    /// be confirmed available.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        if !has_aes() {
            return Err(Error::NotSupported);
        }
        // SAFETY: the AES instructions were just confirmed present.
        unsafe { Self::new_unchecked(key) }
    }

    /// Expands `key` without checking for the AES instructions.
    ///
    /// # Safety
    /// The caller must have confirmed that the AES instructions are
    /// available.
    pub(crate) unsafe fn new_unchecked(key: &[u8]) -> Result<Self, Error> {
        let size = KeySize::for_key(key)?;
        Ok(expand(key, size))
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.size.rounds()
    }

    /// Encrypts one block in place.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed support.
        unsafe { encrypt_blocks(&self.enc, self.rounds(), block) }
    }

    /// Decrypts one block in place.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed support.
        unsafe { decrypt_blocks(&self.dec, self.rounds(), block) }
    }

    /// Encrypts every block in place, independently (ECB).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = Block::flatten_mut(blocks);
        // SAFETY: the struct only exists if try_new confirmed support.
        // SAFETY: the struct only exists if try_new confirmed support;
        // the length is a whole number of blocks.
        unsafe { encrypt_blocks(&self.enc, self.rounds(), data) }
    }

    /// Decrypts every block in place, independently (ECB).
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = Block::flatten_mut(blocks);
        // SAFETY: the struct only exists if try_new confirmed support.
        // SAFETY: the struct only exists if try_new confirmed support;
        // the length is a whole number of blocks.
        unsafe { decrypt_blocks(&self.dec, self.rounds(), data) }
    }
}

impl BlockCipher for Aes {
    type Block = [u8; BLOCK_SIZE];

    fn try_new(key: &[u8]) -> Result<Self, Error> {
        Aes::try_new(key)
    }

    fn encrypt_block(&self, block: &mut Self::Block) {
        Aes::encrypt_block(self, block)
    }

    fn decrypt_block(&self, block: &mut Self::Block) {
        Aes::decrypt_block(self, block)
    }

    fn encrypt_blocks(&self, blocks: &mut [Self::Block]) {
        Aes::encrypt_blocks(self, blocks)
    }

    fn decrypt_blocks(&self, blocks: &mut [Self::Block]) {
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
unsafe fn expand(key: &[u8], size: KeySize) -> Aes {
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
    };
}

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
    fn aes(key: &[u8]) -> Option<Aes> {
        match Aes::try_new(key) {
            Ok(a) => Some(a),
            Err(Error::NotSupported) => None,
            Err(e) => panic!("{e}"),
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

    fn check(key: &str, plain: &str, cipher: &str) {
        let key = &unhex(key)[..key.len() / 2];
        let plain: [u8; 16] = unhex(plain)[..16].try_into().unwrap();
        let cipher: [u8; 16] = unhex(cipher)[..16].try_into().unwrap();
        let Some(aes) = aes(key) else { return };

        let mut block = plain;
        aes.encrypt_block(&mut block);
        assert_eq!(block, cipher, "encrypt");
        aes.decrypt_block(&mut block);
        assert_eq!(block, plain, "decrypt");
    }

    // FIPS 197 Appendix C.
    #[test]
    fn fips197_aes128() {
        check(
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        );
    }

    #[test]
    fn fips197_aes192() {
        check(
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        );
    }

    #[test]
    fn fips197_aes256() {
        check(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        );
    }

    #[test]
    fn matches_portable() {
        for klen in [16, 24, 32] {
            let mut key = [0u8; 32];
            for (i, k) in key.iter_mut().enumerate() {
                *k = (i * 37 + klen) as u8;
            }
            let Some(hw) = aes(&key[..klen]) else { return };
            let sw = portable::Aes::try_new(&key[..klen]).unwrap();
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
    fn rejects_bad_key_lengths() {
        for n in [0, 1, 15, 17, 23, 25, 31, 33, 64] {
            assert_eq!(
                Aes::try_new(&[0; 64][..n]).unwrap_err(),
                Error::InvalidKeyLength(n)
            );
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
