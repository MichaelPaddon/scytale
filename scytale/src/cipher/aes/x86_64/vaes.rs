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
//! [`Aes::try_new`] checks at run time for VAES, AVX2 and operating
//! system support for 256-bit registers, and returns
//! [`Error::NotSupported`] otherwise.
//!
//! # Example
//!
//! ```
//! use scytale::cipher::aes::x86_64::vaes::Aes;
//! use scytale::Error;
//!
//! # fn main() -> Result<(), Error> {
//! match Aes::try_new(&[0u8; 16]) {
//!     Ok(aes) => {
//!         let mut data = [[0u8; 16]; 3];
//!         aes.encrypt_blocks(&mut data);
//!         aes.decrypt_blocks(&mut data);
//!         assert_eq!(data, [[0u8; 16]; 3]);
//!     }
//!     Err(Error::NotSupported) => {} // no VAES on this machine
//!     Err(e) => return Err(e),
//! }
//! # Ok(())
//! # }
//! ```

use core::fmt;

use super::{aesni, expand, has_vaes256, RoundKeys};
use crate::cipher::aes::{KeySize, BLOCK_SIZE};
use crate::cipher::{Block, BlockCipher};
use crate::Error;
use zeroize::ZeroizeOnDrop;

/// Bytes in one 256-bit register: two blocks.
const PAIR: usize = 2 * BLOCK_SIZE;

/// An AES cipher with an expanded key, using VAES.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::try_new`]; the key is wiped on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes {
    /// 128-bit keys; the loops broadcast each into both halves of a
    /// 256-bit register as they load it.
    keys: RoundKeys,
}

impl fmt::Debug for Aes {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes")
            .field("rounds", &self.rounds())
            .finish()
    }
}

impl Aes {
    /// Expands `key`, which must be 16, 24 or 32 bytes long.
    ///
    /// Returns [`Error::NotSupported`] if the processor or operating
    /// system lacks VAES on 256-bit registers.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        if !has_vaes256() {
            return Err(Error::NotSupported);
        }
        // SAFETY: VAES (and so AES-NI) was just confirmed present.
        unsafe { Self::new_unchecked(key) }
    }

    /// Expands `key` without checking for VAES.
    ///
    /// # Safety
    /// The caller must have confirmed that VAES, AVX2 and operating
    /// system support for 256-bit registers are available.
    pub(crate) unsafe fn new_unchecked(key: &[u8]) -> Result<Self, Error> {
        let size = KeySize::for_key(key)?;
        let keys = expand(key, size);
        Ok(Aes { keys })
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.keys.size.rounds()
    }

    /// Encrypts one block in place.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed AES-NI.
        unsafe { aesni::encrypt_blocks(&self.keys, block) }
    }

    /// Decrypts one block in place.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed AES-NI.
        unsafe { aesni::decrypt_blocks(&self.keys, block) }
    }

    /// Encrypts every block in place, independently (ECB).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = Block::flatten_mut(blocks);
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
        let data = Block::flatten_mut(blocks);
        let (pairs, odd) = data.split_at_mut(data.len() / PAIR * PAIR);
        // SAFETY: as in encrypt_blocks.
        unsafe {
            decrypt_pairs(&self.keys, pairs);
            aesni::decrypt_blocks(&self.keys, odd);
        }
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

/// Encrypts a whole number of block pairs.
///
/// # Safety
/// Requires VAES and AVX2; `data.len()` must be a multiple of 32.
unsafe fn encrypt_pairs(keys: &RoundKeys, data: &mut [u8]) {
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

/// Decrypts a whole number of block pairs.
///
/// # Safety
/// Requires VAES and AVX2; `data.len()` must be a multiple of 32.
unsafe fn decrypt_pairs(keys: &RoundKeys, data: &mut [u8]) {
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
    };
}

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
        const MAX: usize = 40;
        for klen in [16, 24, 32] {
            let mut key = [0u8; 32];
            for (i, k) in key.iter_mut().enumerate() {
                *k = (i * 37 + klen) as u8;
            }
            let Some(hw) = aes(&key[..klen]) else { return };
            let sw = portable::Aes::try_new(&key[..klen]).unwrap();
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
