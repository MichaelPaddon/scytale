//! AES using the AES-NI instructions on 128-bit registers, with the
//! block loops in hand-written assembly.
//!
//! The loops run eight blocks through each round together: the
//! instruction is pipelined, so eight independent blocks keep it busy
//! where one block would wait on its own result. This is the
//! interleave Intel recommends for ECB-style processing. A tail of
//! fewer blocks goes through one pass of exactly its width.
//!
//! The S-box lives in hardware, so unlike the table-driven portable
//! implementation this one does not leak key material through cache
//! timing.
//!
//! # Availability
//!
//! [`Aes::try_new`] checks at run time that the processor has AES-NI
//! and returns [`Error::NotSupported`] if it does not.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::x86_64::aesni::Aes;
//! use scytale::symmetric::Error;
//!
//! # fn main() -> Result<(), Error> {
//! match Aes::try_new(&[0u8; 16]) {
//!     Ok(aes) => {
//!         let mut block = [0u8; 16];
//!         aes.encrypt_block(&mut block);
//!         aes.decrypt_block(&mut block);
//!         assert_eq!(block, [0u8; 16]);
//!     }
//!     Err(Error::NotSupported) => {} // no AES-NI on this machine
//!     Err(e) => return Err(e),
//! }
//! # Ok(())
//! # }
//! ```

use core::fmt;

use super::{expand, has_aesni, RoundKeys};
use crate::symmetric::aes::BLOCK_SIZE;
use crate::symmetric::{as_block, BlockCipher, Error};
use zeroize::ZeroizeOnDrop;

/// An AES cipher with an expanded key, using AES-NI.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::try_new`]; the key is wiped on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes {
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
    /// Returns [`Error::NotSupported`] if the processor lacks AES-NI.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        if !has_aesni() {
            return Err(Error::NotSupported);
        }
        // SAFETY: AES-NI was just confirmed present.
        unsafe { Self::new_unchecked(key) }
    }

    /// Expands `key` without checking for AES-NI.
    ///
    /// # Safety
    /// The caller must have confirmed that AES-NI is available.
    pub(crate) unsafe fn new_unchecked(key: &[u8]) -> Result<Self, Error> {
        let size = super::KeySize::for_key(key)?;
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
        unsafe { encrypt_blocks(&self.keys, block) }
    }

    /// Decrypts one block in place.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed AES-NI.
        unsafe { decrypt_blocks(&self.keys, block) }
    }

    /// Encrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of 16; nothing is changed
    /// otherwise.
    pub fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::NotBlockAligned(data.len()));
        }
        // SAFETY: the struct only exists if try_new confirmed AES-NI.
        unsafe { encrypt_blocks(&self.keys, data) }
        Ok(())
    }

    /// Decrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of 16; nothing is changed
    /// otherwise.
    pub fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::NotBlockAligned(data.len()));
        }
        // SAFETY: the struct only exists if try_new confirmed AES-NI.
        unsafe { decrypt_blocks(&self.keys, data) }
        Ok(())
    }
}

impl BlockCipher for Aes {
    const BLOCK_SIZE: usize = BLOCK_SIZE;

    fn try_new(key: &[u8]) -> Result<Self, Error> {
        Aes::try_new(key)
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<(), Error> {
        Aes::encrypt_block(self, as_block(block)?);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<(), Error> {
        Aes::decrypt_block(self, as_block(block)?);
        Ok(())
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        Aes::encrypt_blocks(self, data)
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        Aes::decrypt_blocks(self, data)
    }
}

/// Encrypts a whole number of blocks.
///
/// # Safety
/// Requires AES-NI; `data.len()` must be a multiple of 16.
pub(super) unsafe fn encrypt_blocks(keys: &RoundKeys, data: &mut [u8]) {
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

/// Decrypts a whole number of blocks.
///
/// # Safety
/// Requires AES-NI; `data.len()` must be a multiple of 16.
pub(super) unsafe fn decrypt_blocks(keys: &RoundKeys, data: &mut [u8]) {
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

/// A body that processes `n` blocks at `data`.
type Body = unsafe fn(*const u32, usize, *mut u8);

/// Whole groups of eight through `groups`, then the 1 to 7 leftover
/// blocks through the body of exactly that width, so the tail is one
/// interleaved pass rather than a sequence of single blocks.
///
/// # Safety
/// Requires AES-NI; `data.len()` must be a multiple of 16.
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
// tuned. Blocks live in xmm0..xmm7; round keys stream through xmm8
// from memory (always via `movdqu`: the key array is not 16-byte
// aligned, which legacy SSE memory operands require). The middle
// rounds loop over the key pointer, so one body serves all key sizes.

/// Defines a body that runs the listed registers, loaded from the
/// listed byte offsets, through the cipher once.
macro_rules! body {
    ($name:ident, $mid:literal, $last:literal,
     [$(($r:literal, $off:literal)),+]) => {
        /// # Safety
        /// Requires AES-NI; `rk` must point at `rounds + 1` round keys
        /// and `data` at the blocks this body handles.
        unsafe fn $name(rk: *const u32, rounds: usize, data: *mut u8) {
            core::arch::asm!(
                "movdqu xmm8, [{rk}]",
                $(concat!("movdqu ", $r, ", [{data} + ", $off, "]"),)+
                $(concat!("pxor ", $r, ", xmm8"),)+
                "lea {k}, [{rk} + 16]",
                "mov {n}, {nr}",
                "2:",
                "movdqu xmm8, [{k}]",
                $(concat!($mid, " ", $r, ", xmm8"),)+
                "add {k}, 16",
                "dec {n}",
                "jnz 2b",
                "movdqu xmm8, [{k}]",
                $(concat!($last, " ", $r, ", xmm8"),)+
                $(concat!("movdqu [{data} + ", $off, "], ", $r),)+
                rk = in(reg) rk,
                nr = in(reg) rounds - 1,
                data = in(reg) data,
                k = out(reg) _,
                n = out(reg) _,
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _,
                options(nostack),
            );
        }
    };
}

/// Defines the loop over whole groups of eight blocks.
macro_rules! groups {
    ($name:ident, $mid:literal, $last:literal) => {
        /// # Safety
        /// Requires AES-NI; `rk` must point at `rounds + 1` round keys
        /// and `data` at `groups * 128` writable bytes, `groups >= 1`.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            data: *mut u8,
            groups: usize,
        ) {
            core::arch::asm!(
                "3:",
                "movdqu xmm8, [{rk}]",
                "movdqu xmm0, [{data}]",
                "movdqu xmm1, [{data} + 16]",
                "movdqu xmm2, [{data} + 32]",
                "movdqu xmm3, [{data} + 48]",
                "movdqu xmm4, [{data} + 64]",
                "movdqu xmm5, [{data} + 80]",
                "movdqu xmm6, [{data} + 96]",
                "movdqu xmm7, [{data} + 112]",
                "pxor xmm0, xmm8",
                "pxor xmm1, xmm8",
                "pxor xmm2, xmm8",
                "pxor xmm3, xmm8",
                "pxor xmm4, xmm8",
                "pxor xmm5, xmm8",
                "pxor xmm6, xmm8",
                "pxor xmm7, xmm8",
                "lea {k}, [{rk} + 16]",
                "mov {n}, {nr}",
                "2:",
                "movdqu xmm8, [{k}]",
                concat!($mid, " xmm0, xmm8"),
                concat!($mid, " xmm1, xmm8"),
                concat!($mid, " xmm2, xmm8"),
                concat!($mid, " xmm3, xmm8"),
                concat!($mid, " xmm4, xmm8"),
                concat!($mid, " xmm5, xmm8"),
                concat!($mid, " xmm6, xmm8"),
                concat!($mid, " xmm7, xmm8"),
                "add {k}, 16",
                "dec {n}",
                "jnz 2b",
                "movdqu xmm8, [{k}]",
                concat!($last, " xmm0, xmm8"),
                concat!($last, " xmm1, xmm8"),
                concat!($last, " xmm2, xmm8"),
                concat!($last, " xmm3, xmm8"),
                concat!($last, " xmm4, xmm8"),
                concat!($last, " xmm5, xmm8"),
                concat!($last, " xmm6, xmm8"),
                concat!($last, " xmm7, xmm8"),
                "movdqu [{data}], xmm0",
                "movdqu [{data} + 16], xmm1",
                "movdqu [{data} + 32], xmm2",
                "movdqu [{data} + 48], xmm3",
                "movdqu [{data} + 64], xmm4",
                "movdqu [{data} + 80], xmm5",
                "movdqu [{data} + 96], xmm6",
                "movdqu [{data} + 112], xmm7",
                "add {data}, 128",
                "dec {groups}",
                "jnz 3b",
                rk = in(reg) rk,
                nr = in(reg) rounds - 1,
                data = inout(reg) data => _,
                groups = inout(reg) groups => _,
                k = out(reg) _,
                n = out(reg) _,
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _,
                options(nostack),
            );
        }
    };
}

groups!(encrypt8, "aesenc", "aesenclast");
groups!(decrypt8, "aesdec", "aesdeclast");

body!(encrypt1, "aesenc", "aesenclast", [("xmm0", "0")]);
body!(
    encrypt2,
    "aesenc",
    "aesenclast",
    [("xmm0", "0"), ("xmm1", "16")]
);
body!(
    encrypt3,
    "aesenc",
    "aesenclast",
    [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]
);
body!(
    encrypt4,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48")
    ]
);
body!(
    encrypt5,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
body!(
    encrypt6,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80")
    ]
);
body!(
    encrypt7,
    "aesenc",
    "aesenclast",
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

body!(decrypt1, "aesdec", "aesdeclast", [("xmm0", "0")]);
body!(
    decrypt2,
    "aesdec",
    "aesdeclast",
    [("xmm0", "0"), ("xmm1", "16")]
);
body!(
    decrypt3,
    "aesdec",
    "aesdeclast",
    [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]
);
body!(
    decrypt4,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48")
    ]
);
body!(
    decrypt5,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
body!(
    decrypt6,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80")
    ]
);
body!(
    decrypt7,
    "aesdec",
    "aesdeclast",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::portable;

    /// Returns the cipher, or `None` (skipping the test) without AES-NI.
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
                let mut data = [0u8; 25 * BLOCK_SIZE];
                for (i, b) in data.iter_mut().enumerate() {
                    *b = (i * 13 + klen) as u8;
                }
                let data = &mut data[..nblocks * BLOCK_SIZE];
                let mut expected = [0u8; 25 * BLOCK_SIZE];
                let expected = &mut expected[..data.len()];
                expected.copy_from_slice(data);
                let mut orig = [0u8; 25 * BLOCK_SIZE];
                orig[..data.len()].copy_from_slice(data);

                sw.encrypt_blocks(expected).unwrap();
                hw.encrypt_blocks(data).unwrap();
                assert_eq!(data, expected, "encrypt {klen} {nblocks}");
                hw.decrypt_blocks(data).unwrap();
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
    fn blocks_reject_partial_block() {
        let Some(aes) = aes(&[0; 16]) else { return };
        for n in [1, 15, 17, 31, 33] {
            let mut data = [0x33u8; 33];
            let data = &mut data[..n];
            assert_eq!(
                aes.encrypt_blocks(data).unwrap_err(),
                Error::NotBlockAligned(n)
            );
            assert_eq!(
                aes.decrypt_blocks(data).unwrap_err(),
                Error::NotBlockAligned(n)
            );
            assert!(data.iter().all(|&b| b == 0x33), "data untouched");
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
