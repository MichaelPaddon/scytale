//! AES using the RISC-V vector cryptography extension (Zvkned), with
//! the key schedule and round loops in hand-written assembly.
//!
//! Each 128-bit element group of a vector register holds one block,
//! and one `vaesem.vs` instruction runs a round on every group in a
//! register group. With `LMUL=8` that is eight blocks per instruction
//! on a 128-bit machine and proportionally more on wider ones, so the
//! loop processes whatever the hardware fits in one register group
//! per iteration; the 15 round keys sit in `v16..v30`.
//!
//! The S-box lives in hardware, so this implementation does not leak
//! key material through cache timing.
//!
//! # Availability
//!
//! [`Aes::try_new`] accepts when the crate was compiled with the `v`
//! and `zvkned` target features, or, on Linux, when `riscv_hwprobe`
//! reports them; vector registers must be at least 128 bits wide.
//! Otherwise it returns [`Error::NotSupported`].
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::riscv64::zvkned::Aes;
//! use scytale::symmetric::Error;
//!
//! # fn main() -> Result<(), Error> {
//! match Aes::try_new(&[0u8; 16]) {
//!     Ok(aes) => {
//!         let mut data = [0u8; 48];
//!         aes.encrypt_blocks(&mut data)?;
//!         aes.decrypt_blocks(&mut data)?;
//!         assert_eq!(data, [0u8; 48]);
//!     }
//!     Err(Error::NotSupported) => {} // no Zvkned on this machine
//!     Err(e) => return Err(e),
//! }
//! # Ok(())
//! # }
//! ```

use core::fmt;

use super::has_zvkned;
use crate::symmetric::aes::{expand_words, KeySize, BLOCK_SIZE, MAX_WORDS};
use crate::symmetric::{as_block, BlockCipher, Error};
use zeroize::ZeroizeOnDrop;

/// An AES cipher with an expanded key, using the Zvkned instructions.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::try_new`]; the key is wiped on drop. The vector inverse
/// cipher takes the round keys as they are, so one schedule serves
/// both directions.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes {
    keys: [u32; MAX_WORDS],
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

impl Aes {
    /// Expands `key`, which must be 16, 24 or 32 bytes long.
    ///
    /// Returns [`Error::NotSupported`] if the instructions cannot be
    /// confirmed available.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        if !has_zvkned() {
            return Err(Error::NotSupported);
        }
        // SAFETY: the instructions were just confirmed present.
        unsafe { Self::new_unchecked(key) }
    }

    /// Expands `key` without checking for the instructions.
    ///
    /// # Safety
    /// The caller must have confirmed that the vector extension and
    /// Zvkned are available with `VLEN >= 128`.
    pub(crate) unsafe fn new_unchecked(key: &[u8]) -> Result<Self, Error> {
        let size = KeySize::for_key(key)?;
        let mut keys = [0u32; MAX_WORDS];
        match size {
            KeySize::Aes128 => expand128(key.as_ptr(), keys.as_mut_ptr()),
            KeySize::Aes256 => expand256(key.as_ptr(), keys.as_mut_ptr()),
            // No vector instruction covers AES-192; use the shared
            // schedule with a vector SubWord.
            KeySize::Aes192 => keys = expand_words(key, size, |w| sub_word(w)),
        }
        Ok(Aes { keys, size })
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.size.rounds()
    }

    /// Encrypts one block in place.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed support.
        unsafe { self.encrypt(block.as_mut_ptr(), 1) }
    }

    /// Decrypts one block in place.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed support.
        unsafe { self.decrypt(block.as_mut_ptr(), 1) }
    }

    /// Encrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of 16; nothing is changed
    /// otherwise.
    pub fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::NotBlockAligned(data.len()));
        }
        if !data.is_empty() {
            // SAFETY: the struct only exists if try_new confirmed
            // support; the length is a whole number of blocks.
            unsafe { self.encrypt(data.as_mut_ptr(), data.len() / BLOCK_SIZE) }
        }
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
        if !data.is_empty() {
            // SAFETY: as in encrypt_blocks.
            unsafe { self.decrypt(data.as_mut_ptr(), data.len() / BLOCK_SIZE) }
        }
        Ok(())
    }

    /// # Safety
    /// Requires Zvkned; `data` must hold `blocks` writable blocks,
    /// `blocks >= 1`.
    #[inline]
    unsafe fn encrypt(&self, data: *mut u8, blocks: usize) {
        let rk = self.keys.as_ptr();
        match self.size {
            KeySize::Aes128 => encrypt10(rk, data, blocks),
            KeySize::Aes192 => encrypt12(rk, data, blocks),
            KeySize::Aes256 => encrypt14(rk, data, blocks),
        }
    }

    /// # Safety
    /// As [`Aes::encrypt`].
    #[inline]
    unsafe fn decrypt(&self, data: *mut u8, blocks: usize) {
        let rk = self.keys.as_ptr();
        match self.size {
            KeySize::Aes128 => decrypt10(rk, data, blocks),
            KeySize::Aes192 => decrypt12(rk, data, blocks),
            KeySize::Aes256 => decrypt14(rk, data, blocks),
        }
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

// The key schedules use the dedicated instructions:
// `vaeskf1.vi` derives each AES-128 round key from the previous one,
// and `vaeskf2.vi` each AES-256 round key from the previous two.
// Round keys are written straight into the word array.

/// AES-128 key schedule.
///
/// # Safety
/// Requires the vector extension and Zvkned; `key` must point at 16
/// key bytes and `out` at 44 writable words.
unsafe fn expand128(key: *const u8, out: *mut u32) {
    core::arch::asm!(
        ".option push",
        ".option arch, +v, +zvkned",
        "vsetivli zero, 4, e32, m1, tu, mu",
        "vle32.v v10, ({key})",
        "vaeskf1.vi v11, v10, 1",
        "vaeskf1.vi v12, v11, 2",
        "vaeskf1.vi v13, v12, 3",
        "vaeskf1.vi v14, v13, 4",
        "vaeskf1.vi v15, v14, 5",
        "vaeskf1.vi v16, v15, 6",
        "vaeskf1.vi v17, v16, 7",
        "vaeskf1.vi v18, v17, 8",
        "vaeskf1.vi v19, v18, 9",
        "vaeskf1.vi v20, v19, 10",
        "vse32.v v10, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v11, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v12, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v13, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v14, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v15, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v16, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v17, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v18, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v19, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v20, ({out})",
        ".option pop",
        key = in(reg) key,
        out = inout(reg) out => _,
        out("v10") _,
        out("v11") _,
        out("v12") _,
        out("v13") _,
        out("v14") _,
        out("v15") _,
        out("v16") _,
        out("v17") _,
        out("v18") _,
        out("v19") _,
        out("v20") _,
        options(nostack),
    );
}

/// AES-256 key schedule.
///
/// # Safety
/// Requires the vector extension and Zvkned; `key` must point at 32
/// key bytes and `out` at 60 writable words.
unsafe fn expand256(key: *const u8, out: *mut u32) {
    core::arch::asm!(
        ".option push",
        ".option arch, +v, +zvkned",
        "vsetivli zero, 4, e32, m1, tu, mu",
        "vle32.v v10, ({key})",
        "addi {key}, {key}, 16",
        "vle32.v v11, ({key})",
        "vmv.v.v v12, v10",
        "vaeskf2.vi v12, v11, 2",
        "vmv.v.v v13, v11",
        "vaeskf2.vi v13, v12, 3",
        "vmv.v.v v14, v12",
        "vaeskf2.vi v14, v13, 4",
        "vmv.v.v v15, v13",
        "vaeskf2.vi v15, v14, 5",
        "vmv.v.v v16, v14",
        "vaeskf2.vi v16, v15, 6",
        "vmv.v.v v17, v15",
        "vaeskf2.vi v17, v16, 7",
        "vmv.v.v v18, v16",
        "vaeskf2.vi v18, v17, 8",
        "vmv.v.v v19, v17",
        "vaeskf2.vi v19, v18, 9",
        "vmv.v.v v20, v18",
        "vaeskf2.vi v20, v19, 10",
        "vmv.v.v v21, v19",
        "vaeskf2.vi v21, v20, 11",
        "vmv.v.v v22, v20",
        "vaeskf2.vi v22, v21, 12",
        "vmv.v.v v23, v21",
        "vaeskf2.vi v23, v22, 13",
        "vmv.v.v v24, v22",
        "vaeskf2.vi v24, v23, 14",
        "vse32.v v10, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v11, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v12, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v13, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v14, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v15, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v16, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v17, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v18, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v19, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v20, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v21, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v22, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v23, ({out})",
        "addi {out}, {out}, 16",
        "vse32.v v24, ({out})",
        ".option pop",
        key = inout(reg) key => _,
        out = inout(reg) out => _,
        out("v10") _,
        out("v11") _,
        out("v12") _,
        out("v13") _,
        out("v14") _,
        out("v15") _,
        out("v16") _,
        out("v17") _,
        out("v18") _,
        out("v19") _,
        out("v20") _,
        out("v21") _,
        out("v22") _,
        out("v23") _,
        out("v24") _,
        options(nostack),
    );
}

/// `SubWord` via a final AES round with a zero key on a vector holding
/// the word in every column: ShiftRows then only moves equal bytes
/// around, so every column ends up as `SubWord(w)`.
///
/// # Safety
/// Requires the vector extension and Zvkned.
unsafe fn sub_word(w: u32) -> u32 {
    let out: u64;
    core::arch::asm!(
        ".option push",
        ".option arch, +v, +zvkned",
        "vsetivli zero, 4, e32, m1, ta, ma",
        "vmv.v.x v8, {w}",
        "vmv.v.i v9, 0",
        "vaesef.vv v8, v9",
        "vmv.x.s {out}, v8",
        ".option pop",
        w = in(reg) w,
        out = lateout(reg) out,
        out("v8") _, out("v9") _,
        options(nomem, nostack),
    );
    out as u32
}

// The round loops below are hand-written so the instruction order can
// be tuned. Vector register names cannot be chosen at run time, so
// there is one body per key size, generated by `vaes_body!`. Each
// loads the round keys into v16.. (one 128-bit group each), then
// loops: set vl for up to a whole LMUL=8 register group of blocks,
// load them into v8..v15, run the rounds with the `.vs` forms (one
// key group applied to every block group), store, advance. `avl` is
// counted in 32-bit elements, four per block, so every `vl` is a
// whole number of blocks. The `.option arch` directive only tells the
// assembler the instructions are allowed.

/// Defines `fn $name(rk, data, blocks)` running the rounds given as
/// (instruction, key register) pairs.
macro_rules! vaes_body {
    ($name:ident, $first:literal, [$($mid:literal),*], $last:literal,
     $midop:literal, $lastop:literal) => {
        /// # Safety
        /// Requires the vector extension and Zvkned with VLEN >= 128;
        /// `rk` must point at 15 round keys and `data` at `blocks`
        /// writable blocks, `blocks >= 1`.
        unsafe fn $name(rk: *const u32, data: *mut u8, blocks: usize) {
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
                "2:",
                "vsetvli {vl}, {avl}, e32, m8, ta, ma",
                "vle32.v v8, ({data})",
                concat!("vaesz.vs v8, ", $first),
                $(concat!($midop, " v8, ", $mid),)*
                concat!($lastop, " v8, ", $last),
                "vse32.v v8, ({data})",
                "slli {t}, {vl}, 2",
                "add {data}, {data}, {t}",
                "sub {avl}, {avl}, {vl}",
                "bnez {avl}, 2b",
                ".option pop",
                rk = inout(reg) rk => _,
                data = inout(reg) data => _,
                avl = inout(reg) 4 * blocks => _,
                vl = out(reg) _,
                t = out(reg) _,
                out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                out("v28") _, out("v29") _, out("v30") _,
                options(nostack),
            );
        }
    };
}

// Encryption: key 0, middle rounds with keys 1..R-1, final with R.
vaes_body!(
    encrypt10,
    "v16",
    ["v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25"],
    "v26",
    "vaesem.vs",
    "vaesef.vs"
);
vaes_body!(
    encrypt12,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27"
    ],
    "v28",
    "vaesem.vs",
    "vaesef.vs"
);
vaes_body!(
    encrypt14,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27", "v28", "v29"
    ],
    "v30",
    "vaesem.vs",
    "vaesef.vs"
);

// Decryption runs the same keys backwards: `vaesdm` adds the key
// before InvMixColumns, so the keys need no transformation.
vaes_body!(
    decrypt10,
    "v26",
    ["v25", "v24", "v23", "v22", "v21", "v20", "v19", "v18", "v17"],
    "v16",
    "vaesdm.vs",
    "vaesdf.vs"
);
vaes_body!(
    decrypt12,
    "v28",
    [
        "v27", "v26", "v25", "v24", "v23", "v22", "v21", "v20", "v19", "v18",
        "v17"
    ],
    "v16",
    "vaesdm.vs",
    "vaesdf.vs"
);
vaes_body!(
    decrypt14,
    "v30",
    [
        "v29", "v28", "v27", "v26", "v25", "v24", "v23", "v22", "v21", "v20",
        "v19", "v18", "v17"
    ],
    "v16",
    "vaesdm.vs",
    "vaesdf.vs"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::portable;

    /// Returns the cipher, or `None` (skipping the test) without
    /// Zvkned.
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
        const MAX: usize = 40;
        for klen in [16, 24, 32] {
            let mut key = [0u8; 32];
            for (i, k) in key.iter_mut().enumerate() {
                *k = (i * 37 + klen) as u8;
            }
            let Some(hw) = aes(&key[..klen]) else { return };
            let sw = portable::Aes::try_new(&key[..klen]).unwrap();
            for nblocks in [0, 1, 7, 8, 9, 16, 17, 24, 25, 33, 39] {
                let mut data = [0u8; MAX * BLOCK_SIZE];
                for (i, b) in data.iter_mut().enumerate() {
                    *b = (i * 13 + klen) as u8;
                }
                let data = &mut data[..nblocks * BLOCK_SIZE];
                let mut expected = [0u8; MAX * BLOCK_SIZE];
                let expected = &mut expected[..data.len()];
                expected.copy_from_slice(data);
                let mut orig = [0u8; MAX * BLOCK_SIZE];
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
        if aes(&[0; 16]).is_none() {
            return;
        }
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
