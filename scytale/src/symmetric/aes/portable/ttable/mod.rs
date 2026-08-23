//! Portable AES (FIPS 197) block cipher using T-tables.
//!
//! The implementation combines SubBytes, ShiftRows and MixColumns into
//! four 1 KiB lookup tables per direction, so each round costs sixteen
//! table loads and sixteen xors. It uses no platform intrinsics and no
//! `unsafe`, and works on any target regardless of endianness.
//!
//! # Security: timing side channels
//!
//! This implementation is **not constant time**. Each round indexes
//! the tables with bytes derived from the key and the data, so which
//! cache lines it touches, and therefore how long it takes, depends on
//! secrets. An attacker who can measure that, typically by running
//! code on the same processor (another process, container, virtual
//! machine or browser tab, or a hyperthread sibling), can recover the
//! key. This is a practical attack, not a theoretical one.
//!
//! It is roughly 1.5x to 2x faster than [`bitsliced`](super::bitsliced)
//! on the same hardware, and far slower than any hardware
//! implementation. The automatic choice in
//! [`symmetric::aes::Aes`](crate::symmetric::aes::Aes) never selects
//! it.
//!
//! Use it only when all of the following hold:
//! - no hardware AES is available, and
//! - no untrusted code can run on the same machine while keys are in
//!   use (a dedicated single-tenant device, an isolated embedded
//!   system, an offline tool), and
//! - the extra speed over `bitsliced` actually matters.
//!
//! Do not use it on shared or cloud hosts, on anything that handles
//! keys while running untrusted code, in servers reachable by
//! strangers, or whenever in doubt. Use `bitsliced` instead.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::portable::Aes;
//!
//! # fn main() -> Result<(), scytale::symmetric::Error> {
//! let aes = Aes::try_new(&[0u8; 16])?;
//! let mut block = [0u8; 16];
//! aes.encrypt_block(&mut block);
//! aes.decrypt_block(&mut block);
//! assert_eq!(block, [0u8; 16]);
//! # Ok(())
//! # }
//! ```

pub(crate) mod tables;

use core::fmt;

use crate::symmetric::aes::{expand_words, KeySize, BLOCK_SIZE, MAX_WORDS};
use crate::symmetric::{BlockCipher, Error};
use tables::{INV_SBOX, SBOX, TD, TE};
use zeroize::ZeroizeOnDrop;

/// An AES cipher with an expanded key.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::try_new`]; encryption and decryption then operate on single
/// 16 byte blocks.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes {
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

impl Aes {
    /// Expands `key`, which must be 16, 24 or 32 bytes long.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        let size = KeySize::for_key(key)?;
        let rounds = size.rounds();

        // The shared schedule works on little-endian words; the tables
        // index big-endian ones, so swap each word's bytes.
        let mut enc = expand_words(key, size, sub_word_le);
        for w in enc.iter_mut() {
            *w = w.swap_bytes();
        }

        // The equivalent inverse cipher uses the round keys in reverse
        // order, with InvMixColumns folded into all but the first and
        // last. Folding it here lets decryption rounds use the TD tables
        // directly, mirroring the encryption rounds.
        let mut dec = [0u32; MAX_WORDS];
        for r in 0..=rounds {
            let src = &enc[4 * (rounds - r)..4 * (rounds - r) + 4];
            let dst = &mut dec[4 * r..4 * r + 4];
            if r == 0 || r == rounds {
                dst.copy_from_slice(src);
            } else {
                for (d, &s) in dst.iter_mut().zip(src) {
                    *d = inv_mix_column(s);
                }
            }
        }

        Ok(Aes { enc, dec, size })
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.size.rounds()
    }

    /// Encrypts one block in place.
    ///
    /// Dispatching on the key size once per block lets each variant be
    /// compiled with a constant round count, so the round loop unrolls
    /// and the round key indexing needs no bounds checks.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        match self.size {
            KeySize::Aes128 => encrypt::<10>(&self.enc, block),
            KeySize::Aes192 => encrypt::<12>(&self.enc, block),
            KeySize::Aes256 => encrypt::<14>(&self.enc, block),
        }
    }

    /// Decrypts one block in place.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        match self.size {
            KeySize::Aes128 => decrypt::<10>(&self.dec, block),
            KeySize::Aes192 => decrypt::<12>(&self.dec, block),
            KeySize::Aes256 => decrypt::<14>(&self.dec, block),
        }
    }

    /// Encrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of 16; nothing is changed
    /// otherwise.
    pub fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::NotBlockAligned(data.len()));
        }
        match self.size {
            KeySize::Aes128 => encrypt_many::<10>(&self.enc, data),
            KeySize::Aes192 => encrypt_many::<12>(&self.enc, data),
            KeySize::Aes256 => encrypt_many::<14>(&self.enc, data),
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
        match self.size {
            KeySize::Aes128 => decrypt_many::<10>(&self.dec, data),
            KeySize::Aes192 => decrypt_many::<12>(&self.dec, data),
            KeySize::Aes256 => decrypt_many::<14>(&self.dec, data),
        }
        Ok(())
    }
}

impl BlockCipher for Aes {
    const BLOCK_SIZE: usize = BLOCK_SIZE;

    fn try_new(key: &[u8]) -> Result<Self, Error> {
        Aes::try_new(key)
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        Aes::encrypt_blocks(self, data)
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        Aes::decrypt_blocks(self, data)
    }
}

#[inline(always)]
fn encrypt<const R: usize>(rk: &[u32; MAX_WORDS], block: &mut [u8]) {
    let mut s = load(block, &rk[..4]);
    for r in 1..R {
        s = enc_round(s, &rk[4 * r..4 * r + 4]);
    }
    store(block, enc_last(s, &rk[4 * R..4 * R + 4]));
}

#[inline(always)]
fn decrypt<const R: usize>(rk: &[u32; MAX_WORDS], block: &mut [u8]) {
    let mut s = load(block, &rk[..4]);
    for r in 1..R {
        s = dec_round(s, &rk[4 * r..4 * r + 4]);
    }
    store(block, dec_last(s, &rk[4 * R..4 * R + 4]));
}

/// Encrypts a whole number of blocks with the key size already
/// resolved, so the dispatch happens once per call.
#[inline(always)]
fn encrypt_many<const R: usize>(rk: &[u32; MAX_WORDS], data: &mut [u8]) {
    for block in data.chunks_exact_mut(BLOCK_SIZE) {
        encrypt::<R>(rk, block);
    }
}

#[inline(always)]
fn decrypt_many<const R: usize>(rk: &[u32; MAX_WORDS], data: &mut [u8]) {
    for block in data.chunks_exact_mut(BLOCK_SIZE) {
        decrypt::<R>(rk, block);
    }
}

/// SubWord on a little-endian word, for the shared key schedule.
fn sub_word_le(w: u32) -> u32 {
    u32::from_le_bytes(w.to_le_bytes().map(|b| SBOX[b as usize]))
}

/// InvMixColumns of one column, via the decryption tables. TD is
/// indexed by S-box output, so feed each byte through SBOX first to
/// cancel the InvSubBytes baked into the table.
#[inline(always)]
fn inv_mix_column(w: u32) -> u32 {
    TD[0][SBOX[(w >> 24) as usize] as usize]
        ^ TD[1][SBOX[(w >> 16 & 0xff) as usize] as usize]
        ^ TD[2][SBOX[(w >> 8 & 0xff) as usize] as usize]
        ^ TD[3][SBOX[(w & 0xff) as usize] as usize]
}

/// Loads a block as four big-endian columns and applies the initial
/// round key. `zip` bounds the loop by both sides, so there are no
/// index checks.
#[inline(always)]
fn load(block: &[u8], rk: &[u32]) -> [u32; 4] {
    let mut s = [0u32; 4];
    let columns = block.chunks_exact(4).zip(rk);
    for (s, (c, k)) in s.iter_mut().zip(columns) {
        *s = u32::from_be_bytes([c[0], c[1], c[2], c[3]]) ^ k;
    }
    s
}

#[inline(always)]
fn store(block: &mut [u8], s: [u32; 4]) {
    for (c, w) in block.chunks_exact_mut(4).zip(s) {
        c.copy_from_slice(&w.to_be_bytes());
    }
}

/// Byte `n` (0 = most significant) of `w`. Masking through `u8` lets
/// the compiler drop the bounds check on the 256-entry tables.
#[inline(always)]
fn byte(w: u32, n: u32) -> usize {
    (w >> (24 - 8 * n)) as u8 as usize
}

/// One full encryption round: the column `i` of the output draws its
/// bytes from the diagonal starting at column `i`, which is ShiftRows.
#[inline(always)]
fn enc_round(s: [u32; 4], rk: &[u32]) -> [u32; 4] {
    let mut t = [0u32; 4];
    for i in 0..4 {
        t[i] = TE[0][byte(s[i], 0)]
            ^ TE[1][byte(s[(i + 1) % 4], 1)]
            ^ TE[2][byte(s[(i + 2) % 4], 2)]
            ^ TE[3][byte(s[(i + 3) % 4], 3)]
            ^ rk[i];
    }
    t
}

/// The final round omits MixColumns, so it uses the plain S-box.
#[inline(always)]
fn enc_last(s: [u32; 4], rk: &[u32]) -> [u32; 4] {
    let mut t = [0u32; 4];
    for i in 0..4 {
        t[i] = (SBOX[byte(s[i], 0)] as u32) << 24
            ^ (SBOX[byte(s[(i + 1) % 4], 1)] as u32) << 16
            ^ (SBOX[byte(s[(i + 2) % 4], 2)] as u32) << 8
            ^ SBOX[byte(s[(i + 3) % 4], 3)] as u32
            ^ rk[i];
    }
    t
}

/// One full decryption round; InvShiftRows walks the anti-diagonal.
#[inline(always)]
fn dec_round(s: [u32; 4], rk: &[u32]) -> [u32; 4] {
    let mut t = [0u32; 4];
    for i in 0..4 {
        t[i] = TD[0][byte(s[i], 0)]
            ^ TD[1][byte(s[(i + 3) % 4], 1)]
            ^ TD[2][byte(s[(i + 2) % 4], 2)]
            ^ TD[3][byte(s[(i + 1) % 4], 3)]
            ^ rk[i];
    }
    t
}

#[inline(always)]
fn dec_last(s: [u32; 4], rk: &[u32]) -> [u32; 4] {
    let mut t = [0u32; 4];
    for i in 0..4 {
        t[i] = (INV_SBOX[byte(s[i], 0)] as u32) << 24
            ^ (INV_SBOX[byte(s[(i + 3) % 4], 1)] as u32) << 16
            ^ (INV_SBOX[byte(s[(i + 2) % 4], 2)] as u32) << 8
            ^ INV_SBOX[byte(s[(i + 1) % 4], 3)] as u32
            ^ rk[i];
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let aes = Aes::try_new(key).unwrap();

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

    // FIPS 197 Appendix B.
    #[test]
    fn fips197_appendix_b() {
        check(
            "2b7e151628aed2a6abf7158809cf4f3c",
            "3243f6a8885a308d313198a2e0370734",
            "3925841d02dc09fbdc118597196a0b32",
        );
    }

    // NIST SP 800-38A F.1.1 / F.1.3 / F.1.5, first ECB block.
    #[test]
    fn sp800_38a_ecb() {
        let plain = "6bc1bee22e409f96e93d7e117393172a";
        check(
            "2b7e151628aed2a6abf7158809cf4f3c",
            plain,
            "3ad77bb40d7a3660a89ecaf32466ef97",
        );
        check(
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            plain,
            "bd334f1d6e45f25ff712a214571fa5cc",
        );
        check(
            "603deb1015ca71be2b73aef0857d7781\
             1f352c073b6108d72d9810a30914dff4",
            plain,
            "f3eed1bdb5d2a03c064b5a7e3db181f8",
        );
    }

    #[test]
    fn blocks_match_single_block_path() {
        for klen in [16, 24, 32] {
            let aes = Aes::try_new(&[0x5a; 32][..klen]).unwrap();
            // Lengths cover zero, one lane group, leftovers and more.
            for nblocks in 0..9 {
                let mut data = [0u8; 8 * BLOCK_SIZE];
                for (i, b) in data.iter_mut().enumerate() {
                    *b = (i * 7 + klen) as u8;
                }
                let data = &mut data[..nblocks * BLOCK_SIZE];
                let mut expected = [0u8; 8 * BLOCK_SIZE];
                let expected = &mut expected[..data.len()];
                expected.copy_from_slice(data);
                for block in expected.chunks_exact_mut(BLOCK_SIZE) {
                    aes.encrypt_block(block.try_into().unwrap());
                }
                let orig: [u8; 8 * BLOCK_SIZE] = {
                    let mut o = [0u8; 8 * BLOCK_SIZE];
                    o[..data.len()].copy_from_slice(data);
                    o
                };

                aes.encrypt_blocks(data).unwrap();
                assert_eq!(data, expected, "encrypt {klen} {nblocks}");
                aes.decrypt_blocks(data).unwrap();
                assert_eq!(data, &orig[..data.len()], "decrypt {klen}");
            }
        }
    }

    #[test]
    fn blocks_reject_partial_block() {
        let aes = Aes::try_new(&[0; 16]).unwrap();
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
    fn trait_construction() {
        let a = <Aes as BlockCipher>::try_new(&[1; 24]).unwrap();
        assert_eq!(a.rounds(), 12);
        assert_eq!(
            <Aes as BlockCipher>::try_new(&[1; 20]).unwrap_err(),
            Error::InvalidKeyLength(20)
        );
        let mut data = [7u8; 48];
        BlockCipher::encrypt_blocks(&a, &mut data).unwrap();
        assert_ne!(data, [7u8; 48]);
        BlockCipher::decrypt_blocks(&a, &mut data).unwrap();
        assert_eq!(data, [7u8; 48]);
    }

    #[test]
    fn round_counts() {
        assert_eq!(Aes::try_new(&[0; 16]).unwrap().rounds(), 10);
        assert_eq!(Aes::try_new(&[0; 24]).unwrap().rounds(), 12);
        assert_eq!(Aes::try_new(&[0; 32]).unwrap().rounds(), 14);
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
    fn round_trip_many_blocks() {
        let aes = Aes::try_new(b"0123456789abcdef").unwrap();
        let mut block = [0u8; 16];
        let mut seen = [0u8; 16];
        for i in 0..1000u32 {
            block[..4].copy_from_slice(&i.to_le_bytes());
            let orig = block;
            aes.encrypt_block(&mut block);
            assert_ne!(block, orig);
            seen = block;
            aes.decrypt_block(&mut block);
            assert_eq!(block, orig);
        }
        assert_ne!(seen, [0u8; 16]);
    }

    #[test]
    fn debug_hides_key() {
        let aes = Aes::try_new(&[0x42; 16]).unwrap();
        let mut buf = [0u8; 64];
        let mut w = Writer(&mut buf, 0);
        core::fmt::write(&mut w, format_args!("{aes:?}")).unwrap();
        let len = w.1;
        let s = core::str::from_utf8(&buf[..len]).unwrap();
        assert_eq!(s, "Aes { rounds: 10 }");
    }

    struct Writer<'a>(&'a mut [u8], usize);

    impl fmt::Write for Writer<'_> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.1 + s.len();
            self.0
                .get_mut(self.1..end)
                .ok_or(fmt::Error)?
                .copy_from_slice(s.as_bytes());
            self.1 = end;
            Ok(())
        }
    }
}
