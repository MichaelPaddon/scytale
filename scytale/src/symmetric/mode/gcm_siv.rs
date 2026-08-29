//! AES-GCM-SIV (RFC 8452), which survives a repeated nonce.
//!
//! Every mode before this one fails catastrophically if a nonce is
//! used twice: the keystream repeats and the messages leak into each
//! other, and for GCM an attacker can go on to forge tags at will.
//! GCM-SIV is built so that repeating a nonce reveals only whether
//! two messages were identical, and nothing else.
//!
//! It achieves that by deriving the tag from the message itself and
//! then using the tag as the starting counter, so the keystream
//! depends on what is being encrypted. Fresh keys are also derived
//! for every nonce, from the key given here.
//!
//! # One-shot only
//!
//! There is no incremental form, and there cannot be one for
//! encryption: the counter is the tag, the tag covers the whole
//! message, so nothing can be encrypted until every byte has been
//! seen. Decryption is kept one-shot to match, and because releasing
//! plaintext before the tag has been checked would give away the
//! property this mode exists for.
//!
//! # Using it safely
//!
//! - A repeated nonce is survivable here, not free: an observer still
//!   learns that two messages were the same. Fresh nonces remain
//!   worth having.
//! - The key is 16 or 32 bytes. RFC 8452 defines no 24-byte variant,
//!   so one is refused rather than quietly reinterpreted.
//! - The nonce is always 12 bytes and the tag always 16.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::GcmSiv;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let siv: GcmSiv<Aes> = GcmSiv::try_new(&[0u8; 16])?;
//! let nonce = [0u8; 12];
//!
//! let mut message = *b"hello";
//! let mut tag = [0u8; 16];
//! siv.encrypt(&nonce, b"header", &mut message, &mut tag)?;
//!
//! siv.decrypt(&nonce, b"header", &mut message, &tag)?;
//! assert_eq!(&message, b"hello");
//! # Ok(())
//! # }
//! ```

use core::fmt;

use super::ghash::BLOCK;
use super::polyval::Polyval;
use super::{xor, LANES};
use crate::symmetric::{Block, BlockCipher};
use crate::util;
use crate::Error;

/// The nonce length, fixed by the standard.
const NONCE: usize = 12;

/// The tag length, fixed by the standard.
const TAG: usize = BLOCK;

/// The most bytes of message or additional data allowed: 2^36.
const MAX_FIELD: u64 = 1 << 36;

/// AES-GCM-SIV over a block cipher.
///
/// Unlike most modes this is built from a key rather than a cipher:
/// every nonce gets its own pair of keys derived from it, so a
/// single expanded cipher would be no use.
#[derive(Clone)]
pub struct GcmSiv<C> {
    cipher: C,
    key_len: usize,
}

impl<C> fmt::Debug for GcmSiv<C> {
    /// Deliberately omits the cipher, which holds the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcmSiv").finish_non_exhaustive()
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> GcmSiv<C> {
    /// Takes the key that all others are derived from, which must be
    /// 16 or 32 bytes.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != 16 && key.len() != 32 {
            return Err(Error::InvalidKeyLength(key.len()));
        }
        Ok(GcmSiv {
            cipher: C::try_new(key)?,
            key_len: key.len(),
        })
    }

    /// Encrypts `data` in place and writes its 16-byte tag.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8; TAG],
    ) -> Result<(), Error> {
        check(aad, data.len())?;
        let (hash_key, cipher) = self.derive(nonce)?;

        // The tag covers the plaintext, so it is computed first.
        let full = authenticate(&hash_key, &cipher, nonce, aad, data)?;
        let mut counter = full;
        counter[BLOCK - 1] |= 0x80;
        apply(&cipher, &mut counter, data);

        tag.copy_from_slice(&full);
        Ok(())
    }

    /// Checks `tag` and, if it is right, decrypts `data` in place.
    ///
    /// On failure the buffer is wiped and
    /// [`Error::AuthenticationFailed`] returned.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG],
    ) -> Result<(), Error> {
        check(aad, data.len())?;
        let (hash_key, cipher) = self.derive(nonce)?;

        // The counter comes from the tag, so the message can be
        // decrypted before the tag is known to be right; then the tag
        // is recomputed over the plaintext and compared.
        let mut counter = *tag;
        counter[BLOCK - 1] |= 0x80;
        apply(&cipher, &mut counter, data);

        let full = authenticate(&hash_key, &cipher, nonce, aad, data)?;
        if util::equal(&full, tag) {
            Ok(())
        } else {
            data.fill(0);
            Err(Error::AuthenticationFailed)
        }
    }

    /// Derives the hashing key and the encrypting cipher for one
    /// nonce, as RFC 8452 section 4 does: successive counters with
    /// the nonce, keeping the first half of each result.
    fn derive(&self, nonce: &[u8; NONCE]) -> Result<([u8; BLOCK], C), Error> {
        let mut material = [0u8; 48];
        let blocks = 2 + self.key_len / 8;
        for i in 0..blocks {
            let mut block = [0u8; BLOCK];
            block[..4].copy_from_slice(&(i as u32).to_le_bytes());
            block[4..BLOCK].copy_from_slice(nonce);
            self.cipher.encrypt_block(&mut block);
            material[i * 8..(i + 1) * 8].copy_from_slice(&block[..8]);
        }
        let mut hash_key = [0u8; BLOCK];
        hash_key.copy_from_slice(&material[..BLOCK]);
        let cipher = C::try_new(&material[BLOCK..BLOCK + self.key_len])?;
        Ok((hash_key, cipher))
    }
}

/// Checks the size limits.
fn check(aad: &[u8], message: usize) -> Result<(), Error> {
    if aad.len() as u64 > MAX_FIELD || message as u64 > MAX_FIELD {
        return Err(Error::MessageTooLong);
    }
    Ok(())
}

/// The tag for a plaintext: POLYVAL over the additional data, the
/// message and their lengths, combined with the nonce and encrypted.
fn authenticate<C: BlockCipher<Block = [u8; BLOCK]>>(
    hash_key: &[u8; BLOCK],
    cipher: &C,
    nonce: &[u8; NONCE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<[u8; BLOCK], Error> {
    let mut hash = Polyval::new(hash_key);
    hash.update(aad);
    hash.pad();
    hash.update(plaintext);
    hash.pad();

    let mut lengths = [0u8; BLOCK];
    lengths[..8].copy_from_slice(&((aad.len() as u64) * 8).to_le_bytes());
    lengths[8..].copy_from_slice(&((plaintext.len() as u64) * 8).to_le_bytes());
    hash.update(&lengths);

    let mut tag = hash.finish();
    for (byte, n) in tag.iter_mut().zip(nonce) {
        *byte ^= n;
    }
    // The top bit is cleared here and set again in the counter, which
    // keeps the tag out of the counter's own range.
    tag[BLOCK - 1] &= 0x7f;
    cipher.encrypt_block(&mut tag);
    Ok(tag)
}

/// Counter mode as GCM-SIV defines it: the counter is the first four
/// bytes, read the little-endian way round.
fn apply<C: BlockCipher<Block = [u8; BLOCK]>>(
    cipher: &C,
    counter: &mut [u8; BLOCK],
    data: &mut [u8],
) {
    let (whole, tail) = <[u8; BLOCK]>::split_mut(data);
    let mut keystream = [[0u8; BLOCK]; LANES];
    for group in whole.chunks_mut(LANES) {
        let keystream = &mut keystream[..group.len()];
        counters(counter, keystream);
        cipher.encrypt_blocks(keystream);
        for (block, key) in group.iter_mut().zip(&*keystream) {
            xor(block, key);
        }
    }
    if !tail.is_empty() {
        let mut keystream = *counter;
        increment(counter);
        cipher.encrypt_block(&mut keystream);
        xor(tail, &keystream);
    }
}

/// Fills `blocks` with successive counter values and leaves `counter`
/// on the one after the last, keeping it in registers throughout; see
/// the note on the same function in [`gcm`](super::gcm).
///
/// Read little-endian, the four bytes this mode counts in are the low
/// thirty-two bits of the block, so the same masking works.
#[inline]
fn counters(counter: &mut [u8; BLOCK], blocks: &mut [[u8; BLOCK]]) {
    let base = u128::from_le_bytes(*counter);
    let rest = base & !(u32::MAX as u128);
    let mut n = base as u32;
    for block in blocks.iter_mut() {
        *block = (rest | u128::from(n)).to_le_bytes();
        n = n.wrapping_add(1);
    }
    *counter = (rest | u128::from(n)).to_le_bytes();
}

/// Adds one to the first four bytes, least significant first.
fn increment(counter: &mut [u8; BLOCK]) {
    for byte in counter[..4].iter_mut() {
        let (sum, carried) = byte.overflowing_add(1);
        *byte = sum;
        if !carried {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::Aes;

    /// Buffers big enough for every case below.
    const MAX: usize = 32;

    fn unhex<'a>(text: &str, buffer: &'a mut [u8]) -> &'a [u8] {
        let n = text.len() / 2;
        for i in 0..n {
            buffer[i] =
                u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        &buffer[..n]
    }

    /// RFC 8452 appendix C: key, nonce, additional data, plaintext,
    /// ciphertext, tag.
    const CASES: [[&str; 6]; 6] = [
        [
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "0100000000000000",
            "b5d839330ac7b786",
            "578782fff6013b815b287c22493a364c",
        ],
        [
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "010000000000000000000000",
            "7323ea61d05932260047d942",
            "a4978db357391a0bc4fdec8b0d106639",
        ],
        [
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            "0200000000000000",
            "1e6daba35669f427",
            "3b0a1a2560969cdf790d99759abd1508",
        ],
        [
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "010000000000000000000000",
            "02000000000000000000000000000000",
            "daf46cabd2e1ee43d52942c0f99a3309",
            "b4abb466c906a2777c93bdae563831e1",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000\
             000000",
            "030000000000000000000000",
            "",
            "0100000000000000",
            "c2ef328e5c71c83b",
            "843122130f7364b761e0b97427e3df28",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000\
             000000",
            "030000000000000000000000",
            "010000000000000000000000",
            "02000000000000000000000000000000",
            "a463fcad737f8a3069d2b7575e79c6b7",
            "feae1d0f24321df9ccf01f22033a0b30",
        ],
    ];

    #[test]
    fn rfc8452_test_cases() {
        for (i, case) in CASES.iter().enumerate() {
            let (mut kb, mut nb) = ([0u8; 32], [0u8; 12]);
            let (mut ab, mut pb) = ([0u8; MAX], [0u8; MAX]);
            let (mut cb, mut tb) = ([0u8; MAX], [0u8; 16]);
            let key = unhex(case[0], &mut kb);
            unhex(case[1], &mut nb);
            let nonce = &nb;
            let aad = unhex(case[2], &mut ab);
            let plain = unhex(case[3], &mut pb);
            let cipher = unhex(case[4], &mut cb);
            unhex(case[5], &mut tb);
            let want = &tb;

            let siv = GcmSiv::<Aes>::try_new(key).unwrap();
            let mut data = [0u8; MAX];
            let data = &mut data[..plain.len()];
            data.copy_from_slice(plain);
            let mut tag = [0u8; 16];

            siv.encrypt(nonce, aad, data, &mut tag).unwrap();
            assert_eq!(data, cipher, "case {i} ciphertext");
            assert_eq!(&tag, want, "case {i} tag");

            siv.decrypt(nonce, aad, data, want).unwrap();
            assert_eq!(data, plain, "case {i} plaintext");
        }
    }

    fn siv() -> GcmSiv<Aes> {
        GcmSiv::<Aes>::try_new(&[0x42; 16]).unwrap()
    }

    /// The point of the mode: a repeated nonce must not be a
    /// catastrophe. Two different messages under one nonce must not
    /// share a keystream, which is what would happen in GCM.
    #[test]
    fn a_repeated_nonce_is_survivable() {
        let siv = siv();
        let nonce = [1u8; 12];

        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        second[0] = 1; // differs in one byte only
        let original = second;
        let mut tag_a = [0u8; 16];
        let mut tag_b = [0u8; 16];
        siv.encrypt(&nonce, b"", &mut first, &mut tag_a).unwrap();
        siv.encrypt(&nonce, b"", &mut second, &mut tag_b).unwrap();

        // Under a shared keystream the two ciphertexts would differ
        // in exactly the byte the plaintexts differ in. Here they
        // differ throughout.
        let same: usize =
            first.iter().zip(&second).filter(|(a, b)| a == b).count();
        assert!(same < 8, "{same} bytes matched; keystream was reused");
        assert_ne!(tag_a, tag_b);

        // What it does reveal is that two identical messages are
        // identical.
        let mut third = original;
        let mut tag_c = [0u8; 16];
        siv.encrypt(&nonce, b"", &mut third, &mut tag_c).unwrap();
        assert_eq!(third, second);
        assert_eq!(tag_c, tag_b);
    }

    #[test]
    fn rejects_and_wipes() {
        let siv = siv();
        let nonce = [7u8; 12];
        let plain = [9u8; 20];
        let mut sealed = plain;
        let mut tag = [0u8; 16];
        siv.encrypt(&nonce, b"head", &mut sealed, &mut tag).unwrap();

        let mut wrong = tag;
        wrong[0] ^= 1;
        let mut data = sealed;
        assert_eq!(
            siv.decrypt(&nonce, b"head", &mut data, &wrong).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(data, [0u8; 20], "buffer wiped");

        let mut data = sealed;
        assert_eq!(
            siv.decrypt(&nonce, b"HEAD", &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    /// RFC 8452 defines no 192-bit variant, so one must be refused
    /// rather than quietly treated as something else. Nonce and tag
    /// lengths are fixed by their types.
    #[test]
    fn rejects_bad_lengths() {
        let source = [0u8; 32];
        for n in [0, 1, 15, 17, 24, 31] {
            assert_eq!(
                GcmSiv::<Aes>::try_new(&source[..n]).unwrap_err(),
                Error::InvalidKeyLength(n)
            );
        }
    }

    #[test]
    fn round_trips_at_many_lengths() {
        let siv = GcmSiv::<Aes>::try_new(&[0x5a; 32]).unwrap();
        let nonce = [0x77u8; 12];
        let mut plain = [0u8; 70];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        for n in [0, 1, 15, 16, 17, 31, 32, 33, 70] {
            let mut data = [0u8; 70];
            data[..n].copy_from_slice(&plain[..n]);
            let mut tag = [0u8; 16];
            siv.encrypt(&nonce, &plain[..n], &mut data[..n], &mut tag)
                .unwrap();
            siv.decrypt(&nonce, &plain[..n], &mut data[..n], &tag)
                .unwrap();
            assert_eq!(data[..n], plain[..n], "{n} bytes");
        }
    }

    /// Formatting the state must not print the key.
    #[test]
    fn debug_omits_the_key() {
        struct Buffer([u8; 256], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let mut buffer = Buffer([0; 256], 0);
        core::fmt::write(
            &mut buffer,
            format_args!("{:?}", GcmSiv::<Aes>::try_new(&[0x5a; 32]).unwrap()),
        )
        .unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("5a, 5a"), "{text}");
        assert!(text.starts_with("GcmSiv"));
    }
}
