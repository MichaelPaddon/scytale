//! QUIC header protection (RFC 9001, section 5.4).
//!
//! A mask of five bytes is drawn from a sample of the packet's
//! ciphertext, with AES in one block or with ChaCha20's keystream.

use core::fmt;

use scytale::cipher::aes::{Aes128, Aes256};
use scytale::cipher::chacha20::ChaCha20;
use zeroize::Zeroize;

use crate::{error, hkdf};

const SAMPLE_LEN: usize = super::TAG_LEN;

/// A sample of ciphertext.
pub type Sample = [u8; SAMPLE_LEN];

/// Which cipher a header protection key uses, and what [`Debug`]
/// prints.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Id {
    AES_128,
    AES_256,
    CHACHA20,
}

/// A header protection algorithm. The only values are the `static`s
/// in this module.
pub struct Algorithm {
    id: Id,
    key_len: usize,
}

impl Algorithm {
    /// The length of a key, in bytes.
    #[inline]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The length of the sample a mask is drawn from, in bytes.
    #[inline]
    pub fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.id, f)
    }
}

impl hkdf::KeyType for &'static Algorithm {
    #[inline]
    fn len(&self) -> usize {
        self.key_len()
    }
}

/// AES-128, for the AES-128 cipher suites.
pub static AES_128: Algorithm = Algorithm {
    id: Id::AES_128,
    key_len: 16,
};

/// AES-256, for the AES-256 cipher suites.
pub static AES_256: Algorithm = Algorithm {
    id: Id::AES_256,
    key_len: 32,
};

/// ChaCha20, for the ChaCha20-Poly1305 suite.
pub static CHACHA20: Algorithm = Algorithm {
    id: Id::CHACHA20,
    key_len: 32,
};

enum Inner {
    Aes128(Aes128),
    Aes256(Aes256),
    ChaCha20(ChaCha20),
}

/// A header protection key.
pub struct HeaderProtectionKey {
    inner: Inner,
    algorithm: &'static Algorithm,
}

impl HeaderProtectionKey {
    /// A key for `algorithm`. Fails only if `key_bytes` is the wrong
    /// length.
    pub fn new(
        algorithm: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        let inner = match algorithm.id {
            Id::AES_128 => Inner::Aes128(Aes128::new(&super::key(key_bytes)?)),
            Id::AES_256 => Inner::Aes256(Aes256::new(&super::key(key_bytes)?)),
            Id::CHACHA20 => {
                Inner::ChaCha20(ChaCha20::new(&super::key(key_bytes)?))
            }
        };
        Ok(Self { inner, algorithm })
    }

    /// The mask for `sample`, which must be [`sample_len`] long.
    ///
    /// [`sample_len`]: Algorithm::sample_len
    pub fn new_mask(
        &self,
        sample: &[u8],
    ) -> Result<[u8; 5], error::Unspecified> {
        let sample: &Sample = sample.try_into()?;
        let mut mask = [0u8; 5];
        match &self.inner {
            Inner::Aes128(aes) => {
                mask_aes(|b| aes.encrypt(b), sample, &mut mask)
            }
            Inner::Aes256(aes) => {
                mask_aes(|b| aes.encrypt(b), sample, &mut mask)
            }
            Inner::ChaCha20(chacha) => {
                // The first four bytes are the block counter, the rest
                // the nonce; the mask is the keystream over five zeros.
                let (counter, nonce) = sample.split_at(4);
                let counter = u32::from_le_bytes(counter.try_into()?);
                let nonce: &[u8; 12] = nonce.try_into()?;
                chacha
                    .encrypt(nonce, counter, &mut mask)
                    .map_err(error::erase)?;
            }
        }
        Ok(mask)
    }

    /// The algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// The first five bytes of the sample encrypted as one block.
fn mask_aes(
    encrypt: impl Fn(&mut [[u8; 16]]),
    sample: &Sample,
    mask: &mut [u8; 5],
) {
    let mut block = *sample;
    encrypt(core::slice::from_mut(&mut block));
    mask.copy_from_slice(&block[..5]);
    block.zeroize();
}

impl From<hkdf::Okm<'_, &'static Algorithm>> for HeaderProtectionKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let algorithm = *okm.len();
        let mut bytes = [0u8; super::MAX_KEY_LEN];
        let bytes = &mut bytes[..algorithm.key_len()];
        // A key is far below HKDF's limit, and the buffer is exactly
        // the key's length, so neither step can fail.
        okm.fill(bytes).unwrap_or_else(|error::Unspecified| {
            unreachable!("one key exceeded HKDF's limit")
        });
        let key =
            Self::new(algorithm, bytes).unwrap_or_else(|error::Unspecified| {
                unreachable!("a key of its own length")
            });
        bytes.zeroize();
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    // RFC 9001 appendix A.2, the client Initial.
    #[test]
    fn aes_gives_the_published_mask() {
        let key = HeaderProtectionKey::new(
            &AES_128,
            &hex("9f50449e04a0e810283a1e9933adedd2"),
        )
        .expect("key");
        let mask = key
            .new_mask(&hex("d1b1c98dd7689fb8ec11d242b123dc9b"))
            .expect("mask");
        assert_eq!(&mask[..], &hex("437b9aec36")[..]);
    }

    // RFC 9001 appendix A.5, the ChaCha20 short header packet.
    #[test]
    fn chacha20_gives_the_published_mask() {
        let key = HeaderProtectionKey::new(
            &CHACHA20,
            &hex("25a282b9e82f06f21f488917a4fc8f1b\
                 73573685608597d0efcb076b0ab7a7a4"),
        )
        .expect("key");
        let mask = key
            .new_mask(&hex("5e5cd55c41f69080575d7999c25a5bfb"))
            .expect("mask");
        assert_eq!(&mask[..], &hex("aefefe7d03")[..]);
    }

    #[test]
    fn every_counter_gives_a_mask() {
        let key = HeaderProtectionKey::new(&CHACHA20, &[1u8; 32]).expect("key");
        key.new_mask(&[0xffu8; 16]).expect("the last block");
    }

    #[test]
    fn wrong_lengths_are_refused() {
        assert!(HeaderProtectionKey::new(&AES_256, &[0u8; 16]).is_err());
        let key = HeaderProtectionKey::new(&AES_256, &[0u8; 32]).expect("key");
        assert!(key.new_mask(&[0u8; 15]).is_err());
        assert!(key.new_mask(&[0u8; 17]).is_err());
        assert_eq!(key.algorithm().sample_len(), 16);
    }
}
