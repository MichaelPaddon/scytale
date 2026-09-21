//! HKDF (RFC 5869), extract and expand as separate steps.

use core::fmt;

use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{Sha256, Sha384, Sha512};
use scytale::kdf::hkdf;
use zeroize::Zeroize;

use crate::digest::{self, Id};
use crate::{error, hmac};

/// Which hash HKDF runs over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Algorithm(hmac::Algorithm);

impl Algorithm {
    /// The HMAC it is built on.
    #[inline]
    pub fn hmac_algorithm(&self) -> hmac::Algorithm {
        self.0
    }
}

/// HKDF-SHA-1, only for protocols that still require it.
pub static HKDF_SHA1_FOR_LEGACY_USE_ONLY: Algorithm =
    Algorithm(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY);

/// HKDF-SHA-256.
pub static HKDF_SHA256: Algorithm = Algorithm(hmac::HMAC_SHA256);

/// HKDF-SHA-384.
pub static HKDF_SHA384: Algorithm = Algorithm(hmac::HMAC_SHA384);

/// HKDF-SHA-512.
pub static HKDF_SHA512: Algorithm = Algorithm(hmac::HMAC_SHA512);

impl KeyType for Algorithm {
    fn len(&self) -> usize {
        self.0.digest_algorithm().output_len()
    }
}

/// The length of what an expansion produces. Callers implement it for
/// their own key types, so it is not sealed.
// ring's trait, which callers implement; a length of zero is not a
// case worth a second method.
#[allow(clippy::len_without_is_empty)]
pub trait KeyType {
    /// The length in bytes.
    fn len(&self) -> usize;
}

/// A salt, ready to extract with.
#[derive(Debug)]
pub struct Salt(hmac::Key);

impl Salt {
    /// A salt of any length, which may be empty.
    pub fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        Salt(hmac::Key::new(algorithm.0, value))
    }

    /// The pseudorandom key extracted from `secret`: HMAC of the
    /// secret under the salt.
    pub fn extract(&self, secret: &[u8]) -> Prk {
        let prk = hmac::sign(&self.0, secret);
        Prk::new_less_safe(self.algorithm(), prk.as_ref())
    }

    /// The algorithm.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm(self.0.algorithm())
    }
}

impl From<Okm<'_, Algorithm>> for Salt {
    fn from(okm: Okm<'_, Algorithm>) -> Self {
        let algorithm = *okm.len();
        let mut bytes = [0u8; digest::MAX_OUTPUT_LEN];
        let bytes = &mut bytes[..algorithm.len()];
        okm.fill(bytes).unwrap_or_else(|error::Unspecified| {
            unreachable!("one digest exceeded HKDF's limit")
        });
        let salt = Salt::new(algorithm, bytes);
        bytes.zeroize();
        salt
    }
}

/// A pseudorandom key: extract's output, or a secret a protocol has
/// already derived.
///
/// It is kept as bytes, one digest long in every ordinary use. ring
/// takes a value of any length here, since the value keys an HMAC;
/// one longer than the hash's block is hashed first, which is what
/// HMAC itself does with such a key, so the expansion is the same.
#[derive(Clone)]
pub struct Prk {
    bytes: [u8; digest::MAX_BLOCK_LEN],
    len: usize,
    algorithm: Algorithm,
}

impl Drop for Prk {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for Prk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // ring holds an HMAC key here and prints it; the key's bytes
        // never appear.
        f.debug_tuple("Prk")
            .field(&hmac::KeyName(self.algorithm.0))
            .finish()
    }
}

impl Prk {
    /// A pseudorandom key from bytes the caller already has. "Less
    /// safe" because it bypasses extraction: `value` has to be
    /// uniformly random already.
    pub fn new_less_safe(algorithm: Algorithm, value: &[u8]) -> Self {
        let hash = algorithm.0.digest_algorithm();
        let mut prk = Prk {
            bytes: [0u8; digest::MAX_BLOCK_LEN],
            len: 0,
            algorithm,
        };
        if value.len() <= hash.block_len() {
            prk.bytes[..value.len()].copy_from_slice(value);
            prk.len = value.len();
        } else {
            let d = digest::digest(hash, value);
            prk.bytes[..d.as_ref().len()].copy_from_slice(d.as_ref());
            prk.len = d.as_ref().len();
        }
        prk
    }

    /// Material of length `len`, bound to `info`. Nothing is computed
    /// until [`Okm::fill`]. More than 255 digests is refused, which is
    /// the most HKDF defines.
    #[inline]
    pub fn expand<'a, L: KeyType>(
        &'a self,
        info: &'a [&'a [u8]],
        len: L,
    ) -> Result<Okm<'a, L>, error::Unspecified> {
        let len_cached = len.len();
        let limit = 255 * self.algorithm.0.digest_algorithm().output_len();
        if len_cached > limit {
            return Err(error::Unspecified);
        }
        Ok(Okm {
            prk: self,
            info,
            len,
            len_cached,
        })
    }

    fn fill(
        &self,
        info: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), scytale::Error> {
        let prk = &self.bytes[..self.len];
        match self.algorithm.0.digest_algorithm().id {
            Id::SHA1 => hkdf::expand::<Sha1>(prk, info, out),
            Id::SHA256 => hkdf::expand::<Sha256>(prk, info, out),
            Id::SHA384 => hkdf::expand::<Sha384>(prk, info, out),
            Id::SHA512 => hkdf::expand::<Sha512>(prk, info, out),
            // No static names HKDF over this hash, so no key can.
            Id::SHA512_256 => unreachable!("HKDF-SHA-512/256 has no static"),
        }
    }
}

impl From<Okm<'_, Algorithm>> for Prk {
    fn from(okm: Okm<Algorithm>) -> Self {
        let algorithm = *okm.len();
        let mut bytes = [0u8; digest::MAX_OUTPUT_LEN];
        let bytes = &mut bytes[..algorithm.len()];
        okm.fill(bytes).unwrap_or_else(|error::Unspecified| {
            unreachable!("one digest exceeded HKDF's limit")
        });
        let prk = Prk::new_less_safe(algorithm, bytes);
        bytes.zeroize();
        prk
    }
}

/// Material an expansion will produce, waiting for a buffer.
#[derive(Debug)]
pub struct Okm<'a, L: KeyType> {
    prk: &'a Prk,
    info: &'a [&'a [u8]],
    len: L,
    len_cached: usize,
}

impl<L: KeyType> Okm<'_, L> {
    /// What was asked for.
    #[inline]
    pub fn len(&self) -> &L {
        &self.len
    }

    /// Writes the material into `out`, which must be exactly the length
    /// asked for.
    #[inline]
    pub fn fill(self, out: &mut [u8]) -> Result<(), error::Unspecified> {
        if out.len() != self.len_cached {
            return Err(error::Unspecified);
        }
        self.prk.fill(self.info, out).map_err(error::erase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::format;

    fn hex(bytes: &[u8]) -> std::string::String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    struct Len(usize);

    impl KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    // RFC 5869 test case 1.
    #[test]
    fn extract_then_expand_gives_the_published_output() {
        let ikm = [0x0bu8; 22];
        let salt: std::vec::Vec<u8> = (0x00..=0x0c).collect();
        let info: std::vec::Vec<u8> = (0xf0..=0xf9).collect();
        let prk = Salt::new(HKDF_SHA256, &salt).extract(&ikm);
        let mut okm = [0u8; 42];
        prk.expand(&[&info[..5], &info[5..]], Len(42))
            .expect("expand")
            .fill(&mut okm)
            .expect("fill");
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db0\
             2d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn the_limit_and_the_length_are_enforced() {
        let prk = Prk::new_less_safe(HKDF_SHA256, &[1u8; 32]);
        assert!(prk.expand(&[b"x"], Len(255 * 32)).is_ok());
        assert!(prk.expand(&[b"x"], Len(255 * 32 + 1)).is_err());
        let okm = prk.expand(&[b"x"], Len(16)).expect("expand");
        assert!(okm.fill(&mut [0u8; 15]).is_err());
    }

    // A key longer than the block is hashed down, as HMAC does, so it
    // expands the same as its digest would.
    #[test]
    fn a_long_key_expands_as_its_digest() {
        let long = [0x5au8; 200];
        let short = digest::digest(&digest::SHA384, &long);
        let a = Prk::new_less_safe(HKDF_SHA384, &long);
        let b = Prk::new_less_safe(HKDF_SHA384, short.as_ref());
        let (mut x, mut y) = ([0u8; 64], [0u8; 64]);
        a.expand(&[], Len(64)).expect("a").fill(&mut x).expect("x");
        b.expand(&[], Len(64)).expect("b").fill(&mut y).expect("y");
        assert_eq!(x, y);
    }

    #[test]
    fn an_expansion_can_key_a_mac_or_seed_a_salt() {
        let prk = Prk::new_less_safe(HKDF_SHA512, &[3u8; 64]);
        let okm = prk.expand(&[b"k"], hmac::HMAC_SHA512).expect("expand");
        let key = hmac::Key::from(okm);
        assert_eq!(key.algorithm(), hmac::HMAC_SHA512);
        let okm = prk.expand(&[b"s"], HKDF_SHA512).expect("expand");
        assert_eq!(Salt::from(okm).algorithm(), HKDF_SHA512);
    }

    #[test]
    fn a_prk_prints_its_algorithm_only() {
        let prk = Prk::new_less_safe(HKDF_SHA256, &[9u8; 32]);
        assert_eq!(format!("{prk:?}"), "Prk(Key { algorithm: SHA256 })");
    }
}
