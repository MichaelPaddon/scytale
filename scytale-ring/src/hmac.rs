//! HMAC over the hashes in [`digest`].

use core::fmt;

use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{Sha256, Sha384, Sha512};
use scytale::mac::Mac;
use scytale::mac::hmac::Hmac;
use zeroize::Zeroize;

use crate::digest::{self, Digest, Id};
use crate::{error, hkdf, rand};

/// Which hash an HMAC key is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Algorithm(&'static digest::Algorithm);

impl Algorithm {
    /// The hash.
    #[inline]
    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.0
    }
}

/// HMAC-SHA-1, only for protocols that still require it.
pub static HMAC_SHA1_FOR_LEGACY_USE_ONLY: Algorithm =
    Algorithm(&digest::SHA1_FOR_LEGACY_USE_ONLY);

/// HMAC-SHA-256.
pub static HMAC_SHA256: Algorithm = Algorithm(&digest::SHA256);

/// HMAC-SHA-384.
pub static HMAC_SHA384: Algorithm = Algorithm(&digest::SHA384);

/// HMAC-SHA-512.
pub static HMAC_SHA512: Algorithm = Algorithm(&digest::SHA512);

/// A computed tag.
#[derive(Clone, Copy, Debug)]
pub struct Tag(Digest);

impl AsRef<[u8]> for Tag {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// The keyed MAC, one arm per hash. Keyed once, then cloned for each
/// message, so the key's two blocks are hashed only once.
#[derive(Clone)]
enum State {
    Sha1(Hmac<Sha1>),
    Sha256(Hmac<Sha256>),
    Sha384(Hmac<Sha384>),
    Sha512(Hmac<Sha512>),
}

impl State {
    fn new(algorithm: Algorithm, key: &[u8]) -> Self {
        match algorithm.0.id {
            Id::SHA1 => State::Sha1(Hmac::new(key)),
            Id::SHA256 => State::Sha256(Hmac::new(key)),
            Id::SHA384 => State::Sha384(Hmac::new(key)),
            Id::SHA512 => State::Sha512(Hmac::new(key)),
            // No static names HMAC over this hash, so no key can.
            Id::SHA512_256 => unreachable!("HMAC-SHA-512/256 has no static"),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            State::Sha1(m) => m.update(data),
            State::Sha256(m) => m.update(data),
            State::Sha384(m) => m.update(data),
            State::Sha512(m) => m.update(data),
        }
    }

    fn finish(&mut self, algorithm: &'static digest::Algorithm) -> Tag {
        let out: &[u8] = match self {
            State::Sha1(m) => &m.finalize(),
            State::Sha256(m) => &m.finalize(),
            State::Sha384(m) => &m.finalize(),
            State::Sha512(m) => &m.finalize(),
        };
        Tag(Digest::from_bytes(algorithm, out))
    }
}

/// An HMAC key.
#[derive(Clone)]
pub struct Key {
    state: State,
    algorithm: Algorithm,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&KeyName(self.algorithm), f)
    }
}

/// How a key prints, without its bytes: also how the types that hold
/// one in ring print it.
pub(crate) struct KeyName(pub(crate) Algorithm);

impl fmt::Debug for KeyName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Key")
            .field("algorithm", self.0.digest_algorithm())
            .finish()
    }
}

impl Key {
    /// A fresh key, one digest long, from `rng`.
    pub fn generate(
        algorithm: Algorithm,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::Unspecified> {
        let mut bytes = [0u8; digest::MAX_OUTPUT_LEN];
        let bytes = &mut bytes[..algorithm.0.output_len()];
        let filled = rng.fill(bytes);
        let key = filled.map(|()| Self::new(algorithm, bytes));
        bytes.zeroize();
        key
    }

    /// A key from `key_value`, of any length.
    pub fn new(algorithm: Algorithm, key_value: &[u8]) -> Self {
        Key {
            state: State::new(algorithm, key_value),
            algorithm,
        }
    }

    /// The algorithm.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

impl hkdf::KeyType for Algorithm {
    fn len(&self) -> usize {
        self.digest_algorithm().output_len()
    }
}

impl From<hkdf::Okm<'_, Algorithm>> for Key {
    fn from(okm: hkdf::Okm<Algorithm>) -> Self {
        let algorithm = *okm.len();
        let mut bytes = [0u8; digest::MAX_OUTPUT_LEN];
        let bytes = &mut bytes[..algorithm.0.output_len()];
        // The length is the algorithm's own output, which HKDF can
        // always produce: 255 digests is the limit, and this is one.
        okm.fill(bytes).unwrap_or_else(|error::Unspecified| {
            unreachable!("one digest exceeded HKDF's limit")
        });
        let key = Self::new(algorithm, bytes);
        bytes.zeroize();
        key
    }
}

/// A MAC under way.
#[derive(Clone)]
pub struct Context {
    state: State,
    algorithm: Algorithm,
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Context")
            .field("algorithm", self.algorithm.digest_algorithm())
            .finish()
    }
}

impl Context {
    /// A MAC under `signing_key`.
    pub fn with_key(signing_key: &Key) -> Self {
        Context {
            state: signing_key.state.clone(),
            algorithm: signing_key.algorithm,
        }
    }

    /// Adds `data` to the message.
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// The tag of everything added.
    pub fn sign(mut self) -> Tag {
        self.state.finish(self.algorithm.0)
    }
}

/// The tag of `data` under `key`.
pub fn sign(key: &Key, data: &[u8]) -> Tag {
    let mut ctx = Context::with_key(key);
    ctx.update(data);
    ctx.sign()
}

/// Whether `tag` is the tag of `data` under `key`, compared in
/// constant time.
pub fn verify(
    key: &Key,
    data: &[u8],
    tag: &[u8],
) -> Result<(), error::Unspecified> {
    if scytale::constant_time::equal(sign(key, data).as_ref(), tag) {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::format;

    // RFC 4231 test case 2 for the SHA-2 forms; RFC 2202 test case 2
    // for SHA-1. Key "Jefe".
    #[test]
    fn each_algorithm_gives_the_published_tag() {
        let data = b"what do ya want for nothing?";
        let cases: [(Algorithm, &str); 4] = [
            (
                HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
            (
                HMAC_SHA256,
                "5bdcc146bf60754e6a042426089575c7\
                 5a003f089d2739839dec58b964ec3843",
            ),
            (
                HMAC_SHA384,
                "af45d2e376484031617f78d2b58a6b1b\
                 9c7ef464f5a01b47e42ec3736322445e\
                 8e2240ca5e69e2c78b3239ecfab21649",
            ),
            (
                HMAC_SHA512,
                "164b7a7bfcf819e2e395fbe73b56e0a3\
                 87bd64222e831fd610270cd7ea250554\
                 9758bf75c05a994a6d034f65f8f0e6fd\
                 caeab1a34d4a6b4b636e070a38bce737",
            ),
        ];
        for (algorithm, want) in cases {
            let key = Key::new(algorithm, b"Jefe");
            let tag = sign(&key, data);
            let hex: std::string::String =
                tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, want, "{algorithm:?}");
            verify(&key, data, tag.as_ref()).expect("verify");
            let mut wrong = [0u8; 64];
            let wrong = &mut wrong[..tag.as_ref().len()];
            wrong.copy_from_slice(tag.as_ref());
            wrong[0] ^= 1;
            assert!(verify(&key, data, wrong).is_err());
            assert!(verify(&key, data, &tag.as_ref()[1..]).is_err());
        }
    }

    #[test]
    fn a_context_signs_what_sign_signs() {
        let key = Key::new(HMAC_SHA384, &[7u8; 200]);
        let mut ctx = Context::with_key(&key);
        ctx.update(b"hello, ");
        ctx.update(b"world");
        assert_eq!(ctx.sign().as_ref(), sign(&key, b"hello, world").as_ref());
    }

    #[test]
    fn keys_print_their_algorithm_only() {
        let key = Key::new(HMAC_SHA256, b"secret");
        assert_eq!(format!("{key:?}"), "Key { algorithm: SHA256 }");
    }

    #[test]
    fn a_generated_key_signs() {
        let rng = rand::SystemRandom::new();
        let key = Key::generate(HMAC_SHA512, &rng).expect("generate");
        let tag = sign(&key, b"x");
        verify(&key, b"x", tag.as_ref()).expect("verify");
    }
}
