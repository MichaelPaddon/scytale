//! Message authentication codes.
//!
//! A MAC is a tag over a message that only holders of the key can
//! make, so a message that arrives with the right tag came from one
//! of them and has not been changed. The tag must be checked with
//! [`Mac::verify`] rather than compared byte by byte: a comparison
//! that stops at the first difference tells an attacker, through
//! timing, how much of a guess was right.
//!
//! [`hmac`] builds a MAC from any hash, and [`poly1305`] is the
//! one-time authenticator that ChaCha20-Poly1305 is built on. Hashing
//! the key in front of the message does not make a MAC: for the SHA-2
//! family anyone holding a message's digest can extend the message
//! and compute the digest of the extension, key unseen.
//!
//! ```
//! use scytale::mac::hmac::HmacSha256;
//! use scytale::mac::Mac;
//! use scytale::KeyType;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // Written once, for any MAC. The key is the MAC's own type.
//! fn seal<M: Mac>(
//!     key: &M::Key,
//!     message: &[u8],
//! ) -> Result<M::Tag, scytale::Error> {
//!     let mut mac = M::try_new(key)?;
//!     mac.update(message);
//!     Ok(mac.finalize())
//! }
//! let mut key = HmacSha256::zero_key();
//! key[..3].copy_from_slice(b"key");
//! let tag = seal::<HmacSha256>(&key, b"message")?;
//!
//! // On receipt: never compare the tag yourself. HMAC takes a key
//! // of any length too, and a short one is the same MAC as its
//! // zero-padded block.
//! let mut mac = HmacSha256::try_new(b"key")?;
//! mac.update(b"message");
//! mac.verify(&tag)?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Mac::verify`] takes the same time whether the tag is wrong in
//! its first byte or its last, and says only that it was wrong.

pub mod hmac;
pub mod poly1305;

use crate::{Error, KeyType};

/// A message authentication code, computed incrementally.
///
/// Only construction can fail. [`finalize`](Mac::finalize) and
/// [`verify`](Mac::verify) return the tag or check it and leave the
/// state as [`reset`](Mac::reset) would: at the start of a message,
/// under the same key, without re-deriving anything from it.
///
/// The key and the tag are types, so the trait is usable as an
/// object once they are named: `&mut dyn Mac<Key = [u8; 64], Tag =
/// [u8; 32]>`. Only [`try_new`](Mac::try_new) needs the concrete
/// type.
pub trait Mac: KeyType {
    /// The tag; `[u8; 32]` for HMAC-SHA-256.
    type Tag: Copy + AsRef<[u8]> + AsMut<[u8]>;

    /// Starts a MAC under `key`.
    fn try_new(key: &Self::Key) -> Result<Self, Error>
    where
        Self: Sized;

    /// Returns to the start of a message, under the same key.
    fn reset(&mut self);

    /// Appends `data` to the message.
    fn update(&mut self, data: &[u8]);

    /// Ends the message and returns its tag. The state is then that
    /// of [`reset`](Mac::reset).
    fn finalize(&mut self) -> Self::Tag;

    /// Ends the message and checks its tag against `tag`, in time
    /// that depends on the tag's length and nothing else.
    ///
    /// Returns [`Error::AuthenticationFailed`] if `tag` is not the
    /// message's tag, including when it is the wrong length. Never
    /// says more than that.
    ///
    /// Implementors should leave this alone: the provided body is the
    /// constant-time comparison, and a byte-by-byte one in its place
    /// would leak the tag through timing.
    fn verify(&mut self, tag: &[u8]) -> Result<(), Error> {
        let expected = self.finalize();
        if crate::util::equal(expected.as_ref(), tag) {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::hmac::{HmacSha256, HmacSha512_256};
    use crate::mac::poly1305::Poly1305;

    /// Fed through an object, a MAC gives the tag its type gives.
    #[test]
    fn as_an_object() {
        fn tag(mac: &mut dyn Mac<Key = [u8; 64], Tag = [u8; 32]>) -> [u8; 32] {
            mac.update(b"message");
            mac.finalize()
        }
        let mut mac = HmacSha256::try_new(b"key").unwrap();
        assert_eq!(tag(&mut mac), HmacSha256::mac(b"key", b"message").unwrap());

        fn tag16(
            mac: &mut dyn Mac<Key = [u8; 32], Tag = [u8; 16]>,
        ) -> [u8; 16] {
            mac.update(b"message");
            mac.finalize()
        }
        let key = [7u8; 32];
        let mut fresh = Poly1305::new(&key);
        fresh.update(b"message");
        let expected = fresh.finalize();
        let mut poly = Poly1305::new(&key);
        assert_eq!(tag16(&mut poly), expected);
    }

    /// `finalize` and `verify` leave the keyed state at the start of
    /// a message.
    #[test]
    fn finalize_resets() {
        fn check<M: Mac>(key: &M::Key) {
            let mut mac = M::try_new(key).unwrap();
            mac.update(b"garbage");
            let _ = mac.finalize();
            mac.update(b"abc");
            let tag = mac.finalize();
            let mut fresh = M::try_new(key).unwrap();
            fresh.update(b"abc");
            assert_eq!(tag.as_ref(), fresh.finalize().as_ref());
            mac.update(b"abc");
            mac.verify(tag.as_ref()).unwrap();
            mac.update(b"abc");
            mac.verify(tag.as_ref()).unwrap();
        }
        check::<HmacSha256>(&[3u8; 64]);
        check::<HmacSha512_256>(&[3u8; 128]);
        check::<Poly1305>(&[7u8; 32]);
    }

    #[test]
    fn zero_keys_are_the_key_type() {
        assert_eq!(HmacSha256::zero_key(), [0u8; 64]);
        assert_eq!(HmacSha512_256::zero_key(), [0u8; 128]);
        assert_eq!(Poly1305::zero_key(), [0u8; 32]);
    }
}
