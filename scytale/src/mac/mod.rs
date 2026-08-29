//! Message authentication codes.
//!
//! A MAC is a tag over a message that only holders of the key can
//! make, so a message that arrives with the right tag came from one
//! of them and has not been changed. The tag must be checked with
//! [`Mac::verify`] rather than compared byte by byte: a comparison
//! that stops at the first difference tells an attacker, through
//! timing, how much of a guess was right.
//!
//! [`hmac`] builds a MAC from any hash. Hashing the key in front of
//! the message does not: for the SHA-2 family anyone holding a
//! message's digest can extend the message and compute the digest of
//! the extension, key unseen.

pub mod hmac;

use crate::symmetric::Block;
use crate::Error;

/// A message authentication code, computed incrementally.
///
/// Only construction can fail. A state is consumed by
/// [`finalize`](Mac::finalize) or [`verify`](Mac::verify);
/// [`reset`](Mac::reset) starts another message under the same key
/// without re-deriving anything from it.
pub trait Mac: Clone + Sized {
    /// The tag; `[u8; 32]` for HMAC-SHA-256.
    type Tag: Block;

    /// Starts a MAC under `key`; each MAC decides which lengths it
    /// accepts.
    fn try_new(key: &[u8]) -> Result<Self, Error>;

    /// Returns to the start of a message, under the same key.
    fn reset(&mut self);

    /// Appends `data` to the message.
    fn update(&mut self, data: &[u8]);

    /// Ends the message and returns its tag.
    fn finalize(self) -> Self::Tag;

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
    fn verify(self, tag: &[u8]) -> Result<(), Error> {
        let expected = self.finalize();
        if crate::util::equal(expected.as_ref(), tag) {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}
