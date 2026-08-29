//! Hash functions.
//!
//! A hash function maps a message of any length to a digest of fixed
//! length, such that finding two messages with the same digest, or a
//! message with a given digest, is infeasible. Every hash here is
//! written against [`Hash`], and the ones that are defined over bit
//! strings rather than bytes also offer [`BitHash`].
//!
//! ```
//! use scytale::hash::sha2::{Sha256, Sha512_256};
//! use scytale::hash::{BitHash, Hash};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // Written once, for any hash.
//! fn fingerprint<H: Hash>(
//!     parts: &[&[u8]],
//! ) -> Result<H::Output, scytale::Error> {
//!     let mut hash = H::try_new()?;
//!     for part in parts {
//!         hash.update(part);
//!     }
//!     Ok(hash.finalize())
//! }
//! assert_eq!(fingerprint::<Sha256>(&[b"ab", b"c"])?, Sha256::digest(b"abc")?);
//! let wide = fingerprint::<Sha512_256>(&[b"abc"])?;
//! assert_eq!(wide.len(), 32);
//!
//! // A message of 19 bits: two whole bytes, then the top three bits
//! // of a third.
//! let mut hash = Sha256::new();
//! hash.update(&[0xff, 0x00]);
//! let digest = hash.finalize_bits(0b1010_0000, 3)?;
//! assert_ne!(digest, Sha256::digest(&[0xff, 0x00, 0xa0])?);
//! # Ok(())
//! # }
//! ```
//!
//! # Choosing a hash
//!
//! SHA-256 is the default: every protocol accepts it and most
//! processors have instructions for it. On a 64-bit processor with no
//! such instruction SHA-512/256 is faster, gives the same size of
//! digest, and cannot be length extended (see below), so it is the
//! better choice where nothing dictates SHA-256. SHA-384 and SHA-512
//! are for the larger security levels, when a protocol or policy asks
//! for them. SHA-224 and SHA-512/224 exist for protocols that name
//! them and are not worth choosing otherwise.
//!
//! # Not a MAC
//!
//! Hashing a secret key followed by a message does not make a message
//! authentication code. For the hashes here (the SHA-2 family) anyone
//! who knows the digest of a message can extend that message and
//! compute the digest of the extension, without the key. Use HMAC.

pub mod sha2;

use crate::symmetric::Block;
use crate::Error;

/// A hash function over byte strings, computed incrementally.
///
/// Only construction can fail, and then only for an implementation
/// that needs instructions this processor lacks. A state is consumed
/// by [`finalize`](Hash::finalize), so a digest of a prefix means
/// cloning first.
pub trait Hash: Clone + Sized {
    /// Bytes the compression function takes at a time. Constructions
    /// on top of a hash, HMAC among them, are defined in terms of
    /// this.
    const BLOCK_SIZE: usize;

    /// The digest; `[u8; 32]` for SHA-256.
    type Output: Block;

    /// Starts a new hash.
    fn try_new() -> Result<Self, Error>;

    /// Returns to the state of a new hash, without asking the
    /// processor again.
    fn reset(&mut self);

    /// Appends `data` to the message.
    fn update(&mut self, data: &[u8]);

    /// Ends the message and returns its digest.
    fn finalize(self) -> Self::Output;

    /// The digest of `data`, in one call.
    fn digest(data: &[u8]) -> Result<Self::Output, Error> {
        let mut hash = Self::try_new()?;
        hash.update(data);
        Ok(hash.finalize())
    }
}

/// A hash function defined over bit strings, not only bytes.
///
/// Every hash takes whole bytes through [`Hash::update`]; this adds
/// a way to end a message part way through its last byte. Not every
/// hash is defined that way, so this is a separate trait rather than
/// a method every hash must fake.
pub trait BitHash: Hash {
    /// Ends the message with the top `bits` bits of `last`, where
    /// `bits` is 1 to 7, and returns its digest. The remaining low
    /// bits of `last` are ignored.
    ///
    /// Returns [`Error::InvalidBitCount`] for a `bits` outside that
    /// range: zero extra bits is [`finalize`](Hash::finalize), and
    /// eight is a whole byte for [`update`](Hash::update).
    fn finalize_bits(self, last: u8, bits: u32) -> Result<Self::Output, Error>;
}
