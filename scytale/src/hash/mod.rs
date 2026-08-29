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
//! [`sha3`] is a different design, not a successor: choose it when a
//! protocol names it, or for a digest that cannot be length extended
//! without settling for a truncated one. Its SHAKE functions give
//! output of whatever length is asked for, through [`Xof`] and
//! [`XofReader`] rather than [`Hash`], which is what to reach for
//! when the length is the caller's to decide. Without hardware for
//! it (only AArch64 has any) SHA-3 costs more per byte than SHA-2.
//!
//! # Not a MAC
//!
//! Hashing a secret key followed by a message does not make a message
//! authentication code. For the SHA-2 family anyone who knows the
//! digest of a message can extend that message and compute the digest
//! of the extension, without the key. SHA-3 does not have that flaw,
//! but a construction that is only safe with one family is a trap
//! for the next reader. Use HMAC.

pub mod sha2;
pub mod sha3;

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
    /// Ends the message with the first `bits` bits of `last`, where
    /// `bits` is 1 to 7, and returns its digest. The other bits of
    /// `last` are ignored.
    ///
    /// Which bits are first is the hash's own convention, so that a
    /// bit string laid out as its standard's test files lay it out
    /// can be passed straight through: SHA-2 counts from the most
    /// significant bit of the byte, SHA-3 from the least.
    ///
    /// Returns [`Error::InvalidBitCount`] for a `bits` outside that
    /// range: zero extra bits is [`finalize`](Hash::finalize), and
    /// eight is a whole byte for [`update`](Hash::update).
    fn finalize_bits(self, last: u8, bits: u32) -> Result<Self::Output, Error>;
}

/// An extendable-output function: a hash whose digest is as long as
/// the caller asks, squeezed out after the message is complete.
///
/// The message goes in through [`update`](Xof::update) as for a
/// [`Hash`]; [`finalize_xof`](Xof::finalize_xof) then hands back a
/// reader that yields output in any number of pieces. Two readers
/// over the same message yield the same stream, so a caller wanting
/// `n` bytes and later `m` more gets the first `n + m` bytes of one
/// stream either way.
pub trait Xof: Clone + Sized {
    /// Bytes the sponge takes at a time, the rate.
    const BLOCK_SIZE: usize;

    /// What the output is squeezed from.
    type Reader: XofReader;

    /// Starts a new function.
    fn try_new() -> Result<Self, Error>;

    /// Returns to the state of a new function, without asking the
    /// processor again.
    fn reset(&mut self);

    /// Appends `data` to the message.
    fn update(&mut self, data: &[u8]);

    /// Ends the message and returns the output stream.
    fn finalize_xof(self) -> Self::Reader;
}

/// The output side of an [`Xof`].
pub trait XofReader {
    /// Fills `out` with the next bytes of the stream.
    fn squeeze(&mut self, out: &mut [u8]);
}

/// An extendable-output function defined over bit strings; see
/// [`BitHash`] for the convention.
pub trait BitXof: Xof {
    /// Ends the message with the first `bits` bits of `last`, where
    /// `bits` is 1 to 7, and returns the output stream.
    ///
    /// Returns [`Error::InvalidBitCount`] for a `bits` outside that
    /// range.
    fn finalize_bits_xof(
        self,
        last: u8,
        bits: u32,
    ) -> Result<Self::Reader, Error>;
}
