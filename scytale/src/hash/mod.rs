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
//! // Or as an object, for code that learns its hash at run time.
//! fn feed(hash: &mut dyn Hash<Output = [u8; 32]>) -> [u8; 32] {
//!     hash.update(b"abc");
//!     hash.finalize()
//! }
//! let mut sha256 = Sha256::new();
//! let mut sha512_256 = Sha512_256::new();
//! assert_eq!(feed(&mut sha256), Sha256::digest(b"abc")?);
//! assert_eq!(feed(&mut sha512_256), wide);
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
//! [`sha1`] is not a choice at all. It is broken for collisions and
//! is here only so that the protocols and formats that still name it
//! can be spoken: HMAC-SHA-1, HKDF over it, OAEP's default mask
//! function. Its own documentation says why at greater length.
//!
//! # Not a MAC
//!
//! Hashing a secret key followed by a message does not make a message
//! authentication code. For the SHA-2 family anyone who knows the
//! digest of a message can extend that message and compute the digest
//! of the extension, without the key. SHA-3 does not have that flaw,
//! but a construction that is only safe with one family is a trap
//! for the next reader. Use HMAC.

pub mod sha1;
pub mod sha2;
pub mod sha3;

#[cfg(doc)]
use crate::BlockType;
use crate::Error;

/// A hash function over byte strings, computed incrementally.
///
/// Only construction can fail, and then only for an implementation
/// that needs instructions this processor lacks.
/// [`finalize`](Hash::finalize) returns the digest and leaves the
/// state as [`reset`](Hash::reset) would, so one state can hash
/// message after message; a digest of a prefix means cloning first,
/// and every hash here is `Clone`.
///
/// The digest length is a type, not a constant, so the trait is
/// usable as an object once it is named: `&mut dyn Hash<Output =
/// [u8; 32]>` takes SHA-256, SHA-512/256 or SHA3-256 alike. Only
/// [`try_new`](Hash::try_new) and [`digest`](Hash::digest) need the
/// concrete type. The block a hash is built on is not part of this
/// trait; the concrete types say it through [`BlockType`], for the
/// constructions, HMAC among them, that are defined in terms of it.
pub trait Hash {
    /// The digest; `[u8; 32]` for SHA-256.
    type Output: Copy + AsRef<[u8]> + AsMut<[u8]>;

    /// Starts a new hash.
    fn try_new() -> Result<Self, Error>
    where
        Self: Sized;

    /// Returns to the state of a new hash, without asking the
    /// processor again.
    fn reset(&mut self);

    /// Appends `data` to the message.
    fn update(&mut self, data: &[u8]);

    /// Ends the message and returns its digest. The state is then
    /// that of a new hash, so the next [`update`](Hash::update)
    /// begins another message.
    fn finalize(&mut self) -> Self::Output;

    /// The digest of `data`, in one call.
    fn digest(data: &[u8]) -> Result<Self::Output, Error>
    where
        Self: Sized,
    {
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
    /// eight is a whole byte for [`update`](Hash::update). The state
    /// is then that of a new hash, as after `finalize`.
    fn finalize_bits(
        &mut self,
        last: u8,
        bits: u32,
    ) -> Result<Self::Output, Error>;
}

/// An extendable-output function: a hash whose digest is as long as
/// the caller asks, squeezed out after the message is complete.
///
/// The message goes in through [`update`](Xof::update) as for a
/// [`Hash`]; [`finalize_xof`](Xof::finalize_xof) then hands back a
/// reader that yields output in any number of pieces. Two readers
/// over the same message yield the same stream, so a caller wanting
/// `n` bytes and later `m` more gets the first `n + m` bytes of one
/// stream either way. Once the reader is handed back the function
/// is the state of a new one, ready for another message.
///
/// As with [`Hash`], the trait is usable as an object once its
/// reader type is named; the rate is the concrete type's
/// [`BlockType`].
pub trait Xof {
    /// What the output is squeezed from.
    type Reader: XofReader;

    /// Starts a new function.
    fn try_new() -> Result<Self, Error>
    where
        Self: Sized;

    /// Returns to the state of a new function, without asking the
    /// processor again.
    fn reset(&mut self);

    /// Appends `data` to the message.
    fn update(&mut self, data: &[u8]);

    /// Ends the message and returns the output stream. The state is
    /// then that of a new function.
    fn finalize_xof(&mut self) -> Self::Reader;
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
        &mut self,
        last: u8,
        bits: u32,
    ) -> Result<Self::Reader, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockType;
    use crate::hash::sha1::Sha1;
    use crate::hash::sha2::{Sha256, Sha512, Sha512_256};
    use crate::hash::sha3::{self, Sha3_256, Shake128, Shake256};

    /// Fed through an object, a hash gives the digest its type gives.
    #[test]
    fn as_an_object() {
        fn feed(hash: &mut dyn Hash<Output = [u8; 32]>) -> [u8; 32] {
            hash.update(b"ab");
            hash.update(b"c");
            hash.finalize()
        }
        let mut sha256 = Sha256::new();
        let mut sha512_256 = Sha512_256::new();
        let mut sha3_256 = Sha3_256::new();
        assert_eq!(feed(&mut sha256), Sha256::digest(b"abc").unwrap());
        assert_eq!(feed(&mut sha512_256), Sha512_256::digest(b"abc").unwrap());
        assert_eq!(feed(&mut sha3_256), Sha3_256::digest(b"abc").unwrap());

        fn squeeze(
            xof: &mut dyn Xof<Reader = sha3::Shake128Reader>,
        ) -> [u8; 40] {
            xof.update(b"abc");
            let mut out = [0u8; 40];
            xof.finalize_xof().squeeze(&mut out);
            out
        }
        let mut shake = Shake128::new();
        let mut fresh = Shake128::new();
        fresh.update(b"abc");
        let mut expected = [0u8; 40];
        fresh.finalize_xof().squeeze(&mut expected);
        assert_eq!(squeeze(&mut shake), expected);
    }

    /// `finalize` leaves a new hash: the next message hashes alone.
    #[test]
    fn finalize_resets() {
        fn check<H: Hash>() {
            let mut hash = H::try_new().unwrap();
            hash.update(b"garbage");
            let _ = hash.finalize();
            hash.update(b"abc");
            assert_eq!(
                hash.finalize().as_ref(),
                H::digest(b"abc").unwrap().as_ref()
            );
        }
        check::<Sha1>();
        check::<Sha256>();
        check::<Sha512>();
        check::<Sha3_256>();
    }

    #[test]
    fn xof_finalize_resets() {
        fn check<X: Xof>() {
            let mut xof = X::try_new().unwrap();
            xof.update(b"garbage");
            let _ = xof.finalize_xof();
            xof.update(b"abc");
            let mut again = [0u8; 40];
            xof.finalize_xof().squeeze(&mut again);
            let mut fresh = X::try_new().unwrap();
            fresh.update(b"abc");
            let mut expected = [0u8; 40];
            fresh.finalize_xof().squeeze(&mut expected);
            assert_eq!(again, expected);
        }
        check::<Shake128>();
        check::<Shake256>();
    }

    /// The block each hash is built on, as the standards give it.
    #[test]
    fn block_types_are_the_documented_sizes() {
        fn block<H: BlockType>() -> usize {
            size_of::<H::Block>()
        }
        assert_eq!(block::<Sha1>(), 64);
        assert_eq!(block::<Sha256>(), 64);
        assert_eq!(block::<Sha512>(), 128);
        assert_eq!(block::<Sha512_256>(), 128);
        assert_eq!(block::<Sha3_256>(), 136);
        assert_eq!(block::<Shake128>(), 168);
        assert_eq!(block::<Shake256>(), 136);
        assert_eq!(Sha256::zero_block(), [0u8; 64]);
        assert_eq!(Shake128::zero_block(), [0u8; 168]);
    }
}
