//! What can go wrong.
//!
//! Every fallible call in the library returns this one type. The
//! variants say what was wrong with the request, and never anything
//! about the secret it was made with.
//!
//! The type is `non_exhaustive`, so a `match` needs an arm for
//! whatever a later version adds:
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::Error;
//!
//! match Aes::try_new(&[0u8; 7]) {
//!     Ok(_) => unreachable!(),
//!     Err(Error::InvalidKeyLength(n)) => assert_eq!(n, 7),
//!     Err(Error::NotSupported) => panic!("no implementation at all"),
//!     Err(other) => panic!("{other}"),
//! }
//! ```
//!
//! # Which variant, from where
//!
//! Several variants carry a length, and which one says what was
//! wrong with it. [`Error::InvalidLength`] is malformed input: data
//! that is not a size the call can take, such as a wrapped key that
//! is not a multiple of eight bytes, or more HKDF output than the
//! construction defines. [`Error::OutputTooSmall`] is the caller's
//! buffer, and carries the size it needs to be.
//! [`Error::NotBlockAligned`], [`Error::InvalidNonceLength`],
//! [`Error::InvalidTagLength`] and [`Error::InvalidKeyLength`] name
//! the offending argument. [`Error::InvalidSeedLength`] and
//! [`Error::RequestTooLarge`] come only from the random number
//! generator, and [`Error::InvalidBitCount`] only from ending a hash
//! part way through a byte.

use core::fmt;

/// Anything a scytale call can refuse to do.
///
/// One type for the whole library, so a caller using more than one
/// part of it has a single thing to match on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The key length is not one the cipher accepts.
    InvalidKeyLength(usize),
    /// The data length is not a whole number of blocks.
    NotBlockAligned(usize),
    /// The nonce or initialisation vector is not the length the mode
    /// requires.
    InvalidNonceLength(usize),
    /// The data length does not match what the call requires.
    InvalidLength(usize),
    /// The output buffer is too small. The number is the length it
    /// needs to be.
    OutputTooSmall(usize),
    /// The count of trailing bits is not 1 to 7.
    InvalidBitCount(u32),
    /// The seed is shorter than the generator requires.
    InvalidSeedLength(usize),
    /// More bytes were asked for at once than the generator will give.
    RequestTooLarge(usize),
    /// A call came in an order the mode does not allow, such as
    /// additional data after the message has begun.
    OutOfOrder,
    /// The authentication tag is not a length the mode allows.
    InvalidTagLength(usize),
    /// The message did not authenticate: it is not what was
    /// encrypted, under this key, nonce and additional data.
    ///
    /// Deliberately says no more than that. Which part failed, or how
    /// nearly a guess succeeded, would help an attacker.
    AuthenticationFailed,
    /// The message is longer than the mode can safely handle.
    MessageTooLong,
    /// The radix is outside the range the mode allows.
    InvalidRadix(u32),
    /// A symbol is not a value the radix allows.
    InvalidSymbol(u32),
    /// The set of possible messages is too small to encrypt safely.
    /// A short string in a small alphabet can simply be searched.
    DomainTooSmall,
    /// The iteration count is zero, which would derive nothing.
    InvalidIterations,
    /// The processor lacks the instructions this implementation needs.
    NotSupported,
    /// The system would not supply random bytes. The number is the
    /// error the kernel gave, or zero where there is no such call to
    /// make at all.
    EntropyUnavailable(i32),
    /// A nonce sequence has issued every value it holds. Carrying on
    /// would repeat one, so it stops instead.
    SequenceExhausted,
    /// A generator has drawn as much as it may from one seeding, and
    /// has no source of its own to reseed from. Supply fresh entropy
    /// before asking again.
    ReseedRequired,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeyLength(n) => {
                write!(f, "invalid key length: {n} bytes")
            }
            Error::NotBlockAligned(n) => {
                write!(f, "data length {n} is not a whole number of blocks")
            }
            Error::InvalidNonceLength(n) => {
                write!(f, "invalid nonce or IV length: {n} bytes")
            }
            Error::InvalidLength(n) => {
                write!(f, "invalid data length: {n}")
            }
            Error::OutputTooSmall(n) => {
                write!(f, "output buffer too small: {n} bytes needed")
            }
            Error::InvalidBitCount(n) => {
                write!(f, "invalid trailing bit count: {n}")
            }
            Error::InvalidSeedLength(n) => {
                write!(f, "seed too short: {n} bytes")
            }
            Error::RequestTooLarge(n) => {
                write!(f, "request too large: {n} bytes")
            }
            Error::OutOfOrder => write!(f, "call out of order"),
            Error::InvalidTagLength(n) => {
                write!(f, "invalid authentication tag length: {n} bytes")
            }
            Error::AuthenticationFailed => {
                write!(f, "message failed authentication")
            }
            Error::MessageTooLong => {
                write!(f, "message too long for this mode")
            }
            Error::InvalidRadix(r) => write!(f, "invalid radix: {r}"),
            Error::InvalidSymbol(s) => write!(f, "invalid symbol: {s}"),
            Error::DomainTooSmall => {
                write!(f, "too few possible messages to encrypt safely")
            }
            Error::InvalidIterations => write!(f, "zero iterations"),
            Error::NotSupported => {
                write!(f, "not supported by this processor")
            }
            Error::EntropyUnavailable(n) => {
                write!(f, "cannot read randomness from the system: error {n}")
            }
            Error::SequenceExhausted => {
                write!(f, "nonce sequence exhausted")
            }
            Error::ReseedRequired => {
                write!(f, "generator needs fresh entropy")
            }
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(e: Error, buf: &mut [u8; 64]) -> &str {
        let mut w = Writer(buf, 0);
        core::fmt::write(&mut w, format_args!("{e}")).unwrap();
        let len = w.1;
        core::str::from_utf8(&buf[..len]).unwrap()
    }

    #[test]
    fn error_display() {
        let mut buf = [0u8; 64];
        assert_eq!(
            render(Error::InvalidKeyLength(7), &mut buf),
            "invalid key length: 7 bytes"
        );
        assert_eq!(
            render(Error::NotBlockAligned(17), &mut buf),
            "data length 17 is not a whole number of blocks"
        );
        assert_eq!(
            render(Error::InvalidNonceLength(12), &mut buf),
            "invalid nonce or IV length: 12 bytes"
        );
        assert_eq!(
            render(Error::InvalidLength(7), &mut buf),
            "invalid data length: 7"
        );
        assert_eq!(
            render(Error::NotSupported, &mut buf),
            "not supported by this processor"
        );
        assert_eq!(
            render(Error::EntropyUnavailable(38), &mut buf),
            "cannot read randomness from the system: error 38"
        );
        assert_eq!(
            render(Error::SequenceExhausted, &mut buf),
            "nonce sequence exhausted"
        );
        assert_eq!(
            render(Error::ReseedRequired, &mut buf),
            "generator needs fresh entropy"
        );
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
