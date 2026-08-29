//! What can go wrong.
//!
//! Every fallible call in the library returns this one type. The
//! variants say what was wrong with the request, and never anything
//! about the secret it was made with.

use core::fmt;

/// Anything a scytale call can refuse to do.
///
/// One type for the whole library, so a caller using more than one
/// part of it has a single thing to match on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
