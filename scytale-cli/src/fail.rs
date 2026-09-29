//! What a command reports when it cannot finish, and the exit status
//! each kind carries.
//!
//! Every message has one shape: what is wrong, then what would be
//! right, naming the option it concerns and a length or a name but
//! never the bytes of a value. The command and algorithm the message
//! is about go in front of it by `main`, which knows them:
//!
//!     scytale aead encrypt aes-256-gcm: --key is 16 bytes;
//!     aes-256-gcm takes 32
//!
//! Four statuses, so a script can tell them apart without reading
//! text: 2 is the caller's mistake, an option or a value that could
//! not be what was asked; 1 is a verification that failed, a tag,
//! signature or padding that did not check, which a script may well
//! expect; 3 is everything else, from a file that would not open to
//! a generator that would not seed; and 0 with nothing said when the
//! reader of standard output went away, as the coreutils do.

use std::fmt;

/// Why a command stopped.
#[derive(Debug)]
pub enum Fail {
    /// The request itself was wrong: exit 2.
    Usage(String),
    /// The data did not verify under the key: exit 1.
    Verify(String),
    /// Something outside the request went wrong: exit 3.
    Other(String),
    /// Standard output was closed under us: exit 0, silently.
    Quiet,
}

impl Fail {
    /// The process exit status this failure ends with.
    pub fn code(&self) -> i32 {
        match self {
            Fail::Usage(_) => 2,
            Fail::Verify(_) => 1,
            Fail::Other(_) => 3,
            Fail::Quiet => 0,
        }
    }
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fail::Usage(s) | Fail::Verify(s) | Fail::Other(s) => f.write_str(s),
            Fail::Quiet => Ok(()),
        }
    }
}

/// The library's errors, where a call site has not said something
/// more exact about what it was doing. The verification failures
/// are worded for the caller of a tool; the rest carry the
/// library's own words, which name the argument.
impl From<scytale::Error> for Fail {
    fn from(e: scytale::Error) -> Self {
        use scytale::Error::*;
        match e {
            AuthenticationFailed => Fail::Verify(
                "the message did not authenticate under this key, nonce \
                 and additional data; nothing was written"
                    .into(),
            ),
            InvalidSignature => Fail::Verify(
                "the signature is not valid for this message under this \
                 key"
                .into(),
            ),
            DecryptionFailed => Fail::Verify(
                "the ciphertext did not decrypt under this key, hash and \
                 label"
                    .into(),
            ),
            InvalidPadding => Fail::Verify(
                "the padding is not valid: wrong key, wrong IV, or an \
                 altered ciphertext"
                    .into(),
            ),
            InvalidKeyLength(_)
            | InvalidNonceLength(_)
            | InvalidTagLength(_)
            | InvalidLength(_)
            | NotBlockAligned(_)
            | InvalidRadix(_)
            | InvalidSymbol(_)
            | DomainTooSmall
            | InvalidIterations
            | MessageTooLong
            | InvalidEncoding
            | WrongAlgorithm
            | InconsistentKey
            | UnsupportedVersion
            | NotSupported
            | InvalidPublicKey
            | InvalidPrivateKey => Fail::Usage(e.to_string()),
            _ => Fail::Other(e.to_string()),
        }
    }
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            Fail::Quiet
        } else {
            Fail::Other(e.to_string())
        }
    }
}

pub type Result<T> = std::result::Result<T, Fail>;

/// A [`Fail::Usage`] from a format string.
macro_rules! usage {
    ($($arg:tt)*) => {
        $crate::fail::Fail::Usage(format!($($arg)*))
    };
}

/// A [`Fail::Verify`] from a format string.
macro_rules! verify {
    ($($arg:tt)*) => {
        $crate::fail::Fail::Verify(format!($($arg)*))
    };
}

pub(crate) use {usage, verify};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_words() {
        assert_eq!(Fail::from(scytale::Error::AuthenticationFailed).code(), 1);
        assert_eq!(Fail::from(scytale::Error::InvalidKeyLength(3)).code(), 2);
        assert_eq!(Fail::from(scytale::Error::EntropyUnavailable(1)).code(), 3);
        let pipe = std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        assert_eq!(Fail::from(pipe).code(), 0);
        let s = Fail::from(scytale::Error::InvalidPadding).to_string();
        assert!(s.contains("altered ciphertext"), "{s}");
        assert_eq!(Fail::Quiet.to_string(), "");
    }
}
