//! What a command reports when it cannot finish, and the exit status
//! each kind carries.
//!
//! Three statuses, so a script can tell them apart without reading
//! text: 2 is the caller's mistake, an option or a value that could
//! not be what was asked; 1 is a verification that failed, a tag,
//! signature or padding that did not check, which a script may well
//! expect; 3 is everything else, from a file that would not open to
//! a generator that would not seed.

use std::fmt;

/// Why a command stopped.
#[derive(Debug)]
pub enum Fail {
    /// The request itself was wrong: exit 2.
    Usage(String),
    /// The data did not verify under the key: exit 1.
    Verify,
    /// Something outside the request went wrong: exit 3.
    Other(String),
}

impl Fail {
    /// The process exit status this failure ends with.
    pub fn code(&self) -> i32 {
        match self {
            Fail::Usage(_) => 2,
            Fail::Verify => 1,
            Fail::Other(_) => 3,
        }
    }
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fail::Usage(s) | Fail::Other(s) => f.write_str(s),
            Fail::Verify => f.write_str("verification failed"),
        }
    }
}

impl From<scytale::Error> for Fail {
    fn from(e: scytale::Error) -> Self {
        use scytale::Error::*;
        match e {
            // The message was not made under this key, or was
            // altered since: what a script checking it wants to know,
            // and nothing more, since the library says nothing more.
            AuthenticationFailed | InvalidSignature | DecryptionFailed
            | InvalidPadding => Fail::Verify,
            // A value the caller supplied was not one the call takes.
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
        Fail::Other(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Fail>;

/// A [`Fail::Usage`] from a format string.
macro_rules! usage {
    ($($arg:tt)*) => {
        $crate::fail::Fail::Usage(format!($($arg)*))
    };
}

pub(crate) use usage;
