//! Symmetric (shared key) primitives.

pub mod aes;
pub mod mode;

use core::fmt;

/// Errors produced by symmetric primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The key length is not one the cipher accepts.
    InvalidKeyLength(usize),
    /// The data length is not a whole number of blocks.
    NotBlockAligned(usize),
    /// The nonce or initialisation vector is not the length the mode
    /// requires.
    InvalidNonceLength(usize),
    /// The processor lacks the instructions this implementation needs.
    NotSupported,
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
            Error::NotSupported => {
                write!(f, "not supported by this processor")
            }
        }
    }
}

impl core::error::Error for Error {}

/// Views a slice as a fixed-size block, for forwarding the trait's
/// single-block methods to a cipher's inherent ones.
pub(crate) fn as_block<const N: usize>(
    block: &mut [u8],
) -> Result<&mut [u8; N], Error> {
    let len = block.len();
    block.try_into().map_err(|_| Error::NotBlockAligned(len))
}

/// A block cipher: a keyed permutation of fixed-size blocks.
///
/// Modes of operation are written against this trait so they work
/// with any block cipher.
///
/// Data is passed as a byte slice holding any whole number of blocks,
/// rather than one block at a time, so an implementation can do its
/// per-call setup once rather than once per block.
pub trait BlockCipher {
    /// Block size in bytes.
    const BLOCK_SIZE: usize;

    /// Expands `key`; each cipher decides which lengths it accepts.
    fn try_new(key: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    /// Encrypts one block in place.
    ///
    /// `block.len()` must be `BLOCK_SIZE`. Modes that chain, such as
    /// CBC encryption, need a block at a time and cannot use the bulk
    /// methods below.
    fn encrypt_block(&self, block: &mut [u8]) -> Result<(), Error>;

    /// Decrypts one block in place.
    ///
    /// `block.len()` must be `BLOCK_SIZE`.
    fn decrypt_block(&self, block: &mut [u8]) -> Result<(), Error>;

    /// Encrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of `BLOCK_SIZE`; nothing is
    /// changed otherwise.
    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error>;

    /// Decrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of `BLOCK_SIZE`; nothing is
    /// changed otherwise.
    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error>;
}

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
            render(Error::NotSupported, &mut buf),
            "not supported by this processor"
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
