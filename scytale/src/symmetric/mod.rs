//! Symmetric (shared key) primitives.

pub mod aes;
pub mod mode;

use crate::Error;

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
