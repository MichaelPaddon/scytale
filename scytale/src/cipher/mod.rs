//! Symmetric (shared key) primitives.
//!
//! A block cipher, [`aes`], and the modes of operation that turn it
//! into something a message can be encrypted with, under [`mode`];
//! and a stream cipher, [`chacha20`], with the authenticated mode
//! built on it there too. The block cipher modes are written against
//! the [`BlockCipher`] trait, so each works with any cipher and any
//! of its implementations.
//!
//! # Example
//!
//! ```
//! use scytale::cipher::aes::Aes;
//! use scytale::cipher::mode::Ctr;
//! use scytale::cipher::BlockCipher;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let aes = Aes::try_new(&[0u8; 16])?;
//!
//! // The cipher itself transforms one block at a time.
//! let mut block = [0u8; 16];
//! aes.encrypt_block(&mut block);
//! aes.decrypt_block(&mut block);
//! assert_eq!(block, [0u8; 16]);
//!
//! // A mode carries that over a message of any length.
//! let ctr = Ctr::new(aes);
//! let mut message = *b"a message of any length";
//! ctr.encrypt(&[1u8; 16], &mut message)?;
//! # Ok(())
//! # }
//! ```
//!
//! A raw block cipher is the wrong tool for a message: it encrypts
//! equal blocks to equal blocks, and it authenticates nothing. Reach
//! for a mode, and unless there is a reason not to, an authenticated
//! one: see [`mode`] for which.

pub mod aes;
pub mod chacha20;
pub mod mode;

use crate::Error;

/// One block of a block cipher: a fixed-size array of bytes.
///
/// Implemented here for every `[u8; N]`, which is what a cipher
/// should name its block as. Implementing it for anything else is
/// allowed; getting it wrong spoils that cipher's own output and
/// nothing else, because everything here that touches a foreign
/// block is safe code.
pub trait Block: Copy + AsRef<[u8]> + AsMut<[u8]> {
    /// Size in bytes. Never zero.
    ///
    /// Defaulted, and there is no reason to override it: a block is
    /// its bytes, so its size is the size of the type.
    const SIZE: usize = core::mem::size_of::<Self>();

    /// A block of zeros.
    const ZERO: Self;

    /// Splits `data` into whole blocks and the bytes left over.
    fn split(data: &[u8]) -> (&[Self], &[u8]);

    /// Splits `data` into whole blocks and the bytes left over.
    fn split_mut(data: &mut [u8]) -> (&mut [Self], &mut [u8]);

    /// The blocks as the bytes they are.
    fn flatten(blocks: &[Self]) -> &[u8];

    /// The blocks as the bytes they are.
    fn flatten_mut(blocks: &mut [Self]) -> &mut [u8];
}

impl<const N: usize> Block for [u8; N] {
    const ZERO: Self = [0; N];

    fn split(data: &[u8]) -> (&[Self], &[u8]) {
        data.as_chunks::<N>()
    }

    fn split_mut(data: &mut [u8]) -> (&mut [Self], &mut [u8]) {
        data.as_chunks_mut::<N>()
    }

    fn flatten(blocks: &[Self]) -> &[u8] {
        blocks.as_flattened()
    }

    fn flatten_mut(blocks: &mut [Self]) -> &mut [u8] {
        blocks.as_flattened_mut()
    }
}

/// A block cipher: a keyed permutation of fixed-size blocks.
///
/// Modes of operation are written against this trait so they work
/// with any block cipher.
///
/// Only construction can fail. A block is a type rather than a slice
/// of hopeful length, so there is no misalignment left to report, and
/// the bulk methods take as many blocks as there are.
pub trait BlockCipher: Sized {
    /// The block this cipher transforms; `[u8; 16]` for AES.
    type Block: Block;

    /// Expands `key`; each cipher decides which lengths it accepts.
    fn try_new(key: &[u8]) -> Result<Self, Error>;

    /// Encrypts one block in place.
    fn encrypt_block(&self, block: &mut Self::Block);

    /// Decrypts one block in place.
    fn decrypt_block(&self, block: &mut Self::Block);

    /// Encrypts every block in place, independently (ECB).
    ///
    /// Passing them together rather than one at a time lets an
    /// implementation do its per-call setup once and interleave as
    /// many as its hardware has room for.
    fn encrypt_blocks(&self, blocks: &mut [Self::Block]);

    /// Decrypts every block in place, independently (ECB).
    fn decrypt_blocks(&self, blocks: &mut [Self::Block]);
}
