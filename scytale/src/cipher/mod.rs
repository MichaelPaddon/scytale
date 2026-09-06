//! Symmetric (shared key) primitives.
//!
//! A block cipher, [`aes`], and the modes of operation that turn it
//! into something a message can be encrypted with, under [`mode`];
//! and a stream cipher, [`chacha20`], with the authenticated mode
//! built on it there too. The block cipher modes are written against
//! the [`BlockCipher`] trait, so each works with any cipher and any
//! of its implementations. The block and the key are types, so a
//! cipher of unknown make can still be an object:
//! `&dyn BlockCipher<Block = [u8; 16], Key = [u8; 16]>`.
//!
//! # Example
//!
//! ```
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::mode::Ctr;
//! use scytale::cipher::BlockCipher;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let aes = Aes128::try_new(&[0u8; 16])?;
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

use crate::{BlockType, Error, KeyType};

/// A block cipher: a keyed permutation of fixed-size blocks.
///
/// Modes of operation are written against this trait so they work
/// with any block cipher. The block and the key are types, from
/// [`BlockType`] and [`KeyType`], so a wrong length is a compile
/// error and the trait is usable as an object once they are named:
/// `&dyn BlockCipher<Block = [u8; 16], Key = [u8; 32]>`.
///
/// Only construction can fail. A block is a type rather than a slice
/// of hopeful length, so there is no misalignment left to report, and
/// the bulk methods take as many blocks as there are.
pub trait BlockCipher: BlockType + KeyType {
    /// Expands `key`.
    fn try_new(key: &Self::Key) -> Result<Self, Error>
    where
        Self: Sized;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::{portable, Aes256};

    /// Two implementations behind one object type agree.
    #[test]
    fn as_an_object() {
        fn once(
            cipher: &dyn BlockCipher<Block = [u8; 16], Key = [u8; 32]>,
        ) -> [u8; 16] {
            let mut block = [7u8; 16];
            cipher.encrypt_block(&mut block);
            block
        }
        let key = [0x5au8; 32];
        let best = Aes256::try_new(&key).unwrap();
        let named = portable::ttable::Aes::<32>::try_new(&key).unwrap();
        assert_eq!(once(&best), once(&named));
        assert_ne!(once(&best), [7u8; 16]);
    }

    /// Generic code can make a key and a block without knowing the
    /// cipher.
    #[test]
    fn zero_key_and_block() {
        fn round_trip<C: BlockCipher>() {
            let cipher = C::try_new(&C::zero_key()).unwrap();
            let mut block = C::zero_block();
            cipher.encrypt_block(&mut block);
            assert_ne!(block.as_ref(), C::zero_block().as_ref());
            cipher.decrypt_block(&mut block);
            assert_eq!(block.as_ref(), C::zero_block().as_ref());
        }
        round_trip::<aes::Aes128>();
        round_trip::<aes::Aes192>();
        round_trip::<Aes256>();
        assert_eq!(Aes256::zero_key(), [0u8; 32]);
    }
}
