//! Symmetric (shared key) primitives.
//!
//! A block cipher, [`aes`], and the modes of operation that turn it
//! into something a message can be encrypted with, under [`mode`];
//! and a stream cipher, [`chacha20`]. The block cipher modes are
//! written against the [`BlockCipher`] trait, so each works with any
//! cipher. The block and the key are types, so a cipher of unknown
//! make can still be an object:
//! `&dyn BlockCipher<Block = [u8; 16], Key = [u8; 16]>`.
//!
//! Nothing here authenticates a message. The constructions that do
//! are in [`aead`](crate::aead), and they are what most callers
//! want.
//!
//! # Example
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::mode::Ctr;
//! use scytale::cipher::BlockCipher;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let aes = Aes128::new(&Key::from([0u8; 16]));
//!
//! // The cipher itself transforms blocks, as many as there are.
//! let mut blocks = [[0u8; 16]; 2];
//! aes.encrypt(&mut blocks);
//! aes.decrypt(&mut blocks);
//! assert_eq!(blocks, [[0u8; 16]; 2]);
//!
//! // A mode carries that over a message of any length.
//! let ctr = Ctr::<Aes128>::new(&Key::from([0u8; 16]));
//! let mut message = *b"a message of any length";
//! ctr.encrypt(&[1u8; 16], &mut message)?;
//! # Ok(())
//! # }
//! ```
//!
//! A raw block cipher is the wrong tool for a message: it encrypts
//! equal blocks to equal blocks, and it authenticates nothing. Reach
//! for [`aead`](crate::aead), and come to [`mode`] for the cases it
//! does not cover.
//!
//! Whatever encrypts the message, most of these want an
//! initialisation vector that is *unique* rather than random, which
//! is a stronger requirement than it sounds. [`Nonces`] counts them,
//! so a repeat is impossible rather than merely unlikely. It sits
//! here rather than under [`mode`] because both a mode and a bare
//! stream cipher take one.

pub mod aes;
pub mod chacha20;
pub mod mode;
pub mod nonce;

pub use nonce::Nonces;

use core::any::TypeId;
use core::slice::from_mut;

use crate::{BlockType, KeyType};

/// The 128-bit block AES works in, and with it every construction
/// defined over a 128-bit cipher: XTS, key wrapping, and the
/// format-preserving modes.
///
/// Most code here takes the block from the cipher's own `Block` type
/// and needs no constant. This is for the constructions whose
/// standards fix the width instead, so that a cipher of another block
/// size is a compile error rather than a silent miscalculation.
pub(crate) const BLOCK: usize = 16;

/// A block cipher: a keyed permutation of fixed-size blocks.
///
/// Modes of operation are written against this trait so they work
/// with any block cipher. The block and the key are types, from
/// [`BlockType`] and [`KeyType`], so a wrong length is a compile
/// error and the trait is usable as an object once they are named:
/// `&dyn BlockCipher<Block = [u8; 16], Key = Key<[u8; 32]>>`,
/// where the key type is [`Key`](crate::Key).
///
/// Nothing here can fail. The key is a type of fixed width, so there
/// is no length to reject, and a block is a type rather than a slice
/// of hopeful length, so there is no misalignment left to report.
/// The key also wipes itself when it is dropped; see
/// [`Key`](crate::Key).
///
/// Both operations take as many blocks as there are, which is what
/// lets an implementation interleave them: AES-NI is eight times
/// faster over a run of blocks than over one at a time. A caller
/// with a single block passes `from_mut(&mut block)`.
pub trait BlockCipher: BlockType + KeyType + 'static {
    /// Expands `key`.
    fn new(key: &Self::Key) -> Self
    where
        Self: Sized;

    /// Encrypts every block in place, independently (ECB).
    fn encrypt(&self, blocks: &mut [Self::Block]);

    /// Decrypts every block in place, independently (ECB).
    fn decrypt(&self, blocks: &mut [Self::Block]);
}

/// One block at a time, for the code inside this crate that works
/// that way: a chaining mode has nothing to interleave.
pub(crate) trait OneBlock: BlockCipher {
    fn encrypt_one(&self, block: &mut Self::Block) {
        self.encrypt(from_mut(block));
    }

    fn decrypt_one(&self, block: &mut Self::Block) {
        self.decrypt(from_mut(block));
    }
}

impl<C: BlockCipher + ?Sized> OneBlock for C {}

/// Whether the cipher `C` is `T`.
///
/// A mode uses this when it is built to find out whether the cipher
/// it was asked for is one it has a hand-written implementation of
/// the pair for. `C` is a type parameter, so the answer is a
/// constant in each instantiation.
pub(crate) fn is<T: BlockCipher, C: BlockCipher>() -> bool {
    TypeId::of::<T>() == TypeId::of::<C>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key;
    use crate::cipher::aes::{Aes128, Aes192, Aes256, portable};

    /// Two implementations behind one object type agree.
    #[test]
    fn as_an_object() {
        fn once(
            cipher: &dyn BlockCipher<Block = [u8; 16], Key = Key<[u8; 32]>>,
        ) -> [u8; 16] {
            let mut block = [[7u8; 16]];
            cipher.encrypt(&mut block);
            block[0]
        }
        let key = [0x5au8; 32];
        let best = Aes256::new(&Key::from(key));
        let named = portable::ttable::Aes::<32>::new(&key);
        assert_eq!(once(&best), once(&named));
        assert_ne!(once(&best), [7u8; 16]);
    }

    /// Generic code can make a key and a block without knowing the
    /// cipher.
    #[test]
    fn zero_key_and_block() {
        fn round_trip<C: BlockCipher>() {
            let cipher = C::new(&C::zero_key());
            let mut block = C::zero_block();
            cipher.encrypt_one(&mut block);
            assert_ne!(block.as_ref(), C::zero_block().as_ref());
            cipher.decrypt_one(&mut block);
            assert_eq!(block.as_ref(), C::zero_block().as_ref());
        }
        round_trip::<Aes128>();
        round_trip::<Aes192>();
        round_trip::<Aes256>();
        assert_eq!(Aes256::zero_key(), Key::from([0u8; 32]));
    }
}
