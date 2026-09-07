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

    /// Encrypts the run of blocks made from `counter` by adding
    /// 0, 1, 2 and so on to the field `order` names, and XORs each
    /// result into `data`. Leaves `counter` on the block after the
    /// last.
    ///
    /// This is counter mode's inner loop, and it is here rather than
    /// assembled from [`encrypt_blocks`](Self::encrypt_blocks) by the
    /// caller so that an implementation can keep the counters in
    /// registers. Built from the outside, every block is written to a
    /// scratch buffer, read back to be encrypted, and read again to
    /// be XORed: three trips through memory where one would do.
    ///
    /// `data` must be a whole number of blocks. The four-byte field
    /// must not carry out of itself over the run; a caller counting
    /// in the whole block splits its run at that boundary.
    ///
    /// The default does assemble it from `encrypt_blocks`.
    fn xor_counter_blocks(
        &self,
        counter: &mut Self::Block,
        order: ByteOrder,
        data: &mut [u8],
    ) {
        counter_blocks_via_ecb(self, counter, order, data)
    }
}

/// Which four bytes of a block hold a counter, and which way round.
///
/// GCM counts in the last four, most significant first; GCM-SIV, as
/// RFC 8452 defines it, counts in the first four, least significant
/// first. Read the matching way, both are the low thirty-two bits of
/// the block, which is why one loop serves them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    /// The last four bytes, most significant first.
    Big,
    /// The first four bytes, least significant first.
    Little,
}

/// [`BlockCipher::xor_counter_blocks`] assembled from
/// [`encrypt_blocks`](BlockCipher::encrypt_blocks).
///
/// The default, and the fallback for an implementation whose own loop
/// wants an instruction the processor turns out to lack.
pub(crate) fn counter_blocks_via_ecb<C>(
    cipher: &C,
    counter: &mut C::Block,
    order: ByteOrder,
    data: &mut [u8],
) where
    C: BlockCipher + ?Sized,
{
    let size = counter.as_ref().len();
    debug_assert_eq!(data.len() % size, 0);
    // `*counter` rather than `zero_block`, which an object has no way
    // to call; the values are overwritten below.
    let mut keystream = [*counter; mode::LANES];
    for group in data.chunks_mut(size * mode::LANES) {
        let keystream = &mut keystream[..group.len() / size];
        for block in keystream.iter_mut() {
            *block = *counter;
            add_counter(counter.as_mut(), order, 1);
        }
        cipher.encrypt_blocks(keystream);
        for (chunk, key) in group.chunks_mut(size).zip(&*keystream) {
            mode::xor(chunk, key.as_ref());
        }
    }
}

/// Adds `count` to the counter field `order` names, wrapping inside
/// those four bytes rather than carrying out.
#[inline]
pub(crate) fn add_counter(block: &mut [u8], order: ByteOrder, count: u32) {
    debug_assert!(block.len() >= 4);
    match order {
        ByteOrder::Big => {
            let start = block.len() - 4;
            let f = &mut block[start..];
            let n = u32::from_be_bytes([f[0], f[1], f[2], f[3]]);
            f.copy_from_slice(&n.wrapping_add(count).to_be_bytes());
        }
        ByteOrder::Little => {
            let f = &mut block[..4];
            let n = u32::from_le_bytes([f[0], f[1], f[2], f[3]]);
            f.copy_from_slice(&n.wrapping_add(count).to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::{Aes256, portable};

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
