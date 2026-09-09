//! Symmetric (shared key) primitives.
//!
//! A block cipher, [`aes`], and the modes of operation that turn it
//! into something a message can be encrypted with, under [`mode`];
//! and a stream cipher, [`chacha20`], with the authenticated mode
//! built on it there too. The block cipher modes are written against
//! the [`BlockCipher`] trait, so each works with any cipher. The
//! block and the key are types, so a cipher of unknown make can
//! still be an object:
//! `&dyn BlockCipher<Block = [u8; 16], Key = [u8; 16]>`.
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
//! for a mode, and unless there is a reason not to, an authenticated
//! one: see [`mode`] for which.

pub mod aes;
pub mod chacha20;
pub mod mode;

use core::any::TypeId;
use core::slice::from_mut;

use crate::{BlockType, KeyType};

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

/// Counter mode's inner loop: encrypts the run of blocks made from
/// `counter` by adding 0, 1, 2 and so on to the field `order` names,
/// and XORs each result into `data`, leaving `counter` on the block
/// after the last.
///
/// `data` must be a whole number of blocks, and the four-byte field
/// must not carry out of itself over the run; a caller counting in
/// the whole block splits its run at that boundary.
///
/// The loop is a type of its own rather than a method on
/// [`BlockCipher`] because the fast forms of it are written per
/// cipher and per processor, in assembly, and a mode picks one when
/// it is built. See [`counter_fn`].
pub(crate) type CounterFn<C> =
    fn(&C, &mut <C as BlockType>::Block, ByteOrder, &mut [u8]);

/// A cipher that carries a counter loop of its own, written for it
/// and for the processor rather than assembled from `encrypt`.
///
/// Every implementation of AES in this crate does. Nothing outside
/// the crate can, which is why [`counter_fn`] finds them by asking
/// what type it was given rather than through a bound.
pub(crate) trait CounterBlocks: BlockCipher<Block = [u8; 16]> {
    fn counter_blocks(
        &self,
        counter: &mut [u8; 16],
        order: ByteOrder,
        data: &mut [u8],
    );
}

/// The counter loop for `C`, chosen once, when a mode is built.
///
/// Our own AES carries a loop that keeps the counters in registers
/// and encrypts them where they lie; anything else is served by
/// [`counter_blocks_via_ecb`], which is the same thing assembled
/// from `encrypt`. `C` is a type parameter, so each instantiation
/// settles this at compile time and keeps one arm.
pub(crate) fn counter_fn<C: BlockCipher>() -> CounterFn<C> {
    aes::counter_fn::<C>().unwrap_or(counter_blocks_via_ecb::<C>)
}

/// [`CounterFn`] for the cipher `T`, once `C` is known to be it.
///
/// The downcast asks again what the caller has already established,
/// because the compiler does not carry that knowledge across the
/// function pointer. Both questions answer the same way in the
/// instantiation this was chosen for.
pub(crate) fn counter_blocks_of<T: CounterBlocks, C: BlockCipher>(
    cipher: &C,
    counter: &mut C::Block,
    order: ByteOrder,
    data: &mut [u8],
) {
    let any = cipher as &dyn core::any::Any;
    match (
        any.downcast_ref::<T>(),
        <&mut [u8; 16]>::try_from(counter.as_mut()),
    ) {
        (Some(cipher), Ok(counter)) => {
            cipher.counter_blocks(counter, order, data)
        }
        _ => counter_blocks_via_ecb(cipher, counter, order, data),
    }
}

/// [`CounterFn`] assembled from [`BlockCipher::encrypt`].
///
/// The fallback for a cipher with no loop of its own, and for one
/// whose own loop wants an instruction the processor turns out to
/// lack.
pub(crate) fn counter_blocks_via_ecb<C: BlockCipher>(
    cipher: &C,
    counter: &mut C::Block,
    order: ByteOrder,
    data: &mut [u8],
) {
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
        cipher.encrypt(keystream);
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

    /// Our own ciphers get their own counter loop, and anything
    /// else the generic one. The public widths, the type behind
    /// them and the implementations beneath that are all ours.
    #[test]
    fn our_ciphers_get_their_own_loop() {
        fn own<C: BlockCipher>() -> bool {
            counter_fn::<C>() as *const ()
                != counter_blocks_via_ecb::<C> as fn(_, _, _, _) as *const ()
        }
        assert!(own::<Aes128>());
        assert!(own::<Aes192>());
        assert!(own::<Aes256>());
        assert!(own::<crate::cipher::aes::Aes<16>>());
        assert!(own::<portable::ttable::Aes<32>>());
        assert!(own::<portable::bitsliced::Aes<24>>());
    }

    /// The counter loop chosen for our own AES and the generic one
    /// produce the same keystream.
    #[test]
    fn counter_loops_agree() {
        let cipher = Aes128::new(&Key::from([0x2bu8; 16]));
        let mut data = [0u8; 16 * 9];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut expected = data;

        let mut counter = [0x11u8; 16];
        let mut generic = counter;
        counter_fn::<Aes128>()(
            &cipher,
            &mut counter,
            ByteOrder::Big,
            &mut data,
        );
        counter_blocks_via_ecb(
            &cipher,
            &mut generic,
            ByteOrder::Big,
            &mut expected,
        );
        assert_eq!(data, expected);
        assert_eq!(counter, generic);
    }
}
