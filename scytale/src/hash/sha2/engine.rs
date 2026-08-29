//! The part of SHA-2 that every implementation shares: buffering a
//! message into blocks, padding it, and turning the final state into
//! a digest.
//!
//! An implementation supplies only the compression function, and a
//! variant only its initial value and digest length. Everything here
//! is generic over both, so there is one copy of the bookkeeping
//! rather than one per implementation per variant.
//!
//! # Bit strings
//!
//! SHA-2 is defined over messages of any number of bits, and the
//! length field in the padding counts bits. Only the padding knows
//! that: the compression function sees whole blocks, and a message
//! that is not a whole number of bytes can only end that way, so the
//! last few bits are taken by [`BitHash::finalize_bits`] and the
//! byte-oriented path pays nothing for them.

#![allow(unsafe_code)]

use core::fmt;
use core::marker::PhantomData;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash::{BitHash, Hash};
use crate::symmetric::Block;
use crate::Error;

/// A SHA-256 family compression function.
pub trait Compress32 {
    /// Whether this processor can run it.
    fn supported() -> bool;

    /// Folds every block into `state`.
    ///
    /// # Safety
    /// [`supported`](Compress32::supported) must have returned true
    /// on this processor.
    unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]);
}

/// A SHA-512 family compression function.
pub trait Compress64 {
    /// Whether this processor can run it.
    fn supported() -> bool;

    /// Folds every block into `state`.
    ///
    /// # Safety
    /// [`supported`](Compress64::supported) must have returned true
    /// on this processor.
    unsafe fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]);
}

/// A member of the SHA-256 family: SHA-224 or SHA-256.
pub trait Variant32: Clone {
    /// The initial hash value.
    const IV: [u32; 8];
    /// The digest, a prefix of the final state.
    type Output: Block;
}

/// A member of the SHA-512 family: SHA-384 or SHA-512.
pub trait Variant64: Clone {
    /// The initial hash value.
    const IV: [u64; 8];
    /// The digest, a prefix of the final state.
    type Output: Block;
}

/// Checks the bit count `finalize_bits` is given, and builds the
/// byte that carries those bits and the padding's leading one.
fn trailer(last: u8, bits: u32) -> Result<u8, Error> {
    if !(1..=7).contains(&bits) {
        return Err(Error::InvalidLength(bits as usize));
    }
    let keep = 0xffu8 << (8 - bits);
    Ok((last & keep) | (0x80 >> bits))
}

/// Defines one family's engine. The two differ only in word size,
/// block size and the width of the length field, which is not enough
/// difference to be worth a trait over the word.
macro_rules! engine {
    (
        $(#[$doc:meta])*
        $name:ident, $compress:ident, $variant:ident,
        $word:ty, $block:literal, $length:ty
    ) => {
        $(#[$doc])*
        pub struct $name<C: $compress, V: $variant> {
            state: [$word; 8],
            /// Bytes of a block not yet complete.
            block: [u8; $block],
            used: usize,
            /// Whole bytes taken so far. Wraps rather than fails at
            /// the length the padding cannot express, which no real
            /// message reaches.
            bytes: $length,
            _marker: PhantomData<(C, V)>,
        }

        impl<C: $compress, V: $variant> $name<C, V> {
            /// Starts a hash without asking the processor.
            ///
            /// # Safety
            /// The caller must have confirmed `C::supported()`.
            pub(crate) unsafe fn new_unchecked() -> Self {
                Self::from_state(V::IV)
            }

            /// Starts from `iv` instead of the variant's own value,
            /// which is how the SHA-512/t values are derived.
            // Only the 64-bit engine has a use for it.
            #[cfg(test)]
            #[allow(dead_code)]
            pub(crate) fn with_iv(iv: [$word; 8]) -> Self {
                assert!(C::supported());
                Self::from_state(iv)
            }

            fn from_state(state: [$word; 8]) -> Self {
                $name {
                    state,
                    block: [0; $block],
                    used: 0,
                    bytes: 0,
                    _marker: PhantomData,
                }
            }

            /// Folds whole blocks in.
            fn compress(&mut self, blocks: &[[u8; $block]]) {
                // SAFETY: the engine only exists once `new_unchecked`'s
                // caller confirmed support.
                unsafe { C::compress(&mut self.state, blocks) }
            }

            /// Pads with `trailer` (the leading one bit and any last
            /// bits of message) and `extra` bits beyond whole bytes,
            /// then folds the last block or two in.
            fn pad(&mut self, trailer: u8, extra: $length) {
                let length_field = 2 * core::mem::size_of::<$word>();
                self.block[self.used] = trailer;
                self.used += 1;
                if self.used > $block - length_field {
                    self.block[self.used..].fill(0);
                    let block = self.block;
                    self.compress(&[block]);
                    self.used = 0;
                }
                self.block[self.used..$block - length_field].fill(0);
                let bits = (self.bytes << 3) | extra;
                self.block[$block - length_field..]
                    .copy_from_slice(&bits.to_be_bytes());
                let block = self.block;
                self.compress(&[block]);
            }

            /// The digest: the state as big-endian bytes, cut to the
            /// variant's length.
            fn output(&self) -> V::Output {
                let mut full = [0u8; 8 * core::mem::size_of::<$word>()];
                let width = core::mem::size_of::<$word>();
                for (chunk, word) in
                    full.chunks_exact_mut(width).zip(&self.state)
                {
                    chunk.copy_from_slice(&word.to_be_bytes());
                }
                let mut out = V::Output::ZERO;
                let n = V::Output::SIZE;
                out.as_mut().copy_from_slice(&full[..n]);
                out
            }
        }

        // By hand so that `C` need not be `Clone`: it is a marker.
        impl<C: $compress, V: $variant> Clone for $name<C, V> {
            fn clone(&self) -> Self {
                $name {
                    state: self.state,
                    block: self.block,
                    used: self.used,
                    bytes: self.bytes,
                    _marker: PhantomData,
                }
            }
        }

        impl<C: $compress, V: $variant> Hash for $name<C, V> {
            const BLOCK_SIZE: usize = $block;
            type Output = V::Output;

            fn try_new() -> Result<Self, Error> {
                if !C::supported() {
                    return Err(Error::NotSupported);
                }
                // SAFETY: just confirmed.
                Ok(unsafe { Self::new_unchecked() })
            }

            fn reset(&mut self) {
                self.state = V::IV;
                self.block.zeroize();
                self.used = 0;
                self.bytes = 0;
            }

            fn update(&mut self, mut data: &[u8]) {
                self.bytes = self.bytes.wrapping_add(data.len() as $length);
                if self.used > 0 {
                    let room = $block - self.used;
                    let take = room.min(data.len());
                    self.block[self.used..self.used + take]
                        .copy_from_slice(&data[..take]);
                    self.used += take;
                    data = &data[take..];
                    if self.used < $block {
                        return;
                    }
                    let block = self.block;
                    self.compress(&[block]);
                    self.used = 0;
                }
                let (blocks, rest) = <[u8; $block]>::split(data);
                self.compress(blocks);
                self.block[..rest.len()].copy_from_slice(rest);
                self.used = rest.len();
            }

            fn finalize(mut self) -> Self::Output {
                self.pad(0x80, 0);
                self.output()
            }
        }

        impl<C: $compress, V: $variant> BitHash for $name<C, V> {
            fn finalize_bits(
                mut self,
                last: u8,
                bits: u32,
            ) -> Result<Self::Output, Error> {
                let trailer = trailer(last, bits)?;
                self.pad(trailer, bits as $length);
                Ok(self.output())
            }
        }

        impl<C: $compress, V: $variant> Drop for $name<C, V> {
            /// The buffer holds message, and the state is a function
            /// of it.
            fn drop(&mut self) {
                self.state.zeroize();
                self.block.zeroize();
                self.used.zeroize();
                self.bytes.zeroize();
            }
        }

        impl<C: $compress, V: $variant> ZeroizeOnDrop for $name<C, V> {}

        impl<C: $compress, V: $variant> fmt::Debug for $name<C, V> {
            /// Deliberately omits the state and buffer.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("bytes", &self.bytes)
                    .finish()
            }
        }
    };
}

engine!(
    /// A SHA-224 or SHA-256 computation in progress, over the
    /// compression function `C`.
    Engine32, Compress32, Variant32, u32, 64, u64
);

engine!(
    /// A SHA-384 or SHA-512 computation in progress, over the
    /// compression function `C`.
    Engine64, Compress64, Variant64, u64, 128, u128
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailer_keeps_the_top_bits_and_sets_the_next() {
        assert_eq!(trailer(0xff, 1), Ok(0xc0));
        assert_eq!(trailer(0xff, 7), Ok(0xff));
        assert_eq!(trailer(0x00, 3), Ok(0x10));
        assert_eq!(trailer(0xa5, 4), Ok(0xa8));
    }

    #[test]
    fn trailer_rejects_whole_bytes() {
        assert_eq!(trailer(0, 0), Err(Error::InvalidLength(0)));
        assert_eq!(trailer(0, 8), Err(Error::InvalidLength(8)));
    }
}
