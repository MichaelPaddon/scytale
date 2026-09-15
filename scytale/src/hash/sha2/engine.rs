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
//!
//! This module is public only so that the backend type aliases,
//! `portable::Sha256` and the like, can be named; its traits are
//! sealed and implemented by nothing outside the crate.

use core::fmt;
use core::marker::PhantomData;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash::{BitHash, Hash};
use crate::{BlockType, Error};

/// Keeps the traits here to this crate's own implementations.
mod sealed {
    pub trait Sealed {}
}
pub(crate) use sealed::Sealed;

/// A SHA-256 family compression function. Sealed.
///
/// A value of the type is the proof that this processor can run it:
/// [`probe`](Compress32::probe) is the only way to make one, the
/// hardware ones have no public constructor, and the engine holds
/// the value it was given. So the compression function is a safe
/// call, and the one `unsafe` block in a hardware module is where
/// the value is minted.
pub trait Compress32: Sealed + Copy {
    /// The function, where this processor can run it. Asked once.
    fn probe() -> Option<Self>;

    /// Whether this processor can run it.
    fn supported() -> bool {
        Self::probe().is_some()
    }

    /// Folds every block into `state`.
    fn compress(self, state: &mut [u32; 8], blocks: &[[u8; 64]]);
}

/// A SHA-512 family compression function. Sealed; see
/// [`Compress32`] for what a value of the type means.
pub trait Compress64: Sealed + Copy {
    /// The function, where this processor can run it. Asked once.
    fn probe() -> Option<Self>;

    /// Whether this processor can run it.
    fn supported() -> bool {
        Self::probe().is_some()
    }

    /// Folds every block into `state`.
    fn compress(self, state: &mut [u64; 8], blocks: &[[u8; 128]]);
}

/// A member of the SHA-256 family: SHA-224 or SHA-256. Sealed.
pub trait Variant32: Clone + Sealed {
    /// The initial hash value.
    const IV: [u32; 8];
    /// The digest, a prefix of the final state.
    type Output: Copy + AsRef<[u8]> + AsMut<[u8]>;
    /// A digest of zeros, for the engine to fill.
    fn zero_output() -> Self::Output;
}

/// A member of the SHA-512 family: SHA-384 or SHA-512. Sealed.
pub trait Variant64: Clone + Sealed {
    /// The initial hash value.
    const IV: [u64; 8];
    /// The digest, a prefix of the final state.
    type Output: Copy + AsRef<[u8]> + AsMut<[u8]>;
    /// A digest of zeros, for the engine to fill.
    fn zero_output() -> Self::Output;
}

/// Checks the bit count `finalize_bits` is given, and builds the
/// byte that carries those bits and the padding's leading one.
fn trailer(last: u8, bits: u32) -> Result<u8, Error> {
    if !(1..=7).contains(&bits) {
        return Err(Error::InvalidBitCount(bits));
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
            /// How far into `block` anything of a message may have
            /// been written since it was last wiped, so that a reset
            /// wipes that much and no more: wiping is a store per
            /// byte, and whole blocks never touch the buffer.
            dirty: usize,
            /// Whole bytes taken so far. Wraps rather than fails at
            /// the length the padding cannot express, which no real
            /// message reaches.
            bytes: $length,
            /// The compression function, which is the proof the
            /// processor can run it.
            compress: C,
            _marker: PhantomData<V>,
        }

        impl<C: $compress, V: $variant> $name<C, V> {
            /// Starts a hash over `compress`, which the caller got
            /// from the probe.
            pub(crate) fn with(compress: C) -> Self {
                Self::from_state(compress, V::IV)
            }

            /// Starts from `iv` instead of the variant's own value,
            /// which is how the SHA-512/t values are derived.
            // Only the 64-bit engine has a use for it.
            #[cfg(test)]
            #[allow(dead_code)]
            pub(crate) fn with_iv(compress: C, iv: [$word; 8]) -> Self {
                Self::from_state(compress, iv)
            }

            fn from_state(compress: C, state: [$word; 8]) -> Self {
                $name {
                    state,
                    block: [0; $block],
                    used: 0,
                    dirty: 0,
                    bytes: 0,
                    compress,
                    _marker: PhantomData,
                }
            }

            /// Folds whole blocks in.
            fn compress(&mut self, blocks: &[[u8; $block]]) {
                self.compress.compress(&mut self.state, blocks)
            }

            /// Pads with `trailer` (the leading one bit and any last
            /// bits of message) and `extra` bits beyond whole bytes,
            /// then folds the last block or two in.
            fn pad(&mut self, trailer: u8, extra: $length) {
                let length_field = 2 * core::mem::size_of::<$word>();
                // The trailer can carry the last bits of the message.
                self.block[self.used] = trailer;
                self.used += 1;
                self.dirty = self.dirty.max(self.used);
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
                // The length is not message, but it says something
                // about one, and these few stores are cheap.
                self.block[$block - length_field..].zeroize();
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
                let mut out = V::zero_output();
                let n = core::mem::size_of::<V::Output>();
                out.as_mut().copy_from_slice(&full[..n]);
                out
            }
        }

        // By hand so that `V` need not be `Clone`: it is a marker.
        impl<C: $compress, V: $variant> Clone for $name<C, V> {
            fn clone(&self) -> Self {
                $name {
                    state: self.state,
                    block: self.block,
                    used: self.used,
                    dirty: self.dirty,
                    bytes: self.bytes,
                    compress: self.compress,
                    _marker: PhantomData,
                }
            }
        }

        impl<C: $compress, V: $variant> BlockType for $name<C, V> {
            type Block = [u8; $block];

            fn zero_block() -> Self::Block {
                [0; $block]
            }
        }

        impl<C: $compress, V: $variant> Hash for $name<C, V> {
            type Output = V::Output;

            fn try_new() -> Result<Self, Error> {
                C::probe().map(Self::with).ok_or(Error::NotSupported)
            }

            fn reset(&mut self) {
                self.state = V::IV;
                self.block[..self.dirty].zeroize();
                self.used = 0;
                self.dirty = 0;
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
                    self.dirty = self.dirty.max(self.used);
                    data = &data[take..];
                    if self.used < $block {
                        return;
                    }
                    let block = self.block;
                    self.compress(&[block]);
                    self.used = 0;
                }
                let (blocks, rest) = data.as_chunks::<$block>();
                self.compress(blocks);
                self.block[..rest.len()].copy_from_slice(rest);
                self.used = rest.len();
                self.dirty = self.dirty.max(self.used);
            }

            fn finalize(&mut self) -> Self::Output {
                self.pad(0x80, 0);
                let out = self.output();
                self.reset();
                out
            }
        }

        impl<C: $compress, V: $variant> BitHash for $name<C, V> {
            fn finalize_bits(
                &mut self,
                last: u8,
                bits: u32,
            ) -> Result<Self::Output, Error> {
                let trailer = trailer(last, bits)?;
                self.pad(trailer, bits as $length);
                let out = self.output();
                self.reset();
                Ok(out)
            }
        }

        impl<C: $compress, V: $variant> Drop for $name<C, V> {
            /// The buffer holds message, and the state is a function
            /// of it.
            fn drop(&mut self) {
                self.state.zeroize();
                // Past `dirty` the buffer holds nothing of a message: it was
                // wiped, or never written.
                self.block[..self.dirty].zeroize();
                self.used.zeroize();
                self.dirty.zeroize();
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

    /// Nothing of a message is left in the buffer after a reset or a
    /// finalize, however the message arrived, at both widths.
    #[test]
    fn nothing_is_left_behind() {
        use crate::hash::sha2::portable::Compress;
        use crate::hash::sha2::variant::{Sha256, Sha512};
        let data: [u8; 300] = core::array::from_fn(|i| (i as u8) | 1);
        for len in [1usize, 5, 55, 56, 64, 111, 112, 127, 128, 129, 300] {
            let mut narrow = Engine32::<Compress, Sha256>::with(Compress);
            let mut wide = Engine64::<Compress, Sha512>::with(Compress);
            for chunk in data[..len].chunks(37) {
                narrow.update(chunk);
                wide.update(chunk);
            }
            narrow.finalize();
            wide.finalize();
            assert_eq!(narrow.block, [0u8; 64], "finalize after {len}");
            assert_eq!(wide.block, [0u8; 128], "finalize after {len}");
            for chunk in data[..len].chunks(7) {
                narrow.update(chunk);
                wide.update(chunk);
            }
            narrow.reset();
            wide.reset();
            assert_eq!(narrow.block, [0u8; 64], "reset after {len}");
            assert_eq!(wide.block, [0u8; 128], "reset after {len}");
            narrow.update(&data[..len]);
            wide.update(&data[..len]);
            narrow.finalize_bits(0xff, 3).expect("bits");
            wide.finalize_bits(0xff, 3).expect("bits");
            assert_eq!(narrow.block, [0u8; 64], "bits after {len}");
            assert_eq!(wide.block, [0u8; 128], "bits after {len}");
        }
    }

    #[test]
    fn trailer_rejects_whole_bytes() {
        assert_eq!(trailer(0, 0), Err(Error::InvalidBitCount(0)));
        assert_eq!(trailer(0, 8), Err(Error::InvalidBitCount(8)));
    }
}
