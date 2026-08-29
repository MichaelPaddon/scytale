//! The sponge that every SHA-3 function is: absorb the message into
//! a 1600-bit state a rate's worth at a time, permuting between,
//! then squeeze the output back out the same way.
//!
//! An implementation supplies only the permutation, Keccak-f\[1600\],
//! and a variant only its rate and the bits that separate it from
//! the others. Everything here is generic over both. The traits are
//! sealed; the module is public only so that the backend type
//! aliases can be named.
//!
//! # Bit strings
//!
//! SHA-3 is defined over bit strings, and its padding works in bits:
//! the message, then two or four bits saying which function this is,
//! then a one, zeros, and a one at the end of the block. Bits are
//! numbered from the least significant end of each byte, the
//! opposite of SHA-2, which is why the byte forms of the padding in
//! FIPS 202 look the way they do. Only the padding knows any of
//! this; the permutation sees whole lanes.

#![allow(unsafe_code)]

use core::fmt;
use core::marker::PhantomData;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash::{BitHash, BitXof, Hash, Xof, XofReader};
use crate::symmetric::Block;
use crate::Error;

/// Keeps the traits here to this crate's own implementations.
mod sealed {
    pub trait Sealed {}
}
pub(crate) use sealed::Sealed;

/// Lanes in the state: 5 by 5 of 64 bits.
pub(crate) const LANES: usize = 25;

/// The largest rate any variant uses, SHAKE128's.
const MAX_RATE: usize = 168;

/// Keccak-f\[1600\]. Sealed.
pub trait Permutation: Sealed {
    /// Whether this processor can run it.
    fn supported() -> bool;

    /// Applies the permutation to `state`.
    ///
    /// # Safety
    /// [`supported`](Permutation::supported) must have returned true
    /// on this processor.
    unsafe fn permute(state: &mut [u64; LANES]);
}

/// One of the six functions: its rate and the domain bits that end
/// its messages. Sealed.
pub trait Variant: Clone + Sealed {
    /// Bytes absorbed between permutations.
    const RATE: usize;
    /// The domain separation bits, with the first padding one after
    /// them, as FIPS 202 gives them: `0x06` for the digests, `0x1f`
    /// for SHAKE.
    const SUFFIX: u8;
}

/// A fixed-length digest: SHA3-224 to SHA3-512.
pub trait DigestVariant: Variant {
    /// The digest.
    type Output: Block;
}

/// An extendable-output function: SHAKE128 or SHAKE256.
pub trait XofVariant: Variant {}

/// The state of a sponge, absorbing or squeezing, with the byte
/// position within the current rate.
struct State<P: Permutation> {
    lanes: [u64; LANES],
    /// Bytes of the current block absorbed, or squeezed.
    used: usize,
    _marker: PhantomData<P>,
}

impl<P: Permutation> State<P> {
    fn new() -> Self {
        State {
            lanes: [0; LANES],
            used: 0,
            _marker: PhantomData,
        }
    }

    fn permute(&mut self) {
        // SAFETY: the sponge only exists once its constructor's
        // caller confirmed support.
        unsafe { P::permute(&mut self.lanes) }
    }

    /// Xors `byte` into the state at byte offset `at`.
    #[inline]
    fn xor_byte(&mut self, at: usize, byte: u8) {
        self.lanes[at / 8] ^= u64::from(byte) << (8 * (at % 8));
    }

    /// The state's byte at offset `at`.
    #[inline]
    fn byte(&self, at: usize) -> u8 {
        (self.lanes[at / 8] >> (8 * (at % 8))) as u8
    }

    /// Absorbs `data` at rate `rate`, permuting as each block fills.
    fn absorb(&mut self, rate: usize, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (rate - self.used).min(data.len());
            let (now, rest) = data.split_at(take);
            // Whole lanes at once where the offset allows, which is
            // every lane after the first partial one.
            let mut at = self.used;
            let mut now = now;
            while !at.is_multiple_of(8) && !now.is_empty() {
                self.xor_byte(at, now[0]);
                at += 1;
                now = &now[1..];
            }
            let (lanes, tail) = <[u8; 8]>::split(now);
            for lane in lanes {
                self.lanes[at / 8] ^= u64::from_le_bytes(*lane);
                at += 8;
            }
            for &byte in tail {
                self.xor_byte(at, byte);
                at += 1;
            }
            self.used = at;
            data = rest;
            if self.used == rate {
                self.permute();
                self.used = 0;
            }
        }
    }

    /// Pads and permutes, leaving the state ready to squeeze.
    ///
    /// `trailer` is the suffix and first padding bit already shifted
    /// past any last bits of message; its highest set bit is that
    /// padding one. The padding is `1`, zeros, `1`, ending a block:
    /// when the first one is the last bit of this block, or falls
    /// beyond it, the final one belongs to the next block, which is
    /// otherwise empty.
    fn pad(&mut self, rate: usize, trailer: u16) {
        let low = trailer as u8;
        let high = (trailer >> 8) as u8;
        let first_one = self.used * 8 + (15 - trailer.leading_zeros() as usize);
        self.xor_byte(self.used, low);
        if first_one >= rate * 8 - 1 {
            // Whatever spilt past this block waits for the next.
            self.permute();
            self.xor_byte(0, high);
        } else if high != 0 {
            self.xor_byte(self.used + 1, high);
        }
        self.xor_byte(rate - 1, 0x80);
        self.permute();
        self.used = 0;
    }

    /// Copies out the next `out.len()` bytes, permuting as each
    /// block is used up.
    fn squeeze(&mut self, rate: usize, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.used == rate {
                self.permute();
                self.used = 0;
            }
            let take = (rate - self.used).min(out.len());
            let (now, rest) = out.split_at_mut(take);
            for (i, byte) in now.iter_mut().enumerate() {
                *byte = self.byte(self.used + i);
            }
            self.used += take;
            out = rest;
        }
    }
}

impl<P: Permutation> Clone for State<P> {
    fn clone(&self) -> Self {
        State {
            lanes: self.lanes,
            used: self.used,
            _marker: PhantomData,
        }
    }
}

impl<P: Permutation> Drop for State<P> {
    fn drop(&mut self) {
        self.lanes.zeroize();
        self.used.zeroize();
    }
}

/// Checks the bit count and builds the trailer: the last bits of
/// message with the suffix and first padding bit after them.
fn trailer(suffix: u8, last: u8, bits: u32) -> Result<u16, Error> {
    if !(1..=7).contains(&bits) {
        return Err(Error::InvalidBitCount(bits));
    }
    let keep = !(0xffu16 << bits) as u8;
    Ok(u16::from(last & keep) | (u16::from(suffix) << bits))
}

/// A SHA-3 or SHAKE computation in progress, over the permutation
/// `P`.
pub struct Sponge<P: Permutation, V: Variant> {
    state: State<P>,
    _marker: PhantomData<V>,
}

impl<P: Permutation, V: Variant> Sponge<P, V> {
    /// Starts a sponge without asking the processor.
    ///
    /// # Safety
    /// The caller must have confirmed `P::supported()`.
    pub(crate) unsafe fn new_unchecked() -> Self {
        Sponge {
            state: State::new(),
            _marker: PhantomData,
        }
    }

    fn try_new() -> Result<Self, Error> {
        if !P::supported() {
            return Err(Error::NotSupported);
        }
        // SAFETY: just confirmed.
        Ok(unsafe { Self::new_unchecked() })
    }

    fn reset(&mut self) {
        self.state.lanes.zeroize();
        self.state.used = 0;
    }

    fn update(&mut self, data: &[u8]) {
        const { assert!(V::RATE <= MAX_RATE) };
        self.state.absorb(V::RATE, data);
    }

    /// Pads with `trailer` and returns the state ready to squeeze.
    fn finish(mut self, trailer: u16) -> State<P> {
        self.state.pad(V::RATE, trailer);
        self.state.clone()
    }
}

impl<P: Permutation, V: DigestVariant> Sponge<P, V> {
    fn output(state: &mut State<P>) -> V::Output {
        let mut out = V::Output::ZERO;
        state.squeeze(V::RATE, out.as_mut());
        out
    }
}

impl<P: Permutation, V: DigestVariant> Hash for Sponge<P, V> {
    const BLOCK_SIZE: usize = V::RATE;
    type Output = V::Output;

    fn try_new() -> Result<Self, Error> {
        Sponge::try_new()
    }

    fn reset(&mut self) {
        Sponge::reset(self)
    }

    fn update(&mut self, data: &[u8]) {
        Sponge::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        let mut state = self.finish(u16::from(V::SUFFIX));
        Self::output(&mut state)
    }
}

impl<P: Permutation, V: DigestVariant> BitHash for Sponge<P, V> {
    fn finalize_bits(self, last: u8, bits: u32) -> Result<Self::Output, Error> {
        let trailer = trailer(V::SUFFIX, last, bits)?;
        let mut state = self.finish(trailer);
        Ok(Self::output(&mut state))
    }
}

/// The output of a SHAKE function, squeezed as wanted.
pub struct Reader<P: Permutation, V: XofVariant> {
    state: State<P>,
    _marker: PhantomData<V>,
}

impl<P: Permutation, V: XofVariant> XofReader for Reader<P, V> {
    fn squeeze(&mut self, out: &mut [u8]) {
        self.state.squeeze(V::RATE, out);
    }
}

impl<P: Permutation, V: XofVariant> Clone for Reader<P, V> {
    fn clone(&self) -> Self {
        Reader {
            state: self.state.clone(),
            _marker: PhantomData,
        }
    }
}

impl<P: Permutation, V: XofVariant> ZeroizeOnDrop for Reader<P, V> {}

impl<P: Permutation, V: XofVariant> fmt::Debug for Reader<P, V> {
    /// Deliberately omits the state, which is the output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reader").finish_non_exhaustive()
    }
}

impl<P: Permutation, V: XofVariant> Xof for Sponge<P, V> {
    const BLOCK_SIZE: usize = V::RATE;
    type Reader = Reader<P, V>;

    fn try_new() -> Result<Self, Error> {
        Sponge::try_new()
    }

    fn reset(&mut self) {
        Sponge::reset(self)
    }

    fn update(&mut self, data: &[u8]) {
        Sponge::update(self, data)
    }

    fn finalize_xof(self) -> Self::Reader {
        Reader {
            state: self.finish(u16::from(V::SUFFIX)),
            _marker: PhantomData,
        }
    }
}

impl<P: Permutation, V: XofVariant> BitXof for Sponge<P, V> {
    fn finalize_bits_xof(
        self,
        last: u8,
        bits: u32,
    ) -> Result<Self::Reader, Error> {
        let trailer = trailer(V::SUFFIX, last, bits)?;
        Ok(Reader {
            state: self.finish(trailer),
            _marker: PhantomData,
        })
    }
}

impl<P: Permutation, V: Variant> Clone for Sponge<P, V> {
    fn clone(&self) -> Self {
        Sponge {
            state: self.state.clone(),
            _marker: PhantomData,
        }
    }
}

// The state wipes itself; this only says so.
impl<P: Permutation, V: Variant> ZeroizeOnDrop for Sponge<P, V> {}

impl<P: Permutation, V: Variant> fmt::Debug for Sponge<P, V> {
    /// Deliberately omits the state, which is a function of the
    /// message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sponge")
            .field("used", &self.state.used)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailer_places_the_suffix_after_the_bits() {
        // Five bits of message, then 0b110 from bit five: FIPS 202's
        // example of a 1605-bit message ends in 0x13 and pads to 0xd3.
        assert_eq!(trailer(0x06, 0x13, 5), Ok(0x00d3));
        // Six bits: the padding one spills into the next byte.
        assert_eq!(trailer(0x06, 0xff, 6), Ok(0x01bf));
        // SHAKE's longer suffix spills from four bits on.
        assert_eq!(trailer(0x1f, 0x0f, 4), Ok(0x01ff));
        assert_eq!(trailer(0x1f, 0x00, 1), Ok(0x003e));
    }

    #[test]
    fn trailer_rejects_whole_bytes() {
        assert_eq!(trailer(0x06, 0, 0), Err(Error::InvalidBitCount(0)));
        assert_eq!(trailer(0x06, 0, 8), Err(Error::InvalidBitCount(8)));
    }
}
