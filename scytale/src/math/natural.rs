//! A non-negative integer of bounded size.
//!
//! Just enough for format-preserving encryption, which needs to read
//! a string of symbols in some radix as a number, and to write a
//! number back out in that radix. Both directions come down to three
//! operations: multiply by a small value and add another, divide by a
//! small value, and read or write big-endian bytes.
//!
//! # Not constant time
//!
//! Division by the radix uses the machine's divide instruction, whose
//! timing depends on its operands on some processors. Every value
//! here is derived from the message, so this leaks a little about it.
//! The format-preserving modes say so in their own documentation;
//! nothing else in the library uses this.

/// Words the value is held in.
type Limb = u64;

/// Bits in a limb.
const BITS: usize = Limb::BITS as usize;

/// Bytes in a limb.
const BYTES: usize = BITS / 8;

/// Limbs a value may occupy.
///
/// Sized for the largest message the format-preserving modes accept:
/// half of it, at the largest radix, is 4096 bits, and the value
/// derived from the block cipher alongside is a little larger again.
pub(crate) const LIMBS: usize = 72;

/// Bytes a value may occupy.
pub(crate) const MAX_BYTES: usize = LIMBS * BYTES;

/// A non-negative integer, least significant limb first.
#[derive(Clone)]
pub(crate) struct Natural {
    limbs: [Limb; LIMBS],
}

impl Natural {
    /// Zero.
    pub(crate) fn zero() -> Self {
        Natural { limbs: [0; LIMBS] }
    }

    /// Reads a big-endian byte string, which must fit.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_BYTES);
        let mut value = Natural::zero();
        for (i, chunk) in bytes.rchunks(BYTES).enumerate() {
            let mut word = [0u8; BYTES];
            word[BYTES - chunk.len()..].copy_from_slice(chunk);
            value.limbs[i] = Limb::from_be_bytes(word);
        }
        value
    }

    /// Writes the value big-endian into `out`, left-padded with
    /// zeros. Any part that does not fit is dropped, which callers
    /// rely on: the standard asks for a fixed-width field that the
    /// value is known to fit.
    pub(crate) fn to_bytes(&self, out: &mut [u8]) {
        out.fill(0);
        for (i, chunk) in out.rchunks_mut(BYTES).enumerate() {
            if i >= LIMBS {
                break;
            }
            let word = self.limbs[i].to_be_bytes();
            let take = chunk.len();
            chunk.copy_from_slice(&word[BYTES - take..]);
        }
    }

    /// Multiplies by `factor` and adds `addend`, both of which must
    /// be small enough that neither overflows a limb when combined.
    ///
    /// This is how a string of symbols becomes a number: start at
    /// zero and fold in one symbol at a time.
    pub(crate) fn multiply_add(&mut self, factor: u32, addend: u32) {
        let mut carry = addend as u128;
        for limb in self.limbs.iter_mut() {
            let product = (*limb as u128) * (factor as u128) + carry;
            *limb = product as Limb;
            carry = product >> BITS;
        }
        debug_assert_eq!(carry, 0, "value outgrew its bounds");
    }

    /// The number of bits needed to write the value, or zero for
    /// zero.
    pub(crate) fn bit_length(&self) -> usize {
        for (i, limb) in self.limbs.iter().enumerate().rev() {
            if *limb != 0 {
                return i * BITS + (BITS - limb.leading_zeros() as usize);
            }
        }
        0
    }

    /// Divides by `divisor`, returning the remainder.
    ///
    /// This is how a number becomes a string of symbols: take the
    /// remainder as the next symbol and keep going.
    pub(crate) fn divide(&mut self, divisor: u32) -> u32 {
        debug_assert!(divisor > 1);
        let mut carry = 0u128;
        for limb in self.limbs.iter_mut().rev() {
            let value = (carry << BITS) | (*limb as u128);
            *limb = (value / divisor as u128) as Limb;
            carry = value % divisor as u128;
        }
        carry as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_bytes() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe];
        let value = Natural::from_bytes(&bytes);
        let mut out = [0u8; 9];
        value.to_bytes(&mut out);
        assert_eq!(out, bytes);
    }

    #[test]
    fn pads_and_truncates_on_the_left() {
        let value = Natural::from_bytes(&[0xab, 0xcd]);
        let mut wide = [0xffu8; 4];
        value.to_bytes(&mut wide);
        assert_eq!(wide, [0, 0, 0xab, 0xcd], "padded");
        let mut narrow = [0xffu8; 1];
        value.to_bytes(&mut narrow);
        assert_eq!(narrow, [0xcd], "kept the low byte");
    }

    #[test]
    fn builds_and_takes_apart_a_number_in_a_radix() {
        // 1234 in base ten, fed in digit by digit.
        let mut value = Natural::zero();
        for digit in [1u32, 2, 3, 4] {
            value.multiply_add(10, digit);
        }
        let mut out = [0u8; 2];
        value.to_bytes(&mut out);
        assert_eq!(u16::from_be_bytes(out), 1234);

        // And back out, least significant first.
        let mut digits = [0u32; 4];
        for slot in digits.iter_mut() {
            *slot = value.divide(10);
        }
        assert_eq!(digits, [4, 3, 2, 1]);
    }

    #[test]
    fn bit_length_counts_significant_bits() {
        assert_eq!(Natural::zero().bit_length(), 0);
        assert_eq!(Natural::from_bytes(&[1]).bit_length(), 1);
        assert_eq!(Natural::from_bytes(&[0xff]).bit_length(), 8);
        assert_eq!(Natural::from_bytes(&[1, 0]).bit_length(), 9);
        // Ten to the sixth less one, which needs twenty bits.
        let mut value = Natural::zero();
        for _ in 0..6 {
            value.multiply_add(10, 9);
        }
        assert_eq!(value.bit_length(), 20);
    }

    /// A value far wider than a machine word, to be sure the carries
    /// travel between limbs.
    #[test]
    fn carries_between_limbs() {
        let mut value = Natural::zero();
        for _ in 0..40 {
            value.multiply_add(65536, 65535);
        }
        let mut out = [0u8; 80];
        value.to_bytes(&mut out);

        let mut digits = 0;
        for _ in 0..40 {
            assert_eq!(value.divide(65536), 65535);
            digits += 1;
        }
        assert_eq!(digits, 40);
        // Everything has been taken back out.
        let mut left = [0u8; 80];
        value.to_bytes(&mut left);
        assert_eq!(left, [0u8; 80]);
    }
}
