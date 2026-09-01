//! An unsigned integer of a fixed number of 64-bit limbs.
//!
//! The value type under the Montgomery arithmetic in
//! [`montgomery`](super::montgomery), and so under RSA. The limb
//! count is a const parameter: each user of the arithmetic names the
//! width it needs, and nothing here imposes a ceiling.
//!
//! # Constant time
//!
//! Every operation runs the full width of the number: no loop exits
//! early, comparisons come from a whole-width borrow, and selection
//! is by mask. Only the limb count itself, which is public, shapes
//! the timing.

use zeroize::Zeroize;

/// An unsigned integer of `LIMBS` 64-bit words, least significant
/// first.
#[derive(Clone, Copy, Zeroize)]
pub(crate) struct Uint<const LIMBS: usize>(pub(crate) [u64; LIMBS]);

impl<const LIMBS: usize> Uint<LIMBS> {
    pub(crate) const ZERO: Self = Uint([0; LIMBS]);

    pub(crate) fn one() -> Self {
        let mut limbs = [0; LIMBS];
        limbs[0] = 1;
        Uint(limbs)
    }

    /// Reads a big-endian byte string, which must fit: at most
    /// 8 * `LIMBS` bytes. Shorter strings are values with leading
    /// zeros, as RSA's OS2IP defines.
    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= 8 * LIMBS);
        let mut limbs = [0u64; LIMBS];
        for (i, chunk) in bytes.rchunks(8).enumerate() {
            let mut word = [0u8; 8];
            word[8 - chunk.len()..].copy_from_slice(chunk);
            limbs[i] = u64::from_be_bytes(word);
        }
        Uint(limbs)
    }

    /// Writes the value big-endian into `out`, left-padded with
    /// zeros, as RSA's I2OSP defines. The value must fit; the debug
    /// assertion holds wherever a caller has checked its inputs.
    pub(crate) fn to_be_bytes(self, out: &mut [u8]) {
        out.fill(0);
        for (i, chunk) in out.rchunks_mut(8).enumerate() {
            if i >= LIMBS {
                break;
            }
            let word = self.0[i].to_be_bytes();
            let take = chunk.len();
            chunk.copy_from_slice(&word[8 - take..]);
        }
        for (i, limb) in self.0.iter().enumerate() {
            debug_assert!(
                8 * i < out.len() || *limb == 0,
                "value does not fit the buffer",
            );
        }
    }

    pub(crate) fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    pub(crate) fn is_zero(&self) -> bool {
        let mut acc = 0u64;
        for limb in self.0 {
            acc |= limb;
        }
        acc == 0
    }

    /// `self + other`, and the carry out of the top: 0 or 1.
    pub(crate) fn add_carry(&self, other: &Self) -> (Self, u64) {
        let mut sum = [0u64; LIMBS];
        let mut carry = 0u64;
        let terms = self.0.iter().zip(other.0);
        for (s, (a, b)) in sum.iter_mut().zip(terms) {
            let v = u128::from(*a) + u128::from(b) + u128::from(carry);
            *s = v as u64;
            carry = (v >> 64) as u64;
        }
        (Uint(sum), carry)
    }

    /// `self - other`, and the borrow out of the top: 0 or 1.
    pub(crate) fn sub_borrow(&self, other: &Self) -> (Self, u64) {
        let mut diff = [0u64; LIMBS];
        let mut borrow = 0u64;
        let terms = self.0.iter().zip(other.0);
        for (d, (a, b)) in diff.iter_mut().zip(terms) {
            let (x, b1) = a.overflowing_sub(b);
            let (x, b2) = x.overflowing_sub(borrow);
            *d = x;
            borrow = u64::from(b1 | b2);
        }
        (Uint(diff), borrow)
    }

    /// One where `self < other`, zero otherwise, from the borrow of
    /// a whole-width subtraction.
    pub(crate) fn less_than(&self, other: &Self) -> u64 {
        self.sub_borrow(other).1
    }

    /// Replaces `self` with `other` when `condition` is one, by a
    /// mask rather than a branch.
    pub(crate) fn cmov(&mut self, other: &Self, condition: u64) {
        debug_assert!(condition <= 1);
        let mask = condition.wrapping_neg();
        for (a, b) in self.0.iter_mut().zip(other.0) {
            *a ^= (*a ^ b) & mask;
        }
    }

    /// `2 * self mod n`, for a value already below `n`.
    pub(crate) fn double_mod(&self, n: &Self) -> Self {
        let (doubled, carry) = self.add_carry(self);
        let (reduced, borrow) = doubled.sub_borrow(n);
        // The doubling is below 2n, so one subtraction settles it:
        // taken when the sum overflowed the width or exceeds n.
        let take = carry | (1 - borrow);
        let mut out = doubled;
        out.cmov(&reduced, take);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_with_padding() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11];
        let x = Uint::<2>::from_be_bytes(&bytes);
        assert_eq!(x.0, [0x3456789abcdef011, 0x12]);
        let mut out = [0xffu8; 12];
        x.to_be_bytes(&mut out);
        assert_eq!(out[..3], [0, 0, 0]);
        assert_eq!(out[3..], bytes);
    }

    #[test]
    fn carries_and_borrows_travel() {
        let max = Uint::<2>([u64::MAX, u64::MAX]);
        let one = Uint::<2>::one();
        let (sum, carry) = max.add_carry(&one);
        assert!(sum.is_zero());
        assert_eq!(carry, 1);
        let (diff, borrow) = Uint::<2>::ZERO.sub_borrow(&one);
        assert_eq!(diff.0, [u64::MAX, u64::MAX]);
        assert_eq!(borrow, 1);
    }

    #[test]
    fn comparison_is_a_borrow() {
        let small = Uint::<2>([5, 1]);
        let large = Uint::<2>([2, 3]);
        assert_eq!(small.less_than(&large), 1);
        assert_eq!(large.less_than(&small), 0);
        assert_eq!(small.less_than(&small), 0);
    }

    #[test]
    fn doubling_wraps_the_modulus() {
        // mod 7, walking 3 -> 6 -> 5 -> 3.
        let n = Uint::<1>([7]);
        let mut x = Uint::<1>([3]);
        let expected = [6u64, 5, 3];
        for e in expected {
            x = x.double_mod(&n);
            assert_eq!(x.0, [e]);
        }
        // A modulus with the top bit set exercises the carry path.
        let n = Uint::<1>([(1 << 63) + 1]);
        let x = Uint::<1>([1 << 63]);
        assert_eq!(x.double_mod(&n).0, [(1 << 63) - 1]);
    }
}
