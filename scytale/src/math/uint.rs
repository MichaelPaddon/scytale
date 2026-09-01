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
        self.add_mod(self, n)
    }

    /// `self + other mod n`, for values already below `n`.
    pub(crate) fn add_mod(&self, other: &Self, n: &Self) -> Self {
        let (sum, carry) = self.add_carry(other);
        let (reduced, borrow) = sum.sub_borrow(n);
        // The sum is below 2n, so one subtraction settles it: taken
        // when the sum overflowed the width or exceeds n.
        let take = carry | (1 - borrow);
        let mut out = sum;
        out.cmov(&reduced, take);
        out
    }

    /// `self - other mod n`, for values already below `n`.
    pub(crate) fn sub_mod(&self, other: &Self, n: &Self) -> Self {
        let (diff, borrow) = self.sub_borrow(other);
        let (wrapped, _) = diff.add_carry(n);
        let mut out = diff;
        out.cmov(&wrapped, borrow);
        out
    }

    /// The full double-width product; `OUT` must be twice `LIMBS`.
    pub(crate) fn mul_wide<const OUT: usize>(&self, other: &Self) -> Uint<OUT> {
        assert_eq!(OUT, 2 * LIMBS, "OUT must be 2 * LIMBS");
        let mut out = [0u64; OUT];
        for (i, &a) in self.0.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.0.iter().enumerate() {
                let v = u128::from(out[i + j])
                    + u128::from(a) * u128::from(b)
                    + u128::from(carry);
                out[i + j] = v as u64;
                carry = (v >> 64) as u64;
            }
            // Nothing has written this word yet, so the carry lands
            // whole.
            out[i + LIMBS] = carry;
        }
        Uint(out)
    }

    /// The value in a wider type; `OUT` must not be narrower.
    pub(crate) fn widen<const OUT: usize>(&self) -> Uint<OUT> {
        assert!(OUT >= LIMBS, "OUT must not be narrower");
        let mut out = [0u64; OUT];
        out[..LIMBS].copy_from_slice(&self.0);
        Uint(out)
    }

    /// A value from borrowed limbs, which must fit.
    pub(crate) fn from_limbs(limbs: &[u64]) -> Self {
        debug_assert!(limbs.len() <= LIMBS);
        let mut out = [0u64; LIMBS];
        out[..limbs.len()].copy_from_slice(limbs);
        Uint(out)
    }

    /// The number of bits needed to write the value; zero for zero.
    /// Not constant time: used where the value's size is no secret,
    /// or where only the answer's rough size escapes.
    pub(crate) fn bit_length(&self) -> usize {
        for (i, limb) in self.0.iter().enumerate().rev() {
            if *limb != 0 {
                return 64 * i + (64 - limb.leading_zeros() as usize);
            }
        }
        0
    }

    /// The number of zero bits below the lowest one bit; the full
    /// width for zero. Not constant time, for the same reasons.
    pub(crate) fn trailing_zeros(&self) -> usize {
        let mut count = 0;
        for limb in self.0 {
            if limb == 0 {
                count += 64;
            } else {
                return count + limb.trailing_zeros() as usize;
            }
        }
        count
    }

    /// The value shifted right by `bits`, which must be less than
    /// the width.
    pub(crate) fn shr(&self, bits: usize) -> Self {
        debug_assert!(bits < 64 * LIMBS);
        let words = bits / 64;
        let within = bits % 64;
        let mut out = [0u64; LIMBS];
        for (i, o) in out.iter_mut().take(LIMBS - words).enumerate() {
            let mut limb = self.0[i + words] >> within;
            if within > 0 && i + words + 1 < LIMBS {
                limb |= self.0[i + words + 1] << (64 - within);
            }
            *o = limb;
        }
        Uint(out)
    }

    /// `self * w`, as the in-width limbs and the word that overflows
    /// the top.
    pub(crate) fn mul_word(&self, w: u64) -> (Self, u64) {
        let mut out = [0u64; LIMBS];
        let mut carry = 0u64;
        for (o, limb) in out.iter_mut().zip(self.0) {
            let v = u128::from(limb) * u128::from(w) + u128::from(carry);
            *o = v as u64;
            carry = (v >> 64) as u64;
        }
        (Uint(out), carry)
    }

    /// `(top * 2^width + self) / w` and the remainder, by schoolbook
    /// long division; the quotient must fit the width.
    pub(crate) fn div_rem_word(&self, top: u64, w: u64) -> (Self, u64) {
        debug_assert!(w != 0 && top < w);
        let mut out = [0u64; LIMBS];
        let mut rem = u128::from(top);
        for i in (0..LIMBS).rev() {
            let cur = (rem << 64) | u128::from(self.0[i]);
            out[i] = (cur / u128::from(w)) as u64;
            rem = cur % u128::from(w);
        }
        (Uint(out), rem as u64)
    }

    /// The remainder modulo a single word.
    pub(crate) fn rem_word(&self, w: u64) -> u64 {
        debug_assert!(w != 0);
        let mut rem = 0u128;
        for limb in self.0.iter().rev() {
            rem = ((rem << 64) | u128::from(*limb)) % u128::from(w);
        }
        rem as u64
    }

    /// The remainder modulo `m`, which may be narrower and need not
    /// be odd: one shift-and-subtract per bit, every bit taking the
    /// same operations, so a secret value stays out of the timing.
    pub(crate) fn rem_wide<const OUT: usize>(
        &self,
        m: &Uint<OUT>,
    ) -> Uint<OUT> {
        debug_assert!(!m.is_zero());
        let mut r = Uint::<OUT>::ZERO;
        for i in (0..64 * LIMBS).rev() {
            let bit = (self.0[i / 64] >> (i % 64)) & 1;
            // r = 2r + bit, then one subtraction of m settles it,
            // because r was below m.
            let (doubled, carry) = r.add_carry(&r);
            let mut with_bit = doubled;
            with_bit.0[0] |= bit;
            let (reduced, borrow) = with_bit.sub_borrow(m);
            let take = carry | (1 - borrow);
            r = with_bit;
            r.cmov(&reduced, take);
        }
        r
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
    fn sizes_and_shifts() {
        let x = Uint::<2>([0, 0b1100]);
        assert_eq!(x.bit_length(), 68);
        assert_eq!(x.trailing_zeros(), 66);
        assert_eq!(x.shr(66).0, [0b11, 0]);
        assert_eq!(x.shr(2).0, [0, 0b11]);
        assert_eq!(Uint::<2>::ZERO.bit_length(), 0);
        assert_eq!(Uint::<2>::ZERO.trailing_zeros(), 128);
    }

    #[test]
    fn word_multiply_and_divide_invert() {
        let x = Uint::<2>([0x123456789abcdef0, 0xfedcba9876543210]);
        let (product, top) = x.mul_word(0xdeadbeef);
        let (back, rem) = product.div_rem_word(top, 0xdeadbeef);
        assert_eq!(back.0, x.0);
        assert_eq!(rem, 0);
        // And a remainder that is genuinely there.
        assert_eq!(Uint::<1>([1000]).rem_word(7), 1000 % 7);
        assert_eq!(x.rem_word(65537), {
            // Independently: fold bytes via modular arithmetic.
            let mut r = 0u128;
            for limb in x.0.iter().rev() {
                r = ((r << 64) | u128::from(*limb)) % 65537;
            }
            r as u64
        });
    }

    #[test]
    fn wide_remainder_matches_narrow_arithmetic() {
        // A 256-bit value modulo a 64-bit modulus, against the
        // word-sized path.
        let x = Uint::<4>([0x1111, 0x2222, 0x3333, 0x4444]);
        let m = 0x1234567891u64;
        assert_eq!(x.rem_wide::<1>(&Uint([m])).0, [x.rem_word(m)]);
        // An even modulus, which the Montgomery arithmetic cannot
        // take, works here.
        let m = 0x100000006u64;
        assert_eq!(x.rem_wide::<1>(&Uint([m])).0, [x.rem_word(m)]);
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
