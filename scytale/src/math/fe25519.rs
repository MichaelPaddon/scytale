//! Arithmetic in the field of 2^255 - 19 elements.
//!
//! The field under Curve25519, and so under both X25519 key
//! agreement and Ed25519 signatures. Every operation is a fixed
//! sequence of limb arithmetic: no branch, index or table lookup
//! depends on a value, so a secret in the field stays out of timing
//! and the cache.

use zeroize::Zeroize;

/// A 51-bit limb's worth of ones.
const MASK51: u64 = (1 << 51) - 1;

/// An element of the field of 2^255 - 19 elements, as five limbs of
/// 51 bits, least significant first.
///
/// Limbs are allowed to grow a few bits past 51 between reductions:
/// a short chain of additions and subtractions on reduced values
/// stays under 2^54 per limb, which is still a safe multiplication
/// input, because the largest product sum is five terms of
/// 19 * 2^54 * 2^54, well inside a `u128`.
#[derive(Clone, Copy, Zeroize)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; 5]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Reads 32 little-endian bytes. The top bit is ignored, which
    /// is what RFC 7748 and RFC 8032 both specify for coordinates;
    /// values up to 2^255 - 1 are accepted and reduced by the
    /// arithmetic that follows.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let load = |chunk: &[u8]| {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            u64::from_le_bytes(word)
        };
        Fe([
            load(&bytes[0..8]) & MASK51,
            (load(&bytes[6..14]) >> 3) & MASK51,
            (load(&bytes[12..20]) >> 6) & MASK51,
            (load(&bytes[19..27]) >> 1) & MASK51,
            (load(&bytes[24..32]) >> 12) & MASK51,
        ])
    }

    /// Writes the canonical form: fully reduced, little-endian.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        // Two carry passes bring every limb below 2^52 whatever the
        // arithmetic left behind.
        let mut t = self.0;
        for _ in 0..2 {
            for i in 0..4 {
                t[i + 1] += t[i] >> 51;
                t[i] &= MASK51;
            }
            t[0] += 19 * (t[4] >> 51);
            t[4] &= MASK51;
        }
        // The value is now below 2^255, but may still exceed the
        // prime. Adding 19 overflows bit 255 exactly when it does,
        // and that overflow, times the prime, is what to subtract.
        let mut q = (t[0] + 19) >> 51;
        for limb in &t[1..] {
            q = (limb + q) >> 51;
        }
        t[0] += 19 * q;
        for i in 0..4 {
            t[i + 1] += t[i] >> 51;
            t[i] &= MASK51;
        }
        t[4] &= MASK51;

        let mut out = [0u8; 32];
        let words = [
            t[0] | (t[1] << 51),
            (t[1] >> 13) | (t[2] << 38),
            (t[2] >> 26) | (t[3] << 25),
            (t[3] >> 39) | (t[4] << 12),
        ];
        for (chunk, word) in out.chunks_exact_mut(8).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        t.zeroize();
        out
    }

    pub(crate) fn add(&self, other: &Fe) -> Fe {
        let mut sum = [0u64; 5];
        for (s, (a, b)) in sum.iter_mut().zip(self.0.iter().zip(other.0)) {
            *s = a + b;
        }
        Fe(sum)
    }

    /// `self - other`, computed as `self + 4p - other` so no limb
    /// underflows even when `other` has grown past 51 bits, then
    /// carried back below 2^52 so the result can itself be
    /// subtracted from.
    pub(crate) fn sub(&self, other: &Fe) -> Fe {
        // Four times the prime, limb by limb: 2^53 - 76, then
        // 2^53 - 4.
        const FOUR_P: [u64; 5] = [
            0x1FFFFFFFFFFFB4,
            0x1FFFFFFFFFFFFC,
            0x1FFFFFFFFFFFFC,
            0x1FFFFFFFFFFFFC,
            0x1FFFFFFFFFFFFC,
        ];
        let mut diff = [0u64; 5];
        for i in 0..5 {
            diff[i] = self.0[i] + FOUR_P[i] - other.0[i];
        }
        for i in 0..4 {
            diff[i + 1] += diff[i] >> 51;
            diff[i] &= MASK51;
        }
        diff[0] += 19 * (diff[4] >> 51);
        diff[4] &= MASK51;
        Fe(diff)
    }

    /// `-self`, as `0 - self`.
    pub(crate) fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    pub(crate) fn mul(&self, other: &Fe) -> Fe {
        let a = self.0;
        let b = other.0;
        let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);
        // Schoolbook product. A limb carried past 2^255 is worth 19
        // times its face value, which folds the high half back in.
        let t = [
            wide(a[0], b[0])
                + 19 * (wide(a[1], b[4])
                    + wide(a[2], b[3])
                    + wide(a[3], b[2])
                    + wide(a[4], b[1])),
            wide(a[0], b[1])
                + wide(a[1], b[0])
                + 19 * (wide(a[2], b[4]) + wide(a[3], b[3]) + wide(a[4], b[2])),
            wide(a[0], b[2])
                + wide(a[1], b[1])
                + wide(a[2], b[0])
                + 19 * (wide(a[3], b[4]) + wide(a[4], b[3])),
            wide(a[0], b[3])
                + wide(a[1], b[2])
                + wide(a[2], b[1])
                + wide(a[3], b[0])
                + 19 * wide(a[4], b[4]),
            wide(a[0], b[4])
                + wide(a[1], b[3])
                + wide(a[2], b[2])
                + wide(a[3], b[1])
                + wide(a[4], b[0]),
        ];
        Fe::reduce(t)
    }

    /// Multiplication by a small constant, such as the curve
    /// coefficient 121665.
    pub(crate) fn mul_small(&self, n: u32) -> Fe {
        let n = u128::from(n);
        let mut t = [0u128; 5];
        for (t, limb) in t.iter_mut().zip(self.0) {
            *t = u128::from(limb) * n;
        }
        Fe::reduce(t)
    }

    pub(crate) fn square(&self) -> Fe {
        self.mul(self)
    }

    /// One carry pass over wide limbs, folding the top carry back
    /// through 19. Output limbs are barely past 51 bits, which every
    /// operation here accepts.
    fn reduce(mut t: [u128; 5]) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..4 {
            t[i + 1] += t[i] >> 51;
            r[i] = (t[i] as u64) & MASK51;
        }
        r[4] = (t[4] as u64) & MASK51;
        r[0] += ((t[4] >> 51) as u64) * 19;
        r[1] += r[0] >> 51;
        r[0] &= MASK51;
        Fe(r)
    }

    /// `self` to the power 2^k, by k squarings.
    pub(crate) fn pow2k(&self, k: u32) -> Fe {
        let mut x = *self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }

    /// The powers 2^250 - 1 and 11 of `self`: the shared prefix of
    /// the two fixed exponents below, whose binary forms are a long
    /// run of ones with a short tail.
    fn pow_2250m1_and_11(&self) -> (Fe, Fe) {
        let z2 = self.square();
        let z9 = self.mul(&z2.pow2k(2));
        let z11 = z2.mul(&z9);
        // Each name is the span of one bits in the exponent built so
        // far: 2^5 - 2^0 ones, then doubling spans by squaring.
        let z_5_0 = z9.mul(&z11.square());
        let z_10_0 = z_5_0.pow2k(5).mul(&z_5_0);
        let z_20_0 = z_10_0.pow2k(10).mul(&z_10_0);
        let z_40_0 = z_20_0.pow2k(20).mul(&z_20_0);
        let z_50_0 = z_40_0.pow2k(10).mul(&z_10_0);
        let z_100_0 = z_50_0.pow2k(50).mul(&z_50_0);
        let z_200_0 = z_100_0.pow2k(100).mul(&z_100_0);
        (z_200_0.pow2k(50).mul(&z_50_0), z11)
    }

    /// The multiplicative inverse, as the power p - 2. A fixed
    /// exponent, so a fixed sequence of operations: eleven
    /// multiplications and 254 squarings, whatever the value.
    pub(crate) fn invert(&self) -> Fe {
        let (z_250_0, z11) = self.pow_2250m1_and_11();
        // p - 2 ends in 0b01011: two zeros into the run, then 11.
        z_250_0.pow2k(5).mul(&z11)
    }

    /// The power (p - 5) / 8 = 2^252 - 3, the exponent that square
    /// roots are built from: for the right `self`, this times a
    /// correction by sqrt(-1) yields a root.
    pub(crate) fn pow_p58(&self) -> Fe {
        let (z_250_0, _) = self.pow_2250m1_and_11();
        // 2^252 - 3 is the same run of ones followed by 0b01.
        z_250_0.pow2k(2).mul(self)
    }

    /// Whether the canonical form is odd, which RFC 8032 uses as the
    /// sign of a coordinate.
    pub(crate) fn is_negative(&self) -> u8 {
        self.to_bytes()[0] & 1
    }

    /// Whether this is the field's zero.
    pub(crate) fn is_zero(&self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    /// Equality on values, not on representations.
    pub(crate) fn equals(&self, other: &Fe) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    /// Exchanges `a` and `b` when `condition` is one, by arithmetic
    /// on a mask rather than a branch.
    pub(crate) fn cswap(condition: u64, a: &mut Fe, b: &mut Fe) {
        debug_assert!(condition <= 1);
        let mask = condition.wrapping_neg();
        for (a, b) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let x = (*a ^ *b) & mask;
            *a ^= x;
            *b ^= x;
        }
    }

    /// Replaces `self` with `other` when `condition` is one, again
    /// with a mask rather than a branch.
    pub(crate) fn cmov(&mut self, other: &Fe, condition: u64) {
        debug_assert!(condition <= 1);
        let mask = condition.wrapping_neg();
        for (a, b) in self.0.iter_mut().zip(other.0) {
            *a ^= (*a ^ b) & mask;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_reduces() {
        // p + 1 reads back as 1.
        let mut wrapped = [0u8; 32];
        wrapped[0] = 0xee;
        for byte in wrapped[1..31].iter_mut() {
            *byte = 0xff;
        }
        wrapped[31] = 0x7f;
        assert_eq!(Fe::from_bytes(&wrapped).to_bytes(), Fe::ONE.to_bytes());
    }

    #[test]
    fn inverse_multiplies_to_one() {
        let x = Fe::from_bytes(&[7u8; 32]);
        assert!(x.mul(&x.invert()).equals(&Fe::ONE));
    }

    #[test]
    fn negation_sums_to_zero() {
        let x = Fe::from_bytes(&[42u8; 32]);
        assert!(x.add(&x.neg()).is_zero());
        assert_eq!(x.is_negative() ^ x.neg().is_negative(), 1);
    }

    #[test]
    fn cmov_moves_only_on_one() {
        let a = Fe::from_bytes(&[1u8; 32]);
        let b = Fe::from_bytes(&[2u8; 32]);
        let mut x = a;
        x.cmov(&b, 0);
        assert!(x.equals(&a));
        x.cmov(&b, 1);
        assert!(x.equals(&b));
    }
}
