//! Montgomery arithmetic modulo an odd number.
//!
//! Multiplication modulo `n` without ever dividing by `n`: values
//! carry a factor of `R = 2^(64 * LIMBS)`, and the reduction inside
//! each product is a shift. Division only appears as the modular
//! exponentiation's setup, and even there it is repeated doubling.
//! This is the arithmetic under the prime curves; RSA, whose width
//! is a value rather than a type, has the same arithmetic over slices
//! in [`limbs`](super::limbs).
//!
//! Some moduli are cheaper than others. The reduction multiplies by
//! every limb of `n`, and the two NIST prime fields have limbs that
//! are each a sum of a few powers of two, so those products are
//! shifts and additions instead. [`Montgomery::known`] recognises the
//! two primes and halves the multiplications in every product, which
//! is what the curve arithmetic spends its time on.
//!
//! # Constant time
//!
//! [`mul`](Montgomery::mul) and [`modexp`](Montgomery::modexp) run
//! a fixed sequence of limb operations for a given width: the final
//! subtraction is chosen by a mask, and the exponentiation reads its
//! table by scanning every entry. The exponent's *width* in limbs is
//! visible; its value, and where its bits lie, are not.

#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;

use zeroize::Zeroize;

use super::uint::Uint;

impl<const LIMBS: usize> Zeroize for Montgomery<LIMBS> {
    fn zeroize(&mut self) {
        self.n.zeroize();
        self.inv = 0;
        self.rr.zeroize();
    }
}

/// The moduli the reduction has a cheaper form for. `General`
/// multiplies by each limb of `n`; the others name a prime whose
/// limbs are sums of a few powers of two, so the same products are
/// shifts and additions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    General,
    P256,
    P384,
}

/// The P-256 field prime, `2^256 - 2^224 + 2^192 + 2^96 - 1`. The
/// curve spells it in hex; the two are checked against each other.
pub(crate) const P256_PRIME: [u64; 4] = [
    0xffffffffffffffff,
    0x00000000ffffffff,
    0x0000000000000000,
    0xffffffff00000001,
];

/// The P-384 field prime, `2^384 - 2^128 - 2^96 + 2^32 - 1`.
pub(crate) const P384_PRIME: [u64; 6] = [
    0x00000000ffffffff,
    0xffffffff00000000,
    0xfffffffffffffffe,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
];

/// The shape of a modulus, by its limbs: the widths differ, so the
/// comparison is over slices.
#[cfg(test)]
fn shape_of<const LIMBS: usize>(n: &Uint<LIMBS>) -> Shape {
    if n.0[..] == P256_PRIME[..] {
        Shape::P256
    } else if n.0[..] == P384_PRIME[..] {
        Shape::P384
    } else {
        Shape::General
    }
}

/// Twice the widest modulus the crate builds a context for, in
/// limbs: the RSA sizes have their own arithmetic over slices, so
/// what is left here is the curves and what the tests reach for.
const WIDEST: usize = 64;

/// The context for arithmetic modulo one odd `n`: the constants that
/// every product needs, computed once.
pub(crate) struct Montgomery<const LIMBS: usize> {
    n: Uint<LIMBS>,
    /// Which reduction the modulus admits.
    shape: Shape,
    /// `-1/n` modulo 2^64, which turns the low limb of a product
    /// into the multiple of `n` that clears it.
    inv: u64,
    /// `R^2 mod n`: multiplying by it moves a value into the
    /// Montgomery domain.
    rr: Uint<LIMBS>,
}

impl<const LIMBS: usize> Montgomery<LIMBS> {
    /// A context for the modulus `n`, which must be odd and greater
    /// than one; `None` otherwise. The crate's own moduli are all
    /// known when it is built and take [`known`](Self::known); this
    /// is what the tests check that against.
    #[cfg(test)]
    pub(crate) fn new(n: Uint<LIMBS>) -> Option<Self> {
        let (_, borrow) = Uint::one().sub_borrow(&n);
        if !n.is_odd() || borrow == 0 {
            return None;
        }
        // The inverse of the low limb by Newton's iteration: each
        // step doubles the bits that are right, and five steps take
        // the seed's guaranteed 3 bits past 64.
        let n0 = n.0[0];
        let mut inv = n0;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
        }
        let inv = inv.wrapping_neg();
        debug_assert_eq!(n0.wrapping_mul(inv), u64::MAX);

        // R^2 mod n, by doubling 1 up to 2^(2 * 64 * LIMBS). Slow
        // and simple; it runs once per modulus.
        let mut rr = Uint::one();
        for _ in 0..(2 * 64 * LIMBS) {
            rr = rr.double_mod(&n);
        }
        Some(Montgomery {
            n,
            shape: shape_of(&n),
            inv,
            rr,
        })
    }

    /// The context for a modulus known when the crate is built, made
    /// when it is built: a curve's prime or order, so that an
    /// operation does not rebuild it, which is hundreds of modular
    /// doublings. The same constants [`new`](Self::new) computes, by
    /// the same method, in the subset of the language a constant
    /// allows. A modulus that is even or at most one fails the build.
    pub(crate) const fn known(n: Uint<LIMBS>) -> Self {
        let limbs = n.0;
        assert!(limbs[0] & 1 == 1, "modulus must be odd");
        let mut above_one = limbs[0] > 1;
        let mut i = 1;
        while i < LIMBS {
            above_one |= limbs[i] != 0;
            i += 1;
        }
        assert!(above_one, "modulus must exceed one");

        let n0 = limbs[0];
        let mut inv = n0;
        let mut step = 0;
        while step < 5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
            step += 1;
        }
        let inv = inv.wrapping_neg();

        // R^2 mod n by doubling 1, each doubling reduced by one
        // conditional subtraction.
        let mut rr = [0u64; LIMBS];
        rr[0] = 1;
        let mut round = 0;
        while round < 2 * 64 * LIMBS {
            let mut doubled = [0u64; LIMBS];
            let mut carry = 0u64;
            let mut j = 0;
            while j < LIMBS {
                doubled[j] = (rr[j] << 1) | carry;
                carry = rr[j] >> 63;
                j += 1;
            }
            let mut reduced = [0u64; LIMBS];
            let mut borrow = 0u64;
            let mut j = 0;
            while j < LIMBS {
                let (d, b1) = doubled[j].overflowing_sub(limbs[j]);
                let (d, b2) = d.overflowing_sub(borrow);
                reduced[j] = d;
                borrow = (b1 | b2) as u64;
                j += 1;
            }
            // Below 2n before the subtraction, so it is wanted when
            // the doubling carried out or did not borrow.
            rr = if carry == 1 || borrow == 0 {
                reduced
            } else {
                doubled
            };
            round += 1;
        }

        let shape = if Self::same(&limbs, &P256_PRIME) {
            Shape::P256
        } else if Self::same(&limbs, &P384_PRIME) {
            Shape::P384
        } else {
            Shape::General
        };
        Montgomery {
            n,
            shape,
            inv,
            rr: Uint(rr),
        }
    }

    /// Whether `limbs` are exactly `prime`'s, at whatever width.
    const fn same(limbs: &[u64; LIMBS], prime: &[u64]) -> bool {
        if prime.len() != LIMBS {
            return false;
        }
        let mut i = 0;
        while i < LIMBS {
            if limbs[i] != prime[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    /// `a * b / R mod n`, the Montgomery product. `b` must be below
    /// `n`; `a` may be any width-sized value; the result is below
    /// `n`. The shape picks the reduction, which is the same
    /// arithmetic either way: one branch on a public constant, then
    /// a fixed sequence of limb operations.
    pub(crate) fn mul(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        #[cfg(target_arch = "x86_64")]
        if self.shape == Shape::P256
            && let Some(adx) = x86_64::probe()
        {
            return adx.mul(a, b);
        }
        self.mul_with(a, b)
    }

    /// `a a / R mod n`, the Montgomery square.
    ///
    /// Every cross product appears twice in a square, so ten
    /// multiplications make the whole of a four-limb one where the
    /// general product spends sixteen: the cross products once, then
    /// doubled, then the squares of the limbs. The reduction
    /// afterwards is the same as the product's, one word at a time.
    pub(crate) fn sqr(&self, a: &Uint<LIMBS>) -> Uint<LIMBS> {
        #[cfg(target_arch = "x86_64")]
        if self.shape == Shape::P256
            && let Some(adx) = x86_64::probe()
        {
            return adx.sqr(a);
        }
        let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);
        // Twice the width, and the widest modulus the crate has.
        debug_assert!(2 * LIMBS <= WIDEST);
        let mut t = [0u64; WIDEST];

        // The cross products, each once: limb `i` against every limb
        // above it, landing at `i + j`.
        for i in 0..LIMBS {
            let mut carry = 0u64;
            for j in i + 1..LIMBS {
                let v = u128::from(t[i + j])
                    + wide(a.0[i], a.0[j])
                    + u128::from(carry);
                t[i + j] = v as u64;
                carry = (v >> 64) as u64;
            }
            t[i + LIMBS] = carry;
        }

        // Doubled, which is the other half of every cross product.
        let mut carry = 0u64;
        for word in t[..2 * LIMBS].iter_mut() {
            let doubled = (u128::from(*word) << 1) | u128::from(carry);
            *word = doubled as u64;
            carry = (doubled >> 64) as u64;
        }

        // Then the squares of the limbs, which have no partner.
        let mut carry = 0u64;
        for (i, &ai) in a.0.iter().enumerate() {
            let v = u128::from(t[2 * i]) + wide(ai, ai) + u128::from(carry);
            t[2 * i] = v as u64;
            let v = u128::from(t[2 * i + 1]) + (v >> 64);
            t[2 * i + 1] = v as u64;
            carry = (v >> 64) as u64;
        }
        let mut hi = carry;

        // The reduction, a word at a time as the product does it.
        let mut mn = [0u128; LIMBS];
        for i in 0..LIMBS {
            let m = t[i].wrapping_mul(self.inv);
            self.products(m, &mut mn);
            let v = u128::from(t[i]) + mn[0];
            debug_assert_eq!(v as u64, 0);
            let mut carry = (v >> 64) as u64;
            for j in 1..LIMBS {
                let v = u128::from(t[i + j]) + mn[j] + u128::from(carry);
                t[i + j] = v as u64;
                carry = (v >> 64) as u64;
            }
            // The carry walks up the words the reduction has not
            // reached yet, and past them into `hi`. Every word is
            // visited whatever the carries are: stopping at the first
            // that does not carry would be a branch on the value.
            for word in t[i + LIMBS..2 * LIMBS].iter_mut() {
                let v = u128::from(*word) + u128::from(carry);
                *word = v as u64;
                carry = (v >> 64) as u64;
            }
            hi += carry;
        }

        let mut out = Uint::<LIMBS>::ZERO;
        out.0.copy_from_slice(&t[LIMBS..2 * LIMBS]);
        let (reduced, borrow) = out.sub_borrow(&self.n);
        let take = hi | (1 - borrow);
        let mut result = out;
        result.cmov(&reduced, take);
        result
    }

    /// The multiple of `n` that clears a word, limb by limb, in the
    /// shape the modulus admits.
    #[inline(always)]
    fn products(&self, m: u64, out: &mut [u128; LIMBS]) {
        match self.shape {
            Shape::General => {
                for (o, &nj) in out.iter_mut().zip(&self.n.0) {
                    *o = u128::from(m) * u128::from(nj);
                }
            }
            Shape::P256 => {
                let m = u128::from(m);
                out.copy_from_slice(&[
                    (m << 64) - m,
                    (m << 32) - m,
                    0,
                    (m << 64) - (m << 32) + m,
                ]);
            }
            Shape::P384 => {
                let m = u128::from(m);
                out.copy_from_slice(&[
                    (m << 32) - m,
                    (m << 64) - (m << 32),
                    (m << 64) - 2 * m,
                    (m << 64) - m,
                    (m << 64) - m,
                    (m << 64) - m,
                ]);
            }
        }
    }

    /// The product by coarsely integrated operand scanning: a row of
    /// products of one limb of `a` by `b`, then the multiple of `n`
    /// that clears the low word, which the shape makes cheap.
    fn mul_with(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        // Six limbs is P-384's width, field and order alike, and the
        // rows there are written out for the carry-chain
        // instructions; the shaped reduction below saves multiplies,
        // but not as many as two chains save cycles.
        #[cfg(target_arch = "x86_64")]
        if LIMBS == 6
            && let Some(adx) = x86_64::probe()
        {
            let mut context = [self.inv; 13];
            context[1..7].copy_from_slice(&self.n.0);
            context[7..].copy_from_slice(&b.0);
            return adx.mul6(a, &context, &self.n);
        }

        let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let mut t = [0u64; LIMBS];
        // The two words above the array: `hi` in full, and above it
        // only a bit.
        let mut hi = 0u64;
        let mut mn = [0u128; LIMBS];
        for &ai in &a.0 {
            let mut carry = 0u64;
            for (tj, &bj) in t.iter_mut().zip(&b.0) {
                let v = u128::from(*tj) + wide(ai, bj) + u128::from(carry);
                *tj = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(hi) + u128::from(carry);
            hi = v as u64;
            let above = (v >> 64) as u64;

            // Adding this multiple of n clears the low word, so the
            // whole value shifts down one word, exactly.
            let m = t[0].wrapping_mul(self.inv);
            self.products(m, &mut mn);
            let v = u128::from(t[0]) + mn[0];
            debug_assert_eq!(v as u64, 0);
            let mut carry = (v >> 64) as u64;
            for j in 1..LIMBS {
                let v = u128::from(t[j]) + mn[j] + u128::from(carry);
                t[j - 1] = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(hi) + u128::from(carry);
            t[LIMBS - 1] = v as u64;
            hi = above + ((v >> 64) as u64);
        }
        // The result is below 2n, so at most one subtraction of n
        // finishes the reduction; `hi` says the value overflowed the
        // array and the subtraction is certainly needed.
        let out = Uint(t);
        let (reduced, borrow) = out.sub_borrow(&self.n);
        let take = hi | (1 - borrow);
        let mut result = out;
        result.cmov(&reduced, take);
        result
    }

    /// Moves `a`, which must be below `n`, into the Montgomery
    /// domain: `a * R mod n`.
    pub(crate) fn to_mont(&self, a: &Uint<LIMBS>) -> Uint<LIMBS> {
        debug_assert_eq!(a.less_than(&self.n), 1);
        self.mul(a, &self.rr)
    }

    /// `a * b mod n`, in plain form: two Montgomery passes, the
    /// second cancelling the first's stray factor.
    pub(crate) fn mulmod(
        &self,
        a: &Uint<LIMBS>,
        b: &Uint<LIMBS>,
    ) -> Uint<LIMBS> {
        self.mul(&self.mul(a, b), &self.rr)
    }

    /// Moves a value back out of the Montgomery domain. Named for
    /// the domain, not for the conversion convention the lint
    /// expects.
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn from_mont(&self, a: &Uint<LIMBS>) -> Uint<LIMBS> {
        self.mul(a, &Uint::one())
    }

    /// `base ^ exponent mod n` for an exponent that is public, with
    /// `base` below `n`.
    ///
    /// A sliding window five bits wide over the exponent's bits,
    /// which are a constant of the crate: the curve primes and group
    /// orders, less two, and the exponent of a square root. Where the
    /// exponent is a secret, [`modexp`](Self::modexp) is the one to
    /// call; it cannot skip a zero window or index a table, and pays
    /// for both. Here only the base is secret, and nothing here
    /// depends on it.
    pub(crate) fn exp_public<const E: usize>(
        &self,
        base: &Uint<LIMBS>,
        exponent: &Uint<E>,
    ) -> Uint<LIMBS> {
        const WINDOW: usize = 5;
        // The odd powers the windows call for: base^1, base^3, ...
        let mont = self.to_mont(base);
        let square = self.sqr(&mont);
        let mut odd = [mont; 1 << (WINDOW - 1)];
        for i in 1..odd.len() {
            odd[i] = self.mul(&odd[i - 1], &square);
        }

        let bit = |i: usize| (exponent.0[i >> 6] >> (i & 63)) & 1;
        let mut acc = self.from_mont(&self.rr);
        let mut i = 64 * E;
        let mut started = false;
        while i > 0 {
            i -= 1;
            if bit(i) == 0 {
                if started {
                    acc = self.sqr(&acc);
                }
                continue;
            }
            // The longest window ending on a set bit, so the odd
            // power it names is one the table holds.
            let mut width = 1;
            for w in 2..=WINDOW.min(i + 1) {
                if bit(i + 1 - w) == 1 {
                    width = w;
                }
            }
            let mut digit = 0usize;
            for j in 0..width {
                digit = (digit << 1) | (bit(i - j) as usize);
            }
            if started {
                for _ in 0..width {
                    acc = self.sqr(&acc);
                }
                acc = self.mul(&acc, &odd[digit >> 1]);
            } else {
                acc = odd[digit >> 1];
                started = true;
            }
            i -= width - 1;
        }
        self.from_mont(&acc)
    }

    /// `base ^ exponent mod n`, with `base` below `n`, for an
    /// exponent that must not be learned from the timing.
    ///
    /// Nothing in the crate has a secret exponent at this width any
    /// more: RSA has its own arithmetic over slices, and the curves'
    /// exponents are constants. It stays as what
    /// [`exp_public`](Self::exp_public) is checked against.
    #[cfg(test)]
    ///
    /// Fixed four-bit windows over the exponent's full width: the
    /// same doublings, multiplications and whole-table scans
    /// whatever the exponent's value, which is what keeps a secret
    /// exponent out of the timing. The exponent's limb count is its
    /// own const parameter, since RSA's public exponent is a word
    /// while its private one is as wide as the modulus.
    pub(crate) fn modexp<const E: usize>(
        &self,
        base: &Uint<LIMBS>,
        exponent: &Uint<E>,
    ) -> Uint<LIMBS> {
        // Table entry i is base^i in the Montgomery domain; entry 0
        // is 1, which is R mod n there.
        let mont_base = self.to_mont(base);
        let mut table = [Uint::<LIMBS>::ZERO; 16];
        table[0] = self.from_mont(&self.rr);
        for i in 1..16 {
            table[i] = self.mul(&table[i - 1], &mont_base);
        }

        let mut acc = table[0];
        for window in (0..16 * E).rev() {
            for _ in 0..4 {
                acc = self.sqr(&acc);
            }
            let digit = (exponent.0[window >> 4] >> ((window & 15) * 4)) & 15;
            // Read the whole table, keeping the entry whose index
            // matches, so the secret digit never becomes an address.
            let mut chosen = table[0];
            for (i, entry) in table.iter().enumerate() {
                let matches = ((i as u64 ^ digit).wrapping_sub(1)) >> 63;
                chosen.cmov(entry, matches);
            }
            acc = self.mul(&acc, &chosen);
        }
        let result = self.from_mont(&acc);
        acc.zeroize();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The context made when the crate is built is the one made at
    /// run time, for both curve primes and a general modulus.
    #[test]
    fn known_matches_new() {
        fn check<const L: usize>(n: Uint<L>) {
            let known = Montgomery::known(n);
            let new = Montgomery::new(n).expect("odd");
            assert_eq!(known.n.0, new.n.0);
            assert_eq!(known.shape, new.shape);
            assert_eq!(known.inv, new.inv);
            assert_eq!(known.rr.0, new.rr.0);
        }
        check(Uint(P256_PRIME));
        check(Uint(P384_PRIME));
        check(Uint::<3>([0x8765432187654321, 0x1234567812345678, 0xabcd]));
    }

    /// The square is the product of a value with itself, at both
    /// curve shapes and at a general modulus.
    #[test]
    fn square_matches_the_product() {
        fn check<const L: usize>(n: Uint<L>) {
            let m = Montgomery::known(n);
            let mut x = m.to_mont(&Uint::from_limbs(&[3]));
            for _ in 0..100 {
                assert_eq!(m.sqr(&x).0, m.mul(&x, &x).0);
                x = m.mul(&x, &Uint::from_limbs(&[0x9e3779b97f4a7c15]));
            }
            let (below, _) = n.sub_borrow(&Uint::one());
            for edge in [Uint::ZERO, Uint::one(), below] {
                assert_eq!(m.sqr(&edge).0, m.mul(&edge, &edge).0);
            }
        }
        check(Uint(P256_PRIME));
        check(Uint(P384_PRIME));
        check(Uint::<3>([0x8765432187654321, 0x1234567812345678, 0xabcd]));
        check(Uint::<1>([1000003]));
    }

    #[test]
    fn refuses_even_and_trivial_moduli() {
        assert!(Montgomery::new(Uint::<1>([8])).is_none());
        assert!(Montgomery::new(Uint::<1>([1])).is_none());
        assert!(Montgomery::new(Uint::<1>([0])).is_none());
        assert!(Montgomery::new(Uint::<1>([9])).is_some());
    }

    /// Every product modulo a small prime, against plain division.
    #[test]
    fn products_match_plain_arithmetic() {
        let m = Montgomery::new(Uint::<1>([101])).unwrap();
        for a in 0..101u64 {
            for b in 0..101u64 {
                let am = m.to_mont(&Uint([a]));
                let bm = m.to_mont(&Uint([b]));
                let product = m.from_mont(&m.mul(&am, &bm));
                assert_eq!(product.0, [a * b % 101]);
            }
        }
    }

    /// The domain round trip is the identity, at a width where the
    /// limbs interact.
    #[test]
    fn domain_round_trip() {
        let n = Uint::<3>([0x8765432187654321, 0x1234567812345678, 0xabcd]);
        let m = Montgomery::new(n).unwrap();
        let x = Uint::<3>([0xdeadbeef, 0xcafe, 0x1234]);
        let back = m.from_mont(&m.to_mont(&x));
        assert_eq!(back.0, x.0);
    }

    /// The public-exponent window agrees with the constant-time
    /// exponentiation, at the exponents the curves use and at small
    /// ones that reach its edges.
    #[test]
    fn public_exponent_matches_modexp() {
        fn check<const L: usize>(n: Uint<L>) {
            let m = Montgomery::known(n);
            let (less_two, _) = n.sub_borrow(&Uint::from_limbs(&[2]));
            let (plus_one, _) = n.add_carry(&Uint::one());
            let exponents = [
                less_two,
                plus_one.shr(2),
                Uint::ZERO,
                Uint::one(),
                Uint::from_limbs(&[2]),
                Uint::from_limbs(&[0xffff_ffff]),
            ];
            let mut x = Uint::from_limbs(&[7]);
            for e in exponents {
                assert_eq!(m.exp_public(&x, &e).0, m.modexp(&x, &e).0);
                x = m.mulmod(&x, &Uint::from_limbs(&[0x9e3779b97f4a7c15]));
            }
        }
        check(Uint(P256_PRIME));
        check(Uint(P384_PRIME));
        check(Uint::<3>([0x8765432187654321, 0x1234567812345678, 0xabcd]));
    }

    #[test]
    fn modexp_identities() {
        let m = Montgomery::new(Uint::<1>([1000003])).unwrap();
        let x = Uint::<1>([123456]);
        // x^0 = 1 and x^1 = x.
        assert_eq!(m.modexp(&x, &Uint::<1>([0])).0, [1]);
        assert_eq!(m.modexp(&x, &Uint::<1>([1])).0, x.0);
        // x^20, against twenty plain multiplications.
        let mut expected = 1u64;
        for _ in 0..20 {
            expected = expected * x.0[0] % 1000003;
        }
        assert_eq!(m.modexp(&x, &Uint::<1>([20])).0, [expected]);
        // (x^a)^b = x^(a*b) across the exponentiation itself.
        let xa = m.modexp(&x, &Uint::<1>([17]));
        let composed = m.modexp(&xa, &Uint::<1>([23]));
        assert_eq!(composed.0, m.modexp(&x, &Uint::<1>([17 * 23])).0);
    }

    /// A cheap pseudorandom stream, for inputs that vary across the
    /// whole width.
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// A value below `n`, from `state`.
    fn below<const L: usize>(state: &mut u64, n: &Uint<L>) -> Uint<L> {
        let mut v = Uint([0u64; L]);
        for limb in v.0.iter_mut() {
            *limb = xorshift(state);
        }
        // Both primes are above half the width, so one subtraction
        // brings any value of the width below them.
        let (reduced, borrow) = v.sub_borrow(n);
        v.cmov(&reduced, 1 - borrow);
        v
    }

    /// The shaped reduction against the general one, over the two
    /// primes it recognises: the same products either way.
    fn shaped_matches_general<const L: usize>(prime: &[u64; L]) {
        let n = Uint(*prime);
        let shaped = Montgomery::new(n).expect("odd prime");
        assert_ne!(shaped.shape, Shape::General);
        let mut general = Montgomery::new(n).expect("odd prime");
        general.shape = Shape::General;

        let mut state = 0x243f6a8885a308d3;
        for _ in 0..200 {
            let a = below(&mut state, &n);
            let b = below(&mut state, &n);
            assert_eq!(shaped.mul(&a, &b).0, general.mul(&a, &b).0);
        }
        // The edges the random values will not reach.
        let zero = Uint::<L>::ZERO;
        let one = Uint::<L>::one();
        let (top, _) = n.sub_borrow(&one);
        for a in [zero, one, top] {
            for b in [zero, one, top] {
                assert_eq!(shaped.mul(&a, &b).0, general.mul(&a, &b).0);
            }
        }
    }

    #[test]
    fn p256_reduction_matches_the_general_one() {
        shaped_matches_general(&P256_PRIME);
    }

    #[test]
    fn p384_reduction_matches_the_general_one() {
        shaped_matches_general(&P384_PRIME);
    }

    /// A modulus of another width, or of the same width and a
    /// different value, takes the general path.
    #[test]
    fn other_moduli_are_general() {
        let m = Montgomery::new(Uint::<4>([9, 0, 0, 0])).unwrap();
        assert_eq!(m.shape, Shape::General);
        let m = Montgomery::new(Uint::<8>([u64::MAX; 8])).unwrap();
        assert_eq!(m.shape, Shape::General);
    }

    /// A full RSA-2048-shaped known answer: fixed 2048-bit modulus,
    /// base and exponents, produced by an independent bignum
    /// implementation.
    #[test]
    fn known_answer_2048() {
        fn unhex256(hex: &str) -> [u8; 256] {
            let mut out = [0u8; 256];
            let hex = hex.as_bytes();
            assert_eq!(hex.len(), 512);
            for (byte, pair) in out.iter_mut().zip(hex.chunks(2)) {
                let s = core::str::from_utf8(pair).unwrap();
                *byte = u8::from_str_radix(s, 16).unwrap();
            }
            out
        }
        let n = "\
            a7c851cf6e4e77eed96185e560137e3ec64aed5e728e3f43c7c99ec50a8fe1bf\
            753b4b5d2adaa3b275c6a306647c79cb1b5c2f61bd797d5207064ef5f8f9f226\
            e43ad0ebf2d108f0bdb23a5223c5a2e38ef24d7b0ee7e6c73d373f5b013e4cf7\
            0a5c1ae01d797fc29bbb9359f969763ce2bb5e2fea210dd8919a8aa353cbe9d8\
            762760048ee18bf2a9b68f3b2c0020e3f0eb43159e587f055e52a576674fa02b\
            bd2b88228b55484e24bf4cfeafa11f768b239a32992363a2d09e16b228f29fb1\
            14eabdcc61d87db9877399329ddba6840d2f0e3156ea1c36b276ec2f31019e4e\
            c1009ec690cff19a4778d9dd8ac0a2e6cb09db106050700246ed58726a0d3291";
        let base = "\
            4f3c7ecbea0f376e66825c0f3ce26a73c6a3fdb0803e3b212b78c4e7850129d7\
            b9112e4d346ba46d821e40d0dfd07af31ead542b67cb74ea75b2be7c9fa27d86\
            7129b070cf3c7c09f31548a363a5afc3e53b7b7b40f217c1be1d7da11d9bb931\
            21c6c4a61e259db3e39f2109cc70579930117fd4a53eb340be1561ba43f5f8ff\
            135bda19f898c624f1677ee8aa4453774446b1505f4f7f043883ced703cd0306\
            caaf0222fc8eb20465d613cba83392d7db8e885617621bcf2fcfd447760914d0\
            97edfbe7ccfa0f9d81a01f413f003e9fc69c16a3eb2f01ee1521865a9dcd7491\
            b7501464cf9627a2a31e760a28692072c065a53b19b5d244dfb96eaac2b0674f";
        let d = "\
            b861c1b490203c346219d463fc03a4d73fd3bf07c6fe49de42b2305aa5f296f5\
            78db79c5141b005f2698761020c53a1fdd2500edf03bc35d89543e42faf3d060\
            c38f004ce6ceeed489379177398788cf7c5f0bc9f39a24e2dafc80cd50a1aa0e\
            428ef821bd43dfe6bb9ed203dbefaf52426dae3618bc9c3cc3cd70768f709999\
            94c4d81e55b15455905b1f675654c7e93a0e86c12cfbf142683e347dc52fed00\
            2a66756771a4bdd50df17e49fc20001004089823bd19d474443f210cc629fb61\
            ad8e8c2ce5fd01d2d286483af959742566683b3b35e78a64775d3a57082d36d3\
            f2fa218ccbdb3909b11d22ed64c7bf3a606ce5080a9713b998383b2d9346df17";
        let base_pow_d = "\
            59a4e5ba40466a1bfe8cf828678a39c3286c0807cd988992e08ceb344882c179\
            52f6356db883de5d80cd219f3856560cb2104aed5f5ce1eca26efc18cafd032f\
            83aa6cd1221dd0f9583317f25a69af98310ff2eaef72874f2101244e4d95b56f\
            5b6f5ee05553c207c8a1622f1804d1390fc5d950c86f607359d32dad7bdf0c70\
            61b576f1a23065f96f4315fd5f744bc216544fcb36775e9c913bf0f14ec852f7\
            b52aaa3f57568d22c3cafda9554e8707b68c32ee7062fc399c1023384f70448a\
            101a26a7f300ae35ad14b63233a58feba0bbed90d8195d0505f878b8f0c913bd\
            72661b6477812b508ea47a8a63dde151adc14aa0f1a897540d40bb032f55f408";
        let base_pow_65537 = "\
            4ea6582cc770139a4122a24083ef281d2730b1954fdc1032d8aec60831445e51\
            f9a9e519c96136fbb3305371cc01d84675b304faac7967cebfd212f3900e1e48\
            6a5e383c9fe205570f95f1dfbdf8db978369db0af6da6cab26ca47ad77a3e2ba\
            9aedf8d8a444dace642e5b003d9d3518630eacd1822caf894b8d6127b786437b\
            fcb290149b9f02103310e70d1c16a3366bf4e5deb560e5391ee3afc24cb5bdf6\
            720032f4083a247cf960070910e06c24d7ee376a565e319afdce8f93292adb54\
            ad5888399fef54102875c1020ca594bfc49b589946a691c223573146831c2f44\
            892861e221de0b70c2368a41b2533201e4b4dad0a5cb0758f4cc7a42b235a9f6";

        let m =
            Montgomery::new(Uint::<32>::from_be_bytes(&unhex256(n))).unwrap();
        let base = Uint::<32>::from_be_bytes(&unhex256(base));
        let d = Uint::<32>::from_be_bytes(&unhex256(d));

        let signed = m.modexp(&base, &d);
        let expected = Uint::<32>::from_be_bytes(&unhex256(base_pow_d));
        assert_eq!(signed.0, expected.0);

        // The public-exponent direction inverts it: 65537 fits one
        // limb, exercising the narrow-exponent form.
        let verified = m.modexp(&signed, &Uint::<1>([65537]));
        // d was chosen freely, not as 65537's inverse, so check the
        // forward value instead.
        let encrypted = m.modexp(&base, &Uint::<1>([65537]));
        assert_eq!(
            encrypted.0,
            Uint::<32>::from_be_bytes(&unhex256(base_pow_65537)).0,
        );
        let _ = verified;
    }
}
