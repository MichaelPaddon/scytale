//! Integers of a run-time number of 64-bit limbs, and Montgomery
//! arithmetic over them.
//!
//! The arithmetic under RSA, whose modulus is any length a caller
//! names, so nothing here is a type parameter: a number is a slice
//! of limbs, least significant first, and every operation takes the
//! slices it works on. The fixed-width [`Uint`](super::uint) and
//! [`Montgomery`](super::montgomery) serve the curves, where the
//! width is four or six limbs and known at compile time; this is the
//! same arithmetic written for a width known only at run time, and
//! copies its discipline rather than sharing its code.
//!
//! # Constant time
//!
//! Every operation runs the full length of its slices: no loop exits
//! early, comparisons come from a whole-length borrow, and selection
//! is by mask. Only the lengths, which are public, shape the timing.
//! The exceptions are marked: [`bit_length`] and [`trailing_zeros`]
//! read the value, and are used only where it is no secret or where
//! only its rough size escapes.
//!
//! # Memory
//!
//! Nothing here allocates. Where an operation needs room beyond its
//! output it takes a scratch slice, and says how long.

use zeroize::Zeroize;

/// Reads a big-endian byte string into `out`, least significant limb
/// first, with leading zeros; the string must fit.
pub(crate) fn from_be_bytes(bytes: &[u8], out: &mut [u64]) {
    debug_assert!(bytes.len() <= 8 * out.len());
    out.fill(0);
    for (limb, chunk) in out.iter_mut().zip(bytes.rchunks(8)) {
        let mut word = [0u8; 8];
        word[8 - chunk.len()..].copy_from_slice(chunk);
        *limb = u64::from_be_bytes(word);
    }
}

/// Writes `limbs` big-endian into `out`, left-padded with zeros. The
/// value must fit; the debug assertion holds wherever a caller has
/// checked its inputs.
pub(crate) fn to_be_bytes(limbs: &[u64], out: &mut [u8]) {
    out.fill(0);
    for (chunk, limb) in out.rchunks_mut(8).zip(limbs) {
        let word = limb.to_be_bytes();
        let take = chunk.len();
        chunk.copy_from_slice(&word[8 - take..]);
    }
    for (i, limb) in limbs.iter().enumerate() {
        debug_assert!(8 * i < out.len() || *limb == 0, "does not fit");
    }
}

pub(crate) fn is_odd(a: &[u64]) -> bool {
    a.first().is_some_and(|limb| limb & 1 == 1)
}

pub(crate) fn is_zero(a: &[u64]) -> bool {
    a.iter().fold(0, |acc, limb| acc | limb) == 0
}

/// One where the two are equal, zero otherwise, from every limb.
pub(crate) fn equal(a: &[u64], b: &[u64]) -> u64 {
    debug_assert_eq!(a.len(), b.len());
    let diff = a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y));
    // A zero difference is a one; anything else, a zero.
    (u128::from(diff).wrapping_sub(1) >> 64) as u64 & 1
}

/// `a += b`, returning the carry out of the top: 0 or 1.
pub(crate) fn add_carry(a: &mut [u64], b: &[u64]) -> u64 {
    debug_assert_eq!(a.len(), b.len());
    let mut carry = 0u64;
    for (x, y) in a.iter_mut().zip(b) {
        let v = u128::from(*x) + u128::from(*y) + u128::from(carry);
        *x = v as u64;
        carry = (v >> 64) as u64;
    }
    carry
}

/// `a += b & mask`, for a mask of all ones or all zeros; the carry
/// out of the top.
fn add_masked(a: &mut [u64], b: &[u64], mask: u64) -> u64 {
    debug_assert_eq!(a.len(), b.len());
    let mut carry = 0u64;
    for (x, y) in a.iter_mut().zip(b) {
        let v = u128::from(*x) + u128::from(*y & mask) + u128::from(carry);
        *x = v as u64;
        carry = (v >> 64) as u64;
    }
    carry
}

/// `a -= b`, returning the borrow out of the top: 0 or 1.
pub(crate) fn sub_borrow(a: &mut [u64], b: &[u64]) -> u64 {
    debug_assert_eq!(a.len(), b.len());
    let mut borrow = 0u64;
    for (x, y) in a.iter_mut().zip(b) {
        let (d, b1) = x.overflowing_sub(*y);
        let (d, b2) = d.overflowing_sub(borrow);
        *x = d;
        borrow = u64::from(b1 | b2);
    }
    borrow
}

/// One where `a < b`, zero otherwise, from the borrow of a
/// whole-length subtraction that is not kept.
pub(crate) fn less_than(a: &[u64], b: &[u64]) -> u64 {
    debug_assert_eq!(a.len(), b.len());
    let mut borrow = 0u64;
    for (x, y) in a.iter().zip(b) {
        let (d, b1) = x.overflowing_sub(*y);
        let (_, b2) = d.overflowing_sub(borrow);
        borrow = u64::from(b1 | b2);
    }
    borrow
}

/// Replaces `a` with `b` when `condition` is one, by a mask rather
/// than a branch.
pub(crate) fn cmov(a: &mut [u64], b: &[u64], condition: u64) {
    debug_assert!(condition <= 1);
    debug_assert_eq!(a.len(), b.len());
    let mask = condition.wrapping_neg();
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= (*x ^ y) & mask;
    }
}

/// `a = a + b mod n`, for values already below `n`.
pub(crate) fn add_mod(a: &mut [u64], b: &[u64], n: &[u64]) {
    let carry = add_carry(a, b);
    // The sum is below 2n, so one subtraction settles it; it is
    // wanted when the sum overflowed the length or exceeds n, and
    // otherwise undone.
    let borrow = sub_borrow(a, n);
    let keep = carry | (1 - borrow);
    add_masked(a, n, (1 - keep).wrapping_neg());
}

/// `a = a - b mod n`, for values already below `n`.
pub(crate) fn sub_mod(a: &mut [u64], b: &[u64], n: &[u64]) {
    let borrow = sub_borrow(a, b);
    add_masked(a, n, borrow.wrapping_neg());
}

/// The full product into `out`, which is `a.len() + b.len()` long.
pub(crate) fn mul_wide(a: &[u64], b: &[u64], out: &mut [u64]) {
    debug_assert_eq!(out.len(), a.len() + b.len());
    out.fill(0);
    for (i, &x) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (o, &y) in out[i..].iter_mut().zip(b) {
            let v = u128::from(*o)
                + u128::from(x) * u128::from(y)
                + u128::from(carry);
            *o = v as u64;
            carry = (v >> 64) as u64;
        }
        // Nothing has written this limb yet, so the carry lands whole.
        out[i + b.len()] = carry;
    }
}

/// The number of bits needed to write the value; zero for zero.
/// Not constant time: used where the value's size is no secret, or
/// where only the answer's rough size escapes.
pub(crate) fn bit_length(a: &[u64]) -> usize {
    for (i, limb) in a.iter().enumerate().rev() {
        if *limb != 0 {
            return 64 * i + (64 - limb.leading_zeros() as usize);
        }
    }
    0
}

/// The number of zero bits below the lowest one bit; the full length
/// for zero. Not constant time, for the same reasons.
pub(crate) fn trailing_zeros(a: &[u64]) -> usize {
    let mut count = 0;
    for limb in a {
        if *limb == 0 {
            count += 64;
        } else {
            return count + limb.trailing_zeros() as usize;
        }
    }
    count
}

/// Shifts `a` right by `bits`, in place; `bits` may exceed the
/// length, which leaves zero.
pub(crate) fn shr(a: &mut [u64], bits: usize) {
    let words = bits / 64;
    let within = bits % 64;
    let len = a.len();
    for i in 0..len {
        let from = i + words;
        let mut limb = if from < len { a[from] >> within } else { 0 };
        if within > 0 && from + 1 < len {
            limb |= a[from + 1] << (64 - within);
        }
        a[i] = limb;
    }
}

/// `a *= w`, returning the limb that overflows the top.
pub(crate) fn mul_word(a: &mut [u64], w: u64) -> u64 {
    let mut carry = 0u64;
    for x in a.iter_mut() {
        let v = u128::from(*x) * u128::from(w) + u128::from(carry);
        *x = v as u64;
        carry = (v >> 64) as u64;
    }
    carry
}

/// `a = (top * 2^length + a) / w`, returning the remainder, by
/// schoolbook long division; the quotient must fit the length.
pub(crate) fn div_rem_word(a: &mut [u64], top: u64, w: u64) -> u64 {
    debug_assert!(w != 0 && top < w);
    let mut rem = u128::from(top);
    for x in a.iter_mut().rev() {
        let cur = (rem << 64) | u128::from(*x);
        *x = (cur / u128::from(w)) as u64;
        rem = cur % u128::from(w);
    }
    rem as u64
}

/// The remainder modulo a single word.
pub(crate) fn rem_word(a: &[u64], w: u64) -> u64 {
    debug_assert!(w != 0);
    let mut rem = 0u128;
    for limb in a.iter().rev() {
        rem = ((rem << 64) | u128::from(*limb)) % u128::from(w);
    }
    rem as u64
}

/// `out = value mod m`, where `m` may be shorter than `value` and need
/// not be odd: one shift-and-subtract per bit, every bit taking the
/// same operations, so a secret value stays out of the timing.
pub(crate) fn rem_wide(value: &[u64], m: &[u64], out: &mut [u64]) {
    debug_assert!(!is_zero(m));
    debug_assert_eq!(out.len(), m.len());
    out.fill(0);
    for i in (0..64 * value.len()).rev() {
        let bit = (value[i / 64] >> (i % 64)) & 1;
        // out = 2 out + bit, then one subtraction of m settles it,
        // because out was below m.
        let carry = shl1(out);
        out[0] |= bit;
        let borrow = sub_borrow(out, m);
        let keep = carry | (1 - borrow);
        add_masked(out, m, (1 - keep).wrapping_neg());
    }
}

/// `a <<= 1`, returning the bit shifted out of the top.
fn shl1(a: &mut [u64]) -> u64 {
    let mut carry = 0u64;
    for x in a.iter_mut() {
        let next = *x >> 63;
        *x = (*x << 1) | carry;
        carry = next;
    }
    carry
}

/// Arithmetic modulo one odd `n`, over borrowed limbs: the modulus,
/// the negated inverse of its low limb, and `R^2 mod n` for moving
/// values into the domain, where `R = 2^(64 * n.len())`.
///
/// The words belong to the caller; [`Modulus::prepare`] fills them
/// and a `Modulus` is a view over them.
#[derive(Clone, Copy)]
pub(crate) struct Modulus<'a> {
    n: &'a [u64],
    inv: u64,
    rr: &'a [u64],
}

/// The words [`Modulus::prepare`] writes for a modulus of `limbs`
/// limbs: the modulus and `R^2 mod n`.
pub(crate) const fn modulus_words(limbs: usize) -> usize {
    2 * limbs
}

/// The scratch [`Modulus::modexp`] needs for a modulus of `limbs`
/// limbs: a sixteen-entry table, the base, the accumulator, its
/// square and the entry chosen from the table.
pub(crate) const fn modexp_words(limbs: usize) -> usize {
    20 * limbs
}

impl<'a> Modulus<'a> {
    /// Sets up `n`, which must be odd and greater than one, in
    /// `words`, which is [`modulus_words`] long; the low limb's
    /// negated inverse comes back for the caller to keep beside them.
    /// `None` for an even or trivial modulus.
    pub(crate) fn prepare(n: &[u64], words: &mut [u64]) -> Option<u64> {
        let limbs = n.len();
        debug_assert_eq!(words.len(), modulus_words(limbs));
        if !is_odd(n) || (limbs == 1 && n[0] == 1) {
            return None;
        }
        let (kept, rr) = words.split_at_mut(limbs);
        kept.copy_from_slice(n);

        // The inverse of the low limb by Newton's iteration: each
        // step doubles the bits that are right, and five steps take
        // the seed's guaranteed 3 bits past 64.
        let n0 = n[0];
        let mut inv = n0;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
        }
        let inv = inv.wrapping_neg();
        debug_assert_eq!(n0.wrapping_mul(inv), u64::MAX);

        // R^2 mod n, by doubling 1 up to 2^(2 * 64 * limbs). Slow and
        // simple; it runs once per modulus.
        rr.fill(0);
        rr[0] = 1;
        for _ in 0..2 * 64 * limbs {
            let carry = shl1(rr);
            let borrow = sub_borrow(rr, n);
            let keep = carry | (1 - borrow);
            add_masked(rr, n, (1 - keep).wrapping_neg());
        }
        Some(inv)
    }

    /// A view over words that [`prepare`](Self::prepare) filled, with
    /// the inverse it returned.
    pub(crate) fn new(words: &'a [u64], inv: u64) -> Self {
        let limbs = words.len() / 2;
        let (n, rr) = words.split_at(limbs);
        Modulus { n, inv, rr }
    }

    pub(crate) fn modulus(&self) -> &'a [u64] {
        self.n
    }

    pub(crate) fn limbs(&self) -> usize {
        self.n.len()
    }

    /// `out = a * b / R mod n`, the Montgomery product, by coarsely
    /// integrated operand scanning. `b` must be below `n`; `a` may be
    /// any value of the length; the result is below `n`. `out` may
    /// not alias either input.
    pub(crate) fn mul(&self, a: &[u64], b: &[u64], out: &mut [u64]) {
        let limbs = self.limbs();
        debug_assert!(
            a.len() == limbs && b.len() == limbs && out.len() == limbs
        );
        let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);
        // Resliced to one length, so the compiler can see that every
        // index below is in bounds and drop the checks.
        let n = &self.n[..limbs];
        let t = &mut out[..limbs];
        t.fill(0);
        // The two limbs above the array: `hi` in full, and above it
        // only a bit.
        let mut hi = 0u64;
        for &ai in a {
            let mut carry = 0u64;
            for (tj, &bj) in t.iter_mut().zip(b) {
                let v = u128::from(*tj) + wide(ai, bj) + u128::from(carry);
                *tj = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(hi) + u128::from(carry);
            hi = v as u64;
            let above = (v >> 64) as u64;

            // Adding this multiple of n clears the low limb, so the
            // whole value shifts down one limb, exactly.
            let m = t[0].wrapping_mul(self.inv);
            let v = u128::from(t[0]) + wide(m, n[0]);
            debug_assert_eq!(v as u64, 0);
            let mut carry = (v >> 64) as u64;
            for j in 1..limbs {
                let v = u128::from(t[j]) + wide(m, n[j]) + u128::from(carry);
                t[j - 1] = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(hi) + u128::from(carry);
            t[limbs - 1] = v as u64;
            hi = above + ((v >> 64) as u64);
        }
        // The result is below 2n, so at most one subtraction of n
        // finishes the reduction; `hi` says the value overflowed the
        // array and the subtraction is certainly needed.
        let borrow = sub_borrow(t, n);
        let keep = hi | (1 - borrow);
        add_masked(t, n, (1 - keep).wrapping_neg());
    }

    /// `out = a * R mod n`: lifts `a`, which must be below `n`, into
    /// the Montgomery domain.
    pub(crate) fn lift(&self, a: &[u64], out: &mut [u64]) {
        debug_assert_eq!(less_than(a, self.n), 1);
        self.mul(a, self.rr, out);
    }

    /// `out = a / R mod n`: lowers a value back out of the domain.
    /// The product of `a` and `1` in the domain is the reduction of
    /// `a` alone, since every limb of `1` above the first is zero, so
    /// the one is never built.
    pub(crate) fn lower(&self, a: &[u64], out: &mut [u64]) {
        let limbs = self.limbs();
        let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let t = out;
        t.fill(0);
        let mut hi = 0u64;
        for &ai in a {
            // Multiplying by one adds `ai` to the low limb; the
            // other limbs of the multiplier are zero.
            let v = u128::from(t[0]) + u128::from(ai);
            t[0] = v as u64;
            let mut carry = (v >> 64) as u64;
            for tj in t.iter_mut().skip(1) {
                let v = u128::from(*tj) + u128::from(carry);
                *tj = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(hi) + u128::from(carry);
            hi = v as u64;
            let above = (v >> 64) as u64;

            let m = t[0].wrapping_mul(self.inv);
            let v = u128::from(t[0]) + wide(m, self.n[0]);
            debug_assert_eq!(v as u64, 0);
            let mut carry = (v >> 64) as u64;
            for j in 1..limbs {
                let v =
                    u128::from(t[j]) + wide(m, self.n[j]) + u128::from(carry);
                t[j - 1] = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(hi) + u128::from(carry);
            t[limbs - 1] = v as u64;
            hi = above + ((v >> 64) as u64);
        }
        let borrow = sub_borrow(t, self.n);
        let keep = hi | (1 - borrow);
        add_masked(t, self.n, (1 - keep).wrapping_neg());
    }

    /// `out = a * b mod n`, in plain form: two Montgomery passes, the
    /// second cancelling the first's stray factor. `scratch` is one
    /// length.
    pub(crate) fn mulmod(
        &self,
        a: &[u64],
        b: &[u64],
        out: &mut [u64],
        scratch: &mut [u64],
    ) {
        let limbs = self.limbs();
        let t = &mut scratch[..limbs];
        self.mul(a, b, t);
        self.mul(t, self.rr, out);
        t.zeroize();
    }

    /// `out = value mod n` for a `value` of any length, which may hold
    /// anything; only the result is reduced. `scratch` is two lengths.
    ///
    /// The value is folded a length at a time from the top: each
    /// fold moves the running remainder up a whole length by a
    /// product with `R^2`, which is `R` once the domain factor is
    /// taken, and adds the next piece.
    pub(crate) fn reduce(
        &self,
        value: &[u64],
        out: &mut [u64],
        scratch: &mut [u64],
    ) {
        let limbs = self.limbs();
        let (acc, lifted) = scratch[..2 * limbs].split_at_mut(limbs);
        acc.fill(0);
        let pieces = value.len().div_ceil(limbs);
        for i in (0..pieces).rev() {
            // lifted = acc * R mod n: the Montgomery product of acc
            // and R^2.
            self.mul(acc, self.rr, lifted);
            // The next piece, reduced by the same route: up into
            // the domain by R^2, then back down by one.
            let start = i * limbs;
            let end = (start + limbs).min(value.len());
            out.fill(0);
            out[..end - start].copy_from_slice(&value[start..end]);
            self.mul(out, self.rr, acc);
            self.lower(acc, out);
            add_mod(out, lifted, self.n);
            acc.copy_from_slice(out);
        }
        out.copy_from_slice(acc);
        acc.zeroize();
        lifted.zeroize();
    }

    /// `out = base ^ exponent mod n`, with `base` below `n`.
    ///
    /// Fixed four-bit windows over the exponent's full length: the
    /// same doublings, multiplications and whole-table scans whatever
    /// the exponent's value, which is what keeps a secret exponent
    /// out of the timing. The exponent's length in limbs is visible;
    /// RSA's public exponent is one limb and its private one is the
    /// modulus's length. `scratch` is [`modexp_words`] long.
    pub(crate) fn modexp(
        &self,
        base: &[u64],
        exponent: &[u64],
        out: &mut [u64],
        scratch: &mut [u64],
    ) {
        let limbs = self.limbs();
        debug_assert!(base.len() == limbs && out.len() == limbs);
        debug_assert!(scratch.len() >= modexp_words(limbs));
        let scratch = &mut scratch[..modexp_words(limbs)];
        let (table, rest) = scratch.split_at_mut(16 * limbs);
        let (mont_base, rest) = rest.split_at_mut(limbs);
        let (acc, rest) = rest.split_at_mut(limbs);
        let (square, chosen) = rest.split_at_mut(limbs);

        // Table entry i is base^i in the Montgomery domain; entry 0
        // is 1, which is R mod n there.
        self.lift(base, mont_base);
        {
            let (zero, rest) = table.split_at_mut(limbs);
            self.lower(self.rr, zero);
            let mut previous: &[u64] = zero;
            for entry in rest.chunks_exact_mut(limbs) {
                self.mul(previous, mont_base, entry);
                previous = entry;
            }
        }

        // The accumulator and its product alternate between two
        // slices rather than copying the product back each time.
        let (mut acc, mut product) = (acc, square);
        acc.copy_from_slice(&table[..limbs]);
        for window in (0..16 * exponent.len()).rev() {
            for _ in 0..4 {
                self.mul(acc, acc, product);
                core::mem::swap(&mut acc, &mut product);
            }
            let digit = (exponent[window >> 4] >> ((window & 15) * 4)) & 15;
            // Read the whole table, keeping the entry whose index
            // matches, so the secret digit never becomes an address.
            chosen.copy_from_slice(&table[..limbs]);
            for (i, entry) in table.chunks_exact(limbs).enumerate() {
                let matches = ((i as u64 ^ digit).wrapping_sub(1)) >> 63;
                cmov(chosen, entry, matches);
            }
            self.mul(acc, chosen, product);
            core::mem::swap(&mut acc, &mut product);
        }
        self.lower(acc, out);
        scratch.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_with_padding() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11];
        let mut x = [0u64; 2];
        from_be_bytes(&bytes, &mut x);
        assert_eq!(x, [0x3456789abcdef011, 0x12]);
        let mut out = [0xffu8; 12];
        to_be_bytes(&x, &mut out);
        assert_eq!(out[..3], [0, 0, 0]);
        assert_eq!(out[3..], bytes);
    }

    #[test]
    fn carries_borrows_and_comparison() {
        let mut max = [u64::MAX, u64::MAX];
        assert_eq!(add_carry(&mut max, &[1, 0]), 1);
        assert!(is_zero(&max));
        let mut zero = [0u64, 0];
        assert_eq!(sub_borrow(&mut zero, &[1, 0]), 1);
        assert_eq!(zero, [u64::MAX, u64::MAX]);
        assert_eq!(less_than(&[5, 1], &[2, 3]), 1);
        assert_eq!(less_than(&[2, 3], &[5, 1]), 0);
        assert_eq!(less_than(&[5, 1], &[5, 1]), 0);
        assert_eq!(equal(&[5, 1], &[5, 1]), 1);
        assert_eq!(equal(&[5, 1], &[5, 2]), 0);
    }

    #[test]
    fn modular_add_and_sub_wrap() {
        let n = [7u64];
        let mut x = [3u64];
        for want in [6u64, 5, 3] {
            let copy = x;
            add_mod(&mut x, &copy, &n);
            assert_eq!(x, [want]);
        }
        sub_mod(&mut x, &[5], &n);
        assert_eq!(x, [5]);
        // A modulus with the top bit set exercises the carry path.
        let n = [(1u64 << 63) + 1];
        let mut x = [1u64 << 63];
        let copy = x;
        add_mod(&mut x, &copy, &n);
        assert_eq!(x, [(1 << 63) - 1]);
    }

    #[test]
    fn sizes_shifts_and_words() {
        let mut x = [0u64, 0b1100];
        assert_eq!(bit_length(&x), 68);
        assert_eq!(trailing_zeros(&x), 66);
        shr(&mut x, 66);
        assert_eq!(x, [0b11, 0]);
        let mut x = [0x123456789abcdef0u64, 0xfedcba9876543210];
        let original = x;
        let top = mul_word(&mut x, 0xdeadbeef);
        assert_eq!(div_rem_word(&mut x, top, 0xdeadbeef), 0);
        assert_eq!(x, original);
        assert_eq!(rem_word(&[1000], 7), 1000 % 7);
    }

    #[test]
    fn wide_remainder_matches_the_word_one() {
        let x = [0x1111u64, 0x2222, 0x3333, 0x4444];
        for m in [0x1234567891u64, 0x100000006] {
            let mut out = [0u64];
            rem_wide(&x, &[m], &mut out);
            assert_eq!(out, [rem_word(&x, m)]);
        }
        let mut wide = [0u64; 8];
        mul_wide(&x, &x, &mut wide);
        let mut out = [0u64];
        rem_wide(&wide, &[65537], &mut out);
        let direct = rem_word(&x, 65537) * rem_word(&x, 65537) % 65537;
        assert_eq!(out, [direct]);
    }

    fn modulus(n: &[u64], words: &mut [u64]) -> u64 {
        Modulus::prepare(n, words).expect("odd modulus")
    }

    #[test]
    fn refuses_even_and_trivial_moduli() {
        let mut words = [0u64; 2];
        assert!(Modulus::prepare(&[8], &mut words).is_none());
        assert!(Modulus::prepare(&[1], &mut words).is_none());
        assert!(Modulus::prepare(&[0], &mut words).is_none());
        assert!(Modulus::prepare(&[9], &mut words).is_some());
    }

    /// Every product modulo a small prime, against plain division.
    #[test]
    fn products_match_plain_arithmetic() {
        let mut words = [0u64; 2];
        let inv = modulus(&[101], &mut words);
        let m = Modulus::new(&words, inv);
        let mut scratch = [0u64; 4];
        for a in 0..101u64 {
            for b in 0..101u64 {
                let mut out = [0u64];
                m.mulmod(&[a], &[b], &mut out, &mut scratch);
                assert_eq!(out, [a * b % 101]);
            }
        }
    }

    /// The domain round trip is the identity, at a length where the
    /// limbs interact.
    #[test]
    fn domain_round_trip() {
        let n = [0x8765432187654321u64, 0x1234567812345678, 0xabcd];
        let mut words = [0u64; 6];
        let inv = modulus(&n, &mut words);
        let m = Modulus::new(&words, inv);
        let x = [0xdeadbeefu64, 0xcafe, 0x1234];
        let mut mont = [0u64; 3];
        let mut back = [0u64; 3];
        m.lift(&x, &mut mont);
        m.lower(&mont, &mut back);
        assert_eq!(back, x);
    }

    #[test]
    fn modexp_identities() {
        let mut words = [0u64; 2];
        let inv = modulus(&[1000003], &mut words);
        let m = Modulus::new(&words, inv);
        let mut scratch = [0u64; 20];
        let x = [123456u64];
        let mut out = [0u64];
        m.modexp(&x, &[0], &mut out, &mut scratch);
        assert_eq!(out, [1]);
        m.modexp(&x, &[1], &mut out, &mut scratch);
        assert_eq!(out, x);
        let mut expected = 1u64;
        for _ in 0..20 {
            expected = expected * x[0] % 1000003;
        }
        m.modexp(&x, &[20], &mut out, &mut scratch);
        assert_eq!(out, [expected]);
        let mut xa = [0u64];
        m.modexp(&x, &[17], &mut xa, &mut scratch);
        let mut composed = [0u64];
        m.modexp(&xa, &[23], &mut composed, &mut scratch);
        m.modexp(&x, &[17 * 23], &mut out, &mut scratch);
        assert_eq!(composed, out);
    }

    /// A value wider than the modulus reduces to what the bit-by-bit
    /// remainder says.
    #[test]
    fn reduce_matches_the_slow_remainder() {
        let n = [0x8765432187654321u64, 0x1234567812345678, 0xabcd];
        let mut words = [0u64; 6];
        let inv = modulus(&n, &mut words);
        let m = Modulus::new(&words, inv);
        let value = [0x1111u64, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x77];
        let mut want = [0u64; 3];
        rem_wide(&value, &n, &mut want);
        let mut got = [0u64; 3];
        let mut scratch = [0u64; 6];
        m.reduce(&value, &mut got, &mut scratch);
        assert_eq!(got, want);
        // And a value shorter than the modulus, which is itself.
        m.reduce(&[5], &mut got, &mut scratch);
        assert_eq!(got, [5, 0, 0]);
    }
}
