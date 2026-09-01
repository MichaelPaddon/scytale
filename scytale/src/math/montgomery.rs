//! Montgomery arithmetic modulo an odd number.
//!
//! Multiplication modulo `n` without ever dividing by `n`: values
//! carry a factor of `R = 2^(64 * LIMBS)`, and the reduction inside
//! each product is a shift. Division only appears as the modular
//! exponentiation's setup, and even there it is repeated doubling.
//! This is the arithmetic under RSA, whose moduli are always odd.
//!
//! # Constant time
//!
//! [`mul`](Montgomery::mul) and [`modexp`](Montgomery::modexp) run
//! a fixed sequence of limb operations for a given width: the final
//! subtraction is chosen by a mask, and the exponentiation reads its
//! table by scanning every entry. The exponent's *width* in limbs is
//! visible; its value, and where its bits lie, are not.

use zeroize::Zeroize;

use super::uint::Uint;

/// The context for arithmetic modulo one odd `n`: the constants that
/// every product needs, computed once.
pub(crate) struct Montgomery<const LIMBS: usize> {
    n: Uint<LIMBS>,
    /// `-1/n` modulo 2^64, which turns the low limb of a product
    /// into the multiple of `n` that clears it.
    inv: u64,
    /// `R^2 mod n`: multiplying by it moves a value into the
    /// Montgomery domain.
    rr: Uint<LIMBS>,
}

impl<const LIMBS: usize> Montgomery<LIMBS> {
    /// A context for the modulus `n`, which must be odd and greater
    /// than one; `None` otherwise.
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
        Some(Montgomery { n, inv, rr })
    }

    pub(crate) fn modulus(&self) -> &Uint<LIMBS> {
        &self.n
    }

    /// `a * b / R mod n`, the Montgomery product, by coarsely
    /// integrated operand scanning. Both inputs must be below `n`,
    /// and the result then is too.
    pub(crate) fn mul(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let mut t = [0u64; LIMBS];
        // The two words above the array: `hi` in full, and above it
        // only a bit.
        let mut hi = 0u64;
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
            let v = u128::from(t[0]) + wide(m, self.n.0[0]);
            debug_assert_eq!(v as u64, 0);
            let mut carry = (v >> 64) as u64;
            for j in 1..LIMBS {
                let v =
                    u128::from(t[j]) + wide(m, self.n.0[j]) + u128::from(carry);
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

    /// Moves a value back out of the Montgomery domain. Named for
    /// the domain, not for the conversion convention the lint
    /// expects.
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn from_mont(&self, a: &Uint<LIMBS>) -> Uint<LIMBS> {
        self.mul(a, &Uint::one())
    }

    /// `base ^ exponent mod n`, with `base` below `n`.
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
                acc = self.mul(&acc, &acc);
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
        let n =
            "a7c851cf6e4e77eed96185e560137e3ec64aed5e728e3f43c7c99ec50a8fe1bf\
            753b4b5d2adaa3b275c6a306647c79cb1b5c2f61bd797d5207064ef5f8f9f226\
            e43ad0ebf2d108f0bdb23a5223c5a2e38ef24d7b0ee7e6c73d373f5b013e4cf7\
            0a5c1ae01d797fc29bbb9359f969763ce2bb5e2fea210dd8919a8aa353cbe9d8\
            762760048ee18bf2a9b68f3b2c0020e3f0eb43159e587f055e52a576674fa02b\
            bd2b88228b55484e24bf4cfeafa11f768b239a32992363a2d09e16b228f29fb1\
            14eabdcc61d87db9877399329ddba6840d2f0e3156ea1c36b276ec2f31019e4e\
            c1009ec690cff19a4778d9dd8ac0a2e6cb09db106050700246ed58726a0d3291";
        let base =
            "4f3c7ecbea0f376e66825c0f3ce26a73c6a3fdb0803e3b212b78c4e7850129d7\
            b9112e4d346ba46d821e40d0dfd07af31ead542b67cb74ea75b2be7c9fa27d86\
            7129b070cf3c7c09f31548a363a5afc3e53b7b7b40f217c1be1d7da11d9bb931\
            21c6c4a61e259db3e39f2109cc70579930117fd4a53eb340be1561ba43f5f8ff\
            135bda19f898c624f1677ee8aa4453774446b1505f4f7f043883ced703cd0306\
            caaf0222fc8eb20465d613cba83392d7db8e885617621bcf2fcfd447760914d0\
            97edfbe7ccfa0f9d81a01f413f003e9fc69c16a3eb2f01ee1521865a9dcd7491\
            b7501464cf9627a2a31e760a28692072c065a53b19b5d244dfb96eaac2b0674f";
        let d =
            "b861c1b490203c346219d463fc03a4d73fd3bf07c6fe49de42b2305aa5f296f5\
            78db79c5141b005f2698761020c53a1fdd2500edf03bc35d89543e42faf3d060\
            c38f004ce6ceeed489379177398788cf7c5f0bc9f39a24e2dafc80cd50a1aa0e\
            428ef821bd43dfe6bb9ed203dbefaf52426dae3618bc9c3cc3cd70768f709999\
            94c4d81e55b15455905b1f675654c7e93a0e86c12cfbf142683e347dc52fed00\
            2a66756771a4bdd50df17e49fc20001004089823bd19d474443f210cc629fb61\
            ad8e8c2ce5fd01d2d286483af959742566683b3b35e78a64775d3a57082d36d3\
            f2fa218ccbdb3909b11d22ed64c7bf3a606ce5080a9713b998383b2d9346df17";
        let base_pow_d =
            "59a4e5ba40466a1bfe8cf828678a39c3286c0807cd988992e08ceb344882c179\
            52f6356db883de5d80cd219f3856560cb2104aed5f5ce1eca26efc18cafd032f\
            83aa6cd1221dd0f9583317f25a69af98310ff2eaef72874f2101244e4d95b56f\
            5b6f5ee05553c207c8a1622f1804d1390fc5d950c86f607359d32dad7bdf0c70\
            61b576f1a23065f96f4315fd5f744bc216544fcb36775e9c913bf0f14ec852f7\
            b52aaa3f57568d22c3cafda9554e8707b68c32ee7062fc399c1023384f70448a\
            101a26a7f300ae35ad14b63233a58feba0bbed90d8195d0505f878b8f0c913bd\
            72661b6477812b508ea47a8a63dde151adc14aa0f1a897540d40bb032f55f408";
        let base_pow_65537 =
            "4ea6582cc770139a4122a24083ef281d2730b1954fdc1032d8aec60831445e51\
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
