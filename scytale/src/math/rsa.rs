//! The RSA key machinery shared by the signature and key transport
//! schemes: key validation and import, the modular exponentiations,
//! Chinese remainder recombination with its fault check, key
//! generation, and MGF1. The schemes in [`sig::rsa`](crate::sig::rsa)
//! and [`kex::rsa`](crate::kex::rsa) wrap these in distinct key
//! types, so a signing key cannot decrypt and a decryption key
//! cannot sign.

use zeroize::Zeroize;

use crate::cipher::Block;
use crate::hash::Hash;
use crate::math::montgomery::Montgomery;
use crate::math::uint::Uint;
use crate::random::Random;
use crate::Error;

/// The public half of an RSA key: the modulus in Montgomery form and
/// the public exponent.
pub(crate) struct Public<const LIMBS: usize, const BYTES: usize> {
    pub(crate) m: Montgomery<LIMBS>,
    e: Uint<1>,
}

/// The private half: the exponent, and the Chinese remainder pieces
/// when the key came in with its primes. Wiped on drop.
pub(crate) struct Private<
    const LIMBS: usize,
    const BYTES: usize,
    const HALF: usize,
> {
    d: Uint<LIMBS>,
    crt: Option<Crt<HALF>>,
}

/// The Chinese remainder pieces of a private key.
struct Crt<const HALF: usize> {
    p: Montgomery<HALF>,
    q: Montgomery<HALF>,
    dp: Uint<HALF>,
    dq: Uint<HALF>,
    /// `q^-1 mod p`.
    qinv: Uint<HALF>,
}

impl<const LIMBS: usize, const BYTES: usize> Public<LIMBS, BYTES> {
    /// A public half from its big-endian parts.
    ///
    /// The modulus must be exactly the type's width, top bit set,
    /// and odd. The exponent must be odd, at least 3, and fit eight
    /// bytes, which every deployed key's does.
    pub(crate) fn try_new(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        // A mismatched pair of const parameters is a bug at the
        // definition of an alias, not a runtime condition.
        assert_eq!(8 * LIMBS, BYTES, "BYTES must be 8 * LIMBS");
        if n.len() != BYTES {
            return Err(Error::InvalidKeyLength(n.len()));
        }
        let n = Uint::<LIMBS>::from_be_bytes(n);
        if n.0[LIMBS - 1] >> 63 == 0 {
            return Err(Error::InvalidKeyLength(BYTES));
        }
        let m = Montgomery::new(n).ok_or(Error::InvalidPublicKey)?;

        let e_bytes = strip_leading_zeros(e);
        if e_bytes.len() > 8 {
            return Err(Error::InvalidPublicKey);
        }
        let e = Uint::<1>::from_be_bytes(e_bytes);
        if !e.is_odd() || e.0[0] < 3 {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Public { m, e })
    }

    /// The public operation, `input^e mod n`, or `None` when the
    /// representative is at or above the modulus. The caller names
    /// the error, which differs by scheme.
    pub(crate) fn apply(&self, input: &[u8; BYTES]) -> Option<[u8; BYTES]> {
        let s = Uint::<LIMBS>::from_be_bytes(input);
        if s.less_than(self.m.modulus()) == 0 {
            return None;
        }
        let em = self.m.modexp(&s, &self.e);
        let mut out = [0u8; BYTES];
        em.to_be_bytes(&mut out);
        Some(out)
    }

    /// The modulus, big-endian.
    pub(crate) fn modulus_bytes(&self) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        self.m.modulus().to_be_bytes(&mut out);
        out
    }

    /// The public exponent, big-endian in eight bytes.
    pub(crate) fn exponent_bytes(&self) -> [u8; 8] {
        self.e.0[0].to_be_bytes()
    }
}

impl<const LIMBS: usize, const BYTES: usize, const HALF: usize>
    Private<LIMBS, BYTES, HALF>
{
    /// A private half from the big-endian exponent, which must be
    /// nonzero and below the modulus of `public`.
    pub(crate) fn try_new(
        public: &Public<LIMBS, BYTES>,
        d: &[u8],
    ) -> Result<Self, Error> {
        assert_eq!(2 * HALF, LIMBS, "HALF must be LIMBS / 2");
        if d.len() > BYTES {
            return Err(Error::InvalidPrivateKey);
        }
        let d = Uint::<LIMBS>::from_be_bytes(d);
        if d.is_zero() || d.less_than(public.m.modulus()) == 0 {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(Private { d, crt: None })
    }

    /// A private half with its Chinese remainder pieces: `p` and `q`
    /// exactly half the modulus wide with their top bits set, the
    /// reduced exponents `dp` and `dq`, and `qinv`, the inverse of
    /// `q` modulo `p`.
    ///
    /// The pieces are checked against one another: the primes must
    /// multiply to the modulus and `qinv` must invert `q`. A wrong
    /// `dp` or `dq` cannot be caught here, and is caught instead by
    /// the check every private operation gets before its result is
    /// released.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new_crt(
        public: &Public<LIMBS, BYTES>,
        d: &[u8],
        p: &[u8],
        q: &[u8],
        dp: &[u8],
        dq: &[u8],
        qinv: &[u8],
    ) -> Result<Self, Error> {
        let mut key = Self::try_new(public, d)?;

        let half = |part: &[u8]| -> Result<Uint<HALF>, Error> {
            if part.len() > BYTES / 2 {
                return Err(Error::InvalidPrivateKey);
            }
            Ok(Uint::from_be_bytes(part))
        };
        let p_value = half(p)?;
        let q_value = half(q)?;
        // Top bits set, so each prime is exactly half the width,
        // which the reduction of `q` modulo `p` below relies on.
        if p_value.0[HALF - 1] >> 63 == 0 || q_value.0[HALF - 1] >> 63 == 0 {
            return Err(Error::InvalidPrivateKey);
        }
        let (difference, _) = p_value.sub_borrow(&q_value);
        if difference.is_zero() {
            return Err(Error::InvalidPrivateKey);
        }
        if p_value.mul_wide::<LIMBS>(&q_value).0 != public.m.modulus().0 {
            return Err(Error::InvalidPrivateKey);
        }
        let p = Montgomery::new(p_value).ok_or(Error::InvalidPrivateKey)?;
        let q = Montgomery::new(q_value).ok_or(Error::InvalidPrivateKey)?;

        let dp = half(dp)?;
        let dq = half(dq)?;
        let qinv = half(qinv)?;
        if dp.is_zero()
            || dp.less_than(p.modulus()) == 0
            || dq.is_zero()
            || dq.less_than(q.modulus()) == 0
            || qinv.is_zero()
            || qinv.less_than(p.modulus()) == 0
        {
            return Err(Error::InvalidPrivateKey);
        }
        // qinv really must invert q; a wrong value here would only
        // surface as every private operation failing its final check.
        let q_mod_p = reduce_once_mod(q.modulus(), p.modulus());
        if p.mulmod(&qinv, &q_mod_p).0 != Uint::<HALF>::one().0 {
            return Err(Error::InvalidPrivateKey);
        }

        key.crt = Some(Crt { p, q, dp, dq, qinv });
        Ok(key)
    }

    /// The private operation: `em^d mod n`, or through the primes
    /// when the key carries them.
    pub(crate) fn apply(
        &self,
        public: &Public<LIMBS, BYTES>,
        em: &[u8; BYTES],
    ) -> Result<[u8; BYTES], Error> {
        let m = Uint::<LIMBS>::from_be_bytes(em);
        let s = match &self.crt {
            Some(crt) => {
                let s = crt.apply(&m);
                // One faulty CRT result factors the modulus (Boneh,
                // DeMillo and Lipton), so check with the public
                // exponent before anything leaves. This also catches
                // a wrong dp or dq, which import cannot.
                if public.m.modexp(&s, &public.e).0 != m.0 {
                    return Err(Error::InvalidPrivateKey);
                }
                s
            }
            None => public.m.modexp(&m, &self.d),
        };
        let mut out = [0u8; BYTES];
        s.to_be_bytes(&mut out);
        Ok(out)
    }

    /// Generates a fresh key, with the public exponent 65537 and
    /// every Chinese remainder piece in place.
    ///
    /// The primes are random probable primes: trial division, then
    /// Miller-Rabin with random witnesses, with round counts read
    /// from FIPS 186-5 for random candidates of 1024 bits and up.
    pub(crate) fn generate<R: Random>(
        rng: &mut R,
    ) -> Result<(Public<LIMBS, BYTES>, Self), Error> {
        assert_eq!(2 * HALF, LIMBS, "HALF must be LIMBS / 2");
        const E_WORD: u64 = 65537;

        let mut p = probable_prime::<HALF, R>(rng)?;
        let mut q = Uint::<HALF>::ZERO;
        let mut found = false;
        for _ in 0..64 {
            q = probable_prime::<HALF, R>(rng)?;
            // FIPS 186-5: the primes must not be close, or Fermat
            // factoring splits the modulus.
            let (a, borrow) = p.sub_borrow(&q);
            let mut difference = a;
            difference.cmov(&q.sub_borrow(&p).0, borrow);
            if difference.bit_length() > (64 * HALF).saturating_sub(100) {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::KeyGenerationFailed);
        }

        let n = p.mul_wide::<LIMBS>(&q);

        // phi = (p-1)(q-1) = n - p - q + 1; no borrow can happen.
        let phi = n
            .sub_borrow(&p.widen())
            .0
            .sub_borrow(&q.widen())
            .0
            .add_carry(&Uint::one())
            .0;

        // d = (1 + k * phi) / e for the k that makes the division
        // exact: k = -phi^-1 mod e. The whole inversion happens in
        // one word, because e does.
        let phi_mod_e = phi.rem_word(E_WORD);
        let k = E_WORD - inv_mod_word(phi_mod_e, E_WORD);
        let (k_phi, top) = phi.mul_word(k);
        let (with_one, carry) = k_phi.add_carry(&Uint::one());
        let (mut d, remainder) = with_one.div_rem_word(top + carry, E_WORD);
        debug_assert_eq!(remainder, 0);

        // The Chinese remainder pieces. p is prime, so the inverse
        // of q is a Fermat power, and the exponentiations that need
        // an even modulus are plain bit-by-bit remainders instead.
        let mut p_minus_1 = p.sub_borrow(&Uint::one()).0;
        let mut q_minus_1 = q.sub_borrow(&Uint::one()).0;
        let mut dp = d.rem_wide::<HALF>(&p_minus_1);
        let mut dq = d.rem_wide::<HALF>(&q_minus_1);
        let mont_p = Montgomery::new(p).ok_or(Error::KeyGenerationFailed)?;
        let q_mod_p = reduce_once_mod(&q, &p);
        let mut p_minus_2 = p.sub_borrow(&Uint::from_limbs(&[2])).0;
        let mut qinv = mont_p.modexp(&q_mod_p, &p_minus_2);

        // Out through bytes and back through try_new_crt, so a
        // generated key passes exactly the checks an imported one
        // does.
        let mut n_bytes = [0u8; BYTES];
        n.to_be_bytes(&mut n_bytes);
        let mut d_bytes = [0u8; BYTES];
        d.to_be_bytes(&mut d_bytes);
        let mut halves = [[0u8; BYTES]; 5];
        for (buf, value) in halves.iter_mut().zip([p, q, dp, dq, qinv]) {
            value.to_be_bytes(&mut buf[..BYTES / 2]);
        }
        let key = Public::try_new(&n_bytes, &E_WORD.to_be_bytes()).and_then(
            |public| {
                let private = Self::try_new_crt(
                    &public,
                    &d_bytes,
                    &halves[0][..BYTES / 2],
                    &halves[1][..BYTES / 2],
                    &halves[2][..BYTES / 2],
                    &halves[3][..BYTES / 2],
                    &halves[4][..BYTES / 2],
                )?;
                Ok((public, private))
            },
        );

        p.zeroize();
        q.zeroize();
        d.zeroize();
        dp.zeroize();
        dq.zeroize();
        qinv.zeroize();
        p_minus_1.zeroize();
        q_minus_1.zeroize();
        p_minus_2.zeroize();
        d_bytes.zeroize();
        for buf in halves.iter_mut() {
            buf.zeroize();
        }
        key
    }

    /// The private exponent, big-endian. The caller holds a secret
    /// now, and should wipe it when done.
    pub(crate) fn d_bytes(&self) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        self.d.to_be_bytes(&mut out);
        out
    }

    /// Writes the Chinese remainder pieces, big-endian, into five
    /// buffers of half the modulus width each. Fails with
    /// [`Error::InvalidPrivateKey`] on a key imported without them,
    /// and [`Error::InvalidLength`] on a buffer of the wrong size.
    /// The caller holds secrets now, and should wipe them when done.
    pub(crate) fn crt_bytes(
        &self,
        p: &mut [u8],
        q: &mut [u8],
        dp: &mut [u8],
        dq: &mut [u8],
        qinv: &mut [u8],
    ) -> Result<(), Error> {
        let crt = self.crt.as_ref().ok_or(Error::InvalidPrivateKey)?;
        for out in [&p, &q, &dp, &dq, &qinv] {
            if out.len() != BYTES / 2 {
                return Err(Error::InvalidLength(out.len()));
            }
        }
        crt.p.modulus().to_be_bytes(p);
        crt.q.modulus().to_be_bytes(q);
        crt.dp.to_be_bytes(dp);
        crt.dq.to_be_bytes(dq);
        crt.qinv.to_be_bytes(qinv);
        Ok(())
    }
}

impl<const HALF: usize> Crt<HALF> {
    /// Garner's recombination: exponentiate modulo each prime, then
    /// lift: `s = sq + q * (qinv * (sp - sq) mod p)`, which is below
    /// `p * q` with no final reduction.
    fn apply<const LIMBS: usize>(&self, m: &Uint<LIMBS>) -> Uint<LIMBS> {
        let lo = Uint::<HALF>::from_limbs(&m.0[..HALF]);
        let hi = Uint::<HALF>::from_limbs(&m.0[HALF..]);
        let mut mp = self.p.reduce_wide(&lo, &hi);
        let mut mq = self.q.reduce_wide(&lo, &hi);
        let mut sp = self.p.modexp(&mp, &self.dp);
        let mut sq = self.q.modexp(&mq, &self.dq);

        let sq_mod_p = reduce_once_mod(&sq, self.p.modulus());
        let mut difference = sp.sub_mod(&sq_mod_p, self.p.modulus());
        let mut h = self.p.mulmod(&self.qinv, &difference);
        let (s, carry) = self
            .q
            .modulus()
            .mul_wide::<LIMBS>(&h)
            .add_carry(&sq.widen());
        debug_assert_eq!(carry, 0);

        mp.zeroize();
        mq.zeroize();
        sp.zeroize();
        sq.zeroize();
        difference.zeroize();
        h.zeroize();
        s
    }
}

/// Draws random candidates until one survives trial division and
/// Miller-Rabin. The cap on attempts is FIPS 186-5's, and failing it
/// means the random source is not producing usable candidates.
fn probable_prime<const HALF: usize, R: Random>(
    rng: &mut R,
) -> Result<Uint<HALF>, Error> {
    for _ in 0..5 * 64 * HALF {
        let mut limbs = [0u64; HALF];
        for limb in limbs.iter_mut() {
            let mut bytes = [0u8; 8];
            rng.fill(&mut bytes)?;
            *limb = u64::from_le_bytes(bytes);
        }
        // Odd, and with the top two bits set so the product of two
        // candidates fills the modulus width exactly.
        limbs[0] |= 1;
        limbs[HALF - 1] |= 3 << 62;
        let mut candidate = Uint(limbs);
        limbs.zeroize();

        // Trial division by every odd number to 2000; the composite
        // divisors are redundant but harmless, and the loop stays
        // two lines.
        let mut divisor = 3u64;
        let mut composite = false;
        while divisor < 2000 {
            if candidate.rem_word(divisor) == 0 {
                composite = true;
                break;
            }
            divisor += 2;
        }
        // A prime congruent to 1 mod e would make e share a factor
        // with phi, and no d would exist.
        if composite || candidate.rem_word(65537) == 1 {
            candidate.zeroize();
            continue;
        }
        if miller_rabin(&candidate, rng)? {
            return Ok(candidate);
        }
        candidate.zeroize();
    }
    Err(Error::KeyGenerationFailed)
}

/// Miller-Rabin with random witnesses. Eight rounds: FIPS 186-5
/// table B.1 asks for at most five on random candidates of 1024
/// bits, and the extras are margin for the narrower legacy widths.
fn miller_rabin<const HALF: usize, R: Random>(
    candidate: &Uint<HALF>,
    rng: &mut R,
) -> Result<bool, Error> {
    let m = Montgomery::new(*candidate).ok_or(Error::KeyGenerationFailed)?;
    let one = Uint::<HALF>::one();
    let minus_one = candidate.sub_borrow(&one).0;
    // candidate - 1 = 2^s * t with t odd.
    let s = minus_one.trailing_zeros();
    let mut t = minus_one.shr(s);

    'witness: for _ in 0..8 {
        // A random witness below the candidate: clearing the top
        // bit is enough, since the candidate has it set, and tiny
        // witnesses are nudged to two.
        let mut limbs = [0u64; HALF];
        for limb in limbs.iter_mut() {
            let mut bytes = [0u8; 8];
            rng.fill(&mut bytes)?;
            *limb = u64::from_le_bytes(bytes);
        }
        limbs[HALF - 1] &= !(1 << 63);
        let mut a = Uint(limbs);
        limbs.zeroize();
        if a.bit_length() < 2 {
            a = Uint::from_limbs(&[2]);
        }

        let mut x = m.modexp(&a, &t);
        if x.0 == one.0 || x.0 == minus_one.0 {
            continue;
        }
        for _ in 1..s {
            x = m.mulmod(&x, &x);
            if x.0 == minus_one.0 {
                continue 'witness;
            }
        }
        t.zeroize();
        return Ok(false);
    }
    t.zeroize();
    Ok(true)
}

/// The inverse of `a` modulo `m`, by the extended Euclidean
/// algorithm in one word; `a` and `m` must be coprime.
fn inv_mod_word(a: u64, m: u64) -> u64 {
    let (mut t, mut new_t) = (0i128, 1i128);
    let (mut r, mut new_r) = (i128::from(m), i128::from(a));
    while new_r != 0 {
        let quotient = r / new_r;
        (t, new_t) = (new_t, t - quotient * new_t);
        (r, new_r) = (new_r, r - quotient * new_r);
    }
    debug_assert_eq!(r, 1, "not coprime");
    ((t % i128::from(m) + i128::from(m)) % i128::from(m)) as u64
}

/// The remainder of `value` modulo `n`, where `value` is known to be
/// below `2n`: one conditional subtraction.
fn reduce_once_mod<const LIMBS: usize>(
    value: &Uint<LIMBS>,
    n: &Uint<LIMBS>,
) -> Uint<LIMBS> {
    let (reduced, borrow) = value.sub_borrow(n);
    let mut out = reduced;
    out.cmov(value, borrow);
    out
}

/// MGF1: xors `out` with the counter-indexed digests of `seed`, as
/// RFC 8017 appendix B.2.1 defines the mask. PSS and OAEP both mask
/// with it.
pub(crate) fn mgf1_xor<H: Hash>(
    seed: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    for (counter, chunk) in (0u32..).zip(out.chunks_mut(H::Output::SIZE)) {
        let mut hasher = H::try_new()?;
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        let mask = hasher.finalize();
        for (byte, mask) in chunk.iter_mut().zip(mask.as_ref()) {
            *byte ^= mask;
        }
    }
    Ok(())
}

/// The value without its leading zero bytes.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

impl<const HALF: usize> Zeroize for Crt<HALF> {
    fn zeroize(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
    }
}

impl<const LIMBS: usize, const BYTES: usize, const HALF: usize> Drop
    for Private<LIMBS, BYTES, HALF>
{
    fn drop(&mut self) {
        self.d.zeroize();
        if let Some(crt) = &mut self.crt {
            crt.zeroize();
        }
    }
}

impl<const LIMBS: usize, const BYTES: usize, const HALF: usize>
    zeroize::ZeroizeOnDrop for Private<LIMBS, BYTES, HALF>
{
}
