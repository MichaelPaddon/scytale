//! The RSA key machinery shared by the signature and encryption
//! schemes: key validation and import, the modular exponentiations,
//! Chinese remainder recombination with its fault check, key
//! generation, and MGF1. The schemes in [`sig::rsa`](crate::sig::rsa)
//! and [`pke::rsa`](crate::pke::rsa) wrap these in distinct key
//! types, so a signing key cannot decrypt and a decryption key
//! cannot sign.
//!
//! # Memory
//!
//! A key's length is a value, so its words live in memory the caller
//! brings: a slice that [`Public::fill`] or [`Private::fill`] lays
//! out and a [`Public`] or [`Private`] is a view over. Every
//! operation takes a scratch slice for its temporaries and wipes it
//! before returning. The `*_words` functions say how much of each a
//! key of some number of bits needs, as `const fn`s, so a caller can
//! size an array at compile time from a known maximum or ask at run
//! time for the key in hand.
//!
//! # The layout
//!
//! The public words come first, so a private key's storage begins
//! with its public half and a [`Public`] view over the front of it
//! is the public key:
//!
//! ```text
//! public:  limbs, bits, e, n', n[limbs], R^2[limbs]
//! private: has_crt, half, p', q', d[limbs],
//!          p[half], R^2[half], q[half], R^2[half],
//!          dp[half], dq[half], qinv[half]
//! ```
//!
//! `half` is the length of a prime in limbs, fixed by the bit count
//! rather than by the primes that arrive, so that the layout is a
//! function of the bits alone.

use zeroize::Zeroize;

use crate::Error;
use crate::Random;
use crate::der::{self, Algorithm, Reader, Writer};
use crate::hash::Hash;
use crate::math::limbs::{self, Modulus};
use crate::pem;

/// The narrowest modulus accepted, in bits. Below this RSA is broken
/// rather than merely weak.
pub const MIN_BITS: usize = 1024;

/// The widest modulus accepted, in bits, and the size every owned
/// key and buffer is laid out for.
pub const MAX_BITS: usize = 8192;

/// The public exponent generated keys get.
const E_WORD: u64 = 65537;

/// Limbs in a modulus of `bits`.
pub(crate) const fn limbs(bits: usize) -> usize {
    bits.div_ceil(64)
}

/// Limbs in a prime of a modulus of `bits`: the primes are half the
/// modulus, and the larger of an odd split has the extra bit.
pub(crate) const fn half_limbs(bits: usize) -> usize {
    bits.div_ceil(2).div_ceil(64)
}

/// Bytes in a modulus of `bits`, which is the length of every
/// signature, ciphertext and representative under it.
pub(crate) const fn modulus_len(bits: usize) -> usize {
    bits.div_ceil(8)
}

/// Bytes in a prime of a modulus of `bits`.
pub(crate) const fn prime_len(bits: usize) -> usize {
    bits.div_ceil(2).div_ceil(8)
}

/// The words before the modulus in a public key.
const PUBLIC_HEADER: usize = 4;

/// The words before the private exponent, after the public part.
const PRIVATE_HEADER: usize = 4;

/// Words a public key of `bits` needs.
pub const fn public_words(bits: usize) -> usize {
    PUBLIC_HEADER + limbs::modulus_words(limbs(bits))
}

/// Words a private key of `bits` needs, its public half included.
pub const fn private_words(bits: usize) -> usize {
    public_words(bits)
        + PRIVATE_HEADER
        + limbs(bits)
        + 2 * limbs::modulus_words(half_limbs(bits))
        + 3 * half_limbs(bits)
}

/// Words of scratch any operation under a key of `bits` needs, key
/// generation included. The largest need is an exponentiation at
/// the full length with its input and output beside it.
pub const fn scratch_words(bits: usize) -> usize {
    limbs::modexp_words(limbs(bits)) + 3 * limbs(bits) + 4
}

/// Where the parts of a key of `bits` lie in its storage.
#[derive(Clone, Copy)]
struct Layout {
    limbs: usize,
    half: usize,
    bits: usize,
}

impl Layout {
    fn of(bits: usize) -> Self {
        Layout {
            limbs: limbs(bits),
            half: half_limbs(bits),
            bits,
        }
    }

    fn modulus(self) -> core::ops::Range<usize> {
        PUBLIC_HEADER..PUBLIC_HEADER + limbs::modulus_words(self.limbs)
    }

    fn private(self) -> usize {
        self.modulus().end
    }

    fn d(self) -> core::ops::Range<usize> {
        let start = self.private() + PRIVATE_HEADER;
        start..start + self.limbs
    }

    fn p(self) -> core::ops::Range<usize> {
        let start = self.d().end;
        start..start + limbs::modulus_words(self.half)
    }

    fn q(self) -> core::ops::Range<usize> {
        let start = self.p().end;
        start..start + limbs::modulus_words(self.half)
    }

    fn dp(self) -> core::ops::Range<usize> {
        let start = self.q().end;
        start..start + self.half
    }

    fn dq(self) -> core::ops::Range<usize> {
        let start = self.dp().end;
        start..start + self.half
    }

    fn qinv(self) -> core::ops::Range<usize> {
        let start = self.dq().end;
        start..start + self.half
    }
}

/// The public half of an RSA key, a view over its words.
#[derive(Clone, Copy)]
pub(crate) struct Public<'a> {
    words: &'a [u64],
    layout: Layout,
}

/// The private half with its public half in front, a view over the
/// words. The words are the caller's to wipe; the owned key types
/// do, and say so.
#[derive(Clone, Copy)]
pub(crate) struct Private<'a> {
    words: &'a [u64],
    layout: Layout,
}

/// The bit length of a big-endian integer, with leading zeros
/// ignored, and the bytes that remain.
fn bits_of(bytes: &[u8]) -> (usize, &[u8]) {
    let bytes = strip_leading_zeros(bytes);
    match bytes.first() {
        Some(first) => {
            (8 * bytes.len() - first.leading_zeros() as usize, bytes)
        }
        None => (0, bytes),
    }
}

/// The scratch slice an operation under `bits` needs, or the error
/// that says how much was wanted.
fn scratch_for(bits: usize, scratch: &mut [u64]) -> Result<&mut [u64], Error> {
    let needed = scratch_words(bits);
    match scratch.get_mut(..needed) {
        Some(scratch) => Ok(scratch),
        None => Err(Error::ScratchTooSmall(needed)),
    }
}

/// A one of `len` limbs.
fn one(len: usize) -> [u64; limbs(MAX_BITS)] {
    debug_assert!(len <= limbs(MAX_BITS));
    let mut one = [0u64; limbs(MAX_BITS)];
    one[0] = 1;
    one
}

impl<'a> Public<'a> {
    /// Lays out a public key from its big-endian parts in `storage`,
    /// returning how many words it took.
    ///
    /// The modulus must be odd and between [`MIN_BITS`] and
    /// [`MAX_BITS`] once its leading zeros are dropped. The exponent
    /// must be odd, at least 3, and fit eight bytes, which every
    /// deployed key's does.
    pub(crate) fn fill(
        n: &[u8],
        e: &[u8],
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        let (bits, n) = bits_of(n);
        if !(MIN_BITS..=MAX_BITS).contains(&bits) {
            return Err(Error::InvalidKeyLength(bits));
        }
        let layout = Layout::of(bits);
        let words = public_words(bits);
        let Some(storage) = storage.get_mut(..words) else {
            return Err(Error::ScratchTooSmall(words));
        };

        let e = strip_leading_zeros(e);
        if e.len() > 8 {
            return Err(Error::InvalidPublicKey);
        }
        let mut e_word = [0u64];
        limbs::from_be_bytes(e, &mut e_word);
        let e_word = e_word[0];
        if e_word & 1 == 0 || e_word < 3 {
            return Err(Error::InvalidPublicKey);
        }

        let (header, modulus) = storage.split_at_mut(PUBLIC_HEADER);
        let mut value = [0u64; limbs(MAX_BITS)];
        let value = &mut value[..layout.limbs];
        limbs::from_be_bytes(n, value);
        let inv =
            Modulus::prepare(value, modulus).ok_or(Error::InvalidPublicKey)?;
        header[0] = layout.limbs as u64;
        header[1] = bits as u64;
        header[2] = e_word;
        header[3] = inv;
        Ok(words)
    }

    /// A view over words that [`fill`](Self::fill) laid out. The
    /// header is checked against the slice, so a slice that is not a
    /// key is refused rather than read out of bounds.
    pub(crate) fn new(storage: &'a [u64]) -> Result<Self, Error> {
        let bits = *storage.get(1).ok_or(Error::InvalidPublicKey)? as usize;
        if !(MIN_BITS..=MAX_BITS).contains(&bits)
            || storage[0] as usize != limbs(bits)
            || storage.len() < public_words(bits)
        {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Public {
            words: storage,
            layout: Layout::of(bits),
        })
    }

    /// A view over words this crate laid out itself and remembers
    /// the bits of, so nothing has to be checked again. The owned
    /// key types use it; the debug assertion is the check.
    pub(crate) fn over(storage: &'a [u64], bits: usize) -> Self {
        debug_assert!(Self::new(storage).is_ok_and(|p| p.bits() == bits));
        Public {
            words: storage,
            layout: Layout::of(bits),
        }
    }

    pub(crate) fn bits(&self) -> usize {
        self.layout.bits
    }

    /// The length of the modulus in bytes.
    pub(crate) fn modulus_len(&self) -> usize {
        modulus_len(self.layout.bits)
    }

    fn modulus(&self) -> Modulus<'a> {
        Modulus::new(&self.words[self.layout.modulus()], self.words[3])
    }

    fn e(&self) -> u64 {
        self.words[2]
    }

    /// Whether `input`, of exactly [`modulus_len`](Self::modulus_len)
    /// bytes, is a representative the primitives accept: strictly
    /// below the modulus.
    pub(crate) fn in_range(&self, input: &[u8]) -> bool {
        if input.len() != self.modulus_len() {
            return false;
        }
        let mut value = [0u64; limbs(MAX_BITS)];
        let value = &mut value[..self.layout.limbs];
        limbs::from_be_bytes(input, value);
        limbs::less_than(value, self.modulus().modulus()) != 0
    }

    /// The public operation, `out = input^e mod n`, over
    /// representatives of the modulus length; the input must be in
    /// range, which the caller has checked with its own error.
    pub(crate) fn apply(
        &self,
        input: &[u8],
        out: &mut [u8],
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        debug_assert!(self.in_range(input));
        let scratch = scratch_for(self.layout.bits, scratch)?;
        let limbs = self.layout.limbs;
        let (value, rest) = scratch.split_at_mut(limbs);
        let (result, rest) = rest.split_at_mut(limbs);
        limbs::from_be_bytes(input, value);
        self.modulus().modexp_public(value, self.e(), result, rest);
        limbs::to_be_bytes(result, out);
        scratch.zeroize();
        Ok(())
    }

    /// The modulus, big-endian, into `out`, which is
    /// [`modulus_len`](Self::modulus_len) bytes.
    pub(crate) fn write_modulus(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.modulus_len());
        limbs::to_be_bytes(self.modulus().modulus(), out);
    }

    /// The public exponent, big-endian in eight bytes.
    pub(crate) fn exponent_bytes(&self) -> [u8; 8] {
        self.words[2].to_be_bytes()
    }
}

impl<'a> Private<'a> {
    /// Lays out a private key from the public parts and the
    /// big-endian private exponent, which must be nonzero and below
    /// the modulus, returning how many words it took. The Chinese
    /// remainder slot is left empty.
    pub(crate) fn fill(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        let public = Public::fill(n, e, storage)?;
        let layout = Layout::of(storage[1] as usize);
        let words = private_words(layout.bits);
        let Some(storage) = storage.get_mut(..words) else {
            return Err(Error::ScratchTooSmall(words));
        };
        let (front, private) = storage.split_at_mut(public);
        let public = Public::new(front)?;

        let d = strip_leading_zeros(d);
        if d.len() > public.modulus_len() {
            return Err(Error::InvalidPrivateKey);
        }
        private.fill(0);
        private[1] = layout.half as u64;
        let d_words =
            &mut private[PRIVATE_HEADER..PRIVATE_HEADER + layout.limbs];
        limbs::from_be_bytes(d, d_words);
        if limbs::is_zero(d_words)
            || limbs::less_than(d_words, public.modulus().modulus()) == 0
        {
            d_words.zeroize();
            return Err(Error::InvalidPrivateKey);
        }
        Ok(words)
    }

    /// Lays out a private key with its Chinese remainder pieces: `p`
    /// and `q` of half the modulus's bits, within one bit of each
    /// other, the reduced exponents `dp` and `dq`, and `qinv`, the
    /// inverse of `q` modulo `p`.
    ///
    /// The pieces are checked against one another: the primes must
    /// multiply to the modulus and `qinv` must invert `q`. A wrong
    /// `dp` or `dq` cannot be caught here, and is caught instead by
    /// the check every private operation gets before its result is
    /// released.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn fill_crt(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        p: &[u8],
        q: &[u8],
        dp: &[u8],
        dq: &[u8],
        qinv: &[u8],
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        let words = Self::fill(n, e, d, storage)?;
        let storage = &mut storage[..words];
        let layout = Layout::of(storage[1] as usize);
        let scratch = scratch_for(layout.bits, scratch)?;
        let pieces = Pieces { p, q, dp, dq, qinv };
        let result = Self::fill_crt_checked(layout, pieces, storage, scratch);
        scratch.zeroize();
        if result.is_err() {
            storage[layout.private()..].zeroize();
        }
        result.map(|()| words)
    }

    /// The CRT part of [`fill_crt`](Self::fill_crt), once the public
    /// half and the exponent are in place.
    fn fill_crt_checked(
        layout: Layout,
        pieces: Pieces<'_>,
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        let half = layout.half;
        let half_bits = layout.bits.div_ceil(2);

        // Each prime is half the modulus, within a bit, which is
        // what keeps `q` below `2p` for the reduction below and the
        // product exactly the modulus's length.
        let (p_bits, p) = bits_of(pieces.p);
        let (q_bits, q) = bits_of(pieces.q);
        if p_bits.abs_diff(q_bits) > 1
            || p_bits + q_bits < layout.bits - 1
            || p_bits > half_bits
            || q_bits > half_bits
        {
            return Err(Error::InvalidPrivateKey);
        }
        let (p_value, rest) = scratch.split_at_mut(half);
        let (q_value, rest) = rest.split_at_mut(half);
        limbs::from_be_bytes(p, p_value);
        limbs::from_be_bytes(q, q_value);
        if limbs::equal(p_value, q_value) == 1 {
            return Err(Error::InvalidPrivateKey);
        }
        {
            let (product, _) = rest.split_at_mut(2 * half);
            limbs::mul_wide(p_value, q_value, product);
            let n = &storage[layout.modulus()][..layout.limbs];
            let take = layout.limbs.min(2 * half);
            let (low, high) = product.split_at(take);
            if limbs::equal(low, &n[..take]) == 0
                || !limbs::is_zero(high)
                || !limbs::is_zero(&n[take..])
            {
                return Err(Error::InvalidPrivateKey);
            }
        }

        let p_inv = Modulus::prepare(p_value, &mut storage[layout.p()])
            .ok_or(Error::InvalidPrivateKey)?;
        let q_inv = Modulus::prepare(q_value, &mut storage[layout.q()])
            .ok_or(Error::InvalidPrivateKey)?;

        let half_len = prime_len(layout.bits);
        let exponents = [
            (pieces.dp, layout.dp()),
            (pieces.dq, layout.dq()),
            (pieces.qinv, layout.qinv()),
        ];
        for (part, range) in exponents {
            let part = strip_leading_zeros(part);
            if part.len() > half_len {
                return Err(Error::InvalidPrivateKey);
            }
            limbs::from_be_bytes(part, &mut storage[range]);
        }
        {
            let p = Modulus::new(&storage[layout.p()], p_inv);
            let q = Modulus::new(&storage[layout.q()], q_inv);
            let dp = &storage[layout.dp()];
            let dq = &storage[layout.dq()];
            let qinv = &storage[layout.qinv()];
            if limbs::is_zero(dp)
                || limbs::less_than(dp, p.modulus()) == 0
                || limbs::is_zero(dq)
                || limbs::less_than(dq, q.modulus()) == 0
                || limbs::is_zero(qinv)
                || limbs::less_than(qinv, p.modulus()) == 0
            {
                return Err(Error::InvalidPrivateKey);
            }
            // qinv really must invert q; a wrong value here would
            // only surface as every private operation failing its
            // final check.
            let (q_mod_p, rest) = rest.split_at_mut(half);
            q_mod_p.copy_from_slice(q.modulus());
            reduce_once(q_mod_p, p.modulus());
            let (product, rest) = rest.split_at_mut(half);
            p.mulmod(qinv, q_mod_p, product, rest);
            if limbs::equal(product, &one(half)[..half]) == 0 {
                return Err(Error::InvalidPrivateKey);
            }
        }

        let private = layout.private();
        storage[private] = 1;
        storage[private + 2] = p_inv;
        storage[private + 3] = q_inv;
        Ok(())
    }

    /// A view over words that [`fill`](Self::fill) or
    /// [`fill_crt`](Self::fill_crt) laid out, checked as
    /// [`Public::new`] checks its half.
    pub(crate) fn new(storage: &'a [u64]) -> Result<Self, Error> {
        let public = Public::new(storage)?;
        let layout = public.layout;
        if storage.len() < private_words(layout.bits)
            || storage[layout.private() + 1] as usize != layout.half
            || storage[layout.private()] > 1
        {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(Private {
            words: storage,
            layout,
        })
    }

    /// As [`Public::over`], for a private key's words.
    pub(crate) fn over(storage: &'a [u64], bits: usize) -> Self {
        debug_assert!(Self::new(storage).is_ok_and(|p| p.layout.bits == bits));
        Private {
            words: storage,
            layout: Layout::of(bits),
        }
    }

    /// The public half, as a view over the front of the same words.
    pub(crate) fn public(&self) -> Public<'a> {
        Public {
            words: &self.words[..public_words(self.layout.bits)],
            layout: self.layout,
        }
    }

    fn has_crt(&self) -> bool {
        self.words[self.layout.private()] == 1
    }

    fn d(&self) -> &'a [u64] {
        &self.words[self.layout.d()]
    }

    /// The private operation: `out = em^d mod n`, or through the
    /// primes when the key carries them, over representatives of the
    /// modulus length. `em` must be in range, which the caller has
    /// checked with its own error.
    pub(crate) fn apply(
        &self,
        em: &[u8],
        out: &mut [u8],
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        let public = self.public();
        debug_assert!(public.in_range(em));
        let scratch = scratch_for(self.layout.bits, scratch)?;
        let result = self.apply_in(&public, em, out, scratch);
        scratch.zeroize();
        result
    }

    fn apply_in(
        &self,
        public: &Public<'a>,
        em: &[u8],
        out: &mut [u8],
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        let limbs = self.layout.limbs;
        let (m, rest) = scratch.split_at_mut(limbs);
        let (s, rest) = rest.split_at_mut(limbs);
        limbs::from_be_bytes(em, m);
        if self.has_crt() {
            self.crt_apply(m, s, rest);
            // One faulty CRT result factors the modulus (Boneh,
            // DeMillo and Lipton), so check with the public exponent
            // before anything leaves. This also catches a wrong dp or
            // dq, which import cannot.
            let (check, rest) = rest.split_at_mut(limbs);
            public.modulus().modexp_public(s, public.e(), check, rest);
            if limbs::equal(check, m) == 0 {
                return Err(Error::InvalidPrivateKey);
            }
        } else {
            public.modulus().modexp(m, self.d(), s, rest);
        }
        limbs::to_be_bytes(s, out);
        Ok(())
    }

    /// Garner's recombination: exponentiate modulo each prime, then
    /// lift: `s = sq + q * (qinv * (sp - sq) mod p)`, which is below
    /// `p * q` with no final reduction.
    fn crt_apply(&self, m: &[u64], s: &mut [u64], scratch: &mut [u64]) {
        let layout = self.layout;
        let half = layout.half;
        let private = layout.private();
        let p = Modulus::new(&self.words[layout.p()], self.words[private + 2]);
        let q = Modulus::new(&self.words[layout.q()], self.words[private + 3]);
        let (mp, rest) = scratch.split_at_mut(half);
        let (mq, rest) = rest.split_at_mut(half);
        let (sp, rest) = rest.split_at_mut(half);
        let (sq, rest) = rest.split_at_mut(half);
        let (h, rest) = rest.split_at_mut(half);
        let (wide, rest) = rest.split_at_mut(2 * half);

        p.reduce(m, mp, rest);
        q.reduce(m, mq, rest);
        p.modexp(mp, &self.words[layout.dp()], sp, rest);
        q.modexp(mq, &self.words[layout.dq()], sq, rest);

        // sp - sq mod p, with sq brought below p first: it is below
        // q, which is below 2p.
        h.copy_from_slice(sq);
        reduce_once(h, p.modulus());
        limbs::sub_mod(sp, h, p.modulus());
        p.mulmod(&self.words[layout.qinv()], sp, h, rest);
        limbs::mul_wide(q.modulus(), h, wide);
        {
            let (low, high) = wide.split_at_mut(half);
            let mut carry = limbs::add_carry(low, sq);
            for limb in high.iter_mut() {
                let v = u128::from(*limb) + u128::from(carry);
                *limb = v as u64;
                carry = (v >> 64) as u64;
            }
            debug_assert_eq!(carry, 0);
        }
        // Below the modulus, so the limbs above its length are zero.
        let take = layout.limbs.min(2 * half);
        s.fill(0);
        s[..take].copy_from_slice(&wide[..take]);
        debug_assert!(limbs::is_zero(&wide[take..]));
    }

    /// Generates a fresh key of `bits`, which must be a multiple of
    /// eight between [`MIN_BITS`] and [`MAX_BITS`], with the public
    /// exponent 65537 and every Chinese remainder piece in place,
    /// laid out in `storage`; returns the words it took.
    ///
    /// The primes are random probable primes: trial division, then
    /// Miller-Rabin with random witnesses, with round counts read
    /// from FIPS 186-5 for random candidates of 1024 bits and up.
    pub(crate) fn generate<R: Random>(
        rng: &mut R,
        bits: usize,
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        if !(MIN_BITS..=MAX_BITS).contains(&bits) || !bits.is_multiple_of(8) {
            return Err(Error::InvalidKeyLength(bits));
        }
        let scratch = scratch_for(bits, scratch)?;
        let result = Self::generate_in(rng, bits, storage, scratch);
        scratch.zeroize();
        result
    }

    fn generate_in<R: Random>(
        rng: &mut R,
        bits: usize,
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        let layout = Layout::of(bits);
        let half = layout.half;
        let half_bits = bits / 2;
        let one_half = one(half);
        let one_half = &one_half[..half];

        // The primes and the numbers derived from them go out as
        // bytes and come back through `fill_crt`, so a generated key
        // passes exactly the checks an imported one does.
        let mut parts = Parts::zeroed();
        let (p, rest) = scratch.split_at_mut(half);
        let (q, rest) = rest.split_at_mut(half);
        probable_prime(rng, half_bits, p, rest)?;
        let mut found = false;
        for _ in 0..64 {
            probable_prime(rng, half_bits, q, rest)?;
            // FIPS 186-5: the primes must not be close, or Fermat
            // factoring splits the modulus. Whichever way round the
            // difference is positive.
            let (difference, rest) = rest.split_at_mut(half);
            let (flipped, _) = rest.split_at_mut(half);
            difference.copy_from_slice(p);
            let borrow = limbs::sub_borrow(difference, q);
            flipped.copy_from_slice(q);
            limbs::sub_borrow(flipped, p);
            limbs::cmov(difference, flipped, borrow);
            let far =
                limbs::bit_length(difference) > half_bits.saturating_sub(100);
            difference.zeroize();
            flipped.zeroize();
            if far {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::KeyGenerationFailed);
        }

        let (n, rest) = rest.split_at_mut(2 * half);
        limbs::mul_wide(p, q, n);
        let n_len = modulus_len(bits);
        limbs::to_be_bytes(&n[..layout.limbs], &mut parts.n[..n_len]);

        // phi = (p-1)(q-1) = n - p - q + 1, at the product's length;
        // no borrow can happen.
        let (phi, rest) = rest.split_at_mut(2 * half);
        phi.copy_from_slice(n);
        {
            let (low, high) = phi.split_at_mut(half);
            let mut carry =
                limbs::sub_borrow(low, p) + limbs::sub_borrow(low, q);
            for limb in high.iter_mut() {
                let (v, b) = limb.overflowing_sub(carry);
                *limb = v;
                carry = u64::from(b);
            }
            let one_wide = one(2 * half);
            limbs::add_carry(phi, &one_wide[..2 * half]);
        }

        // d = (1 + k * phi) / e for the k that makes the division
        // exact: k = -phi^-1 mod e. The whole inversion happens in
        // one word, because e does.
        let (d, rest) = rest.split_at_mut(2 * half);
        {
            let phi_mod_e = limbs::rem_word(phi, E_WORD);
            let k = E_WORD - inv_mod_word(phi_mod_e, E_WORD);
            d.copy_from_slice(phi);
            let top = limbs::mul_word(d, k);
            let one_wide = one(2 * half);
            let carry = limbs::add_carry(d, &one_wide[..2 * half]);
            let remainder = limbs::div_rem_word(d, top + carry, E_WORD);
            debug_assert_eq!(remainder, 0);
        }
        limbs::to_be_bytes(&d[..layout.limbs], &mut parts.d[..n_len]);

        // The Chinese remainder pieces. p is prime, so the inverse
        // of q is a Fermat power, and the exponentiations that need
        // an even modulus are plain bit-by-bit remainders instead.
        let half_len = prime_len(bits);
        {
            let (minus_one, rest) = rest.split_at_mut(half);
            let (reduced, rest) = rest.split_at_mut(half);
            for (prime, out) in [(&*p, &mut parts.dp), (&*q, &mut parts.dq)] {
                minus_one.copy_from_slice(prime);
                limbs::sub_borrow(minus_one, one_half);
                limbs::rem_wide(d, minus_one, reduced);
                limbs::to_be_bytes(reduced, &mut out[..half_len]);
            }
            // qinv = q^(p-2) mod p.
            let (modulus, rest) = rest.split_at_mut(limbs::modulus_words(half));
            let inv = Modulus::prepare(p, modulus)
                .ok_or(Error::KeyGenerationFailed)?;
            let mont_p = Modulus::new(modulus, inv);
            let (q_mod_p, rest) = rest.split_at_mut(half);
            q_mod_p.copy_from_slice(q);
            reduce_once(q_mod_p, p);
            minus_one.copy_from_slice(p);
            limbs::sub_borrow(minus_one, one_half);
            limbs::sub_borrow(minus_one, one_half);
            mont_p.modexp(q_mod_p, minus_one, reduced, rest);
            limbs::to_be_bytes(reduced, &mut parts.qinv[..half_len]);
        }
        limbs::to_be_bytes(p, &mut parts.p[..half_len]);
        limbs::to_be_bytes(q, &mut parts.q[..half_len]);
        parts.e = E_WORD.to_be_bytes();

        Self::fill_crt(
            &parts.n[..n_len],
            &parts.e,
            &parts.d[..n_len],
            &parts.p[..half_len],
            &parts.q[..half_len],
            &parts.dp[..half_len],
            &parts.dq[..half_len],
            &parts.qinv[..half_len],
            storage,
            scratch,
        )
    }

    /// The private exponent, big-endian, into `out`, which is the
    /// modulus length. The caller holds a secret now, and should wipe
    /// it when done.
    pub(crate) fn write_d(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.public().modulus_len());
        limbs::to_be_bytes(self.d(), out);
    }

    /// The length of a prime in bytes, which is the length of each
    /// Chinese remainder piece.
    pub(crate) fn prime_len(&self) -> usize {
        prime_len(self.layout.bits)
    }

    /// Writes the Chinese remainder pieces, big-endian, into five
    /// buffers of [`prime_len`](Self::prime_len) bytes each. Fails
    /// with [`Error::InvalidPrivateKey`] on a key laid out without
    /// them, and [`Error::InvalidLength`] on a buffer of the wrong
    /// size. The caller holds secrets now, and should wipe them when
    /// done.
    pub(crate) fn crt_bytes(
        &self,
        p: &mut [u8],
        q: &mut [u8],
        dp: &mut [u8],
        dq: &mut [u8],
        qinv: &mut [u8],
    ) -> Result<(), Error> {
        if !self.has_crt() {
            return Err(Error::InvalidPrivateKey);
        }
        let half_len = self.prime_len();
        for out in [&p, &q, &dp, &dq, &qinv] {
            if out.len() != half_len {
                return Err(Error::InvalidLength(out.len()));
            }
        }
        let layout = self.layout;
        let half = layout.half;
        limbs::to_be_bytes(&self.words[layout.p()][..half], p);
        limbs::to_be_bytes(&self.words[layout.q()][..half], q);
        limbs::to_be_bytes(&self.words[layout.dp()], dp);
        limbs::to_be_bytes(&self.words[layout.dq()], dq);
        limbs::to_be_bytes(&self.words[layout.qinv()], qinv);
        Ok(())
    }
}

/// The Chinese remainder pieces as they arrive, big-endian.
struct Pieces<'a> {
    p: &'a [u8],
    q: &'a [u8],
    dp: &'a [u8],
    dq: &'a [u8],
    qinv: &'a [u8],
}

/// `value mod n` for a `value` known to be below `2n`: one
/// conditional subtraction, in place.
fn reduce_once(value: &mut [u64], n: &[u64]) {
    let mut reduced = [0u64; limbs(MAX_BITS)];
    let reduced = &mut reduced[..value.len()];
    reduced.copy_from_slice(value);
    let borrow = limbs::sub_borrow(reduced, n);
    limbs::cmov(value, reduced, 1 - borrow);
    reduced.zeroize();
}

/// Every integer of an RSAPrivateKey as bytes, ready to write or
/// just made. Laid out for the widest key; a narrower one uses the
/// front of each field. Wiped on drop, since all but `n` and `e` are
/// secret.
#[derive(Zeroize, zeroize::ZeroizeOnDrop)]
struct Parts {
    n: [u8; modulus_len(MAX_BITS)],
    e: [u8; 8],
    d: [u8; modulus_len(MAX_BITS)],
    p: [u8; prime_len(MAX_BITS)],
    q: [u8; prime_len(MAX_BITS)],
    dp: [u8; prime_len(MAX_BITS)],
    dq: [u8; prime_len(MAX_BITS)],
    qinv: [u8; prime_len(MAX_BITS)],
}

impl Parts {
    fn zeroed() -> Self {
        Parts {
            n: [0; modulus_len(MAX_BITS)],
            e: [0; 8],
            d: [0; modulus_len(MAX_BITS)],
            p: [0; prime_len(MAX_BITS)],
            q: [0; prime_len(MAX_BITS)],
            dp: [0; prime_len(MAX_BITS)],
            dq: [0; prime_len(MAX_BITS)],
            qinv: [0; prime_len(MAX_BITS)],
        }
    }
}

/// Draws random candidates of `bits` into `out` until one survives
/// trial division and Miller-Rabin. The cap on attempts is FIPS
/// 186-5's, and failing it means the random source is not producing
/// usable candidates. `scratch` is what an exponentiation at the
/// candidate's length needs, and then some.
fn probable_prime<R: Random>(
    rng: &mut R,
    bits: usize,
    out: &mut [u64],
    scratch: &mut [u64],
) -> Result<(), Error> {
    let half = out.len();
    for _ in 0..5 * bits {
        for limb in out.iter_mut() {
            let mut bytes = [0u8; 8];
            rng.fill(&mut bytes)?;
            *limb = u64::from_le_bytes(bytes);
        }
        // Exactly `bits` long, odd, and with the top two bits set so
        // the product of two candidates fills the modulus exactly.
        let spare = 64 * half - bits;
        if spare > 0 {
            out[half - 1] &= u64::MAX >> spare;
        }
        out[0] |= 1;
        for bit in [bits - 1, bits - 2] {
            out[bit / 64] |= 1 << (bit % 64);
        }

        // Trial division by every odd number to 2000; the composite
        // divisors are redundant but harmless, and the loop stays
        // two lines.
        let mut divisor = 3u64;
        let mut composite = false;
        while divisor < 2000 {
            if limbs::rem_word(out, divisor) == 0 {
                composite = true;
                break;
            }
            divisor += 2;
        }
        // A prime congruent to 1 mod e would make e share a factor
        // with phi, and no d would exist.
        if composite || limbs::rem_word(out, E_WORD) == 1 {
            continue;
        }
        if miller_rabin(out, rng, scratch)? {
            return Ok(());
        }
    }
    out.zeroize();
    Err(Error::KeyGenerationFailed)
}

/// Miller-Rabin with random witnesses. Eight rounds: FIPS 186-5
/// table B.1 asks for at most five on random candidates of 1024
/// bits, and the extras are margin for the narrower legacy widths.
fn miller_rabin<R: Random>(
    candidate: &[u64],
    rng: &mut R,
    scratch: &mut [u64],
) -> Result<bool, Error> {
    let half = candidate.len();
    let (modulus, rest) = scratch.split_at_mut(limbs::modulus_words(half));
    let inv = Modulus::prepare(candidate, modulus)
        .ok_or(Error::KeyGenerationFailed)?;
    let m = Modulus::new(modulus, inv);
    let (minus_one, rest) = rest.split_at_mut(half);
    let (t, rest) = rest.split_at_mut(half);
    let (a, rest) = rest.split_at_mut(half);
    let (x, rest) = rest.split_at_mut(half);
    let (y, rest) = rest.split_at_mut(half);
    let one = one(half);
    let one = &one[..half];
    minus_one.copy_from_slice(candidate);
    limbs::sub_borrow(minus_one, one);
    // candidate - 1 = 2^s * t with t odd.
    let s = limbs::trailing_zeros(minus_one);
    t.copy_from_slice(minus_one);
    limbs::shr(t, s);

    let mut probably = true;
    'witness: for _ in 0..8 {
        // A random witness below the candidate: clearing everything
        // from its top bit up is enough, since the candidate has
        // that bit set, and tiny witnesses are nudged to two.
        for limb in a.iter_mut() {
            let mut bytes = [0u8; 8];
            rng.fill(&mut bytes)?;
            *limb = u64::from_le_bytes(bytes);
        }
        let top = limbs::bit_length(candidate) - 1;
        a[top / 64] &= !(u64::MAX << (top % 64));
        for limb in a.iter_mut().skip(top / 64 + 1) {
            *limb = 0;
        }
        if limbs::bit_length(a) < 2 {
            a.fill(0);
            a[0] = 2;
        }

        m.modexp(a, t, x, rest);
        if limbs::equal(x, one) == 1 || limbs::equal(x, minus_one) == 1 {
            continue;
        }
        for _ in 1..s {
            m.mulmod(x, x, y, rest);
            x.copy_from_slice(y);
            if limbs::equal(x, minus_one) == 1 {
                continue 'witness;
            }
        }
        probably = false;
        break;
    }
    scratch.zeroize();
    Ok(probably)
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

/// The PEM labels a public key may come under, SubjectPublicKeyInfo
/// first, then the bare RSAPublicKey; the order is the one the
/// importers match on.
const PUBLIC_LABELS: [&str; 2] = ["PUBLIC KEY", "RSA PUBLIC KEY"];

/// The same for a private key: PrivateKeyInfo, then RSAPrivateKey.
const PRIVATE_LABELS: [&str; 2] = ["PRIVATE KEY", "RSA PRIVATE KEY"];

/// Room for any DER form of a public key of the widest modulus.
const PUBLIC_DER: usize = 4 * modulus_len(MAX_BITS);

/// Room for any DER form of a private key of the widest modulus.
const PRIVATE_DER: usize = 8 * modulus_len(MAX_BITS);

/// Whether an AlgorithmIdentifier names an RSA key: `rsaEncryption`
/// with no parameters to speak of, or, when `pss` allows it,
/// `id-RSASSA-PSS` with whatever it carries, which constrains the
/// scheme rather than the key and is not read.
fn rsa_algorithm(algorithm: &Algorithm, pss: bool) -> Result<(), Error> {
    let ok = (algorithm.oid == der::RSA_ENCRYPTION && algorithm.no_params())
        || (pss && algorithm.oid == der::RSASSA_PSS);
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidEncoding)
    }
}

/// `der` as a PEM block under `label`, into the front of `out`.
fn to_pem(label: &str, der: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let needed = pem::encoded_len(label, der.len());
    if out.len() < needed {
        return Err(Error::OutputTooSmall(needed));
    }
    Ok(pem::encode(label, der, out))
}

impl<'a> Public<'a> {
    /// The RSAPublicKey structure of RFC 8017 A.1.1, laid out in
    /// `storage`.
    pub(crate) fn fill_from_pkcs1(
        der: &[u8],
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        let mut outer = Reader::new(der);
        let mut key = outer.sequence()?;
        outer.end()?;
        let n = key.integer()?;
        let e = key.integer()?;
        key.end()?;
        Self::fill(n, e, storage)
    }

    /// A SubjectPublicKeyInfo around one; `pss` says whether the
    /// PSS-only algorithm is accepted beside `rsaEncryption`.
    pub(crate) fn fill_from_spki(
        der: &[u8],
        pss: bool,
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        let (algorithm, key) = der::read_spki(der)?;
        rsa_algorithm(&algorithm, pss)?;
        Self::fill_from_pkcs1(key, storage)
    }

    fn write_pkcs1(&self, w: &mut Writer) {
        let mut n = [0u8; modulus_len(MAX_BITS)];
        let n = &mut n[..self.modulus_len()];
        self.write_modulus(n);
        let e = self.exponent_bytes();
        w.sequence(|w| {
            w.integer(n);
            w.integer(&e);
        });
    }

    pub(crate) fn pkcs1_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        der::encode(out, |w| self.write_pkcs1(w))
    }

    pub(crate) fn spki_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        der::write_spki(out, der::RSA_ENCRYPTION, true, |w| self.write_pkcs1(w))
    }

    /// Either DER form from a PEM block, told apart by its label.
    pub(crate) fn fill_from_pem(
        pem: &[u8],
        pss: bool,
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        let mut der = [0u8; PUBLIC_DER];
        let (form, n) = pem::decode(&PUBLIC_LABELS, pem, &mut der)?;
        match form {
            0 => Self::fill_from_spki(&der[..n], pss, storage),
            _ => Self::fill_from_pkcs1(&der[..n], storage),
        }
    }

    /// The key as a PEM block, around the bare RSAPublicKey when
    /// `pkcs1` and the SubjectPublicKeyInfo otherwise.
    pub(crate) fn pem_bytes(
        &self,
        out: &mut [u8],
        pkcs1: bool,
    ) -> Result<usize, Error> {
        let mut der = [0u8; PUBLIC_DER];
        let (label, n) = if pkcs1 {
            (PUBLIC_LABELS[1], self.pkcs1_bytes(&mut der)?)
        } else {
            (PUBLIC_LABELS[0], self.spki_bytes(&mut der)?)
        };
        to_pem(label, &der[..n], out)
    }
}

impl<'a> Private<'a> {
    /// The RSAPrivateKey structure of RFC 8017 A.1.2, with the
    /// public half it carries, laid out in `storage`. The structure
    /// holds the primes, so every key read this way is a CRT key.
    pub(crate) fn fill_from_pkcs1(
        der: &[u8],
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        let mut outer = Reader::new(der);
        let mut key = outer.sequence()?;
        outer.end()?;
        // Version 0 is a two-prime key. Version 1 is multi-prime,
        // which nothing here handles.
        if key.integer()? != [0] {
            return Err(Error::InvalidEncoding);
        }
        let n = key.integer()?;
        let e = key.integer()?;
        let d = key.integer()?;
        let p = key.integer()?;
        let q = key.integer()?;
        let dp = key.integer()?;
        let dq = key.integer()?;
        let qinv = key.integer()?;
        key.end()?;
        Self::fill_crt(n, e, d, p, q, dp, dq, qinv, storage, scratch)
    }

    /// A PKCS#8 PrivateKeyInfo around one; `pss` as for
    /// [`Public::fill_from_spki`].
    pub(crate) fn fill_from_pkcs8(
        der: &[u8],
        pss: bool,
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        let info = der::read_pkcs8(der)?;
        rsa_algorithm(&info.algorithm, pss)?;
        Self::fill_from_pkcs1(info.private_key, storage, scratch)
    }

    /// The integers to write, which needs the CRT parts: the
    /// structure has no place for their absence.
    fn parts(&self) -> Result<Parts, Error> {
        let public = self.public();
        let n_len = public.modulus_len();
        let half_len = self.prime_len();
        let mut parts = Parts::zeroed();
        public.write_modulus(&mut parts.n[..n_len]);
        parts.e = public.exponent_bytes();
        self.write_d(&mut parts.d[..n_len]);
        let Parts {
            p, q, dp, dq, qinv, ..
        } = &mut parts;
        self.crt_bytes(
            &mut p[..half_len],
            &mut q[..half_len],
            &mut dp[..half_len],
            &mut dq[..half_len],
            &mut qinv[..half_len],
        )?;
        Ok(parts)
    }

    fn write_pkcs1(&self, parts: &Parts, w: &mut Writer) {
        let n_len = self.public().modulus_len();
        let half_len = self.prime_len();
        w.sequence(|w| {
            w.integer(&[0]);
            w.integer(&parts.n[..n_len]);
            w.integer(&parts.e);
            w.integer(&parts.d[..n_len]);
            let pieces =
                [&parts.p, &parts.q, &parts.dp, &parts.dq, &parts.qinv];
            for part in pieces {
                w.integer(&part[..half_len]);
            }
        });
    }

    pub(crate) fn pkcs1_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        let parts = self.parts()?;
        der::encode(out, |w| self.write_pkcs1(&parts, w))
    }

    pub(crate) fn pkcs8_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        let parts = self.parts()?;
        der::write_pkcs8(out, der::RSA_ENCRYPTION, true, |w| {
            self.write_pkcs1(&parts, w)
        })
    }

    /// Either DER form from a PEM block, told apart by its label.
    pub(crate) fn fill_from_pem(
        pem: &[u8],
        pss: bool,
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        let mut der = [0u8; PRIVATE_DER];
        let result = pem::decode(&PRIVATE_LABELS, pem, &mut der).and_then(
            |(form, n)| match form {
                0 => Self::fill_from_pkcs8(&der[..n], pss, storage, scratch),
                _ => Self::fill_from_pkcs1(&der[..n], storage, scratch),
            },
        );
        der.zeroize();
        result
    }

    /// The key as a PEM block, around the bare RSAPrivateKey when
    /// `pkcs1` and the PrivateKeyInfo otherwise.
    pub(crate) fn pem_bytes(
        &self,
        out: &mut [u8],
        pkcs1: bool,
    ) -> Result<usize, Error> {
        let mut der = [0u8; PRIVATE_DER];
        let encoded = if pkcs1 {
            self.pkcs1_bytes(&mut der).map(|n| (PRIVATE_LABELS[1], n))
        } else {
            self.pkcs8_bytes(&mut der).map(|n| (PRIVATE_LABELS[0], n))
        };
        let result =
            encoded.and_then(|(label, n)| to_pem(label, &der[..n], out));
        der.zeroize();
        result
    }
}

/// MGF1: xors `out` with the counter-indexed digests of `seed`, as
/// RFC 8017 appendix B.2.1 defines the mask. PSS and OAEP both mask
/// with it.
pub(crate) fn mgf1_xor<H: Hash>(
    seed: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    for (counter, chunk) in (0u32..).zip(out.chunks_mut(size_of::<H::Output>()))
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout's parts are disjoint, in order, and end where the
    /// word count says, at every length in range.
    #[test]
    fn the_layout_tiles_its_words() {
        for bits in [MIN_BITS, 1200, 2048, 2049, 3072, 4096, MAX_BITS] {
            let layout = Layout::of(bits);
            assert_eq!(layout.modulus().start, PUBLIC_HEADER);
            assert_eq!(layout.modulus().end, public_words(bits));
            assert_eq!(layout.d().start, layout.private() + PRIVATE_HEADER);
            let ranges = [
                layout.d(),
                layout.p(),
                layout.q(),
                layout.dp(),
                layout.dq(),
                layout.qinv(),
            ];
            for pair in ranges.windows(2) {
                assert_eq!(pair[0].end, pair[1].start, "{bits}");
            }
            assert_eq!(layout.qinv().end, private_words(bits), "{bits}");
            assert!(2 * layout.half >= layout.limbs, "{bits}");
        }
    }

    #[test]
    fn lengths_in_bits_and_bytes() {
        assert_eq!(limbs(2048), 32);
        assert_eq!(limbs(2049), 33);
        assert_eq!(half_limbs(2048), 16);
        assert_eq!(half_limbs(2049), 17);
        assert_eq!(modulus_len(1200), 150);
        assert_eq!(prime_len(1200), 75);
        assert_eq!(prime_len(2049), 129);
        assert_eq!(bits_of(&[0, 0, 0x80, 1]).0, 16);
        assert_eq!(bits_of(&[0, 0]).0, 0);
    }

    #[test]
    fn inverse_of_a_word() {
        assert_eq!(inv_mod_word(3, 65537) * 3 % 65537, 1);
        assert_eq!(inv_mod_word(65536, 65537) * 65536 % 65537, 1);
    }
}
