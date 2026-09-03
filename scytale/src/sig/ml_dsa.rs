//! ML-DSA (FIPS 204), the module-lattice signature standardised
//! from Dilithium, in its three parameter sets.
//!
//! A key pair is again a matrix equation over polynomials, the
//! public `t = A s1 + s2` for a public `A` and small secret `s1`,
//! `s2`; a signature is a short vector `z = y + c s1` for a masking
//! vector `y` and a challenge `c` hashed from the message and a
//! commitment to `y`, with hints that let the verifier reconstruct
//! that commitment from `z` and the public key. Forging one means
//! finding a short preimage in the lattice. Each parameter set is a
//! module of its own, [`ml_dsa_44`], [`ml_dsa_65`] and
//! [`ml_dsa_87`], with the same two key types and the same calls; 65
//! is the set most deployments choose.
//!
//! Signing is hedged by default, as FIPS 204 prefers: 32 random
//! bytes are mixed into the nonce derivation beside the key and the
//! message, so a fault or a reused message leaks nothing, while the
//! signature stays unforgeable even if the random bytes were known.
//! [`sign_deterministic`](ml_dsa_65::PrivateKey::sign_deterministic)
//! fixes those bytes to zero for the settings that need repeatable
//! output and can rule faults out.
//!
//! Every signature takes a context string of up to 255 bytes, empty
//! unless a protocol assigns one, which separates the signatures of
//! one key across uses. This is the pure ML-DSA of FIPS 204 section
//! 5.2; the pre-hashed variant is not offered.
//!
//! A private key is a 32-byte seed from which FIPS 204 derives
//! everything else; the expanded form of 2560 to 4896 bytes is what
//! the algorithms consume. Both are read and written, the seed being
//! the form to store.
//!
//! ```
//! use scytale::random::{Rng, System};
//! use scytale::sig::ml_dsa::ml_dsa_65::{PrivateKey, PublicKey};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let key = PrivateKey::generate(&mut rng)?;
//! let signature = key.sign(&mut rng, b"", b"release v1.2")?;
//!
//! let public = PublicKey::try_new(&key.public_key().bytes())?;
//! public.verify(b"", b"release v1.2", &signature)?;
//! assert!(public.verify(b"", b"release v1.3", &signature).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! Coefficient arithmetic is branch-free on values below the
//! modulus, with the rounding and hint functions written as masks
//! as the reference implementation writes them. Signing is a
//! rejection loop, and the number of rounds it takes is visible;
//! that is inherent in the scheme and independent of the key, and
//! within a round no branch or index depends on a secret.
//! Verification handles only public values.

use zeroize::Zeroize;

use crate::hash::sha3::{Shake128, Shake256};
use crate::hash::{Xof, XofReader};
use crate::util;
use crate::Error;

/// The modulus.
const Q: u32 = 8_380_417;

/// Coefficients in a polynomial.
const N: usize = 256;

/// The bits `Power2Round` drops from `t`.
const D: u32 = 13;

/// The length of a seed.
const SEED: usize = 32;

/// The longest context string.
const CONTEXT_MAX: usize = 255;

/// What a parameter set fixes beyond the matrix shape `K` by `L`.
struct Params {
    eta: u32,
    tau: usize,
    beta: u32,
    gamma1: u32,
    gamma2: u32,
    omega: usize,
    /// The length of the challenge hash, `lambda / 4`.
    c_tilde: usize,
    /// Bits per coefficient in a packed `s1` or `s2`.
    s_bits: usize,
    /// Bits per coefficient in a packed `z` or `y`.
    z_bits: usize,
    /// Bits per coefficient in a packed `w1`.
    w1_bits: usize,
}

const PARAMS_44: Params = Params {
    eta: 2,
    tau: 39,
    beta: 78,
    gamma1: 1 << 17,
    gamma2: (Q - 1) / 88,
    omega: 80,
    c_tilde: 32,
    s_bits: 3,
    z_bits: 18,
    w1_bits: 6,
};

const PARAMS_65: Params = Params {
    eta: 4,
    tau: 49,
    beta: 196,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    omega: 55,
    c_tilde: 48,
    s_bits: 4,
    z_bits: 20,
    w1_bits: 4,
};

const PARAMS_87: Params = Params {
    eta: 2,
    tau: 60,
    beta: 120,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    omega: 75,
    c_tilde: 64,
    s_bits: 3,
    z_bits: 20,
    w1_bits: 4,
};

/// The parameters of the set with `K` rows.
const fn params<const K: usize>() -> &'static Params {
    match K {
        4 => &PARAMS_44,
        6 => &PARAMS_65,
        _ => &PARAMS_87,
    }
}

const fn public_len(k: usize) -> usize {
    32 + 320 * k
}

const fn private_len(k: usize, l: usize, p: &Params) -> usize {
    128 + 32 * p.s_bits * (l + k) + 416 * k
}

const fn signature_len(k: usize, l: usize, p: &Params) -> usize {
    p.c_tilde + 32 * p.z_bits * l + p.omega + k
}

// The ring: polynomials modulo x^256 + 1 over the integers modulo q.

const fn bitrev8(i: usize) -> usize {
    let mut out = 0;
    let mut bit = 0;
    while bit < 8 {
        out |= ((i >> bit) & 1) << (7 - bit);
        bit += 1;
    }
    out
}

/// `1753^e mod q`; 1753 is the root of unity the transform uses.
const fn zeta_pow(mut e: usize) -> u32 {
    let mut result = 1u64;
    let mut base = 1753u64;
    let q = Q as u64;
    while e > 0 {
        if e & 1 == 1 {
            result = result * base % q;
        }
        base = base * base % q;
        e >>= 1;
    }
    result as u32
}

/// The roots in the order the butterflies use them.
const ZETAS: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = zeta_pow(bitrev8(i));
        i += 1;
    }
    table
};

/// `a mod q` for `a` below `2q`.
fn csub(a: u32) -> u32 {
    let r = a as i32 - Q as i32;
    (r + ((r >> 31) & Q as i32)) as u32
}

fn add(a: u32, b: u32) -> u32 {
    csub(a + b)
}

fn sub(a: u32, b: u32) -> u32 {
    csub(a + Q - b)
}

/// The product, reduced by division by the constant modulus, which
/// compiles to a multiply and a shift.
fn mul(a: u32, b: u32) -> u32 {
    (u64::from(a) * u64::from(b) % u64::from(Q)) as u32
}

/// The representative in `(-q/2, q/2]`.
fn signed(a: u32) -> i32 {
    let a = a as i32;
    let half = ((Q - 1) / 2) as i32;
    a - (Q as i32 & ((half - a) >> 31))
}

/// Back from a representative in `(-q, q)`.
fn unsigned(v: i32) -> u32 {
    (v + ((v >> 31) & Q as i32)) as u32
}

/// `Power2Round`: `r = r1 2^d + r0` with `r0` in `(-2^(d-1), 2^(d-1)]`.
fn power2round(r: u32) -> (u32, i32) {
    let r1 = (r + (1 << (D - 1)) - 1) >> D;
    (r1, r as i32 - (r1 << D) as i32)
}

/// `Decompose`: `r = r1 (2 gamma2) + r0` with the wrap at `q - 1`
/// folded in, by the reference implementation's arithmetic.
fn decompose(r: u32, gamma2: u32) -> (u32, i32) {
    let mut r1 = (r + 127) >> 7;
    if gamma2 == (Q - 1) / 32 {
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        r1 &= 15;
    } else {
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        r1 ^= (((43i32 - r1 as i32) >> 31) as u32) & r1;
    }
    let mut r0 = r as i32 - (r1 * 2 * gamma2) as i32;
    r0 -= ((((Q - 1) / 2) as i32 - r0) >> 31) & Q as i32;
    (r1, r0)
}

/// A polynomial with coefficients in `[0, q)`.
#[derive(Clone, Copy)]
struct Poly([u32; N]);

impl Poly {
    const ZERO: Poly = Poly([0; N]);

    /// The transform, algorithm 41.
    fn ntt(&mut self) {
        let w = &mut self.0;
        let mut m = 0;
        let mut len = 128;
        while len >= 1 {
            for start in (0..N).step_by(2 * len) {
                m += 1;
                let z = ZETAS[m];
                for j in start..start + len {
                    let t = mul(z, w[j + len]);
                    w[j + len] = sub(w[j], t);
                    w[j] = add(w[j], t);
                }
            }
            len /= 2;
        }
    }

    /// The inverse transform, algorithm 42.
    fn inverse_ntt(&mut self) {
        let w = &mut self.0;
        let mut m = 256;
        let mut len = 1;
        while len < N {
            for start in (0..N).step_by(2 * len) {
                m -= 1;
                let z = Q - ZETAS[m];
                for j in start..start + len {
                    let t = w[j];
                    w[j] = add(t, w[j + len]);
                    w[j + len] = mul(z, sub(t, w[j + len]));
                }
            }
            len *= 2;
        }
        // 256^-1 mod q.
        for c in w.iter_mut() {
            *c = mul(*c, 8_347_681);
        }
    }

    fn mul_ntt(&self, other: &Poly) -> Poly {
        let mut out = Poly::ZERO;
        for ((c, a), b) in out.0.iter_mut().zip(&self.0).zip(&other.0) {
            *c = mul(*a, *b);
        }
        out
    }

    fn add_assign(&mut self, other: &Poly) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a = add(*a, *b);
        }
    }

    fn sub_assign(&mut self, other: &Poly) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a = sub(*a, *b);
        }
    }

    /// Whether any coefficient's magnitude reaches `bound`.
    fn norm_reaches(&self, bound: u32) -> bool {
        let mut reached = 0u32;
        for &c in &self.0 {
            let v = signed(c);
            let magnitude = (v ^ (v >> 31)) - (v >> 31);
            reached |= ((bound as i32 - 1 - magnitude) >> 31) as u32;
        }
        reached & 1 == 1
    }

    /// `SimpleBitPack`: coefficients below `2^bits` into `32 bits`
    /// bytes.
    fn pack(&self, bits: usize, out: &mut [u8]) {
        debug_assert_eq!(out.len(), 32 * bits);
        let mut acc = 0u64;
        let mut have = 0;
        let mut pos = 0;
        for &c in &self.0 {
            acc |= u64::from(c) << have;
            have += bits;
            while have >= 8 {
                out[pos] = acc as u8;
                pos += 1;
                acc >>= 8;
                have -= 8;
            }
        }
    }

    /// `SimpleBitUnpack`.
    fn unpack(bits: usize, bytes: &[u8]) -> Poly {
        debug_assert_eq!(bytes.len(), 32 * bits);
        let mut out = Poly::ZERO;
        let mask = (1u64 << bits) - 1;
        let mut acc = 0u64;
        let mut have = 0;
        let mut pos = 0;
        for c in out.0.iter_mut() {
            while have < bits {
                acc |= u64::from(bytes[pos]) << have;
                pos += 1;
                have += 8;
            }
            *c = (acc & mask) as u32;
            acc >>= bits;
            have -= bits;
        }
        out
    }

    /// `BitPack` of coefficients in `[-a, b]`, stored as `b - w`.
    fn pack_signed(&self, b: u32, bits: usize, out: &mut [u8]) {
        let mut shifted = Poly::ZERO;
        for (s, &c) in shifted.0.iter_mut().zip(&self.0) {
            *s = (b as i32 - signed(c)) as u32;
        }
        shifted.pack(bits, out);
    }

    /// `BitUnpack`, the reverse; a value that decodes outside
    /// `[-a, b]` is left to the range checks that follow.
    fn unpack_signed(b: u32, bits: usize, bytes: &[u8]) -> Poly {
        let mut out = Poly::unpack(bits, bytes);
        for c in out.0.iter_mut() {
            *c = unsigned(b as i32 - *c as i32);
        }
        out
    }

    /// `RejNTTPoly`: the entry of `A` at `row`, `col`, from
    /// SHAKE-128 over the seed and the indices, column first.
    fn sample_ntt(rho: &[u8; 32], row: u8, col: u8) -> Result<Poly, Error> {
        let mut xof = Shake128::try_new()?;
        xof.update(rho);
        xof.update(&[col, row]);
        let mut reader = xof.finalize_xof();
        let mut out = Poly::ZERO;
        let mut filled = 0;
        let mut buf = [0u8; 168];
        while filled < N {
            reader.squeeze(&mut buf);
            for chunk in buf.chunks_exact(3) {
                let z = u32::from(chunk[0])
                    | u32::from(chunk[1]) << 8
                    | u32::from(chunk[2] & 0x7f) << 16;
                if filled < N && z < Q {
                    out.0[filled] = z;
                    filled += 1;
                }
            }
        }
        Ok(out)
    }

    /// `RejBoundedPoly`: coefficients in `[-eta, eta]` from SHAKE-256
    /// over the seed and a two-byte index, one nibble a candidate.
    fn sample_bounded(eta: u32, rho: &[u8; 64], r: u16) -> Result<Poly, Error> {
        let mut xof = Shake256::try_new()?;
        xof.update(rho);
        xof.update(&r.to_le_bytes());
        let mut reader = xof.finalize_xof();
        let mut out = Poly::ZERO;
        let mut filled = 0;
        let mut buf = [0u8; 136];
        while filled < N {
            reader.squeeze(&mut buf);
            for &byte in &buf {
                for z in [u32::from(byte & 15), u32::from(byte >> 4)] {
                    let coefficient = if eta == 2 {
                        (z < 15).then(|| unsigned(2 - (z % 5) as i32))
                    } else {
                        (z < 9).then(|| unsigned(4 - z as i32))
                    };
                    if let (Some(c), true) = (coefficient, filled < N) {
                        out.0[filled] = c;
                        filled += 1;
                    }
                }
            }
        }
        out.0.iter_mut().for_each(|c| *c = csub(*c));
        Ok(out)
    }

    /// `SampleInBall`: `tau` coefficients of `1` or `-1` placed by a
    /// shuffle driven by SHAKE-256 over the challenge hash.
    fn sample_in_ball(tau: usize, c_tilde: &[u8]) -> Result<Poly, Error> {
        let mut xof = Shake256::try_new()?;
        xof.update(c_tilde);
        let mut reader = xof.finalize_xof();
        let mut signs = [0u8; 8];
        reader.squeeze(&mut signs);
        let signs = u64::from_le_bytes(signs);
        let mut out = Poly::ZERO;
        for i in N - tau..N {
            let mut j = [0u8; 1];
            loop {
                reader.squeeze(&mut j);
                if usize::from(j[0]) <= i {
                    break;
                }
            }
            let j = usize::from(j[0]);
            out.0[i] = out.0[j];
            let negative = (signs >> (i + tau - N)) & 1 == 1;
            out.0[j] = if negative { Q - 1 } else { 1 };
        }
        Ok(out)
    }
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// `H`, SHAKE-256 over the parts, `out.len()` bytes.
fn h(parts: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    let mut xof = Shake256::try_new()?;
    for part in parts {
        xof.update(part);
    }
    xof.finalize_xof().squeeze(out);
    Ok(())
}

/// The expanded matrix `A` in the transform domain, `ExpandA`.
fn expand_a<const K: usize, const L: usize>(
    rho: &[u8; 32],
) -> Result<[[Poly; L]; K], Error> {
    let mut a = [[Poly::ZERO; L]; K];
    for (r, row) in a.iter_mut().enumerate() {
        for (s, entry) in row.iter_mut().enumerate() {
            *entry = Poly::sample_ntt(rho, r as u8, s as u8)?;
        }
    }
    Ok(a)
}

/// `A v` for `v` already in the transform domain, the result too.
fn matrix_mul<const K: usize, const L: usize>(
    a: &[[Poly; L]; K],
    v: &[Poly; L],
) -> [Poly; K] {
    let mut out = [Poly::ZERO; K];
    for (o, row) in out.iter_mut().zip(a) {
        for (entry, v_j) in row.iter().zip(v) {
            o.add_assign(&entry.mul_ntt(v_j));
        }
    }
    out
}

/// The `HintBitPack` of `h` into `omega + K` bytes.
fn pack_hints<const K: usize>(h: &[Poly; K], omega: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), omega + K);
    out.fill(0);
    let mut index = 0;
    for (i, poly) in h.iter().enumerate() {
        for (j, &bit) in poly.0.iter().enumerate() {
            if bit != 0 {
                out[index] = j as u8;
                index += 1;
            }
        }
        out[omega + i] = index as u8;
    }
}

/// `HintBitUnpack`, refusing every encoding but the canonical one:
/// counts that decrease or exceed `omega`, indices not increasing,
/// and padding that is not zero.
fn unpack_hints<const K: usize>(
    omega: usize,
    bytes: &[u8],
) -> Option<[Poly; K]> {
    let mut h = [Poly::ZERO; K];
    let mut index = 0usize;
    for (i, poly) in h.iter_mut().enumerate() {
        let end = usize::from(bytes[omega + i]);
        if end < index || end > omega {
            return None;
        }
        let mut first = true;
        while index < end {
            let j = usize::from(bytes[index]);
            if !first && j <= usize::from(bytes[index - 1]) {
                return None;
            }
            first = false;
            poly.0[j] = 1;
            index += 1;
        }
    }
    if bytes[index..omega].iter().any(|&b| b != 0) {
        return None;
    }
    Some(h)
}

/// `pkEncode` layout: `rho || t1`.
fn encode_public<const K: usize>(
    rho: &[u8; 32],
    t1: &[Poly; K],
    out: &mut [u8],
) {
    out[..32].copy_from_slice(rho);
    for (i, t) in t1.iter().enumerate() {
        t.pack(10, &mut out[32 + 320 * i..32 + 320 * (i + 1)]);
    }
}

/// `ML-DSA.KeyGen_internal`, algorithm 6.
fn key_gen<const K: usize, const L: usize>(
    xi: &[u8; SEED],
    pk: &mut [u8],
    sk: &mut [u8],
) -> Result<(), Error> {
    let p = params::<K>();
    let mut seeds = [0u8; 128];
    h(&[xi, &[K as u8, L as u8]], &mut seeds)?;
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&seeds[..32]);
    let mut rho_prime = [0u8; 64];
    rho_prime.copy_from_slice(&seeds[32..96]);
    let key = &seeds[96..];

    let a = expand_a::<K, L>(&rho)?;
    let mut s1 = [Poly::ZERO; L];
    let mut s2 = [Poly::ZERO; K];
    for (r, s) in s1.iter_mut().enumerate() {
        *s = Poly::sample_bounded(p.eta, &rho_prime, r as u16)?;
    }
    for (r, s) in s2.iter_mut().enumerate() {
        *s = Poly::sample_bounded(p.eta, &rho_prime, (L + r) as u16)?;
    }
    let mut s1_hat = s1;
    s1_hat.iter_mut().for_each(Poly::ntt);
    let mut t = matrix_mul(&a, &s1_hat);
    for (t_i, s2_i) in t.iter_mut().zip(&s2) {
        t_i.inverse_ntt();
        t_i.add_assign(s2_i);
    }
    let mut t1 = [Poly::ZERO; K];
    let mut t0 = [Poly::ZERO; K];
    for i in 0..K {
        for j in 0..N {
            let (high, low) = power2round(t[i].0[j]);
            t1[i].0[j] = high;
            t0[i].0[j] = unsigned(low);
        }
    }
    encode_public(&rho, &t1, pk);
    let mut tr = [0u8; 64];
    h(&[pk], &mut tr)?;

    // skEncode: rho || K || tr || s1 || s2 || t0.
    sk[..32].copy_from_slice(&rho);
    sk[32..64].copy_from_slice(key);
    sk[64..128].copy_from_slice(&tr);
    let s_len = 32 * p.s_bits;
    let mut pos = 128;
    for s in s1.iter().chain(&s2) {
        s.pack_signed(p.eta, p.s_bits, &mut sk[pos..pos + s_len]);
        pos += s_len;
    }
    for t in &t0 {
        t.pack_signed(1 << (D - 1), 13, &mut sk[pos..pos + 416]);
        pos += 416;
    }
    seeds.zeroize();
    rho_prime.zeroize();
    s1.zeroize();
    s2.zeroize();
    s1_hat.zeroize();
    t0.zeroize();
    Ok(())
}

/// The private key's parts, decoded and transformed once for a
/// signature; wiped on drop.
struct Expanded<const K: usize, const L: usize> {
    rho: [u8; 32],
    key: [u8; 32],
    tr: [u8; 64],
    s1_hat: [Poly; L],
    s2_hat: [Poly; K],
    t0_hat: [Poly; K],
}

impl<const K: usize, const L: usize> Expanded<K, L> {
    /// `skDecode`, with the secret vectors moved into the transform
    /// domain.
    fn decode(sk: &[u8]) -> Self {
        let p = params::<K>();
        let mut out = Expanded {
            rho: [0; 32],
            key: [0; 32],
            tr: [0; 64],
            s1_hat: [Poly::ZERO; L],
            s2_hat: [Poly::ZERO; K],
            t0_hat: [Poly::ZERO; K],
        };
        out.rho.copy_from_slice(&sk[..32]);
        out.key.copy_from_slice(&sk[32..64]);
        out.tr.copy_from_slice(&sk[64..128]);
        let s_len = 32 * p.s_bits;
        let mut pos = 128;
        for s in out.s1_hat.iter_mut().chain(out.s2_hat.iter_mut()) {
            *s = Poly::unpack_signed(p.eta, p.s_bits, &sk[pos..pos + s_len]);
            s.ntt();
            pos += s_len;
        }
        for t in out.t0_hat.iter_mut() {
            *t = Poly::unpack_signed(1 << (D - 1), 13, &sk[pos..pos + 416]);
            t.ntt();
            pos += 416;
        }
        out
    }
}

impl<const K: usize, const L: usize> Drop for Expanded<K, L> {
    fn drop(&mut self) {
        self.key.zeroize();
        self.s1_hat.zeroize();
        self.s2_hat.zeroize();
        self.t0_hat.zeroize();
    }
}

/// The public key a private key implies, for checking one that came
/// in expanded: `s1` and `s2` within `eta`, then `t = A s1 + s2`
/// recomputed and rounded, and compared with the stored `t0` and the
/// stored hash of the public key.
fn check_private<const K: usize, const L: usize>(
    sk: &[u8],
    pk: &mut [u8],
) -> Result<bool, Error> {
    let p = params::<K>();
    let s_len = 32 * p.s_bits;
    let in_range =
        sk[128..128 + s_len * (L + K)]
            .chunks_exact(s_len)
            .all(|chunk| {
                !Poly::unpack_signed(p.eta, p.s_bits, chunk)
                    .norm_reaches(p.eta + 1)
            });
    if !in_range {
        return Ok(false);
    }
    let e = Expanded::<K, L>::decode(sk);
    let a = expand_a::<K, L>(&e.rho)?;
    let mut t = matrix_mul(&a, &e.s1_hat);
    let mut t1 = [Poly::ZERO; K];
    let mut same = true;
    for i in 0..K {
        let mut s2 = e.s2_hat[i];
        s2.inverse_ntt();
        t[i].inverse_ntt();
        t[i].add_assign(&s2);
        let mut t0 = e.t0_hat[i];
        t0.inverse_ntt();
        for j in 0..N {
            let (high, low) = power2round(t[i].0[j]);
            t1[i].0[j] = high;
            same &= unsigned(low) == t0.0[j];
        }
    }
    encode_public(&e.rho, &t1, pk);
    let mut tr = [0u8; 64];
    h(&[pk], &mut tr)?;
    Ok(same && util::equal(&tr, &e.tr))
}

/// `ML-DSA.Sign_internal`, algorithm 7, over the formatted message
/// `m_prime` with the hedging bytes `rnd`, into `sig`.
fn sign<const K: usize, const L: usize>(
    sk: &[u8],
    m_prime: &[&[u8]],
    rnd: &[u8; 32],
    sig: &mut [u8],
) -> Result<(), Error> {
    let p = params::<K>();
    let e = Expanded::<K, L>::decode(sk);
    let a = expand_a::<K, L>(&e.rho)?;
    let mut mu = [0u8; 64];
    {
        let mut xof = Shake256::try_new()?;
        xof.update(&e.tr);
        for part in m_prime {
            xof.update(part);
        }
        xof.finalize_xof().squeeze(&mut mu);
    }
    let mut rho_double = [0u8; 64];
    h(&[&e.key, rnd, &mu], &mut rho_double)?;

    let z_len = 32 * p.z_bits;
    let w1_len = 32 * p.w1_bits;
    let mut w1_bytes = [0u8; 192 * 8];
    let w1_bytes = &mut w1_bytes[..w1_len * K];
    let mut kappa = 0u16;
    loop {
        // y = ExpandMask(rho'', kappa), one polynomial per column.
        let mut y = [Poly::ZERO; L];
        let mut y_bytes = [0u8; 640];
        for (r, y_r) in y.iter_mut().enumerate() {
            h(
                &[&rho_double, &(kappa + r as u16).to_le_bytes()],
                &mut y_bytes[..z_len],
            )?;
            *y_r = Poly::unpack_signed(p.gamma1, p.z_bits, &y_bytes[..z_len]);
        }
        kappa += L as u16;

        let mut y_hat = y;
        y_hat.iter_mut().for_each(Poly::ntt);
        let mut w = matrix_mul(&a, &y_hat);
        w.iter_mut().for_each(Poly::inverse_ntt);
        let mut w1 = [Poly::ZERO; K];
        for (i, w_i) in w.iter().enumerate() {
            for j in 0..N {
                w1[i].0[j] = decompose(w_i.0[j], p.gamma2).0;
            }
            w1[i].pack(p.w1_bits, &mut w1_bytes[w1_len * i..w1_len * (i + 1)]);
        }
        let c_tilde = &mut sig[..p.c_tilde];
        h(&[&mu, w1_bytes], c_tilde)?;
        let mut c_hat = Poly::sample_in_ball(p.tau, c_tilde)?;
        c_hat.ntt();

        // z = y + c s1; r0 = LowBits(w - c s2).
        let mut z = [Poly::ZERO; L];
        for (i, z_i) in z.iter_mut().enumerate() {
            let mut cs1 = c_hat.mul_ntt(&e.s1_hat[i]);
            cs1.inverse_ntt();
            *z_i = y[i];
            z_i.add_assign(&cs1);
        }
        let mut w_minus_cs2 = [Poly::ZERO; K];
        let mut reject = false;
        for (i, r) in w_minus_cs2.iter_mut().enumerate() {
            let mut cs2 = c_hat.mul_ntt(&e.s2_hat[i]);
            cs2.inverse_ntt();
            *r = w[i];
            r.sub_assign(&cs2);
            let mut r0 = Poly::ZERO;
            for j in 0..N {
                r0.0[j] = unsigned(decompose(r.0[j], p.gamma2).1);
            }
            reject |= r0.norm_reaches(p.gamma2 - p.beta);
        }
        for z_i in &z {
            reject |= z_i.norm_reaches(p.gamma1 - p.beta);
        }
        if reject {
            y.zeroize();
            y_hat.zeroize();
            z.zeroize();
            continue;
        }

        // Hints: h = MakeHint(-c t0, w - c s2 + c t0).
        let mut hints = [Poly::ZERO; K];
        let mut count = 0usize;
        for i in 0..K {
            let mut ct0 = c_hat.mul_ntt(&e.t0_hat[i]);
            ct0.inverse_ntt();
            reject |= ct0.norm_reaches(p.gamma2);
            for j in 0..N {
                let r = add(w_minus_cs2[i].0[j], ct0.0[j]);
                let with_z = sub(r, ct0.0[j]);
                let hint =
                    decompose(r, p.gamma2).0 != decompose(with_z, p.gamma2).0;
                hints[i].0[j] = u32::from(hint);
                count += usize::from(hint);
            }
        }
        if reject || count > p.omega {
            y.zeroize();
            y_hat.zeroize();
            z.zeroize();
            continue;
        }

        // sigEncode: c_tilde || z || h.
        let mut pos = p.c_tilde;
        for z_i in &z {
            z_i.pack_signed(p.gamma1, p.z_bits, &mut sig[pos..pos + z_len]);
            pos += z_len;
        }
        pack_hints(&hints, p.omega, &mut sig[pos..]);
        y.zeroize();
        y_hat.zeroize();
        z.zeroize();
        rho_double.zeroize();
        return Ok(());
    }
}

/// `ML-DSA.Verify_internal`, algorithm 8.
fn verify<const K: usize, const L: usize>(
    pk: &[u8],
    m_prime: &[&[u8]],
    sig: &[u8],
) -> Result<(), Error> {
    let p = params::<K>();
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);
    let z_len = 32 * p.z_bits;
    let w1_len = 32 * p.w1_bits;

    // sigDecode, refusing what does not decode.
    let c_tilde = &sig[..p.c_tilde];
    let mut z = [Poly::ZERO; L];
    let mut pos = p.c_tilde;
    for z_i in z.iter_mut() {
        *z_i = Poly::unpack_signed(p.gamma1, p.z_bits, &sig[pos..pos + z_len]);
        pos += z_len;
    }
    let hints = unpack_hints::<K>(p.omega, &sig[pos..])
        .ok_or(Error::InvalidSignature)?;
    if z.iter().any(|z_i| z_i.norm_reaches(p.gamma1 - p.beta)) {
        return Err(Error::InvalidSignature);
    }

    let a = expand_a::<K, L>(&rho)?;
    let mut tr = [0u8; 64];
    h(&[pk], &mut tr)?;
    let mut mu = [0u8; 64];
    {
        let mut xof = Shake256::try_new()?;
        xof.update(&tr);
        for part in m_prime {
            xof.update(part);
        }
        xof.finalize_xof().squeeze(&mut mu);
    }
    let mut c_hat = Poly::sample_in_ball(p.tau, c_tilde)?;
    c_hat.ntt();

    // w' = A z - c t1 2^d, then the hints recover w1.
    z.iter_mut().for_each(Poly::ntt);
    let mut w = matrix_mul(&a, &z);
    let mut w1_bytes = [0u8; 192 * 8];
    let w1_bytes = &mut w1_bytes[..w1_len * K];
    let m = (Q - 1) / (2 * p.gamma2);
    for i in 0..K {
        let mut t1 = Poly::unpack(10, &pk[32 + 320 * i..32 + 320 * (i + 1)]);
        t1.0.iter_mut().for_each(|c| *c <<= D);
        t1.ntt();
        w[i].sub_assign(&c_hat.mul_ntt(&t1));
        w[i].inverse_ntt();
        let mut w1 = Poly::ZERO;
        for j in 0..N {
            let (r1, r0) = decompose(w[i].0[j], p.gamma2);
            w1.0[j] = if hints[i].0[j] == 0 {
                r1
            } else if r0 > 0 {
                (r1 + 1) % m
            } else {
                (r1 + m - 1) % m
            };
        }
        w1.pack(p.w1_bits, &mut w1_bytes[w1_len * i..w1_len * (i + 1)]);
    }
    let mut again = [0u8; 64];
    h(&[&mu, w1_bytes], &mut again[..p.c_tilde])?;
    if util::equal(&again[..p.c_tilde], c_tilde) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// The message as the pure interface formats it: `0 || |ctx| || ctx
/// || M`, or [`Error::InvalidLength`] for a context too long.
fn format_message<'a>(
    context: &'a [u8],
    message: &'a [u8],
    prefix: &'a mut [u8; 2],
) -> Result<[&'a [u8]; 3], Error> {
    if context.len() > CONTEXT_MAX {
        return Err(Error::InvalidLength(context.len()));
    }
    prefix[1] = context.len() as u8;
    Ok([&prefix[..], context, message])
}

/// The OID prefix of the three parameter sets,
/// 2.16.840.1.101.3.4.3; the last arc is 17, 18 or 19.
const OID_PREFIX: [u8; 8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];

/// Room for any encoding of any key here.
const SCRATCH: usize = 8192;

const PRIVATE_LABEL: &str = "PRIVATE KEY";
const PUBLIC_LABEL: &str = "PUBLIC KEY";

/// One parameter set's public types.
macro_rules! parameter_set {
    ($k:literal, $l:literal, $arc:literal, $name:literal) => {
        use zeroize::Zeroize;

        use crate::der::SeedOrExpanded;
        use crate::random::Random;
        use crate::sig::ml_dsa::{self, params};
        use crate::Error;

        /// The length of a private key's seed, the form to store.
        pub const SEED_SIZE: usize = 32;

        /// The length of an expanded private key.
        pub const KEY_SIZE: usize = ml_dsa::private_len($k, $l, params::<$k>());

        /// The length of a public key.
        pub const PUBLIC_KEY_SIZE: usize = ml_dsa::public_len($k);

        /// The length of a signature.
        pub const SIGNATURE_SIZE: usize =
            ml_dsa::signature_len($k, $l, params::<$k>());

        /// The longest context string a signature takes.
        pub const CONTEXT_MAX: usize = 255;

        const OID: [u8; 9] = {
            let mut oid = [0u8; 9];
            let mut i = 0;
            while i < 8 {
                oid[i] = ml_dsa::OID_PREFIX[i];
                i += 1;
            }
            oid[8] = $arc;
            oid
        };

        #[doc = concat!("An ", $name, " signing key, with its seed")]
        /// when it was made from one; wiped on drop.
        pub struct PrivateKey {
            seed: Option<[u8; SEED_SIZE]>,
            expanded: [u8; KEY_SIZE],
            public: PublicKey,
        }

        #[doc = concat!("An ", $name, " verification key.")]
        #[derive(Clone)]
        pub struct PublicKey {
            bytes: [u8; PUBLIC_KEY_SIZE],
        }

        impl Drop for PrivateKey {
            fn drop(&mut self) {
                self.seed.zeroize();
                self.expanded.zeroize();
            }
        }

        impl PrivateKey {
            /// A fresh key from 32 random bytes of seed.
            pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
                let mut seed = [0u8; SEED_SIZE];
                rng.fill(&mut seed)?;
                let key = Self::try_from_seed(&seed);
                seed.zeroize();
                key
            }

            /// The key a seed expands to, by FIPS 204's
            /// `ML-DSA.KeyGen_internal`. Any 32 bytes are a seed.
            pub fn try_from_seed(
                seed: &[u8; SEED_SIZE],
            ) -> Result<Self, Error> {
                let mut expanded = [0u8; KEY_SIZE];
                let mut bytes = [0u8; PUBLIC_KEY_SIZE];
                ml_dsa::key_gen::<$k, $l>(seed, &mut bytes, &mut expanded)?;
                Ok(PrivateKey {
                    seed: Some(*seed),
                    expanded,
                    public: PublicKey { bytes },
                })
            }

            /// A key from its expanded form, checked: the public key
            /// it implies must match the hash and the rounding it
            /// carries, or it is [`Error::InvalidPrivateKey`]. A key
            /// that comes in this way has no seed to give back.
            pub fn try_new(expanded: &[u8; KEY_SIZE]) -> Result<Self, Error> {
                let mut bytes = [0u8; PUBLIC_KEY_SIZE];
                if !ml_dsa::check_private::<$k, $l>(expanded, &mut bytes)? {
                    return Err(Error::InvalidPrivateKey);
                }
                Ok(PrivateKey {
                    seed: None,
                    expanded: *expanded,
                    public: PublicKey { bytes },
                })
            }

            /// The seed, when the key was made from one, and
            /// [`Error::InvalidPrivateKey`] when it came in expanded
            /// and has none. The caller holds a secret now.
            pub fn seed_bytes(&self) -> Result<[u8; SEED_SIZE], Error> {
                self.seed.ok_or(Error::InvalidPrivateKey)
            }

            /// The expanded form. The caller holds a secret now, and
            /// should wipe it when done.
            pub fn key_bytes(&self) -> [u8; KEY_SIZE] {
                self.expanded
            }

            /// The public half.
            pub fn public_key(&self) -> &PublicKey {
                &self.public
            }

            /// Signs `message` under `context`, hedged with 32 bytes
            /// from `rng`, which is FIPS 204's default. The context
            /// is usually empty; a protocol that assigns one must
            /// present the same one to verify, and one over 255 bytes
            /// is [`Error::InvalidLength`].
            pub fn sign<R: Random>(
                &self,
                rng: &mut R,
                context: &[u8],
                message: &[u8],
            ) -> Result<[u8; SIGNATURE_SIZE], Error> {
                let mut rnd = [0u8; 32];
                rng.fill(&mut rnd)?;
                let signature = self.sign_with(context, message, &rnd);
                rnd.zeroize();
                signature
            }

            /// Signs with the hedging bytes fixed to zero, so the same
            /// key, context and message always give the same
            /// signature. Only for settings that need repeatable
            /// output and can rule out faults during signing.
            pub fn sign_deterministic(
                &self,
                context: &[u8],
                message: &[u8],
            ) -> Result<[u8; SIGNATURE_SIZE], Error> {
                self.sign_with(context, message, &[0u8; 32])
            }

            fn sign_with(
                &self,
                context: &[u8],
                message: &[u8],
                rnd: &[u8; 32],
            ) -> Result<[u8; SIGNATURE_SIZE], Error> {
                let mut prefix = [0u8; 2];
                let m_prime =
                    ml_dsa::format_message(context, message, &mut prefix)?;
                let mut out = [0u8; SIGNATURE_SIZE];
                ml_dsa::sign::<$k, $l>(
                    &self.expanded,
                    &m_prime,
                    rnd,
                    &mut out,
                )?;
                Ok(out)
            }

            /// A key from its DER PKCS#8 `PrivateKeyInfo`, the form
            /// under `PRIVATE KEY` in a PEM file, holding the seed,
            /// the expanded key, or both; a pair that disagrees is
            /// refused as corrupt. Another parameter set, or anything
            /// else wrong with the bytes, is [`Error::InvalidEncoding`].
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                let info = crate::der::read_pkcs8(der)?;
                let algorithm = &info.algorithm;
                if algorithm.oid != OID || !algorithm.params.is_empty() {
                    return Err(Error::InvalidEncoding);
                }
                let SeedOrExpanded { seed, expanded } =
                    crate::der::read_seed_or_expanded(info.private_key)?;
                match (seed, expanded) {
                    (Some(seed), expanded) => {
                        let seed: &[u8; SEED_SIZE] = seed
                            .try_into()
                            .map_err(|_| Error::InvalidEncoding)?;
                        let key = Self::try_from_seed(seed)?;
                        if expanded.is_some_and(|e| e[..] != key.expanded[..]) {
                            return Err(Error::InvalidEncoding);
                        }
                        Ok(key)
                    }
                    (None, Some(expanded)) => {
                        let expanded: &[u8; KEY_SIZE] = expanded
                            .try_into()
                            .map_err(|_| Error::InvalidEncoding)?;
                        Self::try_new(expanded)
                    }
                    (None, None) => Err(Error::InvalidEncoding),
                }
            }

            /// Writes the key as a `PrivateKeyInfo` into the front of
            /// `out`, returning the length: the seed when the key has
            /// one, the expanded key otherwise. A secret, to be wiped.
            pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let seed_tag = crate::der::context_primitive(0);
                crate::der::write_pkcs8(out, &OID, false, |w| {
                    match &self.seed {
                        Some(seed) => w.primitive(seed_tag, seed),
                        None => w.octet_string(&self.expanded),
                    }
                })
            }

            /// A key from a `PRIVATE KEY` PEM block (RFC 7468) around
            /// the DER above; whitespace and line ends are read
            /// leniently, and anything else that is not exactly one
            /// well-formed block is [`Error::InvalidEncoding`].
            pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
                let mut der = [0u8; ml_dsa::SCRATCH];
                let labels = [ml_dsa::PRIVATE_LABEL];
                let result = crate::pem::decode(&labels, pem, &mut der)
                    .and_then(|(_, n)| Self::try_from_der(&der[..n]));
                der.zeroize();
                result
            }

            /// Writes the key as a `PRIVATE KEY` PEM block, ASCII with
            /// LF line ends, into the front of `out`, returning the
            /// length. A secret, to be wiped.
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let mut der = [0u8; ml_dsa::SCRATCH];
                let label = ml_dsa::PRIVATE_LABEL;
                let result = self
                    .der_bytes(&mut der)
                    .and_then(|n| crate::pem::write(label, &der[..n], out));
                der.zeroize();
                result
            }
        }

        impl PublicKey {
            /// A public key from its bytes. Every string of the right
            /// length decodes, so nothing is checked beyond the type.
            pub fn try_new(
                bytes: &[u8; PUBLIC_KEY_SIZE],
            ) -> Result<Self, Error> {
                Ok(PublicKey { bytes: *bytes })
            }

            /// The key's bytes.
            pub fn bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
                self.bytes
            }

            /// Checks that `signature` signs `message` under
            /// `context`. [`Error::InvalidSignature`] for anything
            /// that does not, which deliberately says no more.
            pub fn verify(
                &self,
                context: &[u8],
                message: &[u8],
                signature: &[u8; SIGNATURE_SIZE],
            ) -> Result<(), Error> {
                let mut prefix = [0u8; 2];
                let m_prime =
                    ml_dsa::format_message(context, message, &mut prefix)?;
                ml_dsa::verify::<$k, $l>(&self.bytes, &m_prime, signature)
            }

            /// A key from its DER `SubjectPublicKeyInfo`, the form
            /// under `PUBLIC KEY` in a PEM file, which must name this
            /// parameter set.
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                let (algorithm, key) = crate::der::read_spki(der)?;
                if algorithm.oid != OID || !algorithm.params.is_empty() {
                    return Err(Error::InvalidEncoding);
                }
                let key: &[u8; PUBLIC_KEY_SIZE] =
                    key.try_into().map_err(|_| Error::InvalidEncoding)?;
                Self::try_new(key)
            }

            /// Writes the key as a `SubjectPublicKeyInfo` into the
            /// front of `out`, returning the length.
            pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                crate::der::write_spki(out, &OID, false, |w| w.raw(&self.bytes))
            }

            /// A key from a `PUBLIC KEY` PEM block, read as
            /// [`PrivateKey::try_from_pem`] reads its own.
            pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
                let mut der = [0u8; ml_dsa::SCRATCH];
                let labels = [ml_dsa::PUBLIC_LABEL];
                let (_, n) = crate::pem::decode(&labels, pem, &mut der)?;
                Self::try_from_der(&der[..n])
            }

            /// Writes the key as a `PUBLIC KEY` PEM block into the
            /// front of `out`, returning the length.
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let mut der = [0u8; ml_dsa::SCRATCH];
                let n = self.der_bytes(&mut der)?;
                crate::pem::write(ml_dsa::PUBLIC_LABEL, &der[..n], out)
            }
        }
    };
}

/// ML-DSA-44: security category 2, the smallest signatures.
pub mod ml_dsa_44 {
    parameter_set!(4, 4, 17, "ML-DSA-44");
}

/// ML-DSA-65: security category 3, the set most deployments use.
pub mod ml_dsa_65 {
    parameter_set!(6, 5, 18, "ML-DSA-65");
}

/// ML-DSA-87: security category 5.
pub mod ml_dsa_87 {
    parameter_set!(8, 7, 19, "ML-DSA-87");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_arithmetic() {
        let mut f = Poly::ZERO;
        let mut g = Poly::ZERO;
        for i in 0..N {
            f.0[i] = ((i as u64 * 7_919_337 + 13) % u64::from(Q)) as u32;
            g.0[i] = ((i as u64 * i as u64 * 1237 + 5) % u64::from(Q)) as u32;
        }
        let mut back = f;
        back.ntt();
        back.inverse_ntt();
        assert_eq!(back.0, f.0);

        let mut expected = Poly::ZERO;
        for i in 0..N {
            for k in 0..N {
                let c = mul(f.0[i], g.0[k]);
                if i + k < N {
                    expected.0[i + k] = add(expected.0[i + k], c);
                } else {
                    expected.0[i + k - N] = sub(expected.0[i + k - N], c);
                }
            }
        }
        let (mut fh, mut gh) = (f, g);
        fh.ntt();
        gh.ntt();
        let mut product = fh.mul_ntt(&gh);
        product.inverse_ntt();
        assert_eq!(product.0, expected.0);
    }

    /// The rounding functions against their definitions, over a
    /// sweep of the field.
    #[test]
    fn rounding() {
        for r in (0..Q).step_by(7_001).chain([Q - 1, Q - 2, 1, 0]) {
            let (r1, r0) = power2round(r);
            assert_eq!(i64::from(r), (i64::from(r1) << D) + i64::from(r0));
            assert!(r0 > -(1 << (D - 1)) && r0 <= 1 << (D - 1));
            for gamma2 in [(Q - 1) / 88, (Q - 1) / 32] {
                let (r1, r0) = decompose(r, gamma2);
                // r1 (2 gamma2) + r0 = r mod q, with r0 centred, and
                // the wrap at q - 1 folded into r1 = 0.
                let rebuilt = (i64::from(r1) * 2 * i64::from(gamma2)
                    + i64::from(r0))
                .rem_euclid(i64::from(Q));
                assert_eq!(rebuilt, i64::from(r), "r = {r}, gamma2 = {gamma2}");
                assert!(r0 > -(gamma2 as i32) && r0 <= gamma2 as i32);
                assert!(r1 < (Q - 1) / (2 * gamma2));
            }
            assert_eq!(unsigned(signed(r)), r);
        }
    }

    /// Hints pack canonically and unpack strictly.
    #[test]
    fn hints() {
        let mut h = [Poly::ZERO; 4];
        h[0].0[3] = 1;
        h[0].0[200] = 1;
        h[2].0[0] = 1;
        let mut bytes = [0u8; 84];
        pack_hints(&h, 80, &mut bytes);
        assert_eq!(&bytes[..3], &[3, 200, 0]);
        assert_eq!(&bytes[80..], &[2, 2, 3, 3]);
        let back = unpack_hints::<4>(80, &bytes).unwrap();
        for i in 0..4 {
            assert_eq!(back[i].0, h[i].0);
        }
        // Indices out of order, a count that decreases, one past
        // omega, and non-zero padding.
        let mut bad = bytes;
        bad.swap(0, 1);
        assert!(unpack_hints::<4>(80, &bad).is_none());
        let mut bad = bytes;
        bad[81] = 1;
        assert!(unpack_hints::<4>(80, &bad).is_none());
        let mut bad = bytes;
        bad[83] = 81;
        assert!(unpack_hints::<4>(80, &bad).is_none());
        let mut bad = bytes;
        bad[50] = 7;
        assert!(unpack_hints::<4>(80, &bad).is_none());
    }

    /// Every set signs and verifies, deterministically when asked,
    /// refuses what it should, and round-trips its formats.
    #[test]
    fn round_trips() {
        macro_rules! check {
            ($module:ident) => {{
                use $module::*;
                let mut rng = crate::random::Rng::try_new(
                    crate::random::System::try_new().unwrap(),
                )
                .unwrap();
                let key = PrivateKey::generate(&mut rng).unwrap();
                let public = key.public_key();
                let sig = key.sign(&mut rng, b"ctx", b"message").unwrap();
                public.verify(b"ctx", b"message", &sig).unwrap();
                assert!(public.verify(b"ctx", b"messagf", &sig).is_err());
                assert!(public.verify(b"", b"message", &sig).is_err());
                let mut bad = sig;
                bad[0] ^= 1;
                assert!(public.verify(b"ctx", b"message", &bad).is_err());
                let mut bad = sig;
                bad[SIGNATURE_SIZE - 1] = 0xff;
                assert!(public.verify(b"ctx", b"message", &bad).is_err());
                let det = key.sign_deterministic(b"", b"m").unwrap();
                assert_eq!(det, key.sign_deterministic(b"", b"m").unwrap());
                public.verify(b"", b"m", &det).unwrap();
                assert_eq!(
                    key.sign(&mut rng, &[0u8; 256], b"m").err(),
                    Some(Error::InvalidLength(256))
                );

                let again =
                    PrivateKey::try_from_seed(&key.seed_bytes().unwrap())
                        .unwrap();
                assert_eq!(again.key_bytes(), key.key_bytes());
                let expanded = PrivateKey::try_new(&key.key_bytes()).unwrap();
                assert_eq!(expanded.public_key().bytes(), public.bytes());
                assert_eq!(
                    expanded.sign_deterministic(b"", b"m").unwrap(),
                    det
                );
                let mut broken = key.key_bytes();
                broken[64] ^= 1;
                assert_eq!(
                    PrivateKey::try_new(&broken).err(),
                    Some(Error::InvalidPrivateKey)
                );
                broken = key.key_bytes();
                broken[KEY_SIZE - 1] ^= 1;
                assert_eq!(
                    PrivateKey::try_new(&broken).err(),
                    Some(Error::InvalidPrivateKey)
                );

                let mut out = [0u8; 8192];
                let n = key.der_bytes(&mut out).unwrap();
                let back = PrivateKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.seed_bytes(), key.seed_bytes());
                let n = expanded.der_bytes(&mut out).unwrap();
                let back = PrivateKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.key_bytes(), key.key_bytes());
                let n = key.pem_bytes(&mut out).unwrap();
                let back = PrivateKey::try_from_pem(&out[..n]).unwrap();
                assert_eq!(back.key_bytes(), key.key_bytes());
                let n = public.der_bytes(&mut out).unwrap();
                let back = PublicKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.bytes(), public.bytes());
                let n = public.pem_bytes(&mut out).unwrap();
                let back = PublicKey::try_from_pem(&out[..n]).unwrap();
                assert_eq!(back.bytes(), public.bytes());
            }};
        }
        check!(ml_dsa_44);
        check!(ml_dsa_65);
        check!(ml_dsa_87);
    }

    #[test]
    fn sets_do_not_mix() {
        let key = ml_dsa_44::PrivateKey::try_from_seed(&[1u8; 32]).unwrap();
        let mut out = [0u8; 8192];
        let n = key.der_bytes(&mut out).unwrap();
        assert_eq!(
            ml_dsa_65::PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
        let n = key.public_key().der_bytes(&mut out).unwrap();
        assert_eq!(
            ml_dsa_65::PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
    }
}
