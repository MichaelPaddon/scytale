//! ML-KEM (FIPS 203), the module-lattice key encapsulation
//! mechanism standardised from Kyber, in its three parameter sets.
//!
//! A key pair is a matrix equation over polynomials: the public key
//! is `t = A s + e` with `A` expanded from a public seed and `s`, `e`
//! small and secret; a ciphertext encrypts a random message under
//! it, and the shared secret is derived from that message and the
//! public key. Recovering `s` from `t` and `A` is the module
//! learning-with-errors problem, which no known quantum algorithm
//! solves. Each parameter set is a module of its own, [`ml_kem_512`],
//! [`ml_kem_768`] and [`ml_kem_1024`], with the same two key types
//! and the same calls; 768 is the set most deployments choose.
//!
//! The construction is Fujisaki-Okamoto with implicit rejection:
//! decapsulation re-encrypts the recovered message and, when the
//! result is not the ciphertext it was given, returns a secret
//! derived from the ciphertext and a hidden value instead of an
//! error, so a forged ciphertext yields a random key and no signal.
//! [`decapsulate`](ml_kem_768::PrivateKey::decapsulate) therefore
//! never fails on a well-formed ciphertext; that is the design, not
//! an omission.
//!
//! A private key is 64 bytes of seed, `d || z`, from which FIPS 203
//! derives everything else; the expanded form of 1632 to 3168 bytes
//! is what the standard's algorithms consume. Both are read and
//! written here, the seed being the form to store.
//!
//! ```
//! use scytale::kem::ml_kem::ml_kem_768::{PrivateKey, PublicKey};
//! use scytale::random::{Rng, System};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let key = PrivateKey::generate(&mut rng)?;
//!
//! // The sender has only the public key, and makes a ciphertext
//! // and a secret from it.
//! let public = PublicKey::try_new(&key.public_key().bytes())?;
//! let (ciphertext, secret) = public.encapsulate(&mut rng)?;
//!
//! // The key holder recovers the same secret from the ciphertext.
//! assert_eq!(key.decapsulate(&ciphertext), secret);
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! Every coefficient operation is branch-free arithmetic on values
//! below the modulus, with reductions by multiply-and-shift rather
//! than division; the one comparison decapsulation makes, of the
//! ciphertext against its re-encryption, reads every byte and
//! chooses the result by a mask. Rejection sampling of the public
//! matrix `A` varies with the public seed alone.

use zeroize::Zeroize;

use crate::der::{self, Reader};
use crate::hash::sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
use crate::hash::{Hash, Xof, XofReader};
use crate::pem;
use crate::util;
use crate::Error;

/// The modulus.
const Q: u32 = 3329;

/// Coefficients in a polynomial.
const N: usize = 256;

/// The length of a seed, `d || z`.
const SEED: usize = 64;

/// The length of a shared secret.
const SECRET: usize = 32;

/// What a parameter set fixes beyond the module rank `K`: the noise
/// widths and the ciphertext compression.
struct Params {
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
}

const PARAMS_512: Params = Params {
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
};

const PARAMS_768: Params = Params {
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
};

const PARAMS_1024: Params = Params {
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
};

/// The length of an encapsulation key for rank `K`.
const fn public_len(k: usize) -> usize {
    384 * k + 32
}

/// The length of an expanded decapsulation key for rank `K`.
const fn private_len(k: usize) -> usize {
    768 * k + 96
}

/// The length of a ciphertext.
const fn ciphertext_len(k: usize, p: &Params) -> usize {
    32 * (p.du * k + p.dv)
}

// The ring: polynomials modulo x^256 + 1 over the integers modulo
// q, held in the number-theoretic transform domain for products.

/// The seven-bit reversal FIPS 203 orders its roots of unity by.
const fn bitrev7(i: usize) -> usize {
    let mut out = 0;
    let mut bit = 0;
    while bit < 7 {
        out |= ((i >> bit) & 1) << (6 - bit);
        bit += 1;
    }
    out
}

/// `17^e mod q`; 17 is the root of unity the transform is built on.
const fn zeta_pow(mut e: usize) -> u16 {
    let mut result = 1u32;
    let mut base = 17u32;
    while e > 0 {
        if e & 1 == 1 {
            result = result * base % Q;
        }
        base = base * base % Q;
        e >>= 1;
    }
    result as u16
}

/// The roots the transform's butterflies use, in the order it uses
/// them: `17^bitrev7(i)`.
const ZETAS: [u16; 128] = {
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = zeta_pow(bitrev7(i));
        i += 1;
    }
    table
};

/// The roots the pairwise products use: `17^(2 bitrev7(i) + 1)`.
const GAMMAS: [u16; 128] = {
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = zeta_pow(2 * bitrev7(i) + 1);
        i += 1;
    }
    table
};

/// `a mod q` for `a` below `2q`, by one masked subtraction.
fn csub(a: u32) -> u16 {
    let r = a as i32 - Q as i32;
    (r + ((r >> 31) & Q as i32)) as u16
}

/// `a mod q` for any `a` below 2^26, by Barrett reduction: the
/// quotient estimate is off by at most one, which the final
/// subtraction absorbs.
fn reduce(a: u32) -> u16 {
    let quotient = ((u64::from(a) * 20158) >> 26) as u32;
    csub(a - quotient * Q)
}

fn add(a: u16, b: u16) -> u16 {
    csub(u32::from(a) + u32::from(b))
}

fn sub(a: u16, b: u16) -> u16 {
    csub(u32::from(a) + Q - u32::from(b))
}

fn mul(a: u16, b: u16) -> u16 {
    reduce(u32::from(a) * u32::from(b))
}

/// A polynomial, its coefficients in `[0, q)`, in whichever domain
/// its use says.
#[derive(Clone, Copy)]
struct Poly([u16; N]);

impl Poly {
    const ZERO: Poly = Poly([0; N]);

    /// The transform, algorithm 9.
    fn ntt(&mut self) {
        let f = &mut self.0;
        let mut i = 1;
        let mut len = 128;
        while len >= 2 {
            for start in (0..N).step_by(2 * len) {
                let zeta = ZETAS[i];
                i += 1;
                for j in start..start + len {
                    let t = mul(zeta, f[j + len]);
                    f[j + len] = sub(f[j], t);
                    f[j] = add(f[j], t);
                }
            }
            len /= 2;
        }
    }

    /// The inverse transform, algorithm 10.
    fn inverse_ntt(&mut self) {
        let f = &mut self.0;
        let mut i = 127;
        let mut len = 2;
        while len <= 128 {
            for start in (0..N).step_by(2 * len) {
                let zeta = ZETAS[i];
                i -= 1;
                for j in start..start + len {
                    let t = f[j];
                    f[j] = add(t, f[j + len]);
                    f[j + len] = mul(zeta, sub(f[j + len], t));
                }
            }
            len *= 2;
        }
        // Divided by 128, which the butterflies left multiplied in.
        for c in f.iter_mut() {
            *c = mul(*c, 3303);
        }
    }

    /// The product in the transform domain, algorithm 11: pairs of
    /// coefficients multiplied modulo `x^2 - gamma`.
    fn mul_ntt(&self, other: &Poly) -> Poly {
        let mut out = Poly::ZERO;
        let pairs = out
            .0
            .chunks_exact_mut(2)
            .zip(self.0.chunks_exact(2))
            .zip(other.0.chunks_exact(2));
        for (((c, a), b), gamma) in pairs.zip(GAMMAS) {
            let (a0, a1) = (a[0], a[1]);
            let (b0, b1) = (b[0], b[1]);
            c[0] = add(mul(a0, b0), mul(mul(a1, b1), gamma));
            c[1] = add(mul(a0, b1), mul(a1, b0));
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

    /// Writes the coefficients as `d`-bit values, algorithm 5, into
    /// `32 d` bytes.
    fn encode(&self, d: usize, out: &mut [u8]) {
        debug_assert_eq!(out.len(), 32 * d);
        let mut acc = 0u64;
        let mut bits = 0;
        let mut pos = 0;
        for &c in &self.0 {
            acc |= u64::from(c) << bits;
            bits += d;
            while bits >= 8 {
                out[pos] = acc as u8;
                pos += 1;
                acc >>= 8;
                bits -= 8;
            }
        }
    }

    /// Reads `d`-bit coefficients, algorithm 6; at `d = 12` they are
    /// reduced modulo `q`, as the standard says, which is what makes
    /// the round trip check on a public key meaningful.
    fn decode(d: usize, bytes: &[u8]) -> Poly {
        debug_assert_eq!(bytes.len(), 32 * d);
        let mut out = Poly::ZERO;
        let mask = (1u64 << d) - 1;
        let mut acc = 0u64;
        let mut bits = 0;
        let mut pos = 0;
        for c in out.0.iter_mut() {
            while bits < d {
                acc |= u64::from(bytes[pos]) << bits;
                pos += 1;
                bits += 8;
            }
            let value = (acc & mask) as u32;
            acc >>= d;
            bits -= d;
            *c = if d == 12 { reduce(value) } else { value as u16 };
        }
        out
    }

    /// `Compress_d`, rounding `x q^-1 2^d`; the division is by a
    /// constant and compiles to a multiply.
    fn compress(&self, d: usize) -> Poly {
        let mut out = *self;
        for c in out.0.iter_mut() {
            let scaled = (u32::from(*c) << d) + Q / 2;
            *c = ((scaled / Q) & ((1 << d) - 1)) as u16;
        }
        out
    }

    /// `Decompress_d`, rounding `y 2^-d q`.
    fn decompress(&self, d: usize) -> Poly {
        let mut out = *self;
        for c in out.0.iter_mut() {
            *c = ((u32::from(*c) * Q + (1 << (d - 1))) >> d) as u16;
        }
        out
    }

    /// `SampleNTT`, algorithm 7: the entry of `A` at `row`, `col`,
    /// by rejection sampling from SHAKE-128 over the seed and the
    /// two indices, column first as the standard has it.
    fn sample_ntt(rho: &[u8; 32], row: u8, col: u8) -> Result<Poly, Error> {
        let mut xof = Shake128::try_new()?;
        xof.update(rho);
        xof.update(&[col, row]);
        let mut reader = xof.finalize_xof();
        let mut out = Poly::ZERO;
        let mut filled = 0;
        // Three bytes give two twelve-bit candidates; a block of the
        // sponge's rate at a time.
        let mut buf = [0u8; 168];
        while filled < N {
            reader.squeeze(&mut buf);
            for chunk in buf.chunks_exact(3) {
                let d1 =
                    u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0f) << 8);
                let d2 = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);
                for d in [d1, d2] {
                    if filled < N && u32::from(d) < Q {
                        out.0[filled] = d;
                        filled += 1;
                    }
                }
            }
        }
        Ok(out)
    }

    /// `SamplePolyCBD_eta`, algorithm 8, over `64 eta` bytes of PRF
    /// output: each coefficient a difference of two `eta`-bit sums.
    fn sample_cbd(eta: usize, bytes: &[u8]) -> Poly {
        debug_assert_eq!(bytes.len(), 64 * eta);
        let bit = |n: usize| u16::from((bytes[n / 8] >> (n % 8)) & 1);
        let mut out = Poly::ZERO;
        for (i, c) in out.0.iter_mut().enumerate() {
            let mut x = 0u16;
            let mut y = 0u16;
            for j in 0..eta {
                x += bit(2 * i * eta + j);
                y += bit(2 * i * eta + eta + j);
            }
            *c = sub(x, y);
        }
        out
    }

    /// A polynomial of small coefficients from the PRF of `seed` and
    /// the counter `n`, `PRF_eta` feeding `SamplePolyCBD_eta`.
    fn sample_noise(eta: usize, seed: &[u8; 32], n: u8) -> Result<Poly, Error> {
        let mut xof = Shake256::try_new()?;
        xof.update(seed);
        xof.update(&[n]);
        let mut bytes = [0u8; 64 * 3];
        xof.finalize_xof().squeeze(&mut bytes[..64 * eta]);
        let out = Poly::sample_cbd(eta, &bytes[..64 * eta]);
        bytes.zeroize();
        Ok(out)
    }
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// The scheme, over an expanded key of rank K.

/// `G`, SHA3-512 split in two.
fn g(parts: &[&[u8]]) -> Result<([u8; 32], [u8; 32]), Error> {
    let mut hash = Sha3_512::try_new()?;
    for part in parts {
        hash.update(part);
    }
    let digest = hash.finalize();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&digest[..32]);
    b.copy_from_slice(&digest[32..]);
    Ok((a, b))
}

/// `H`, SHA3-256.
fn h(data: &[u8]) -> Result<[u8; 32], Error> {
    Sha3_256::digest(data)
}

/// `J`, 32 bytes of SHAKE-256, for the implicit rejection secret.
fn j(z: &[u8], c: &[u8]) -> Result<[u8; SECRET], Error> {
    let mut xof = Shake256::try_new()?;
    xof.update(z);
    xof.update(c);
    let mut out = [0u8; SECRET];
    xof.finalize_xof().squeeze(&mut out);
    Ok(out)
}

/// `K-PKE.KeyGen` and the wrapping of algorithm 16: the encapsulation
/// key into `ek` and the expanded decapsulation key into `dk`, from
/// the seed `d || z`.
fn key_gen<const K: usize>(
    seed: &[u8; SEED],
    ek: &mut [u8],
    dk: &mut [u8],
) -> Result<(), Error> {
    debug_assert_eq!(ek.len(), public_len(K));
    debug_assert_eq!(dk.len(), private_len(K));
    let (d, z) = seed.split_at(32);
    let (rho, mut sigma) = g(&[d, &[K as u8]])?;
    let eta1 = params::<K>().eta1;

    let mut s = [Poly::ZERO; K];
    let mut e = [Poly::ZERO; K];
    for (i, s_i) in s.iter_mut().enumerate() {
        *s_i = Poly::sample_noise(eta1, &sigma, i as u8)?;
        s_i.ntt();
    }
    for (i, e_i) in e.iter_mut().enumerate() {
        *e_i = Poly::sample_noise(eta1, &sigma, (K + i) as u8)?;
        e_i.ntt();
    }
    sigma.zeroize();

    // t = A s + e, one row of A at a time, never stored whole.
    for i in 0..K {
        let mut t = e[i];
        for (j, s_j) in s.iter().enumerate() {
            let a = Poly::sample_ntt(&rho, i as u8, j as u8)?;
            t.add_assign(&a.mul_ntt(s_j));
        }
        t.encode(12, &mut ek[384 * i..384 * (i + 1)]);
    }
    ek[384 * K..].copy_from_slice(&rho);

    for (i, s_i) in s.iter().enumerate() {
        s_i.encode(12, &mut dk[384 * i..384 * (i + 1)]);
    }
    let rest = &mut dk[384 * K..];
    rest[..public_len(K)].copy_from_slice(ek);
    rest[public_len(K)..public_len(K) + 32].copy_from_slice(&h(ek)?);
    rest[public_len(K) + 32..].copy_from_slice(z);
    s.zeroize();
    e.zeroize();
    Ok(())
}

/// `K-PKE.Encrypt`, algorithm 14: the message `m` under `ek` with
/// randomness `r`, into `c`.
fn encrypt<const K: usize>(
    ek: &[u8],
    m: &[u8; 32],
    r: &[u8; 32],
    c: &mut [u8],
) -> Result<(), Error> {
    let p = params::<K>();
    debug_assert_eq!(c.len(), ciphertext_len(K, p));
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..]);

    let mut y = [Poly::ZERO; K];
    for (i, y_i) in y.iter_mut().enumerate() {
        *y_i = Poly::sample_noise(p.eta1, r, i as u8)?;
        y_i.ntt();
    }
    // u = A^T y + e1: the transpose, so A's row index is the inner
    // one; sampled as it is needed.
    for i in 0..K {
        let mut u = Poly::ZERO;
        for (j, y_j) in y.iter().enumerate() {
            let a = Poly::sample_ntt(&rho, j as u8, i as u8)?;
            u.add_assign(&a.mul_ntt(y_j));
        }
        u.inverse_ntt();
        let e1 = Poly::sample_noise(p.eta2, r, (K + i) as u8)?;
        u.add_assign(&e1);
        u.compress(p.du)
            .encode(p.du, &mut c[32 * p.du * i..32 * p.du * (i + 1)]);
    }
    // v = t . y + e2 + Decompress_1(m).
    let mut v = Poly::ZERO;
    for (i, y_i) in y.iter().enumerate() {
        let t = Poly::decode(12, &ek[384 * i..384 * (i + 1)]);
        v.add_assign(&t.mul_ntt(y_i));
    }
    v.inverse_ntt();
    let e2 = Poly::sample_noise(p.eta2, r, (2 * K) as u8)?;
    v.add_assign(&e2);
    v.add_assign(&Poly::decode(1, m).decompress(1));
    v.compress(p.dv).encode(p.dv, &mut c[32 * p.du * K..]);
    y.zeroize();
    Ok(())
}

/// `K-PKE.Decrypt`, algorithm 15: the message from `c` under the
/// secret polynomials at the front of `dk`.
fn decrypt<const K: usize>(dk: &[u8], c: &[u8]) -> [u8; 32] {
    let p = params::<K>();
    let mut v = Poly::decode(p.dv, &c[32 * p.du * K..]).decompress(p.dv);
    let mut w = Poly::ZERO;
    for i in 0..K {
        let mut u = Poly::decode(p.du, &c[32 * p.du * i..32 * p.du * (i + 1)])
            .decompress(p.du);
        u.ntt();
        let s = Poly::decode(12, &dk[384 * i..384 * (i + 1)]);
        w.add_assign(&s.mul_ntt(&u));
    }
    w.inverse_ntt();
    v.sub_assign(&w);
    let mut m = [0u8; 32];
    v.compress(1).encode(1, &mut m);
    w.zeroize();
    v.zeroize();
    m
}

/// `ML-KEM.Encaps_internal`, algorithm 17: the ciphertext into `c`
/// and the shared secret returned, from the message `m`.
fn encapsulate<const K: usize>(
    ek: &[u8],
    m: &[u8; 32],
    c: &mut [u8],
) -> Result<[u8; SECRET], Error> {
    let (key, mut r) = g(&[m, &h(ek)?])?;
    encrypt::<K>(ek, m, &r, c)?;
    r.zeroize();
    Ok(key)
}

/// `ML-KEM.Decaps_internal`, algorithm 18, with the implicit
/// rejection chosen by a mask.
fn decapsulate<const K: usize>(
    dk: &[u8],
    c: &[u8],
) -> Result<[u8; SECRET], Error> {
    let ek = &dk[384 * K..384 * K + public_len(K)];
    let hash = &dk[384 * K + public_len(K)..384 * K + public_len(K) + 32];
    let z = &dk[384 * K + public_len(K) + 32..];
    let mut m = decrypt::<K>(dk, c);
    let (mut key, mut r) = g(&[&m, hash])?;
    let rejected = j(z, c)?;
    let mut again = [0u8; 1568];
    let again = &mut again[..c.len()];
    encrypt::<K>(ek, &m, &r, again)?;
    // Both secrets are in hand; the comparison picks one without
    // saying which, or when.
    let same = util::equal(c, again);
    let mask = (same as u8).wrapping_neg();
    for (k, rej) in key.iter_mut().zip(&rejected) {
        *k = (*k & mask) | (rej & !mask);
    }
    m.zeroize();
    r.zeroize();
    again.zeroize();
    Ok(key)
}

/// The parameters of the set with rank `K`.
const fn params<const K: usize>() -> &'static Params {
    match K {
        2 => &PARAMS_512,
        3 => &PARAMS_768,
        _ => &PARAMS_1024,
    }
}

/// The encapsulation key check of algorithm 20: every coefficient
/// below the modulus, which decoding and re-encoding tells.
fn public_key_is_valid<const K: usize>(ek: &[u8]) -> bool {
    let mut again = [0u8; 384];
    (0..K).all(|i| {
        let chunk = &ek[384 * i..384 * (i + 1)];
        Poly::decode(12, chunk).encode(12, &mut again);
        again[..] == chunk[..]
    })
}

/// The decapsulation key check of algorithm 21: the hash inside
/// matches the encapsulation key inside.
fn private_key_is_valid<const K: usize>(dk: &[u8]) -> Result<bool, Error> {
    let ek = &dk[384 * K..384 * K + public_len(K)];
    let hash = &dk[384 * K + public_len(K)..384 * K + public_len(K) + 32];
    Ok(h(ek)?[..] == hash[..])
}

// Formats: the IETF LAMPS profile for ML-KEM keys, which puts the
// bare encapsulation key in a SubjectPublicKeyInfo and one of the
// seed, the expanded key or both in PKCS#8, under the parameter
// set's own OID and no parameters.

/// The OID prefix of the three parameter sets,
/// 2.16.840.1.101.3.4.4; the last arc is 1, 2 or 3.
const OID_PREFIX: [u8; 8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04];

/// Room for any encoding of any key here: an expanded ML-KEM-1024
/// key with both forms is under this.
const SCRATCH: usize = 4096;

const PRIVATE_LABEL: &str = "PRIVATE KEY";
const PUBLIC_LABEL: &str = "PUBLIC KEY";

/// Which of the private key's forms a PKCS#8 carried.
struct PrivateForms<'a> {
    seed: Option<&'a [u8]>,
    expanded: Option<&'a [u8]>,
}

/// The `ML-KEM-PrivateKey` CHOICE: `[0]` a seed, an OCTET STRING an
/// expanded key, a SEQUENCE both.
fn read_private_forms(der: &[u8]) -> Result<PrivateForms<'_>, Error> {
    let mut outer = Reader::new(der);
    let forms = if let Some(seed) = outer.optional(der::context_primitive(0))? {
        PrivateForms {
            seed: Some(seed),
            expanded: None,
        }
    } else if let Some(mut both) = outer.optional_sequence()? {
        let seed = both.element(der::context_primitive(0))?;
        let expanded = both.octet_string()?;
        both.end()?;
        PrivateForms {
            seed: Some(seed),
            expanded: Some(expanded),
        }
    } else {
        PrivateForms {
            seed: None,
            expanded: Some(outer.octet_string()?),
        }
    };
    outer.end()?;
    Ok(forms)
}

fn to_pem(label: &str, der: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let needed = pem::encoded_len(label, der.len());
    if out.len() < needed {
        return Err(Error::OutputTooSmall(needed));
    }
    Ok(pem::encode(label, der, out))
}

/// One parameter set's public types.
macro_rules! parameter_set {
    ($k:literal, $arc:literal, $name:literal) => {
        use zeroize::Zeroize;

        use crate::kem::ml_kem::{self, params, PrivateForms};
        use crate::random::Random;
        use crate::Error;

        /// The length of a private key's seed, `d || z`, the form to
        /// store.
        pub const SEED_SIZE: usize = 64;

        /// The length of an expanded private key, FIPS 203's
        /// decapsulation key.
        pub const KEY_SIZE: usize = 768 * $k + 96;

        /// The length of a public key, FIPS 203's encapsulation key.
        pub const PUBLIC_KEY_SIZE: usize = 384 * $k + 32;

        /// The length of a ciphertext.
        pub const CIPHERTEXT_SIZE: usize =
            32 * (params::<$k>().du * $k + params::<$k>().dv);

        /// The length of a shared secret.
        pub const SHARED_SECRET_SIZE: usize = 32;

        /// The last arc of the parameter set's OID under
        /// 2.16.840.1.101.3.4.4.
        const OID: [u8; 9] = {
            let mut oid = [0u8; 9];
            let mut i = 0;
            while i < 8 {
                oid[i] = ml_kem::OID_PREFIX[i];
                i += 1;
            }
            oid[8] = $arc;
            oid
        };

        #[doc = concat!("An ", $name, " private key, FIPS 203's")]
        /// decapsulation key, with its seed when it was made from
        /// one; wiped on drop.
        pub struct PrivateKey {
            seed: Option<[u8; SEED_SIZE]>,
            expanded: [u8; KEY_SIZE],
            public: PublicKey,
        }

        #[doc = concat!("An ", $name, " public key, FIPS 203's")]
        /// encapsulation key, checked to be well formed.
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
            fn from_expanded(
                seed: Option<[u8; SEED_SIZE]>,
                expanded: [u8; KEY_SIZE],
            ) -> Self {
                let mut bytes = [0u8; PUBLIC_KEY_SIZE];
                bytes.copy_from_slice(
                    &expanded[384 * $k..384 * $k + PUBLIC_KEY_SIZE],
                );
                PrivateKey {
                    seed,
                    expanded,
                    public: PublicKey { bytes },
                }
            }

            /// A fresh key from 64 random bytes of seed.
            pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
                let mut seed = [0u8; SEED_SIZE];
                rng.fill(&mut seed)?;
                let key = Self::try_from_seed(&seed);
                seed.zeroize();
                key
            }

            /// The key a seed `d || z` expands to, by FIPS 203's
            /// `ML-KEM.KeyGen_internal`. Any 64 bytes are a seed.
            pub fn try_from_seed(
                seed: &[u8; SEED_SIZE],
            ) -> Result<Self, Error> {
                let mut expanded = [0u8; KEY_SIZE];
                let mut ek = [0u8; PUBLIC_KEY_SIZE];
                ml_kem::key_gen::<$k>(seed, &mut ek, &mut expanded)?;
                Ok(Self::from_expanded(Some(*seed), expanded))
            }

            /// A key from its expanded form, checked as FIPS 203
            /// requires: the hash inside must match the public key
            /// inside, and that key must be well formed. A key that
            /// comes in this way has no seed to give back.
            pub fn try_new(expanded: &[u8; KEY_SIZE]) -> Result<Self, Error> {
                let ek = &expanded[384 * $k..384 * $k + PUBLIC_KEY_SIZE];
                if !ml_kem::private_key_is_valid::<$k>(expanded)?
                    || !ml_kem::public_key_is_valid::<$k>(ek)
                {
                    return Err(Error::InvalidPrivateKey);
                }
                Ok(Self::from_expanded(None, *expanded))
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

            /// The shared secret a ciphertext carries.
            ///
            /// This cannot fail on a ciphertext of the right length:
            /// one that was not made for this key yields a secret
            /// derived from the ciphertext and a hidden value, which
            /// matches nothing the sender holds, so a forgery learns
            /// nothing from the outcome. That is FIPS 203's implicit
            /// rejection, and the reason there is no error to return.
            pub fn decapsulate(
                &self,
                ciphertext: &[u8; CIPHERTEXT_SIZE],
            ) -> [u8; SHARED_SECRET_SIZE] {
                // The hashes cannot fail once the key exists: the same
                // ones ran to make it.
                ml_kem::decapsulate::<$k>(&self.expanded, ciphertext)
                    .unwrap_or([0u8; SHARED_SECRET_SIZE])
            }

            /// A key from its DER PKCS#8 `PrivateKeyInfo`, the form
            /// under `PRIVATE KEY` in a PEM file, which holds the
            /// seed, the expanded key, or both; both are checked, and
            /// a pair that disagrees is refused as corrupt. Another
            /// parameter set, or anything else wrong with the bytes,
            /// is [`Error::InvalidEncoding`].
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                let info = crate::der::read_pkcs8(der)?;
                let algorithm = &info.algorithm;
                if algorithm.oid != OID || !algorithm.params.is_empty() {
                    return Err(Error::InvalidEncoding);
                }
                let PrivateForms { seed, expanded } =
                    ml_kem::read_private_forms(info.private_key)?;
                let key = match (seed, expanded) {
                    (Some(seed), expanded) => {
                        let seed: &[u8; SEED_SIZE] = seed
                            .try_into()
                            .map_err(|_| Error::InvalidEncoding)?;
                        let key = Self::try_from_seed(seed)?;
                        if expanded.is_some_and(|e| e[..] != key.expanded[..]) {
                            return Err(Error::InvalidEncoding);
                        }
                        key
                    }
                    (None, Some(expanded)) => {
                        let expanded: &[u8; KEY_SIZE] = expanded
                            .try_into()
                            .map_err(|_| Error::InvalidEncoding)?;
                        Self::try_new(expanded)?
                    }
                    (None, None) => return Err(Error::InvalidEncoding),
                };
                Ok(key)
            }

            /// Writes the key as a `PrivateKeyInfo` into the front of
            /// `out`, returning the length: the seed when the key has
            /// one, since that is the form to store, and the expanded
            /// key otherwise. The output is a secret, to be wiped.
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
                let mut der = [0u8; ml_kem::SCRATCH];
                let labels = [ml_kem::PRIVATE_LABEL];
                let result = crate::pem::decode(&labels, pem, &mut der)
                    .and_then(|(_, n)| Self::try_from_der(&der[..n]));
                der.zeroize();
                result
            }

            /// Writes the key as a `PRIVATE KEY` PEM block, ASCII with
            /// LF line ends, into the front of `out`, returning the
            /// length. A secret, to be wiped.
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let mut der = [0u8; ml_kem::SCRATCH];
                let label = ml_kem::PRIVATE_LABEL;
                let result = self
                    .der_bytes(&mut der)
                    .and_then(|n| ml_kem::to_pem(label, &der[..n], out));
                der.zeroize();
                result
            }
        }

        impl PublicKey {
            /// A public key from its bytes, checked as FIPS 203
            /// requires: every coefficient below the modulus.
            pub fn try_new(
                bytes: &[u8; PUBLIC_KEY_SIZE],
            ) -> Result<Self, Error> {
                if !ml_kem::public_key_is_valid::<$k>(bytes) {
                    return Err(Error::InvalidPublicKey);
                }
                Ok(PublicKey { bytes: *bytes })
            }

            /// The key's bytes, FIPS 203's encapsulation key.
            pub fn bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
                self.bytes
            }

            /// A ciphertext and the shared secret it carries, from 32
            /// random bytes; the holder of the private key recovers
            /// the secret from the ciphertext alone.
            pub fn encapsulate<R: Random>(
                &self,
                rng: &mut R,
            ) -> Result<
                ([u8; CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE]),
                Error,
            > {
                let mut m = [0u8; 32];
                rng.fill(&mut m)?;
                let mut c = [0u8; CIPHERTEXT_SIZE];
                let secret = ml_kem::encapsulate::<$k>(&self.bytes, &m, &mut c);
                m.zeroize();
                Ok((c, secret?))
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
                let mut der = [0u8; ml_kem::SCRATCH];
                let (_, n) =
                    crate::pem::decode(&[ml_kem::PUBLIC_LABEL], pem, &mut der)?;
                Self::try_from_der(&der[..n])
            }

            /// Writes the key as a `PUBLIC KEY` PEM block into the
            /// front of `out`, returning the length.
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let mut der = [0u8; ml_kem::SCRATCH];
                let n = self.der_bytes(&mut der)?;
                ml_kem::to_pem(ml_kem::PUBLIC_LABEL, &der[..n], out)
            }
        }
    };
}

/// ML-KEM-512: security category 1, the smallest keys.
pub mod ml_kem_512 {
    parameter_set!(2, 1, "ML-KEM-512");
}

/// ML-KEM-768: security category 3, the set most deployments use.
pub mod ml_kem_768 {
    parameter_set!(3, 2, "ML-KEM-768");
}

/// ML-KEM-1024: security category 5.
pub mod ml_kem_1024 {
    parameter_set!(4, 3, "ML-KEM-1024");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transform inverts, and the transform-domain product is
    /// the schoolbook product modulo x^256 + 1.
    #[test]
    fn ring_arithmetic() {
        let mut f = Poly::ZERO;
        let mut g = Poly::ZERO;
        for i in 0..N {
            f.0[i] = ((i * 7919 + 13) % Q as usize) as u16;
            g.0[i] = ((i * i + 5) % Q as usize) as u16;
        }
        let mut back = f;
        back.ntt();
        back.inverse_ntt();
        assert_eq!(back.0, f.0);

        let mut expected = Poly::ZERO;
        for i in 0..N {
            for k in 0..N {
                let c = mul(f.0[i], g.0[k]);
                // x^256 = -1.
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

    /// Every value below 2^26 reduces as plain division says.
    #[test]
    fn reductions() {
        for a in (0..1 << 26).step_by(9973) {
            assert_eq!(u32::from(reduce(a)), a % Q, "{a}");
        }
        assert_eq!(u32::from(reduce((1 << 26) - 1)), ((1 << 26) - 1) % Q);
        for a in 0..2 * Q {
            assert_eq!(u32::from(csub(a)), a % Q);
        }
        assert_eq!(ZETAS[1], 1729);
        assert_eq!(GAMMAS[0], 17);
    }

    /// Encoding and decoding invert at every width, and compression
    /// round-trips through decompression.
    #[test]
    fn encodings() {
        for d in [1usize, 4, 5, 10, 11, 12] {
            let mut f = Poly::ZERO;
            for (i, c) in f.0.iter_mut().enumerate() {
                *c = ((i * 2731 + 17) % (1 << d)) as u16;
                if d == 12 {
                    *c %= Q as u16;
                }
            }
            let mut bytes = [0u8; 384];
            f.encode(d, &mut bytes[..32 * d]);
            assert_eq!(Poly::decode(d, &bytes[..32 * d]).0, f.0, "d = {d}");
            if d < 12 {
                let round = f.decompress(d).compress(d);
                assert_eq!(round.0, f.0, "d = {d}");
            }
        }
    }

    /// Both directions agree on all three sets, a seed gives the
    /// same key twice, and a damaged ciphertext gives the rejection
    /// secret rather than an error or the real one.
    #[test]
    fn round_trips_and_rejection() {
        macro_rules! check {
            ($module:ident) => {{
                use $module::*;
                let mut rng = crate::random::Rng::try_new(
                    crate::random::System::try_new().unwrap(),
                )
                .unwrap();
                let key = PrivateKey::generate(&mut rng).unwrap();
                let (c, k) = key.public_key().encapsulate(&mut rng).unwrap();
                assert_eq!(key.decapsulate(&c), k);
                let again =
                    PrivateKey::try_from_seed(&key.seed_bytes().unwrap())
                        .unwrap();
                assert_eq!(again.key_bytes(), key.key_bytes());
                let expanded = PrivateKey::try_new(&key.key_bytes()).unwrap();
                assert_eq!(expanded.decapsulate(&c), k);
                assert_eq!(
                    expanded.seed_bytes(),
                    Err(Error::InvalidPrivateKey)
                );

                let mut bad = c;
                bad[3] ^= 1;
                let rejected = key.decapsulate(&bad);
                assert_ne!(rejected, k);
                let z = &key.key_bytes()[KEY_SIZE - 32..];
                assert_eq!(rejected, j(z, &bad).unwrap());

                // A public key with a coefficient at the modulus is
                // refused; a private key with a wrong hash is refused.
                let mut ek = key.public_key().bytes();
                ek[0] = 0x01;
                ek[1] = 0x0d;
                assert_eq!(
                    PublicKey::try_new(&ek).err(),
                    Some(Error::InvalidPublicKey)
                );
                let mut dk = key.key_bytes();
                dk[KEY_SIZE - 40] ^= 1;
                assert_eq!(
                    PrivateKey::try_new(&dk).err(),
                    Some(Error::InvalidPrivateKey)
                );

                // DER and PEM, in the seed form and the expanded form.
                let mut out = [0u8; 6000];
                let n = key.der_bytes(&mut out).unwrap();
                assert_eq!(n, 2 + 3 + 13 + 2 + 2 + 64);
                let back = PrivateKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.seed_bytes(), key.seed_bytes());
                let n = expanded.der_bytes(&mut out).unwrap();
                let back = PrivateKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.key_bytes(), key.key_bytes());
                let n = key.pem_bytes(&mut out).unwrap();
                assert!(out.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
                let back = PrivateKey::try_from_pem(&out[..n]).unwrap();
                assert_eq!(back.key_bytes(), key.key_bytes());
                let n = key.public_key().der_bytes(&mut out).unwrap();
                let back = PublicKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.bytes(), key.public_key().bytes());
                let n = key.public_key().pem_bytes(&mut out).unwrap();
                let back = PublicKey::try_from_pem(&out[..n]).unwrap();
                assert_eq!(back.bytes(), key.public_key().bytes());
            }};
        }
        check!(ml_kem_512);
        check!(ml_kem_768);
        check!(ml_kem_1024);
    }

    /// A key of one set is not a key of another, in either format.
    #[test]
    fn sets_do_not_mix() {
        let mut rng = crate::random::Rng::try_new(
            crate::random::System::try_new().unwrap(),
        )
        .unwrap();
        let key = ml_kem_512::PrivateKey::generate(&mut rng).unwrap();
        let mut out = [0u8; 2048];
        let n = key.der_bytes(&mut out).unwrap();
        assert_eq!(
            ml_kem_768::PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
        let n = key.public_key().der_bytes(&mut out).unwrap();
        assert_eq!(
            ml_kem_768::PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
    }

    /// The `both` form of the private key reads, and is refused when
    /// its halves disagree.
    #[test]
    fn both_forms() {
        use ml_kem_768::*;
        let seed = [7u8; 64];
        let key = PrivateKey::try_from_seed(&seed).unwrap();
        let expanded = key.key_bytes();
        let mut out = [0u8; 4096];
        let oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02];
        let n = der::write_pkcs8(&mut out, &oid, false, |w| {
            w.sequence(|w| {
                w.primitive(der::context_primitive(0), &seed);
                w.octet_string(&expanded);
            })
        })
        .unwrap();
        assert_eq!(
            PrivateKey::try_from_der(&out[..n]).unwrap().key_bytes(),
            expanded
        );
        let pos = out[..n].windows(64).position(|w| w == seed).unwrap();
        out[pos] ^= 1;
        assert_eq!(
            PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
    }
}
