//! The NIST prime curves, P-256 and P-384: the arithmetic under both
//! ECDH and ECDSA, and the key handling the two schemes share.
//!
//! Each curve is `y^2 = x^3 - 3x + b` over a prime field, with a
//! base point of prime order `n`, so every point but the identity
//! generates the whole group and there is no cofactor to clear. The
//! field and the scalar ring both run on [`Montgomery`], which is
//! generic over the width; nothing here is specialised to a curve
//! beyond its constants, so a third curve is a constant away.
//!
//! # Constant time
//!
//! Points are projective, and added by the complete formulas of
//! Renes, Costello and Batina (2016) for `a = -3`: one routine
//! handles doubling, the identity and inverse pairs with no case
//! analysis, so a scalar multiplication is a fixed sequence of
//! field operations. The scalar is consumed in four-bit windows with
//! the table read by scanning every entry, as [`Montgomery::modexp`]
//! reads its own. Inversion and square roots are exponentiations.
//! The only value-dependent control flow is the retry ECDSA makes
//! when a nonce yields a zero `r` or `s`, which happens once in
//! 2^256 signatures.

use zeroize::Zeroize;

use super::montgomery::Montgomery;
use super::uint::Uint;
use crate::cipher::Block;
use crate::der::{self, Reader, Writer};
use crate::hash::Hash;
use crate::mac::hmac::Hmac;
use crate::mac::Mac;
use crate::pem;
use crate::random::Random;
use crate::Error;

/// A curve's constants, each as a big-endian hex string of the
/// curve's width, and the OID that names it in a certificate.
pub(crate) struct Curve<const L: usize> {
    p: Uint<L>,
    b: Uint<L>,
    n: Uint<L>,
    gx: Uint<L>,
    gy: Uint<L>,
    pub(crate) oid: &'static [u8],
}

/// A hex string of exactly `16 * L` digits, as limbs.
const fn from_hex<const L: usize>(hex: &str) -> Uint<L> {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 16 * L, "wrong width");
    let mut limbs = [0u64; L];
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not hex"),
        };
        // The first sixteen digits are the top limb.
        let limb = L - 1 - i / 16;
        limbs[limb] = (limbs[limb] << 4) | v as u64;
        i += 1;
    }
    Uint(limbs)
}

/// The width of a coordinate or scalar in bytes.
pub(crate) const fn width<const L: usize>() -> usize {
    8 * L
}

/// P-256, secp256r1, prime256v1: FIPS 186-5 and SEC 2.
pub(crate) const P256: Curve<4> = Curve {
    p: from_hex(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    ),
    b: from_hex(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    ),
    n: from_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    ),
    gx: from_hex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    ),
    gy: from_hex(
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    ),
    // 1.2.840.10045.3.1.7
    oid: &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
};

/// P-384, secp384r1.
pub(crate) const P384: Curve<6> = Curve {
    p: from_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
         ffffffff0000000000000000ffffffff",
    ),
    b: from_hex(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
         c656398d8a2ed19d2a85c8edd3ec2aef",
    ),
    n: from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
         581a0db248b0a77aecec196accc52973",
    ),
    gx: from_hex(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
         5502f25dbf55296c3a545e3872760ab7",
    ),
    gy: from_hex(
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
         0a60b1ce1d7e819d7a431d7c90ea0e5f",
    ),
    // 1.3.132.0.34
    oid: &[0x2b, 0x81, 0x04, 0x00, 0x22],
};

/// The contents of the OID `id-ecPublicKey`, 1.2.840.10045.2.1,
/// which names every prime-curve key; the parameters say which.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// A point in projective coordinates, `(X : Y : Z)` for the affine
/// `(X/Z, Y/Z)`, every coordinate in the field's Montgomery domain.
/// The identity is any point with `Z = 0`.
#[derive(Clone, Copy)]
struct Point<const L: usize> {
    x: Uint<L>,
    y: Uint<L>,
    z: Uint<L>,
}

impl<const L: usize> Point<L> {
    fn cmov(&mut self, other: &Self, condition: u64) {
        self.x.cmov(&other.x, condition);
        self.y.cmov(&other.y, condition);
        self.z.cmov(&other.z, condition);
    }
}

/// Arithmetic ready for one curve: both moduli in Montgomery form,
/// and the constants the formulas need already in the field's
/// domain. Built afresh for each operation; the setup is a few
/// hundred limb additions.
pub(crate) struct Engine<'a, const L: usize> {
    curve: &'a Curve<L>,
    field: Montgomery<L>,
    order: Montgomery<L>,
    /// `b`, in the domain.
    b: Uint<L>,
    /// One, in the domain: `R mod p`.
    one: Uint<L>,
    g: Point<L>,
}

/// A Montgomery context for a curve modulus.
fn context<const L: usize>(n: &Uint<L>) -> Montgomery<L> {
    match Montgomery::new(*n) {
        Some(m) => m,
        // Both moduli of both curves are odd primes, so this is a
        // constant of the crate, not a condition.
        None => unreachable!("curve moduli are odd"),
    }
}

impl<'a, const L: usize> Engine<'a, L> {
    pub(crate) fn new(curve: &'a Curve<L>) -> Self {
        let field = context(&curve.p);
        let order = context(&curve.n);
        let one = field.to_mont(&Uint::one());
        let g = Point {
            x: field.to_mont(&curve.gx),
            y: field.to_mont(&curve.gy),
            z: one,
        };
        let b = field.to_mont(&curve.b);
        Engine {
            curve,
            field,
            order,
            b,
            one,
            g,
        }
    }

    // The field, everything in the Montgomery domain.

    fn mul(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        self.field.mul(a, b)
    }

    fn add(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        a.add_mod(b, &self.curve.p)
    }

    fn sub(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        a.sub_mod(b, &self.curve.p)
    }

    /// `a^-1`, by Fermat: `a^(p-2)`. Zero maps to zero.
    fn invert(&self, a: &Uint<L>) -> Uint<L> {
        let (exponent, _) = self.curve.p.sub_borrow(&Uint::from_limbs(&[2]));
        let plain = self.field.modexp(&self.field.from_mont(a), &exponent);
        self.field.to_mont(&plain)
    }

    /// A square root of `a`, or `None` when it has none. Both
    /// primes are 3 mod 4, so the root is `a^((p+1)/4)`; squaring
    /// the candidate back is what tells a non-residue apart.
    fn sqrt(&self, a: &Uint<L>) -> Option<Uint<L>> {
        let (exponent, _) = self.curve.p.add_carry(&Uint::one());
        let exponent = exponent.shr(2);
        let root = self
            .field
            .to_mont(&self.field.modexp(&self.field.from_mont(a), &exponent));
        if self.mul(&root, &root).0 == a.0 {
            Some(root)
        } else {
            None
        }
    }

    /// `x^3 - 3x + b`, the right-hand side of the curve equation.
    fn rhs(&self, x: &Uint<L>) -> Uint<L> {
        let x2 = self.mul(x, x);
        let x3 = self.mul(&x2, x);
        let three_x = self.add(&self.add(x, x), x);
        self.add(&self.sub(&x3, &three_x), &self.b)
    }

    // The group.

    fn identity(&self) -> Point<L> {
        Point {
            x: Uint::ZERO,
            y: self.one,
            z: Uint::ZERO,
        }
    }

    /// `p + q`, by algorithm 4 of Renes, Costello and Batina: the
    /// complete formulas for `a = -3`, which need no case for
    /// doubling or for the identity.
    fn point_add(&self, p: &Point<L>, q: &Point<L>) -> Point<L> {
        let (x1, y1, z1) = (&p.x, &p.y, &p.z);
        let (x2, y2, z2) = (&q.x, &q.y, &q.z);
        let b = &self.b;

        let t0 = self.mul(x1, x2);
        let t1 = self.mul(y1, y2);
        let t2 = self.mul(z1, z2);
        let t3 = self.add(x1, y1);
        let t4 = self.add(x2, y2);
        let t3 = self.mul(&t3, &t4);
        let t4 = self.add(&t0, &t1);
        let t3 = self.sub(&t3, &t4);
        let t4 = self.add(y1, z1);
        let x3 = self.add(y2, z2);
        let t4 = self.mul(&t4, &x3);
        let x3 = self.add(&t1, &t2);
        let t4 = self.sub(&t4, &x3);
        let x3 = self.add(x1, z1);
        let y3 = self.add(x2, z2);
        let x3 = self.mul(&x3, &y3);
        let y3 = self.add(&t0, &t2);
        let y3 = self.sub(&x3, &y3);
        let z3 = self.mul(b, &t2);
        let x3 = self.sub(&y3, &z3);
        let z3 = self.add(&x3, &x3);
        let x3 = self.add(&x3, &z3);
        let z3 = self.sub(&t1, &x3);
        let x3 = self.add(&t1, &x3);
        let y3 = self.mul(b, &y3);
        let t1 = self.add(&t2, &t2);
        let t2 = self.add(&t1, &t2);
        let y3 = self.sub(&y3, &t2);
        let y3 = self.sub(&y3, &t0);
        let t1 = self.add(&y3, &y3);
        let y3 = self.add(&t1, &y3);
        let t1 = self.add(&t0, &t0);
        let t0 = self.add(&t1, &t0);
        let t0 = self.sub(&t0, &t2);
        let t1 = self.mul(&t4, &y3);
        let t2 = self.mul(&t0, &y3);
        let y3 = self.mul(&x3, &z3);
        let y3 = self.add(&y3, &t2);
        let x3 = self.mul(&t3, &x3);
        let x3 = self.sub(&x3, &t1);
        let z3 = self.mul(&t4, &z3);
        let t1 = self.mul(&t3, &t0);
        let z3 = self.add(&z3, &t1);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `k * p`, by fixed four-bit windows over the scalar's full
    /// width, the table read by scanning it whole.
    fn point_mul(&self, p: &Point<L>, k: &Uint<L>) -> Point<L> {
        let mut table = [self.identity(); 16];
        for i in 1..16 {
            table[i] = self.point_add(&table[i - 1], p);
        }
        let mut acc = self.identity();
        for window in (0..16 * L).rev() {
            for _ in 0..4 {
                acc = self.point_add(&acc, &acc);
            }
            let digit = (k.0[window >> 4] >> ((window & 15) * 4)) & 15;
            let mut chosen = table[0];
            for (i, entry) in table.iter().enumerate() {
                let matches = ((i as u64 ^ digit).wrapping_sub(1)) >> 63;
                chosen.cmov(entry, matches);
            }
            acc = self.point_add(&acc, &chosen);
        }
        acc
    }

    /// The affine coordinates, plain, or `None` for the identity.
    fn to_affine(&self, p: &Point<L>) -> Option<(Uint<L>, Uint<L>)> {
        if p.z.is_zero() {
            return None;
        }
        let zi = self.invert(&p.z);
        let x = self.field.from_mont(&self.mul(&p.x, &zi));
        let y = self.field.from_mont(&self.mul(&p.y, &zi));
        Some((x, y))
    }

    fn lift(&self, public: &Public<L>) -> Point<L> {
        Point {
            x: self.field.to_mont(&public.x),
            y: self.field.to_mont(&public.y),
            z: self.one,
        }
    }

    // The scalar ring, in plain form.

    fn scalar_mul(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        self.order.mulmod(a, b)
    }

    fn scalar_invert(&self, a: &Uint<L>) -> Uint<L> {
        let (exponent, _) = self.curve.n.sub_borrow(&Uint::from_limbs(&[2]));
        self.order.modexp(a, &exponent)
    }

    /// A value below `2^(64 L)` reduced modulo `n`, which takes one
    /// conditional subtraction because `n` is above half the width.
    fn reduce_scalar(&self, a: &Uint<L>) -> Uint<L> {
        let (reduced, borrow) = a.sub_borrow(&self.curve.n);
        let mut out = *a;
        out.cmov(&reduced, 1 - borrow);
        out
    }

    /// Whether `a` is a scalar a key or a signature may hold: in
    /// `[1, n - 1]`.
    fn scalar_in_range(&self, a: &Uint<L>) -> bool {
        !a.is_zero() && a.less_than(&self.curve.n) == 1
    }

    /// The leftmost `8 L` bytes of a digest as a scalar, as FIPS
    /// 186-5 section 6.4.1 and RFC 6979's `bits2int` both define;
    /// a shorter digest is the whole of it.
    fn hash_to_scalar(&self, digest: &[u8]) -> Uint<L> {
        let take = digest.len().min(width::<L>());
        self.reduce_scalar(&Uint::from_be_bytes(&digest[..take]))
    }
}

/// A private scalar in `[1, n - 1]`, wiped on drop.
pub(crate) struct Secret<const L: usize> {
    d: Uint<L>,
}

impl<const L: usize> Drop for Secret<L> {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

/// A public point in affine coordinates, plain, known to lie on
/// the curve: nothing constructs one without checking.
#[derive(Clone, Copy)]
pub(crate) struct Public<const L: usize> {
    x: Uint<L>,
    y: Uint<L>,
}

/// The tries key generation makes before giving up, each failing
/// with probability below 2^-32 on either curve.
const GENERATE_TRIES: usize = 100;

impl<const L: usize> Secret<L> {
    /// A scalar from its big-endian bytes, exactly the curve's
    /// width, refused unless in `[1, n - 1]`.
    pub(crate) fn try_new(e: &Engine<L>, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != width::<L>() {
            return Err(Error::InvalidKeyLength(bytes.len()));
        }
        let d = Uint::from_be_bytes(bytes);
        if !e.scalar_in_range(&d) {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(Secret { d })
    }

    /// A fresh scalar, by rejection: random bytes of the width,
    /// kept when in range, which nearly always they are.
    pub(crate) fn generate<R: Random>(
        e: &Engine<L>,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut buf = [[0u8; 8]; L];
        for _ in 0..GENERATE_TRIES {
            rng.fill(buf.as_flattened_mut())?;
            let d = Uint::from_be_bytes(buf.as_flattened());
            if e.scalar_in_range(&d) {
                buf.zeroize();
                return Ok(Secret { d });
            }
        }
        Err(Error::KeyGenerationFailed)
    }

    /// The scalar, big-endian, into `out` of the curve's width.
    pub(crate) fn bytes(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), width::<L>());
        self.d.to_be_bytes(out);
    }

    /// The public point, `d * G`.
    pub(crate) fn public(&self, e: &Engine<L>) -> Public<L> {
        let p = e.point_mul(&e.g, &self.d);
        // A scalar in range times a generator of prime order is
        // never the identity.
        let (x, y) = e.to_affine(&p).unwrap_or((Uint::ZERO, Uint::ZERO));
        Public { x, y }
    }

    /// The x-coordinate of `d * Q`, the ECDH shared secret, into
    /// `out` of the curve's width.
    pub(crate) fn shared_secret(
        &self,
        e: &Engine<L>,
        public: &Public<L>,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let p = e.point_mul(&e.lift(public), &self.d);
        // Unreachable for a validated point on a prime-order curve,
        // and checked anyway: the identity has no x to share.
        let (mut x, mut y) = e.to_affine(&p).ok_or(Error::InvalidPublicKey)?;
        x.to_be_bytes(out);
        x.zeroize();
        y.zeroize();
        Ok(())
    }

    /// An ECDSA signature over `message`, `r || s` into `out` of
    /// twice the curve's width, with the nonce from RFC 6979.
    pub(crate) fn sign<H: Hash>(
        &self,
        e: &Engine<L>,
        message: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        debug_assert_eq!(out.len(), 2 * width::<L>());
        let z = e.hash_to_scalar(H::digest(message)?.as_ref());

        let mut d_bytes = [[0u8; 8]; L];
        self.d.to_be_bytes(d_bytes.as_flattened_mut());
        let mut z_bytes = [[0u8; 8]; L];
        z.to_be_bytes(z_bytes.as_flattened_mut());
        let mut nonce =
            Nonce::<H>::new(d_bytes.as_flattened(), z_bytes.as_flattened())?;
        d_bytes.zeroize();

        loop {
            let mut k = nonce.next(e)?;
            let r = match e.to_affine(&e.point_mul(&e.g, &k)) {
                Some((x, _)) => e.reduce_scalar(&x),
                None => Uint::ZERO,
            };
            // s = k^-1 (z + r d) mod n.
            let mut rd = e.scalar_mul(&r, &self.d);
            let mut sum = z.add_mod(&rd, &e.curve.n);
            let mut k_inverse = e.scalar_invert(&k);
            let s = e.scalar_mul(&k_inverse, &sum);
            k.zeroize();
            rd.zeroize();
            sum.zeroize();
            k_inverse.zeroize();
            if r.is_zero() || s.is_zero() {
                continue;
            }
            let (r_out, s_out) = out.split_at_mut(width::<L>());
            r.to_be_bytes(r_out);
            s.to_be_bytes(s_out);
            return Ok(());
        }
    }
}

impl<const L: usize> Public<L> {
    /// A point from its plain affine coordinates, checked to lie on
    /// the curve; the identity has no such coordinates and so is
    /// never accepted.
    fn try_from_affine(
        e: &Engine<L>,
        x: Uint<L>,
        y: Uint<L>,
    ) -> Result<Self, Error> {
        if x.less_than(&e.curve.p) == 0 || y.less_than(&e.curve.p) == 0 {
            return Err(Error::InvalidPublicKey);
        }
        let xm = e.field.to_mont(&x);
        let ym = e.field.to_mont(&y);
        if e.mul(&ym, &ym).0 != e.rhs(&xm).0 {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Public { x, y })
    }

    /// A point from its SEC 1 encoding: `04 || x || y`, or `02` or
    /// `03` followed by `x` alone, the tag giving the parity of the
    /// `y` to recover. Anything else, the identity's lone zero byte
    /// included, is [`Error::InvalidPublicKey`].
    pub(crate) fn try_from_sec1(
        e: &Engine<L>,
        sec1: &[u8],
    ) -> Result<Self, Error> {
        let width = width::<L>();
        match sec1 {
            [0x04, rest @ ..] if rest.len() == 2 * width => {
                let (x, y) = rest.split_at(width);
                Self::try_from_affine(
                    e,
                    Uint::from_be_bytes(x),
                    Uint::from_be_bytes(y),
                )
            }
            [tag @ (0x02 | 0x03), rest @ ..] if rest.len() == width => {
                let x = Uint::from_be_bytes(rest);
                if x.less_than(&e.curve.p) == 0 {
                    return Err(Error::InvalidPublicKey);
                }
                let xm = e.field.to_mont(&x);
                let root =
                    e.sqrt(&e.rhs(&xm)).ok_or(Error::InvalidPublicKey)?;
                let mut y = e.field.from_mont(&root);
                // The root and its negation have opposite parity,
                // since p is odd; the tag says which was meant.
                if y.is_odd() != (*tag == 0x03) {
                    y = Uint::ZERO.sub_mod(&y, &e.curve.p);
                }
                Ok(Public { x, y })
            }
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// The uncompressed SEC 1 encoding, `04 || x || y`, into `out`
    /// of one more than twice the curve's width.
    pub(crate) fn sec1(&self, out: &mut [u8]) {
        let width = width::<L>();
        debug_assert_eq!(out.len(), 1 + 2 * width);
        out[0] = 0x04;
        self.x.to_be_bytes(&mut out[1..1 + width]);
        self.y.to_be_bytes(&mut out[1 + width..]);
    }

    /// Checks an ECDSA signature `r || s` over `message`.
    pub(crate) fn verify<H: Hash>(
        &self,
        e: &Engine<L>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let width = width::<L>();
        if signature.len() != 2 * width {
            return Err(Error::InvalidSignature);
        }
        let r = Uint::from_be_bytes(&signature[..width]);
        let s = Uint::from_be_bytes(&signature[width..]);
        if !e.scalar_in_range(&r) || !e.scalar_in_range(&s) {
            return Err(Error::InvalidSignature);
        }
        let z = e.hash_to_scalar(H::digest(message)?.as_ref());
        // R = (z / s) G + (r / s) Q, whose x must be r modulo n.
        let w = e.scalar_invert(&s);
        let u1 = e.scalar_mul(&z, &w);
        let u2 = e.scalar_mul(&r, &w);
        let sum = e.point_add(
            &e.point_mul(&e.g, &u1),
            &e.point_mul(&e.lift(self), &u2),
        );
        let (x, _) = e.to_affine(&sum).ok_or(Error::InvalidSignature)?;
        if e.reduce_scalar(&x).0 == r.0 {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

/// The nonce generator of RFC 6979 section 3.2: HMAC-DRBG over the
/// signature's hash, seeded with the private key and the message's
/// digest, so the same key and message always give the same nonce
/// and nothing else can.
struct Nonce<H: Hash> {
    k: H::Output,
    v: H::Output,
}

impl<H: Hash> Nonce<H> {
    /// Steps b through g, given `int2octets(x)` and
    /// `bits2octets(h1)`.
    fn new(x: &[u8], h: &[u8]) -> Result<Self, Error> {
        let mut v = H::Output::ZERO;
        v.as_mut().fill(0x01);
        let k = H::Output::ZERO;
        let mut nonce = Nonce { k, v };
        nonce.seed(0x00, x, h)?;
        nonce.seed(0x01, x, h)?;
        Ok(nonce)
    }

    /// `K = HMAC_K(V || tag || x || h)`, then `V = HMAC_K(V)`.
    fn seed(&mut self, tag: u8, x: &[u8], h: &[u8]) -> Result<(), Error> {
        let mut mac = Hmac::<H>::try_new(self.k.as_ref())?;
        mac.update(self.v.as_ref());
        mac.update(&[tag]);
        mac.update(x);
        mac.update(h);
        self.k = mac.finalize();
        self.v = Hmac::<H>::mac(self.k.as_ref(), self.v.as_ref())?;
        Ok(())
    }

    /// The next candidate in `[1, n - 1]`, step h; a candidate out
    /// of range is skipped as the RFC says, and a previous one that
    /// the signature rejected has been skipped the same way.
    fn next<const L: usize>(
        &mut self,
        e: &Engine<L>,
    ) -> Result<Uint<L>, Error> {
        loop {
            let mut t = [[0u8; 8]; L];
            let mut filled = 0;
            while filled < width::<L>() {
                self.v = Hmac::<H>::mac(self.k.as_ref(), self.v.as_ref())?;
                let out = &mut t.as_flattened_mut()[filled..];
                let take = out.len().min(H::Output::SIZE);
                out[..take].copy_from_slice(&self.v.as_ref()[..take]);
                filled += take;
            }
            let k = Uint::from_be_bytes(t.as_flattened());
            t.zeroize();
            self.seed_again()?;
            if e.scalar_in_range(&k) {
                return Ok(k);
            }
        }
    }

    /// `K = HMAC_K(V || 0x00)`, `V = HMAC_K(V)`: what follows every
    /// candidate, taken or not.
    fn seed_again(&mut self) -> Result<(), Error> {
        self.seed(0x00, &[], &[])
    }
}

impl<H: Hash> Drop for Nonce<H> {
    fn drop(&mut self) {
        self.k.as_mut().zeroize();
        self.v.as_mut().zeroize();
    }
}

// Formats: SEC 1 points inside the RFC 5480 SubjectPublicKeyInfo
// and the RFC 5915 ECPrivateKey, itself inside PKCS#8.

/// Room to encode or decode any key on these curves: the largest,
/// a PKCS#8 with attributes, is well under this.
const SCRATCH: usize = 512;

/// The PEM labels a private key may come under: PKCS#8 first, then
/// the bare ECPrivateKey that `openssl ecparam -genkey` writes.
const PRIVATE_LABELS: [&str; 2] = ["PRIVATE KEY", "EC PRIVATE KEY"];

const PUBLIC_LABEL: &str = "PUBLIC KEY";

/// Whether an AlgorithmIdentifier names a key on this curve:
/// `id-ecPublicKey` with the curve's own OID as its parameters.
fn is_this_curve<const L: usize>(
    curve: &Curve<L>,
    algorithm: &der::Algorithm,
) -> bool {
    let mut params = Reader::new(algorithm.params);
    algorithm.oid == EC_PUBLIC_KEY
        && params.oid().is_ok_and(|oid| oid == curve.oid)
        && params.end().is_ok()
}

fn algorithm_identifier<const L: usize>(curve: &Curve<L>, w: &mut Writer) {
    w.oid(EC_PUBLIC_KEY);
    w.oid(curve.oid);
}

/// `der` as a PEM block under `label`, into the front of `out`.
fn to_pem(label: &str, der: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let needed = pem::encoded_len(label, der.len());
    if out.len() < needed {
        return Err(Error::OutputTooSmall(needed));
    }
    Ok(pem::encode(label, der, out))
}

impl<const L: usize> Public<L> {
    /// A point from a SubjectPublicKeyInfo naming this curve.
    pub(crate) fn from_spki(e: &Engine<L>, der: &[u8]) -> Result<Self, Error> {
        let (algorithm, point) = der::read_spki(der)?;
        if !is_this_curve(e.curve, &algorithm) {
            return Err(Error::InvalidEncoding);
        }
        Self::try_from_sec1(e, point)
    }

    /// The SubjectPublicKeyInfo, with the point uncompressed.
    pub(crate) fn spki(
        &self,
        e: &Engine<L>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut sec1 = [0u8; SCRATCH];
        let sec1 = &mut sec1[..1 + 2 * width::<L>()];
        self.sec1(sec1);
        der::write_spki_with(
            out,
            |w| algorithm_identifier(e.curve, w),
            |w| w.raw(sec1),
        )
    }

    pub(crate) fn from_pem(e: &Engine<L>, pem: &[u8]) -> Result<Self, Error> {
        let mut der = [0u8; SCRATCH];
        let (_, n) = pem::decode(&[PUBLIC_LABEL], pem, &mut der)?;
        Self::from_spki(e, &der[..n])
    }

    pub(crate) fn pem(
        &self,
        e: &Engine<L>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut der = [0u8; SCRATCH];
        let n = self.spki(e, &mut der)?;
        to_pem(PUBLIC_LABEL, &der[..n], out)
    }
}

impl<const L: usize> Secret<L> {
    /// An RFC 5915 ECPrivateKey, with the public point it carried
    /// if any. Its parameters, when present, must name this curve;
    /// inside PKCS#8 they are usually left out, since the outer
    /// algorithm identifier already says.
    fn from_ec_private_key(
        e: &Engine<L>,
        der: &[u8],
    ) -> Result<(Self, Option<Public<L>>), Error> {
        let mut outer = Reader::new(der);
        let mut key = outer.sequence()?;
        outer.end()?;
        if key.integer()? != [1] {
            return Err(Error::InvalidEncoding);
        }
        let d = key.octet_string()?;
        if let Some(params) = key.optional(der::context(0))? {
            let mut params = Reader::new(params);
            if params.oid()? != e.curve.oid {
                return Err(Error::InvalidEncoding);
            }
            params.end()?;
        }
        // A scalar of another width is another curve's, whatever
        // the parameters said; one out of range is a bad key.
        let secret = Self::try_new(e, d).map_err(|err| match err {
            Error::InvalidKeyLength(_) => Error::InvalidEncoding,
            other => other,
        })?;
        let public = match key.optional(der::context(1))? {
            Some(wrapped) => {
                let mut wrapped = Reader::new(wrapped);
                let point = wrapped.bit_string()?;
                wrapped.end()?;
                Some(Public::try_from_sec1(e, point)?)
            }
            None => None,
        };
        key.end()?;
        Ok((secret, public))
    }

    /// The public point, derived, and checked against the one the
    /// structure carried when it carried one: a pair that disagrees
    /// has been corrupted.
    fn with_public(
        self,
        e: &Engine<L>,
        carried: Option<Public<L>>,
    ) -> Result<(Self, Public<L>), Error> {
        let public = self.public(e);
        if let Some(carried) = carried {
            if carried.x.0 != public.x.0 || carried.y.0 != public.y.0 {
                return Err(Error::InvalidEncoding);
            }
        }
        Ok((self, public))
    }

    /// A key from a PKCS#8 PrivateKeyInfo naming this curve.
    pub(crate) fn from_pkcs8(
        e: &Engine<L>,
        der: &[u8],
    ) -> Result<(Self, Public<L>), Error> {
        let info = der::read_pkcs8(der)?;
        if !is_this_curve(e.curve, &info.algorithm) {
            return Err(Error::InvalidEncoding);
        }
        let (secret, carried) = Self::from_ec_private_key(e, info.private_key)?;
        secret.with_public(e, carried)
    }

    /// A key from a bare ECPrivateKey, the `EC PRIVATE KEY` form.
    pub(crate) fn from_sec1_der(
        e: &Engine<L>,
        der: &[u8],
    ) -> Result<(Self, Public<L>), Error> {
        let (secret, carried) = Self::from_ec_private_key(e, der)?;
        secret.with_public(e, carried)
    }

    /// The PKCS#8 PrivateKeyInfo, around an ECPrivateKey that
    /// carries the public point and leaves the parameters to the
    /// outer identifier, which is the form OpenSSL writes.
    pub(crate) fn pkcs8(
        &self,
        e: &Engine<L>,
        public: &Public<L>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut d = [[0u8; 8]; L];
        self.d.to_be_bytes(d.as_flattened_mut());
        let mut sec1 = [0u8; SCRATCH];
        let sec1 = &mut sec1[..1 + 2 * width::<L>()];
        public.sec1(sec1);
        let result = der::write_pkcs8_with(
            out,
            |w| algorithm_identifier(e.curve, w),
            |w| {
                w.sequence(|w| {
                    w.integer(&[1]);
                    w.octet_string(d.as_flattened());
                    w.context(1, |w| w.bit_string(sec1));
                })
            },
        );
        d.zeroize();
        result
    }

    /// Either private form from a PEM block, told apart by its label.
    pub(crate) fn from_pem(
        e: &Engine<L>,
        pem: &[u8],
    ) -> Result<(Self, Public<L>), Error> {
        let mut der = [0u8; SCRATCH];
        let result = pem::decode(&PRIVATE_LABELS, pem, &mut der).and_then(
            |(form, n)| match form {
                0 => Self::from_pkcs8(e, &der[..n]),
                _ => Self::from_sec1_der(e, &der[..n]),
            },
        );
        der.zeroize();
        result
    }

    /// The PKCS#8 form as a `PRIVATE KEY` PEM block.
    pub(crate) fn pem(
        &self,
        e: &Engine<L>,
        public: &Public<L>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut der = [0u8; SCRATCH];
        let result = self
            .pkcs8(e, public, &mut der)
            .and_then(|n| to_pem(PRIVATE_LABELS[0], &der[..n], out));
        der.zeroize();
        result
    }
}

/// An ECDSA signature `r || s` as the DER `ECDSA-Sig-Value` of RFC
/// 5480, `SEQUENCE { INTEGER r, INTEGER s }`, into the front of
/// `out`; the length varies with the values' leading bits.
pub(crate) fn signature_to_der(
    rs: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let (r, s) = rs.split_at(rs.len() / 2);
    der::encode(out, |w| {
        w.sequence(|w| {
            w.integer(r);
            w.integer(s);
        })
    })
}

/// The reverse: `r || s` of `out`'s width from a DER signature. An
/// integer wider than the curve is not a signature on it.
pub(crate) fn signature_from_der(
    der: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let width = out.len() / 2;
    let mut outer = Reader::new(der);
    let mut seq = outer.sequence()?;
    outer.end()?;
    let r = seq.integer()?;
    let s = seq.integer()?;
    seq.end()?;
    if r.len() > width || s.len() > width {
        return Err(Error::InvalidEncoding);
    }
    out.fill(0);
    out[width - r.len()..width].copy_from_slice(r);
    out[2 * width - s.len()..].copy_from_slice(s);
    Ok(())
}

/// The key types of one curve for one scheme: the constants, the
/// two structs, and everything on them that is not the scheme's own
/// operation. Invoked inside a module per curve by `sig::ecdsa` and
/// `kex::ecdh`, which add `sign` and `verify`, or `shared_secret`.
///
/// `$job` is what the key does, for the docs; `$curve` names it.
macro_rules! key_types {
    (
        $constants:expr, $limbs:literal, $curve:literal, $job:literal,
        der $der:literal, public der $public_der:literal
    ) => {
        use crate::math::ec::{Engine, Public, Secret};
        use crate::random::Random;
        use crate::Error;

        /// The length of a private key.
        pub const KEY_SIZE: usize = 8 * $limbs;

        /// The length of a public key in its uncompressed SEC 1
        /// form, `04 || x || y`.
        pub const PUBLIC_KEY_SIZE: usize = 1 + 16 * $limbs;

        /// The length of a private key's DER encoding, a PKCS#8
        /// `PrivateKeyInfo` around an RFC 5915 `ECPrivateKey` that
        /// carries the public point.
        pub const DER_SIZE: usize = $der;

        /// The length of a public key's DER encoding, a
        /// `SubjectPublicKeyInfo` (RFC 5480).
        pub const PUBLIC_KEY_DER_SIZE: usize = $public_der;

        /// The length of a private key's PEM encoding, a
        /// `PRIVATE KEY` block.
        pub const PEM_SIZE: usize =
            crate::pem::encoded_len("PRIVATE KEY", DER_SIZE);

        /// The length of a public key's PEM encoding, a `PUBLIC KEY`
        /// block.
        pub const PUBLIC_KEY_PEM_SIZE: usize =
            crate::pem::encoded_len("PUBLIC KEY", PUBLIC_KEY_DER_SIZE);

        #[doc = concat!("A ", $job, " key on ", $curve, ": a secret")]
        /// scalar in `[1, n - 1]`, wiped on drop, with its public
        /// point alongside.
        pub struct PrivateKey {
            secret: Secret<$limbs>,
            public: PublicKey,
        }

        #[doc = concat!("A public key on ", $curve, ": a point known")]
        /// to lie on the curve, since every way of making one checks.
        #[derive(Clone, Copy)]
        pub struct PublicKey {
            point: Public<$limbs>,
        }

        impl PrivateKey {
            fn from_secret(
                secret: Secret<$limbs>,
                public: Public<$limbs>,
            ) -> Self {
                PrivateKey {
                    secret,
                    public: PublicKey { point: public },
                }
            }

            /// A fresh key: a uniform scalar in `[1, n - 1]`, by
            /// rejection sampling, which fails once in 2^32 draws
            /// and is retried; the public point is derived.
            pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                let secret = Secret::generate(&e, rng)?;
                let public = secret.public(&e);
                Ok(Self::from_secret(secret, public))
            }

            /// A key from its secret scalar, big-endian, which must be
            /// in `[1, n - 1]`: [`Error::InvalidPrivateKey`] for zero
            /// or a value at or above the order.
            pub fn try_new(secret: &[u8; KEY_SIZE]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                let secret = Secret::try_new(&e, secret)?;
                let public = secret.public(&e);
                Ok(Self::from_secret(secret, public))
            }

            /// The secret scalar, big-endian. The caller holds a
            /// secret now, and should wipe it when done.
            pub fn secret_bytes(&self) -> [u8; KEY_SIZE] {
                let mut out = [0u8; KEY_SIZE];
                self.secret.bytes(&mut out);
                out
            }

            /// The public half.
            pub fn public_key(&self) -> &PublicKey {
                &self.public
            }

            /// A key from its DER PKCS#8 `PrivateKeyInfo`, the form
            /// under `PRIVATE KEY` in a PEM file: `id-ecPublicKey`
            /// naming this curve, around an RFC 5915 `ECPrivateKey`.
            /// A public point carried inside is checked against the
            /// secret's own, and a pair that disagrees is refused as
            /// corrupt. A key on another curve, or anything else wrong
            /// with the bytes, is [`Error::InvalidEncoding`].
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                let (secret, public) = Secret::from_pkcs8(&e, der)?;
                Ok(Self::from_secret(secret, public))
            }

            /// Writes the key as a `PrivateKeyInfo` into the front of
            /// `out`, returning the length, always [`DER_SIZE`]; a
            /// buffer too small gets [`Error::OutputTooSmall`]. The
            /// output is a secret, to be wiped when done.
            pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let e = Engine::new(&$constants);
                self.secret.pkcs8(&e, &self.public.point, out)
            }

            /// A key from a PEM block (RFC 7468) labelled
            /// `PRIVATE KEY`, around the PKCS#8 form, or
            /// `EC PRIVATE KEY`, around the bare `ECPrivateKey` that
            /// `openssl ecparam -genkey` writes. Whitespace and line
            /// ends are read leniently; anything else that is not
            /// exactly one well-formed block for this curve, an
            /// encrypted key included, is [`Error::InvalidEncoding`].
            pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                let (secret, public) = Secret::from_pem(&e, pem)?;
                Ok(Self::from_secret(secret, public))
            }

            /// Writes the key as a `PRIVATE KEY` PEM block, ASCII with
            /// LF line ends, into the front of `out`, returning the
            /// length, always [`PEM_SIZE`]. A secret, to be wiped.
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let e = Engine::new(&$constants);
                self.secret.pem(&e, &self.public.point, out)
            }
        }

        impl PublicKey {
            /// A key from its SEC 1 encoding: `04 || x || y`, or the
            /// compressed `02 || x` and `03 || x` with the tag giving
            /// the parity of `y`. The point must lie on the curve;
            /// anything else is [`Error::InvalidPublicKey`].
            pub fn try_from_sec1(sec1: &[u8]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                Ok(PublicKey {
                    point: Public::try_from_sec1(&e, sec1)?,
                })
            }

            /// The uncompressed SEC 1 encoding, `04 || x || y`.
            pub fn sec1_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
                let mut out = [0u8; PUBLIC_KEY_SIZE];
                self.point.sec1(&mut out);
                out
            }

            /// A key from its DER `SubjectPublicKeyInfo` (RFC 5480),
            /// the form under `PUBLIC KEY` in a PEM file, which must
            /// name this curve; the point inside may be compressed.
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                Ok(PublicKey {
                    point: Public::from_spki(&e, der)?,
                })
            }

            /// Writes the key as a `SubjectPublicKeyInfo`, the point
            /// uncompressed, into the front of `out`, returning the
            /// length, always [`PUBLIC_KEY_DER_SIZE`].
            pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let e = Engine::new(&$constants);
                self.point.spki(&e, out)
            }

            /// A key from a `PUBLIC KEY` PEM block, read as
            /// [`PrivateKey::try_from_pem`] reads its own.
            pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                Ok(PublicKey {
                    point: Public::from_pem(&e, pem)?,
                })
            }

            /// Writes the key as a `PUBLIC KEY` PEM block into the
            /// front of `out`, returning the length, always
            /// [`PUBLIC_KEY_PEM_SIZE`].
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let e = Engine::new(&$constants);
                self.point.pem(&e, out)
            }
        }
    };
}

pub(crate) use key_types;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::{Sha256, Sha384};

    /// Affine coordinates as limbs, comparable.
    fn affine<const L: usize>(
        e: &Engine<L>,
        p: &Point<L>,
    ) -> Option<([u64; L], [u64; L])> {
        e.to_affine(p).map(|(x, y)| (x.0, y.0))
    }

    fn unhex<'a>(hex: &str, buf: &'a mut [u8]) -> &'a [u8] {
        let hex = hex.as_bytes();
        for (byte, pair) in buf.iter_mut().zip(hex.chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        &buf[..hex.len() / 2]
    }

    /// The generator is on the curve, and doubling it by the
    /// complete formula agrees with adding it to itself, and with
    /// multiplying by two; the identity behaves.
    #[test]
    fn group_law_basics() {
        fn check<const L: usize>(curve: &Curve<L>) {
            let e = Engine::new(curve);
            let g = Public {
                x: curve.gx,
                y: curve.gy,
            };
            Public::try_from_affine(&e, g.x, g.y).unwrap();
            let two_g = e.point_add(&e.g, &e.g);
            let by_mul = e.point_mul(&e.g, &Uint::from_limbs(&[2]));
            assert_eq!(affine(&e, &two_g), affine(&e, &by_mul));
            let (x, y) = e.to_affine(&two_g).unwrap();
            Public::try_from_affine(&e, x, y).unwrap();
            // Identity plus G is G; n G is the identity; (n-1) G = -G.
            let id = e.identity();
            assert_eq!(affine(&e, &e.point_add(&id, &e.g)), affine(&e, &e.g));
            assert!(e.to_affine(&e.point_mul(&e.g, &curve.n)).is_none());
            let (minus_one, _) = curve.n.sub_borrow(&Uint::one());
            let (x, y) = e.to_affine(&e.point_mul(&e.g, &minus_one)).unwrap();
            assert_eq!(x.0, curve.gx.0);
            assert_eq!(y.0, Uint::ZERO.sub_mod(&curve.gy, &curve.p).0);
            assert!(e.to_affine(&e.point_mul(&e.g, &Uint::ZERO)).is_none());
        }
        check(&P256);
        check(&P384);
    }

    /// Public keys from the ACVP ECDSA keyGen sample, one per curve,
    /// which is `d * G` against an external answer.
    #[test]
    fn public_keys_match_nist() {
        let mut buf = [0u8; 48];
        let e = Engine::new(&P256);
        let d = Secret::try_new(
            &e,
            unhex(
                "bf049d775057f1199612f4bd6ab0af69\
                 5a78fb488453e261ca3c277ad57e55db",
                &mut buf,
            ),
        )
        .unwrap();
        let public = d.public(&e);
        let mut sec1 = [0u8; 65];
        public.sec1(&mut sec1);
        let mut expected = [0u8; 65];
        unhex(
            "04c6e20135457dc6f738e60cf6999d2416f31d7c12afea248434a547a9aa8a34b0\
             6e5610c1cfc091ad58aa43f2b8a96d9561ee80594c5bc5dc4cb08be679aa45ff",
            &mut expected,
        );
        assert_eq!(sec1, expected);
        assert_eq!(
            Public::try_from_sec1(&e, &expected).unwrap().x.0,
            public.x.0
        );

        let e = Engine::new(&P384);
        let d = Secret::try_new(
            &e,
            unhex(
                "958baeccb7bb953aa92fce3a136a7b8a\
                 68001c4ed00cf7da6fcf83c0f552636d\
                 0063e7c8a511cc45534f1a7f0f7dd959",
                &mut buf,
            ),
        )
        .unwrap();
        let public = d.public(&e);
        let mut sec1 = [0u8; 97];
        public.sec1(&mut sec1);
        let mut expected = [0u8; 97];
        unhex(
            "0419f324cf1cbc7d17c1284f1d887eecafb1e11f4c9709566b3094fe3152f63fdb\
             c937018f93918b80a84d4a9ffb8e132c75a66d983f39cca1dddebb881969adea\
             be03b8c84b16e9e8b1de4b79ba3c41701145762eb90cc59c5f61f568d0601c08",
            &mut expected,
        );
        assert_eq!(sec1, expected);
    }

    /// Compressed points decompress to the same key, with either
    /// parity, and a non-residue x is refused.
    #[test]
    fn compressed_points() {
        fn check<const L: usize>(curve: &Curve<L>) {
            let e = Engine::new(curve);
            let mut rng = crate::random::Rng::try_new(
                crate::random::System::try_new().unwrap(),
            )
            .unwrap();
            let mut sec1 = [0u8; 97];
            let w = width::<L>();
            for _ in 0..4 {
                let public = Secret::generate(&e, &mut rng).unwrap().public(&e);
                public.sec1(&mut sec1[..1 + 2 * w]);
                let mut compressed = [0u8; 49];
                compressed[..1 + w].copy_from_slice(&sec1[..1 + w]);
                compressed[0] = 0x02 | (sec1[2 * w] & 1);
                let back =
                    Public::try_from_sec1(&e, &compressed[..1 + w]).unwrap();
                assert_eq!(back.y.0, public.y.0);
                // The other parity is the negated point, also valid.
                compressed[0] ^= 1;
                let other =
                    Public::try_from_sec1(&e, &compressed[..1 + w]).unwrap();
                assert_eq!(
                    other.y.0,
                    Uint::ZERO.sub_mod(&public.y, &curve.p).0
                );
                // A point off the curve, and the wrong lengths.
                sec1[1 + 2 * w - 1] ^= 1;
                assert!(Public::try_from_sec1(&e, &sec1[..1 + 2 * w]).is_err());
                assert!(Public::try_from_sec1(&e, &sec1[..2 * w]).is_err());
                assert!(Public::try_from_sec1(&e, &[0]).is_err());
            }
            // Among small x, some have no y: those are refused, and
            // the rest decompress to points that re-encode.
            let mut refused = 0;
            for x in 1..20u8 {
                let mut compressed = [0u8; 49];
                compressed[0] = 0x02;
                compressed[w] = x;
                match Public::try_from_sec1(&e, &compressed[..1 + w]) {
                    Ok(p) => {
                        p.sec1(&mut sec1[..1 + 2 * w]);
                        assert_eq!(sec1[1..1 + w], compressed[1..1 + w]);
                        assert_eq!(sec1[2 * w] & 1, 0);
                    }
                    Err(Error::InvalidPublicKey) => refused += 1,
                    Err(e) => panic!("{e}"),
                }
            }
            assert!(refused > 0, "no non-residue among small x");
        }
        check(&P256);
        check(&P384);
    }

    /// RFC 6979 appendix A.2.5 and A.2.6: deterministic signatures
    /// over "sample" and "test" with the private key given there.
    #[test]
    fn rfc6979_vectors() {
        let mut buf = [0u8; 48];
        let e = Engine::new(&P256);
        let d = Secret::try_new(
            &e,
            unhex(
                "c9afa9d845ba75166b5c215767b1d693\
                 4e50c3db36e89b127b8a622b120f6721",
                &mut buf,
            ),
        )
        .unwrap();
        let mut sig = [0u8; 64];
        d.sign::<Sha256>(&e, b"sample", &mut sig).unwrap();
        let mut expected = [0u8; 64];
        unhex(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
             f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            &mut expected,
        );
        assert_eq!(sig, expected);
        d.public(&e).verify::<Sha256>(&e, b"sample", &sig).unwrap();
        d.sign::<Sha256>(&e, b"test", &mut sig).unwrap();
        unhex(
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367\
             019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            &mut expected,
        );
        assert_eq!(sig, expected);

        let e = Engine::new(&P384);
        let d = Secret::try_new(
            &e,
            unhex(
                "6b9d3dad2e1b8c1c05b19875b6659f4d\
                 e23c3b667bf297ba9aa47740787137d8\
                 96d5724e4c70a825f872c9ea60d2edf5",
                &mut buf,
            ),
        )
        .unwrap();
        let mut sig = [0u8; 96];
        d.sign::<Sha384>(&e, b"sample", &mut sig).unwrap();
        let mut expected = [0u8; 96];
        unhex(
            "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c\
             81a648152e44acf96e36dd1e80fabe4699ef4aeb15f178cea1fe40db2603138f\
             130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
            &mut expected,
        );
        assert_eq!(sig, expected);
        d.public(&e).verify::<Sha384>(&e, b"sample", &sig).unwrap();
    }

    /// Verification refuses what it should: a changed message, a
    /// changed signature, zero or out-of-range parts, another key.
    #[test]
    fn verify_refusals() {
        let e = Engine::new(&P256);
        let mut rng = crate::random::Rng::try_new(
            crate::random::System::try_new().unwrap(),
        )
        .unwrap();
        let d = Secret::generate(&e, &mut rng).unwrap();
        let public = d.public(&e);
        let mut sig = [0u8; 64];
        d.sign::<Sha256>(&e, b"message", &mut sig).unwrap();
        public.verify::<Sha256>(&e, b"message", &sig).unwrap();
        let bad = |s: &[u8], m: &[u8]| {
            assert_eq!(
                public.verify::<Sha256>(&e, m, s),
                Err(Error::InvalidSignature)
            );
        };
        bad(&sig, b"messagf");
        let mut t = sig;
        t[0] ^= 1;
        bad(&t, b"message");
        t = sig;
        t[63] ^= 1;
        bad(&t, b"message");
        t = sig;
        t[..32].fill(0);
        bad(&t, b"message");
        t = sig;
        t[32..].fill(0xff);
        bad(&t, b"message");
        bad(&sig[..63], b"message");
        let other = Secret::generate(&e, &mut rng).unwrap().public(&e);
        assert!(other.verify::<Sha256>(&e, b"message", &sig).is_err());
    }

    /// Both sides of an agreement land on the same secret, and a
    /// key of the other curve or an off-curve point is refused.
    #[test]
    fn agreement() {
        let e = Engine::new(&P384);
        let mut rng = crate::random::Rng::try_new(
            crate::random::System::try_new().unwrap(),
        )
        .unwrap();
        let a = Secret::generate(&e, &mut rng).unwrap();
        let b = Secret::generate(&e, &mut rng).unwrap();
        let mut ab = [0u8; 48];
        let mut ba = [0u8; 48];
        a.shared_secret(&e, &b.public(&e), &mut ab).unwrap();
        b.shared_secret(&e, &a.public(&e), &mut ba).unwrap();
        assert_eq!(ab, ba);
        assert_ne!(ab, [0u8; 48]);
    }

    /// Scalars out of range are not keys.
    #[test]
    fn scalar_range() {
        let e = Engine::new(&P256);
        let mut buf = [0u8; 32];
        assert_eq!(
            Secret::try_new(&e, &buf).err(),
            Some(Error::InvalidPrivateKey)
        );
        P256.n.to_be_bytes(&mut buf);
        assert_eq!(
            Secret::try_new(&e, &buf).err(),
            Some(Error::InvalidPrivateKey)
        );
        buf[31] -= 1;
        assert!(Secret::try_new(&e, &buf).is_ok());
        assert_eq!(
            Secret::try_new(&e, &buf[..31]).err(),
            Some(Error::InvalidKeyLength(31))
        );
        assert_eq!(
            Secret::try_new(&e, &[1u8; 48]).err(),
            Some(Error::InvalidKeyLength(48))
        );
    }
}
