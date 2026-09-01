//! Ed25519 (RFC 8032): signatures over the edwards25519 curve.
//!
//! The signer's secret is 32 bytes; SHA-512 expands it into a scalar
//! and a prefix. A signature commits to the message twice over: `R`
//! is a point derived from the prefix and the message, and `s` binds
//! the secret scalar to a hash of `R`, the public key and the
//! message. Verification checks the one equation `sB = R + kA`.
//!
//! Signing is deterministic: the same key and message always give
//! the same signature, and no randomness is consumed, so a weak
//! generator cannot leak the key the way it can with ECDSA.
//!
//! This is the plain Ed25519 of RFC 8032 section 5.1: no context
//! string, no pre-hashing. Ed25519ctx and Ed25519ph can be added if
//! a protocol requires them.
//!
//! # Constant time
//!
//! Signing performs the same sequence of field and scalar operations
//! whatever the secret: scalar multiplication is a fixed ladder of
//! doublings and additions with the result chosen by a mask.
//! Verification handles only public data.
//!
//! # What verification accepts
//!
//! The checks are the ones RFC 8032 requires: the public key and `R`
//! must decode (a coordinate at or above the field prime does not),
//! and `s` must be below the group order, which is what stops an
//! accepted signature from being malleated into a second accepted
//! one. The equation is checked without the cofactor, matching the
//! bulk of deployed verifiers.

use zeroize::Zeroize;

use crate::hash::sha2::Sha512;
use crate::hash::Hash;
use crate::math::fe25519::Fe;
use crate::Error;

/// The length of a secret key.
pub const KEY_SIZE: usize = 32;

/// The length of a public key.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// The length of a signature.
pub const SIGNATURE_SIZE: usize = 64;

/// The public key belonging to `secret`.
///
/// Any 32 bytes are a valid secret key; take them from
/// [`random`](crate::random).
pub fn public_key(
    secret: &[u8; KEY_SIZE],
) -> Result<[u8; PUBLIC_KEY_SIZE], Error> {
    let mut h = Sha512::digest(secret)?;
    let mut a = secret_scalar(&h);
    let public = Point::BASE.scalar_mul(&a).compress();
    h.zeroize();
    a.zeroize();
    Ok(public)
}

/// Signs `message` with `secret`.
pub fn sign(
    secret: &[u8; KEY_SIZE],
    message: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let mut h = Sha512::digest(secret)?;
    let mut a = secret_scalar(&h);
    let public = Point::BASE.scalar_mul(&a).compress();

    // The nonce: a hash of the secret prefix and the message, so it
    // is unique per message without consuming randomness.
    let mut hasher = Sha512::try_new()?;
    hasher.update(&h[32..]);
    hasher.update(message);
    let mut wide = hasher.finalize();
    let mut r = Scalar::from_bytes_wide(&wide);
    let big_r = Point::BASE.scalar_mul(&r).compress();

    // The challenge binds R, the public key and the message.
    let mut hasher = Sha512::try_new()?;
    hasher.update(&big_r);
    hasher.update(&public);
    hasher.update(message);
    let k = Scalar::from_bytes_wide(&hasher.finalize());

    let s = k.mulmod(&a).addmod(&r);
    let mut signature = [0u8; SIGNATURE_SIZE];
    signature[..32].copy_from_slice(&big_r);
    signature[32..].copy_from_slice(&s.to_bytes());

    h.zeroize();
    a.zeroize();
    wide.zeroize();
    r.zeroize();
    Ok(signature)
}

/// Checks that `signature` signs `message` under `public`.
///
/// [`Error::InvalidPublicKey`] when the key does not name a point on
/// the curve; [`Error::InvalidSignature`] for everything else, which
/// deliberately says no more than that.
pub fn verify(
    public: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), Error> {
    let a = Point::decompress(public).ok_or(Error::InvalidPublicKey)?;

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    // s at or above the group order is the malleable form of another
    // signature, and RFC 8032 says to refuse it.
    if !Scalar::is_below_order(&s_bytes) {
        return Err(Error::InvalidSignature);
    }
    let s = Scalar::from_bytes_reduced(&s_bytes);

    let mut hasher = Sha512::try_new()?;
    hasher.update(&signature[..32]);
    hasher.update(public);
    hasher.update(message);
    let k = Scalar::from_bytes_wide(&hasher.finalize());

    // sB = R + kA, checked as R = sB - kA so R need never be
    // decompressed: its bytes are compared directly.
    let big_r = Point::BASE
        .scalar_mul(&s)
        .add(&a.neg().scalar_mul(&k))
        .compress();
    if big_r == signature[..32] {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// The secret scalar: the low half of the expanded secret, clamped
/// as RFC 8032 section 5.1.5 requires, reduced into the group.
///
/// Reduction changes nothing the curve can see: the base point's
/// order divides out.
fn secret_scalar(h: &[u8; 64]) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&h[..32]);
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    let scalar = Scalar::from_bytes_reduced(&bytes);
    bytes.zeroize();
    scalar
}

/// The curve constant d = -121665/121666.
const D: Fe = Fe([
    0x34dca135978a3,
    0x1a8283b156ebd,
    0x5e7a26001c029,
    0x739c663a03cbb,
    0x52036cee2b6ff,
]);

/// 2d, which the addition formula wants ready-made.
const D2: Fe = Fe([
    0x69b9426b2f159,
    0x35050762add7a,
    0x3cf44c0038052,
    0x6738cc7407977,
    0x2406d9dc56dff,
]);

/// A square root of -1, for correcting the root in decompression.
const SQRT_M1: Fe = Fe([
    0x61b274a0ea0b0,
    0x0d5a5fc8f189d,
    0x7ef5e9cbd0c60,
    0x78595a6804c9e,
    0x2b8324804fc1d,
]);

/// A point in extended coordinates: x = X/Z, y = Y/Z, T = XY/Z.
///
/// The extra T coordinate is what lets one addition formula serve
/// every case, doubling included, with no exceptional inputs.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    /// The neutral element: (0, 1).
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// The base point B: y = 4/5, x the even root for it.
    const BASE: Point = Point {
        x: Fe([
            0x62d608f25d51a,
            0x412a4b4f6592a,
            0x75b7171a4b31d,
            0x1ff60527118fe,
            0x216936d3cd6e5,
        ]),
        y: Fe([
            0x6666666666658,
            0x4cccccccccccc,
            0x1999999999999,
            0x3333333333333,
            0x6666666666666,
        ]),
        z: Fe::ONE,
        t: Fe([
            0x68ab3a5b7dda3,
            0x00eea2a5eadbb,
            0x2af8df483c27e,
            0x332b375274732,
            0x67875f0fd78b7,
        ]),
    };

    /// The unified addition of Hisil, Wong, Carter and Dawson,
    /// specialised to a = -1: correct for any pair of inputs,
    /// doubling included.
    fn add(&self, other: &Point) -> Point {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&D2).mul(&other.t);
        let zz = self.z.mul(&other.z);
        let d = zz.add(&zz);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Doubling, cheaper than adding a point to itself.
    fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let zz = self.z.square();
        let c = zz.add(&zz);
        let d = a.neg();
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    fn neg(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Replaces `self` with `other` when `condition` is one, by a
    /// mask rather than a branch.
    fn cmov(&mut self, other: &Point, condition: u64) {
        self.x.cmov(&other.x, condition);
        self.y.cmov(&other.y, condition);
        self.z.cmov(&other.z, condition);
        self.t.cmov(&other.t, condition);
    }

    /// `scalar` times `self`: one doubling and one masked addition
    /// per bit, the same work whatever the scalar.
    fn scalar_mul(&self, scalar: &Scalar) -> Point {
        let bytes = scalar.to_bytes();
        let mut acc = Point::IDENTITY;
        // The group order is below 2^253, so 253 bits cover every
        // reduced scalar.
        for i in (0..253).rev() {
            acc = acc.double();
            let sum = acc.add(self);
            let bit = u64::from((bytes[i >> 3] >> (i & 7)) & 1);
            acc.cmov(&sum, bit);
        }
        acc
    }

    /// The 32-byte encoding: y, with the sign of x in the top bit.
    fn compress(&self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let mut out = y.to_bytes();
        out[31] |= x.is_negative() << 7;
        out
    }

    /// Decoding per RFC 8032 section 5.1.3; `None` where it says to
    /// reject. Public data only, so the branches are fine.
    fn decompress(bytes: &[u8; 32]) -> Option<Point> {
        let sign = bytes[31] >> 7;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        if !below_prime(&y_bytes) {
            return None;
        }
        let y = Fe::from_bytes(&y_bytes);

        // x^2 = (y^2 - 1) / (d y^2 + 1). The root, when there is
        // one, is u v^3 (u v^7)^((p-5)/8), possibly times sqrt(-1).
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = yy.mul(&D).add(&Fe::ONE);
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_p58());

        let vxx = v.mul(&x.square());
        if vxx.equals(&u.neg()) {
            x = x.mul(&SQRT_M1);
        } else if !vxx.equals(&u) {
            return None;
        }

        // Zero has no sign, so the encoding claiming one is invalid.
        if x.is_zero() {
            if sign == 1 {
                return None;
            }
        } else if x.is_negative() != sign {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }
}

/// Whether the 32 little-endian bytes name a value below 2^255 - 19,
/// as canonical decoding requires. The caller clears the sign bit.
fn below_prime(bytes: &[u8; 32]) -> bool {
    if bytes[0] < 0xed {
        return true;
    }
    if bytes[31] != 0x7f {
        return true;
    }
    bytes[1..31].iter().any(|&b| b != 0xff)
}

/// The group order l = 2^252 + 27742317777372353535851937790883648493,
/// as four little-endian words.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// -1/l modulo 2^64, the Montgomery constant.
const MU: u64 = 0xd2b51da312547e1b;

/// 2^256 modulo l. Montgomery-multiplying by it reduces a value.
const R1: [u64; 4] = [
    0xd6ec31748d98951d,
    0xc6ef5bf4737dcf70,
    0xfffffffffffffffe,
    0x0fffffffffffffff,
];

/// 2^512 modulo l, for converting into the Montgomery domain.
const R2: [u64; 4] = [
    0xa40611e3449c0f01,
    0xd00e1ba768859347,
    0xceec73d217f5be65,
    0x0399411b7c309a3d,
];

/// An integer modulo the group order, four little-endian words,
/// always fully reduced.
///
/// Products go through Montgomery multiplication: an extra
/// multiplication by 2^512 mod l puts the stray 2^-256 factor back,
/// which costs one more pass but keeps every value in plain form.
/// The arithmetic is a fixed sequence of word operations, with the
/// final subtraction chosen by a mask.
#[derive(Clone, Copy, Zeroize)]
struct Scalar([u64; 4]);

impl Scalar {
    /// Reads 32 bytes, reducing modulo l.
    fn from_bytes_reduced(bytes: &[u8; 32]) -> Scalar {
        Scalar::montmul(&load_words(bytes), &R1)
    }

    /// Reads 64 bytes, as SHA-512 leaves them, reducing modulo l.
    fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar {
        let mut half = [0u8; 32];
        half.copy_from_slice(&bytes[..32]);
        let lo = Scalar::montmul(&load_words(&half), &R1);
        half.copy_from_slice(&bytes[32..]);
        let hi = Scalar::montmul(&load_words(&half), &R2);
        half.zeroize();
        lo.addmod(&hi)
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(8).zip(self.0) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Whether the 32 bytes already name a value below l. Used on
    /// the public `s` of a signature, so it need not hide anything.
    fn is_below_order(bytes: &[u8; 32]) -> bool {
        let words = load_words(bytes);
        for i in (0..4).rev() {
            if words[i] < L[i] {
                return true;
            }
            if words[i] > L[i] {
                return false;
            }
        }
        false
    }

    /// `self * other * 2^-256 mod l`, the Montgomery product, by
    /// coarsely integrated operand scanning.
    fn montmul(a: &[u64; 4], b: &[u64; 4]) -> Scalar {
        let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let mut t = [0u64; 6];
        for &ai in a {
            let mut carry = 0u64;
            for j in 0..4 {
                let v = u128::from(t[j]) + wide(ai, b[j]) + u128::from(carry);
                t[j] = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(t[4]) + u128::from(carry);
            t[4] = v as u64;
            t[5] = (v >> 64) as u64;

            // Adding this multiple of l zeroes the low word, so the
            // whole value shifts down one word, exactly.
            let m = t[0].wrapping_mul(MU);
            let v = u128::from(t[0]) + wide(m, L[0]);
            debug_assert_eq!(v as u64, 0);
            let mut carry = (v >> 64) as u64;
            for j in 1..4 {
                let v = u128::from(t[j]) + wide(m, L[j]) + u128::from(carry);
                t[j - 1] = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(t[4]) + u128::from(carry);
            t[3] = v as u64;
            let v = u128::from(t[5]) + (v >> 64);
            t[4] = v as u64;
            t[5] = 0;
        }
        // l is below 2^253, so the result is below 2l and fits four
        // words; at most one subtraction finishes the job.
        debug_assert_eq!(t[4], 0);
        Scalar::reduce_once([t[0], t[1], t[2], t[3]])
    }

    /// One conditional subtraction of l, chosen by a mask.
    fn reduce_once(t: [u64; 4]) -> Scalar {
        let mut r = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b1) = t[i].overflowing_sub(L[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            r[i] = d;
            borrow = u64::from(b1 | b2);
        }
        // A borrow out means t was already reduced: keep it.
        let keep = borrow.wrapping_neg();
        for i in 0..4 {
            r[i] ^= (r[i] ^ t[i]) & keep;
        }
        Scalar(r)
    }

    /// `self * other mod l`: two Montgomery passes, the second
    /// cancelling the first's 2^-256.
    fn mulmod(&self, other: &Scalar) -> Scalar {
        Scalar::montmul(&Scalar::montmul(&self.0, &other.0).0, &R2)
    }

    /// `self + other mod l`.
    fn addmod(&self, other: &Scalar) -> Scalar {
        let mut sum = [0u64; 4];
        let mut carry = 0u64;
        let terms = self.0.iter().zip(other.0);
        for (s, (a, b)) in sum.iter_mut().zip(terms) {
            let v = u128::from(*a) + u128::from(b) + u128::from(carry);
            *s = v as u64;
            carry = (v >> 64) as u64;
        }
        // Both inputs are below l < 2^253, so the sum fits.
        debug_assert_eq!(carry, 0);
        Scalar::reduce_once(sum)
    }
}

/// Reads 32 little-endian bytes as four words.
fn load_words(bytes: &[u8; 32]) -> [u64; 4] {
    let mut words = [0u64; 4];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        *word = u64::from_le_bytes(buf);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes hex into `buf`, returning the filled prefix.
    fn unhex<'a>(hex: &str, buf: &'a mut [u8]) -> &'a [u8] {
        let hex = hex.as_bytes();
        assert!(hex.len().is_multiple_of(2));
        assert!(hex.len() / 2 <= buf.len());
        for (byte, pair) in buf.iter_mut().zip(hex.chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        &buf[..hex.len() / 2]
    }

    fn unhex32(hex: &str) -> [u8; 32] {
        let mut buf = [0u8; 32];
        unhex(hex, &mut buf);
        buf
    }

    fn unhex64(hex: &str) -> [u8; 64] {
        let mut buf = [0u8; 64];
        unhex(hex, &mut buf);
        buf
    }

    /// The RFC 8032 section 7.1 vectors: secret key, public key,
    /// message, signature. The 1023-byte message exercises multi
    /// block hashing; the last vector is SHA-512("abc").
    const VECTORS: &[(&str, &str, &str, &str)] = &[
        (
            "9d61b19deffd5a60ba844af492ec2cc4\
             4449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a\
             0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f\
             5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc\
             9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540\
             a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c\
             387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b1\
             66d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f058\
             0816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a3\
             0ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc659\
             4a7c15e9716ed28dc027beceea1ec40a",
        ),
        (
            "f5e5767cf153319517630f226876b86c\
             8160cc583bc013744c6bf255f5cc0ee5",
            "278117fc144c72340f67d0f2316e8386\
             ceffbf2b2428c9c51fef7c597f1d426e",
            "08b8b2b733424243760fe426a4b54908\
             632110a66c2f6591eabd3345e3e4eb98\
             fa6e264bf09efe12ee50f8f54e9f77b1\
             e355f6c50544e23fb1433ddf73be84d8\
             79de7c0046dc4996d9e773f4bc9efe57\
             38829adb26c81b37c93a1b270b20329d\
             658675fc6ea534e0810a4432826bf58c\
             941efb65d57a338bbd2e26640f89ffbc\
             1a858efcb8550ee3a5e1998bd177e93a\
             7363c344fe6b199ee5d02e82d522c4fe\
             ba15452f80288a821a579116ec6dad2b\
             3b310da903401aa62100ab5d1a36553e\
             06203b33890cc9b832f79ef80560ccb9\
             a39ce767967ed628c6ad573cb116dbef\
             efd75499da96bd68a8a97b928a8bbc10\
             3b6621fcde2beca1231d206be6cd9ec7\
             aff6f6c94fcd7204ed3455c68c83f4a4\
             1da4af2b74ef5c53f1d8ac70bdcb7ed1\
             85ce81bd84359d44254d95629e9855a9\
             4a7c1958d1f8ada5d0532ed8a5aa3fb2\
             d17ba70eb6248e594e1a2297acbbb39d\
             502f1a8c6eb6f1ce22b3de1a1f40cc24\
             554119a831a9aad6079cad88425de6bd\
             e1a9187ebb6092cf67bf2b13fd65f270\
             88d78b7e883c8759d2c4f5c65adb7553\
             878ad575f9fad878e80a0c9ba63bcbcc\
             2732e69485bbc9c90bfbd62481d9089b\
             eccf80cfe2df16a2cf65bd92dd597b07\
             07e0917af48bbb75fed413d238f5555a\
             7a569d80c3414a8d0859dc65a46128ba\
             b27af87a71314f318c782b23ebfe808b\
             82b0ce26401d2e22f04d83d1255dc51a\
             ddd3b75a2b1ae0784504df543af8969b\
             e3ea7082ff7fc9888c144da2af58429e\
             c96031dbcad3dad9af0dcbaaaf268cb8\
             fcffead94f3c7ca495e056a9b47acdb7\
             51fb73e666c6c655ade8297297d07ad1\
             ba5e43f1bca32301651339e22904cc8c\
             42f58c30c04aafdb038dda0847dd988d\
             cda6f3bfd15c4b4c4525004aa06eeff8\
             ca61783aacec57fb3d1f92b0fe2fd1a8\
             5f6724517b65e614ad6808d6f6ee34df\
             f7310fdc82aebfd904b01e1dc54b2927\
             094b2db68d6f903b68401adebf5a7e08\
             d78ff4ef5d63653a65040cf9bfd4aca7\
             984a74d37145986780fc0b16ac451649\
             de6188a7dbdf191f64b5fc5e2ab47b57\
             f7f7276cd419c17a3ca8e1b939ae49e4\
             88acba6b965610b5480109c8b17b80e1\
             b7b750dfc7598d5d5011fd2dcc5600a3\
             2ef5b52a1ecc820e308aa342721aac09\
             43bf6686b64b2579376504ccc493d97e\
             6aed3fb0f9cd71a43dd497f01f17c0e2\
             cb3797aa2a2f256656168e6c496afc5f\
             b93246f6b1116398a346f1a641f3b041\
             e989f7914f90cc2c7fff357876e506b5\
             0d334ba77c225bc307ba537152f3f161\
             0e4eafe595f6d9d90d11faa933a15ef1\
             369546868a7f3a45a96768d40fd9d034\
             12c091c6315cf4fde7cb68606937380d\
             b2eaaa707b4c4185c32eddcdd306705e\
             4dc1ffc872eeee475a64dfac86aba41c\
             0618983f8741c5ef68d3a101e8a3b8ca\
             c60c905c15fc910840b94c00a0b9d0",
            "0aab4c900501b3e24d7cdf4663326a3a\
             87df5e4843b2cbdb67cbf6e460fec350\
             aa5371b1508f9f4528ecea23c436d94b\
             5e8fcd4f681e30a6ac00a9704a188a03",
        ),
        (
            "833fe62409237b9d62ec77587520911e\
             9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034\
             c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae204131\
             12e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd\
             454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00\
             201009a3efbf3ecb69bea2186c26b589\
             09351fc9ac90b3ecfdfbc7c66431e030\
             3dca179c138ac17ad9bef1177331a704",
        ),
    ];

    #[test]
    fn rfc8032_vectors() {
        let mut msg_buf = [0u8; 1024];
        for (sk, pk, msg, sig) in VECTORS {
            let secret = unhex32(sk);
            let expected_public = unhex32(pk);
            let message = unhex(msg, &mut msg_buf);
            let expected_sig = unhex64(sig);

            assert_eq!(public_key(&secret), Ok(expected_public));
            let signature = sign(&secret, message).unwrap();
            assert_eq!(signature, expected_sig);
            assert_eq!(verify(&expected_public, message, &signature), Ok(()),);
        }
    }

    #[test]
    fn rejects_tampering() {
        let (sk, pk, _, _) = VECTORS[2];
        let secret = unhex32(sk);
        let public = unhex32(pk);
        let message = *b"af82 is not this message";
        let signature = sign(&secret, &message).unwrap();
        assert_eq!(verify(&public, &message, &signature), Ok(()));

        let mut wrong = message;
        wrong[0] ^= 1;
        assert_eq!(
            verify(&public, &wrong, &signature),
            Err(Error::InvalidSignature),
        );

        for byte in [0, 31, 32, 63] {
            let mut bad = signature;
            bad[byte] ^= 1;
            assert_eq!(
                verify(&public, &message, &bad),
                Err(Error::InvalidSignature),
            );
        }
    }

    /// Adding the group order to s gives the classic malleated twin,
    /// which RFC 8032's range check refuses.
    #[test]
    fn rejects_high_s() {
        let (sk, pk, msg, _) = VECTORS[1];
        let secret = unhex32(sk);
        let public = unhex32(pk);
        let mut msg_buf = [0u8; 4];
        let message = unhex(msg, &mut msg_buf);
        let mut signature = sign(&secret, message).unwrap();
        let l_bytes = {
            let mut out = [0u8; 32];
            for (chunk, word) in out.chunks_exact_mut(8).zip(L) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            out
        };
        let mut carry = 0u16;
        for i in 0..32 {
            let v =
                u16::from(signature[32 + i]) + u16::from(l_bytes[i]) + carry;
            signature[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "s + l still fits 32 bytes");
        assert_eq!(
            verify(&public, message, &signature),
            Err(Error::InvalidSignature),
        );
    }

    #[test]
    fn rejects_undecodable_public_key() {
        let (_, _, _, sig) = VECTORS[0];
        let signature = unhex64(sig);
        // y = 2^255 - 1 is not below the prime.
        let mut public = [0xffu8; 32];
        public[31] = 0x7f;
        assert_eq!(
            verify(&public, b"", &signature),
            Err(Error::InvalidPublicKey),
        );
    }

    /// The scalar field's corners: reduction of the wide hash, and
    /// the boundary of the order check.
    #[test]
    fn scalar_arithmetic_corners() {
        // l itself is not below l; l - 1 is.
        let mut l_bytes = [0u8; 32];
        for (chunk, word) in l_bytes.chunks_exact_mut(8).zip(L) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        assert!(!Scalar::is_below_order(&l_bytes));
        let mut l_minus_1 = l_bytes;
        l_minus_1[0] -= 1;
        assert!(Scalar::is_below_order(&l_minus_1));

        // l reduces to zero, and l - 1 stays put.
        assert_eq!(Scalar::from_bytes_reduced(&l_bytes).to_bytes(), [0u8; 32],);
        assert_eq!(
            Scalar::from_bytes_reduced(&l_minus_1).to_bytes(),
            l_minus_1,
        );

        // (l - 1) * (l - 1) = 1 mod l, since l - 1 = -1.
        let minus_one = Scalar::from_bytes_reduced(&l_minus_1);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(minus_one.mulmod(&minus_one).to_bytes(), one);
        // And -1 + 1 = 0.
        let unit = Scalar::from_bytes_reduced(&one);
        assert_eq!(minus_one.addmod(&unit).to_bytes(), [0u8; 32]);
    }

    /// Compression inverts decompression on the base point, and
    /// scalar multiplication by the order gives the identity.
    #[test]
    fn point_roundtrip_and_order() {
        let encoded = Point::BASE.compress();
        let decoded = Point::decompress(&encoded).unwrap();
        assert_eq!(decoded.compress(), encoded);

        let mut one = [0u8; 32];
        one[0] = 1;
        let unit = Scalar::from_bytes_reduced(&one);
        let same = Point::BASE.scalar_mul(&unit);
        assert_eq!(same.compress(), encoded);

        // l * B is the identity, whose encoding is y = 1.
        let zero = Scalar([0; 4]);
        let identity = Point::BASE.scalar_mul(&zero);
        assert_eq!(identity.compress(), Point::IDENTITY.compress());
    }
}
