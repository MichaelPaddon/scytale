//! X25519 (RFC 7748): Diffie-Hellman over Curve25519.
//!
//! Each party multiplies the curve's base point by a secret scalar
//! to make a public key, then multiplies the other's public key by
//! the same scalar. Both arrive at the same point, and its
//! u-coordinate is the shared secret. Recovering a scalar from a
//! public key is the elliptic curve discrete logarithm problem,
//! which is what the construction rests on.
//!
//! The shared secret is a curve point, not a uniform string: feed it
//! to [`hkdf`](crate::kdf::hkdf) to make keys, never use it as one.
//!
//! # Constant time
//!
//! The scalar multiplication is a Montgomery ladder: the same two
//! field operations sequence for every scalar, with the working
//! values exchanged by a masked swap rather than a branch. Field
//! arithmetic is plain limb multiplication with no table lookups.
//!
//! # Low-order public keys
//!
//! A handful of points on the curve generate tiny subgroups, and a
//! peer who sends one learns nothing but forces the shared secret to
//! a value anyone can compute. [`shared_secret`] refuses them, which
//! is the check RFC 7748 section 6.1 asks for. The raw [`x25519`]
//! function performs no such check, because the protocols that need
//! the unchecked function say so explicitly.

use zeroize::Zeroize;

use crate::Error;

/// The length of a secret key, a public key, and the shared secret.
pub const KEY_SIZE: usize = 32;

/// The u-coordinate of the base point: 9.
const BASE_POINT: [u8; KEY_SIZE] = {
    let mut u = [0u8; KEY_SIZE];
    u[0] = 9;
    u
};

/// The public key belonging to `secret`.
///
/// Any 32 bytes are a valid secret key; take them from
/// [`random`](crate::random). The bits that clamping fixes are fixed
/// here, so unclamped and clamped forms of a secret name the same
/// public key.
pub fn public_key(secret: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    x25519(secret, &BASE_POINT)
}

/// The secret shared between `secret` and a peer's `public` key.
///
/// Fails with [`Error::InvalidPublicKey`] when `public` is a
/// low-order point, whose shared secret anyone can compute.
pub fn shared_secret(
    secret: &[u8; KEY_SIZE],
    public: &[u8; KEY_SIZE],
) -> Result<[u8; KEY_SIZE], Error> {
    let mut shared = x25519(secret, public);
    // All low-order points, and only those, land on zero. The check
    // runs over every byte whatever their values.
    let mut acc = 0u8;
    for byte in shared {
        acc |= byte;
    }
    if acc == 0 {
        shared.zeroize();
        return Err(Error::InvalidPublicKey);
    }
    Ok(shared)
}

/// The X25519 function of RFC 7748 section 5: the scalar `k` times
/// the point whose u-coordinate is `u`.
///
/// [`public_key`] and [`shared_secret`] are this function applied to
/// the base point and to a peer's key; reach for this form only when
/// a protocol asks for it by name.
pub fn x25519(k: &[u8; KEY_SIZE], u: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    // Clamping clears the cofactor bits, so the multiple lands in
    // the prime-order subgroup, and fixes the top bit, so every
    // scalar takes the same ladder length.
    let mut k = *k;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;

    // One ladder step per scalar bit, high to low. Rather than
    // swapping unconditionally and undoing it, each iteration swaps
    // only when this bit differs from the last, which the running
    // `swap` tracks.
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let bit = u64::from((k[t >> 3] >> (t & 7)) & 1);
        swap ^= bit;
        Fe::cswap(swap, &mut x2, &mut x3);
        Fe::cswap(swap, &mut z2, &mut z3);
        swap = bit;

        // The combined double-and-add of RFC 7748 section 5.
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_small(121665)));
    }
    Fe::cswap(swap, &mut x2, &mut x3);
    Fe::cswap(swap, &mut z2, &mut z3);

    let out = x2.mul(&z2.invert()).to_bytes();

    // The named intermediates hold functions of the secret. `Fe` is
    // `Copy`, so the compiler may have spilled other copies; wiping
    // these is the best that can be done without owning the frame.
    k.zeroize();
    x2.0.zeroize();
    z2.0.zeroize();
    x3.0.zeroize();
    z3.0.zeroize();
    out
}

/// A 51-bit limb's worth of ones.
const MASK51: u64 = (1 << 51) - 1;

/// An element of the field of 2^255 - 19 elements, as five limbs of
/// 51 bits, least significant first.
///
/// Limbs are allowed to grow a little past 51 bits between
/// reductions: an addition's output, at worst 53 bits per limb, is
/// still a safe multiplication input, because the largest product
/// sum is five terms of 19 * 2^53 * 2^53, well inside a `u128`.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Reads 32 little-endian bytes. The top bit is ignored, as RFC
    /// 7748 section 5 requires; values up to 2^255 - 1 are accepted
    /// and reduced by the arithmetic that follows.
    fn from_bytes(bytes: &[u8; 32]) -> Fe {
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
    fn to_bytes(self) -> [u8; 32] {
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

    fn add(&self, other: &Fe) -> Fe {
        let mut sum = [0u64; 5];
        for (s, (a, b)) in sum.iter_mut().zip(self.0.iter().zip(other.0)) {
            *s = a + b;
        }
        Fe(sum)
    }

    /// `self - other`, computed as `self + 2p - other` so no limb
    /// underflows whatever the operands.
    fn sub(&self, other: &Fe) -> Fe {
        // Twice the prime, limb by limb: 2^52 - 38, then 2^52 - 2.
        const TWO_P: [u64; 5] = [
            0xFFFFFFFFFFFDA,
            0xFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFE,
        ];
        let mut diff = [0u64; 5];
        for i in 0..5 {
            diff[i] = self.0[i] + TWO_P[i] - other.0[i];
        }
        Fe(diff)
    }

    fn mul(&self, other: &Fe) -> Fe {
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

    /// Multiplication by a small constant; the ladder needs 121665.
    fn mul_small(&self, n: u32) -> Fe {
        let n = u128::from(n);
        let mut t = [0u128; 5];
        for (t, limb) in t.iter_mut().zip(self.0) {
            *t = u128::from(limb) * n;
        }
        Fe::reduce(t)
    }

    fn square(&self) -> Fe {
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
    fn pow2k(&self, k: u32) -> Fe {
        let mut x = *self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }

    /// The multiplicative inverse, as the power p - 2. A fixed
    /// exponent, so a fixed sequence of operations: eleven
    /// multiplications and 254 squarings, whatever the value.
    fn invert(&self) -> Fe {
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
        let z_250_0 = z_200_0.pow2k(50).mul(&z_50_0);
        // p - 2 ends in 0b01011: two zeros into the run, then 11.
        z_250_0.pow2k(5).mul(&z11)
    }

    /// Exchanges `a` and `b` when `condition` is one, by arithmetic
    /// on a mask rather than a branch.
    fn cswap(condition: u64, a: &mut Fe, b: &mut Fe) {
        debug_assert!(condition <= 1);
        let mask = condition.wrapping_neg();
        for (a, b) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let x = (*a ^ *b) & mask;
            *a ^= x;
            *b ^= x;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes the RFC's lowercase hex into bytes.
    fn unhex(hex: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        bytes
    }

    /// RFC 7748 section 5.2, both one-shot vectors.
    #[test]
    fn rfc7748_function_vectors() {
        let k = unhex(
            "a546e36bf0527c9d3b16154b82465edd\
             62144c0ac1fc5a18506a2244ba449ac4",
        );
        let u = unhex(
            "e6db6867583030db3594c1a424b15f7c\
             726624ec26b3353b10a903a6d0ab1c4c",
        );
        let out = unhex(
            "c3da55379de9c6908e94ea4df28d084f\
             32eccf03491c71f754b4075577a28552",
        );
        assert_eq!(x25519(&k, &u), out);

        let k = unhex(
            "4b66e9d4d1b4673c5ad22691957d6af5\
             c11b6421e0ea01d42ca4169e7918ba0d",
        );
        let u = unhex(
            "e5210f12786811d3f4b7959d0538ae2c\
             31dbe7106fc03c3efc4cd549c715a493",
        );
        let out = unhex(
            "95cbde9476e8907d7aade45cb4b873f8\
             8b595a68799fa152e6f8f7647aac7957",
        );
        assert_eq!(x25519(&k, &u), out);
    }

    /// RFC 7748 section 5.2: the function iterated, each output
    /// becoming the next scalar and the old scalar the next point.
    /// One check after the first call, one after a thousand; the
    /// million-call value is in the RFC but takes minutes.
    #[test]
    fn rfc7748_iterated() {
        let mut k = BASE_POINT;
        let mut u = BASE_POINT;
        for i in 1..=1000 {
            let out = x25519(&k, &u);
            u = k;
            k = out;
            if i == 1 {
                let one = unhex(
                    "422c8e7a6227d7bca1350b3e2bb7279f\
                     7897b87bb6854b783c60e80311ae3079",
                );
                assert_eq!(k, one);
            }
        }
        let thousand = unhex(
            "684cf59ba83309552800ef566f2f4d3c\
             1c3887c49360e3875f2eb94d99532c51",
        );
        assert_eq!(k, thousand);
    }

    /// RFC 7748 section 6.1: the worked Diffie-Hellman exchange.
    #[test]
    fn rfc7748_diffie_hellman() {
        let alice_secret = unhex(
            "77076d0a7318a57d3c16c17251b26645\
             df4c2f87ebc0992ab177fba51db92c2a",
        );
        let bob_secret = unhex(
            "5dab087e624a8a4b79e17f8b83800ee6\
             6f3bb1292618b6fd1c2f8b27ff88e0eb",
        );
        let alice_public = unhex(
            "8520f0098930a754748b7ddcb43ef75a\
             0dbf3a0d26381af4eba4a98eaa9b4e6a",
        );
        let bob_public = unhex(
            "de9edb7d7b7dc1b4d35b61c2ece43537\
             3f8343c85b78674dadfc7e146f882b4f",
        );
        assert_eq!(public_key(&alice_secret), alice_public);
        assert_eq!(public_key(&bob_secret), bob_public);

        let shared = unhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25\
             e07e21c947d19e3376f09b3c1e161742",
        );
        let alice_view = shared_secret(&alice_secret, &bob_public);
        let bob_view = shared_secret(&bob_secret, &alice_public);
        assert_eq!(alice_view, Ok(shared));
        assert_eq!(bob_view, Ok(shared));
    }

    /// Low-order points force a zero shared secret, and are refused.
    /// Zero and one are the low-order points with small
    /// u-coordinates; any secret hits the same subgroup.
    #[test]
    fn refuses_low_order_public_keys() {
        let secret = unhex(
            "77076d0a7318a57d3c16c17251b26645\
             df4c2f87ebc0992ab177fba51db92c2a",
        );
        for low in [0u8, 1] {
            let mut public = [0u8; 32];
            public[0] = low;
            assert_eq!(
                shared_secret(&secret, &public),
                Err(Error::InvalidPublicKey),
            );
        }
    }

    /// The top bit of a peer's coordinate is ignored, as section 5
    /// requires, so a key with it set agrees with the key without.
    #[test]
    fn masks_the_high_bit_of_u() {
        let k = unhex(
            "4b66e9d4d1b4673c5ad22691957d6af5\
             c11b6421e0ea01d42ca4169e7918ba0d",
        );
        let mut u = unhex(
            "e5210f12786811d3f4b7959d0538ae2c\
             31dbe7106fc03c3efc4cd549c715a493",
        );
        let plain = x25519(&k, &u);
        u[31] |= 0x80;
        assert_eq!(x25519(&k, &u), plain);
    }

    /// A non-canonical coordinate (the prime plus two, which is the
    /// point at u = 2 spelled a second way) reads the same as its
    /// reduced form.
    #[test]
    fn reduces_non_canonical_u() {
        let k = unhex(
            "a546e36bf0527c9d3b16154b82465edd\
             62144c0ac1fc5a18506a2244ba449ac4",
        );
        let mut canonical = [0u8; 32];
        canonical[0] = 2;
        // p + 2 = 2^255 - 17, little-endian.
        let mut wrapped = [0xffu8; 32];
        wrapped[0] = 0xef;
        wrapped[31] = 0x7f;
        assert_eq!(x25519(&k, &wrapped), x25519(&k, &canonical));
    }

    /// Clamping happens inside, so a pre-clamped secret and its raw
    /// form name the same public key.
    #[test]
    fn clamps_the_scalar() {
        let raw = [0xffu8; 32];
        let mut clamped = raw;
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        assert_eq!(public_key(&raw), public_key(&clamped));
    }
}
