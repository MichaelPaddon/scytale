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
//! Keys are 32 bytes each way. [`PrivateKey`] and [`PublicKey`] are
//! the pair to reach for: the secret is held in a [`Key`], so it is
//! wiped when it goes out of scope, and each carries the RFC 8410
//! encodings the rest of the world stores keys in. The free functions
//! below take the bare bytes, for code that already has them.
//!
//! ```
//! use scytale::Key;
//! use scytale::kex::x25519::PrivateKey;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let alice = PrivateKey::new(&Key::from([0x11u8; 32]));
//! let bob = PrivateKey::new(&Key::from([0x22u8; 32]));
//!
//! let ours = alice.shared_secret(bob.public_key())?;
//! let theirs = bob.shared_secret(alice.public_key())?;
//! assert_eq!(ours, theirs);
//! # Ok(())
//! # }
//! ```
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

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use crate::der;
use crate::math::fe25519::Fe;
use crate::{Key, Random};

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
    x2.zeroize();
    z2.zeroize();
    x3.zeroize();
    z3.zeroize();
    out
}

/// The length of a secret key's DER encoding, a PKCS#8
/// `PrivateKeyInfo` (RFC 8410 section 7).
pub const DER_SIZE: usize = 48;

/// The length of a public key's DER encoding, a
/// `SubjectPublicKeyInfo` (RFC 8410 section 4).
pub const PUBLIC_KEY_DER_SIZE: usize = 44;

/// The length of a secret key's PEM encoding, a `PRIVATE KEY` block.
pub const PEM_SIZE: usize = 119;

/// The length of a public key's PEM encoding, a `PUBLIC KEY` block.
pub const PUBLIC_KEY_PEM_SIZE: usize = 113;

/// A secret key from its DER PKCS#8 `PrivateKeyInfo`, the form under
/// `PRIVATE KEY` in a PEM file, which RFC 8410 fixes for X25519: the
/// 32 bytes in an OCTET STRING of their own inside the one PKCS#8
/// provides. A version 1 structure that also carries the public key
/// is read, and refused when that key is not the secret's, since a
/// pair that disagrees has been corrupted. Anything else that is not
/// this structure under `id-X25519`, the other curve's key
/// included, is [`Error::InvalidEncoding`].
pub fn secret_from_der(der: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    let (secret, carried) = der::curve_secret_from_der(&der::X25519, der)?;
    checked(secret, carried)
}

/// The secret a structure carried, once the public key it may
/// have carried beside it is checked to be the secret's own: a pair
/// that disagrees has been corrupted, and neither half is returned.
fn checked(
    mut secret: [u8; KEY_SIZE],
    carried: Option<[u8; KEY_SIZE]>,
) -> Result<[u8; KEY_SIZE], Error> {
    if let Some(carried) = carried
        && carried != public_key(&secret)
    {
        secret.zeroize();
        return Err(Error::InvalidEncoding);
    }
    Ok(secret)
}

/// The secret key's DER encoding, a version 0 `PrivateKeyInfo`. The
/// output is a secret, to be wiped when done.
pub fn secret_der(secret: &[u8; KEY_SIZE]) -> [u8; DER_SIZE] {
    der::curve_secret_der(&der::X25519, secret)
}

/// A public key from its DER `SubjectPublicKeyInfo`, the form under
/// `PUBLIC KEY`. The bytes are not checked to be a point here, any
/// more than the argument type of the functions that take them
/// checks; those refuse one that is not.
pub fn public_key_from_der(der: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    der::curve_public_from_der(&der::X25519, der)
}

/// The public key's DER encoding.
pub fn public_key_der(public: &[u8; KEY_SIZE]) -> [u8; PUBLIC_KEY_DER_SIZE] {
    der::curve_public_der(&der::X25519, public)
}

/// A secret key from a `PRIVATE KEY` PEM block (RFC 7468) around
/// [`secret_der`]'s bytes. Whitespace and line ends are read
/// leniently; anything else that is not exactly one well-formed
/// block, an encrypted key included, is [`Error::InvalidEncoding`].
pub fn secret_from_pem(pem: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    let (secret, carried) = der::curve_secret_from_pem(&der::X25519, pem)?;
    checked(secret, carried)
}

/// The secret key as a `PRIVATE KEY` PEM block: ASCII with LF line
/// ends, always [`PEM_SIZE`] bytes. A secret, to be wiped when done.
pub fn secret_pem(secret: &[u8; KEY_SIZE]) -> [u8; PEM_SIZE] {
    der::curve_secret_pem(&der::X25519, secret)
}

/// A public key from a `PUBLIC KEY` PEM block, read as
/// [`secret_from_pem`] reads its block.
pub fn public_key_from_pem(pem: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    der::curve_public_from_pem(&der::X25519, pem)
}

/// The public key as a `PUBLIC KEY` PEM block, always
/// [`PUBLIC_KEY_PEM_SIZE`] bytes.
pub fn public_key_pem(public: &[u8; KEY_SIZE]) -> [u8; PUBLIC_KEY_PEM_SIZE] {
    der::curve_public_pem(&der::X25519, public)
}

/// The length of a key pair's DER encoding, a version 1
/// `PrivateKeyInfo` carrying the public key beside the secret.
pub const PAIR_DER_SIZE: usize = der::CURVE_PAIR_DER;

/// The length of a key pair's PEM encoding, a `PRIVATE KEY` block.
pub const PAIR_PEM_SIZE: usize = der::CURVE_PAIR_PEM;

/// One side's secret key, and the public key that goes with it.
///
/// The secret is held in a [`Key`], so it is wiped when the key goes
/// out of scope; the free functions above take the bare bytes for
/// code that has them already.
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    secret: Key<[u8; KEY_SIZE]>,
    #[zeroize(skip)]
    public: PublicKey,
}

/// The other side's public key: a u-coordinate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; KEY_SIZE],
}

impl fmt::Debug for PrivateKey {
    /// Deliberately omits the secret; the public key is not one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey").finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// A key drawn from `rng`. Any 32 bytes are a secret key.
    pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
        let mut secret = Key::zeroed();
        rng.fill(secret.as_mut())?;
        Ok(Self::new(&secret))
    }

    /// The key `secret` is.
    pub fn new(secret: &Key<[u8; KEY_SIZE]>) -> Self {
        let public = PublicKey {
            bytes: public_key(secret.array()),
        };
        PrivateKey {
            secret: secret.clone(),
            public,
        }
    }

    /// The secret, to store or to hand to code that wants the bytes.
    pub fn secret_bytes(&self) -> [u8; KEY_SIZE] {
        *self.secret.array()
    }

    /// The public key, derived when this key was built.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The secret shared with `public`, as [`shared_secret`]
    /// computes it and with the same refusal of a low-order point.
    pub fn shared_secret(
        &self,
        public: &PublicKey,
    ) -> Result<[u8; KEY_SIZE], Error> {
        shared_secret(self.secret.array(), &public.bytes)
    }

    /// A key from its DER `PrivateKeyInfo`, of either version; a
    /// version 1 structure's public key is checked against the
    /// secret's own, as [`secret_from_der`] describes.
    pub fn try_from_der(bytes: &[u8]) -> Result<Self, Error> {
        let mut secret = Key::from(secret_from_der(bytes)?);
        let key = Self::new(&secret);
        secret.zeroize();
        Ok(key)
    }

    /// The key pair as a version 1 `PrivateKeyInfo`, which carries
    /// the public key beside the secret. The output is a secret, to
    /// be wiped when done.
    ///
    /// [`secret_der`] writes the version 0 form, which is what
    /// OpenSSL emits; this one is what readers that require the
    /// public key accept.
    pub fn der_bytes(&self) -> [u8; PAIR_DER_SIZE] {
        der::curve_pair_der(
            &der::X25519,
            self.secret.array(),
            &self.public.bytes,
        )
    }

    /// A key from a `PRIVATE KEY` PEM block, read as
    /// [`secret_from_pem`] reads one.
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        let mut secret = Key::from(secret_from_pem(pem)?);
        let key = Self::new(&secret);
        secret.zeroize();
        Ok(key)
    }

    /// The key pair as a `PRIVATE KEY` PEM block around
    /// [`der_bytes`](Self::der_bytes). A secret, to be wiped when
    /// done.
    pub fn pem_bytes(&self) -> [u8; PAIR_PEM_SIZE] {
        der::curve_pair_pem(
            &der::X25519,
            self.secret.array(),
            &self.public.bytes,
        )
    }
}

impl PublicKey {
    /// The key those bytes are. Every 32 bytes name a u-coordinate;
    /// the ones that are useless are refused where they are used, by
    /// [`PrivateKey::shared_secret`].
    pub fn new(bytes: &[u8; KEY_SIZE]) -> Self {
        PublicKey { bytes: *bytes }
    }

    /// The u-coordinate.
    pub fn bytes(&self) -> [u8; KEY_SIZE] {
        self.bytes
    }

    /// A key from its DER `SubjectPublicKeyInfo`.
    pub fn try_from_der(bytes: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            bytes: public_key_from_der(bytes)?,
        })
    }

    /// The key's `SubjectPublicKeyInfo`.
    pub fn der_bytes(&self) -> [u8; PUBLIC_KEY_DER_SIZE] {
        public_key_der(&self.bytes)
    }

    /// A key from a `PUBLIC KEY` PEM block.
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            bytes: public_key_from_pem(pem)?,
        })
    }

    /// The key as a `PUBLIC KEY` PEM block.
    pub fn pem_bytes(&self) -> [u8; PUBLIC_KEY_PEM_SIZE] {
        public_key_pem(&self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::{CtrDrbg, MIN_SEED};

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
    /// The key types are the free functions with the secret held in
    /// something that wipes itself, so they must agree at every step,
    /// and the pair encoding must read back as what it wrote.
    #[test]
    fn key_types_match_the_functions() {
        let alice = PrivateKey::new(&Key::from([0x11u8; KEY_SIZE]));
        let bob = PrivateKey::new(&Key::from([0x22u8; KEY_SIZE]));
        assert_eq!(alice.public_key().bytes(), public_key(&[0x11; KEY_SIZE]));

        // Both sides reach the same secret, which is what the free
        // functions reach too.
        let one = alice.shared_secret(bob.public_key()).expect("shared");
        let two = bob.shared_secret(alice.public_key()).expect("shared");
        assert_eq!(one, two);
        assert_eq!(
            one,
            shared_secret(&[0x11; KEY_SIZE], &public_key(&[0x22; KEY_SIZE]))
                .unwrap()
        );

        // A low-order point is refused through the type as well.
        assert_eq!(
            alice.shared_secret(&PublicKey::new(&[0u8; KEY_SIZE])),
            Err(Error::InvalidPublicKey)
        );

        // The version 1 encoding carries the public key, and reading
        // it back checks the pair agrees.
        let der = alice.der_bytes();
        let read = PrivateKey::try_from_der(&der).expect("der");
        assert_eq!(read.secret_bytes(), alice.secret_bytes());
        assert_eq!(read.public_key(), alice.public_key());
        let pem = alice.pem_bytes();
        assert_eq!(
            PrivateKey::try_from_pem(&pem).unwrap().secret_bytes(),
            alice.secret_bytes()
        );

        // The version 0 form still reads, and is the shorter one.
        let short = secret_der(&alice.secret_bytes());
        assert!(short.len() < der.len());
        assert_eq!(
            PrivateKey::try_from_der(&short).unwrap().public_key(),
            alice.public_key()
        );

        // A public key round-trips through both encodings.
        let public = *alice.public_key();
        assert_eq!(
            PublicKey::try_from_der(&public.der_bytes()).unwrap(),
            public
        );
        assert_eq!(
            PublicKey::try_from_pem(&public.pem_bytes()).unwrap(),
            public
        );
    }

    /// A drawn key takes its whole secret from the source.
    #[test]
    fn generate_draws_the_secret() {
        let mut rng = CtrDrbg::from_seed(&[0x77u8; MIN_SEED]).expect("seed");
        let one = PrivateKey::generate(&mut rng).expect("one");
        let two = PrivateKey::generate(&mut rng).expect("two");
        assert_ne!(one.secret_bytes(), two.secret_bytes());
        assert_ne!(one.public_key(), two.public_key());
    }

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

    /// What OpenSSL 3.5 writes for a fresh key, from
    /// `openssl genpkey -algorithm X25519` and `openssl pkey`, with
    /// and without `-pubout`, in DER and PEM.
    #[test]
    fn openssl_encodings() {
        let secret = unhex(
            "78c179133120e7cb303d50493d8531b1\
             7b6f1b1ffb9fe5ed30c36fc30d6d2075",
        );
        let public = unhex(
            "4a98fc0bb6a135d01c8465380a18ff93\
             d9e5790bbef9f51d636167b95ce9bd27",
        );
        let mut secret_der_bytes = [0u8; DER_SIZE];
        secret_der_bytes[..16].copy_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x6e, 0x04, 0x22, 0x04, 0x20,
        ]);
        secret_der_bytes[16..].copy_from_slice(&secret);
        let mut public_der_bytes = [0u8; PUBLIC_KEY_DER_SIZE];
        public_der_bytes[..12].copy_from_slice(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21,
            0x00,
        ]);
        public_der_bytes[12..].copy_from_slice(&public);
        let secret_pem_text = b"-----BEGIN PRIVATE KEY-----\n\
            MC4CAQAwBQYDK2VuBCIEIHjBeRMxIOfLMD1QST2FMbF7bxsf+5/l7TDDb8MNbSB1\n\
            -----END PRIVATE KEY-----\n";
        let public_pem_text = b"-----BEGIN PUBLIC KEY-----\n\
            MCowBQYDK2VuAyEASpj8C7ahNdAchGU4Chj/k9nleQu++fUdY2FnuVzpvSc=\n\
            -----END PUBLIC KEY-----\n";

        assert_eq!(public_key(&secret), public);
        assert_eq!(secret_from_der(&secret_der_bytes), Ok(secret));
        assert_eq!(public_key_from_der(&public_der_bytes), Ok(public));
        assert_eq!(secret_der(&secret), secret_der_bytes);
        assert_eq!(public_key_der(&public), public_der_bytes);
        assert_eq!(secret_from_pem(secret_pem_text), Ok(secret));
        assert_eq!(public_key_from_pem(public_pem_text), Ok(public));
        assert_eq!(secret_pem(&secret)[..], secret_pem_text[..]);
        assert_eq!(public_key_pem(&public)[..], public_pem_text[..]);

        // An Ed25519 key is not an X25519 key.
        let mut e = secret_der_bytes;
        e[11] = 0x70;
        assert_eq!(secret_from_der(&e), Err(Error::InvalidEncoding));
        let mut e = public_der_bytes;
        e[8] = 0x70;
        assert_eq!(public_key_from_der(&e), Err(Error::InvalidEncoding));

        // A version 1 structure carrying the public key reads when
        // the pair agrees and is refused when it does not.
        let mut v1 = [0u8; 83];
        v1[..16].copy_from_slice(&[
            0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x6e, 0x04, 0x22, 0x04, 0x20,
        ]);
        v1[16..48].copy_from_slice(&secret);
        v1[48..51].copy_from_slice(&[0x81, 0x21, 0x00]);
        v1[51..].copy_from_slice(&public);
        assert_eq!(secret_from_der(&v1), Ok(secret));
        v1[82] ^= 1;
        assert_eq!(secret_from_der(&v1), Err(Error::InvalidEncoding));
    }
}
