//! RSA signatures (RFC 8017): PSS and PKCS#1 v1.5.
//!
//! A key is a modulus `n`, the product of two secret primes, with a
//! public exponent `e` and a private exponent `d` that undo one
//! another. Signing raises an encoding of the message's digest to
//! `d`; anyone can raise the signature back through `e` and compare.
//!
//! Two signature encodings are in use. PSS is the modern one, with a
//! security argument and a salt; PKCS#1 v1.5 is the fixed padding
//! that most deployed certificates still carry. Sign with PSS unless
//! a protocol demands otherwise; verify whichever the peer sends.
//!
//! The raw primitives under both,
//! [`sign_primitive`](PrivateKey::sign_primitive) and
//! [`verify_primitive`](PublicKey::verify_primitive), are public for
//! building an encoding this crate does not have and for the ACVP
//! component suites; they encode nothing and check nothing.
//!
//! The keys here only sign. RSA encryption is a different job with
//! its own keys, under [`pke::rsa`](crate::pke::rsa), and a key
//! should do one or the other: a key that both signs and decrypts
//! hands an attacker two oracles against the same secret, and the
//! proofs for either scheme assume it has the key to itself.
//!
//! # Keys are measured in bits
//!
//! A key's length is a value, not a type: [`PrivateKey::generate`]
//! takes the number of bits, any multiple of eight from [`MIN_BITS`]
//! to [`MAX_BITS`], and an imported key is whatever length its
//! modulus is. [`bits`](PublicKey::bits) says which, and
//! [`modulus_len`](PublicKey::modulus_len) is the same in bytes,
//! which is the length of every signature. A [`Signature`] carries
//! its own length, so nothing has to be sized by the caller.
//!
//! Keys are imported from their integer parts, or generated fresh,
//! which fixes the public exponent at 65537 and derives every
//! Chinese remainder piece; the accessors on both key types hand the
//! parts back for storage. Keys also read and write the formats
//! everything else stores them in: a public key as a DER
//! `SubjectPublicKeyInfo` and a private key as PKCS#8, through
//! [`try_from_der`] and [`der_bytes`] on each type, the bare PKCS#1
//! structures inside those through `try_from_pkcs1` and
//! `pkcs1_bytes`, and any of them in PEM through `try_from_pem` and
//! the `pem_bytes` pair. A signing key may be marked `rsaEncryption`
//! or `id-RSASSA-PSS` when it comes in, and goes out as the former.
//!
//! [`try_from_der`]: PrivateKey::try_from_der
//! [`der_bytes`]: PrivateKey::der_bytes
//!
//! # Memory the caller owns
//!
//! [`PublicKey`] and [`PrivateKey`] own their words, laid out for the
//! widest key, and keep the temporaries an operation needs on the
//! stack: about seven kilobytes for a key pair and twenty-four for a
//! signature, whatever the key's length. Where that is too much, or
//! the memory must come from somewhere particular, [`PublicKeyRef`]
//! and [`PrivateKeyRef`] are the same keys as views over a `[u64]`
//! the caller brings, sized by [`public_words`] or [`private_words`]
//! for the bits in hand, with a scratch slice of [`scratch_words`]
//! handed to each operation. The owned keys are those views with an
//! array behind them; the arithmetic is the same.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::random::CtrDrbg;
//! use scytale::sig::rsa::{PrivateKey, PublicKey};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let key = PrivateKey::generate(&mut rng, 2048)?;
//!
//! // PSS with a fresh salt of the digest's length.
//! let signature = key.sign_pss::<Sha256, _>(&mut rng, b"the message")?;
//! let public = key.public_key();
//! public.verify_pss::<Sha256>(b"the message", signature.as_ref())?;
//!
//! // The public half in the form a certificate or a peer expects.
//! let mut der = [0u8; 2 * 256];
//! let n = public.der_bytes(&mut der)?;
//! let public = PublicKey::try_from_der(&der[..n])?;
//! assert_eq!(public.bits(), 2048);
//! public.verify_pss::<Sha256>(b"the message", signature.as_ref())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! The private exponentiation is a fixed sequence of limb operations
//! whose reads never depend on `d` or the primes. Verification, and
//! the padding checks on both sides, handle only public values.
//! Generation is the one operation whose time varies with its
//! secrets: how many candidates fall to the primality tests depends
//! on the randomness drawn, as it does in every implementation.
//!
//! A key imported with its primes, through
//! [`PrivateKey::try_new_crt`], signs by the Chinese remainder
//! theorem: two half-length exponentiations in place of one full one,
//! roughly three times faster. Every CRT signature is checked with
//! the public exponent before release, because a wrong result there
//! is not merely wrong: one faulty CRT signature factors the modulus
//! (Boneh, DeMillo and Lipton), so nothing unchecked ever leaves.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use crate::Random;
use crate::hash::Hash;
use crate::math::rsa::{Private, Public, mgf1_xor};

pub use crate::math::rsa::{
    MAX_BITS, MIN_BITS, private_words, public_words, scratch_words,
};

/// The length of the widest signature, and of the buffer behind a
/// [`Signature`].
const MAX_LEN: usize = MAX_BITS / 8;

/// Words in an owned public key: enough for the widest.
const PUBLIC_WORDS: usize = public_words(MAX_BITS);

/// Words in an owned private key: enough for the widest.
const PRIVATE_WORDS: usize = private_words(MAX_BITS);

/// Scratch an owned key keeps on the stack for an operation.
const SCRATCH_WORDS: usize = scratch_words(MAX_BITS);

/// A hash that PKCS#1 v1.5 can name: one with a DER `DigestInfo`
/// prefix. All the SHA-2 and SHA-3 digests have one, under the one
/// NIST arc, and SHA-1 has its own for verifying what was signed
/// before it was withdrawn; PSS needs no such name and takes any
/// [`Hash`].
pub trait DigestInfo: Hash {
    /// The DER in front of the digest: two SEQUENCEs, the algorithm's
    /// OID, a NULL, and the OCTET STRING header.
    const PREFIX: &'static [u8];
}

/// The 19-byte prefix of a digest under 2.16.840.1.101.3.4.2.x.
macro_rules! nist_prefix {
    ($oid:literal, $len:literal) => {
        &[
            0x30,
            0x11 + $len,
            0x30,
            0x0d,
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            $oid,
            0x05,
            0x00,
            0x04,
            $len,
        ]
    };
}

macro_rules! digest_info {
    ($($hash:ty => $oid:literal, $len:literal;)*) => {
        $(impl DigestInfo for $hash {
            const PREFIX: &'static [u8] = nist_prefix!($oid, $len);
        })*
    };
}

digest_info! {
    crate::hash::sha2::Sha224 => 4, 28;
    crate::hash::sha2::Sha256 => 1, 32;
    crate::hash::sha2::Sha384 => 2, 48;
    crate::hash::sha2::Sha512 => 3, 64;
    crate::hash::sha2::Sha512_224 => 5, 28;
    crate::hash::sha2::Sha512_256 => 6, 32;
    crate::hash::sha3::Sha3_224 => 7, 28;
    crate::hash::sha3::Sha3_256 => 8, 32;
    crate::hash::sha3::Sha3_384 => 9, 48;
    crate::hash::sha3::Sha3_512 => 10, 64;
}

impl DigestInfo for crate::hash::sha1::Sha1 {
    // 1.3.14.3.2.26, under the old OIW arc.
    const PREFIX: &'static [u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
        0x00, 0x04, 0x14,
    ];
}

/// A signature, as long as the key's modulus.
///
/// Held by value so that nothing has to be sized by the caller; the
/// bytes are [`as_ref`](AsRef::as_ref), and go on the wire as they
/// are.
#[derive(Clone, Copy)]
pub struct Signature {
    bytes: [u8; MAX_LEN],
    len: usize,
}

impl Signature {
    fn zeroed(len: usize) -> Self {
        Signature {
            bytes: [0; MAX_LEN],
            len,
        }
    }

    /// The length in bytes, which is the key's
    /// [`modulus_len`](PublicKey::modulus_len).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Never: a signature is at least [`MIN_BITS`] / 8 bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for Signature {}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature").field("len", &self.len).finish()
    }
}

/// A verification key as a view over words the caller owns.
///
/// [`fill`](Self::fill) and the `fill_from_*` importers lay a key
/// out in a `[u64]` of at least [`public_words`] for its bits, and
/// [`new`](Self::new) is the view over it. Every operation takes a
/// scratch slice of at least [`scratch_words`] for the key's bits;
/// a shorter one is [`Error::ScratchTooSmall`] with the length
/// wanted. [`PublicKey`] is this with an array behind it.
#[derive(Clone, Copy)]
pub struct PublicKeyRef<'a> {
    raw: Public<'a>,
}

/// A signing key as a view over words the caller owns; see
/// [`PublicKeyRef`]. The words hold the private exponent and the
/// primes, and are the caller's to wipe; [`PrivateKey`] does so on
/// drop.
#[derive(Clone, Copy)]
pub struct PrivateKeyRef<'a> {
    raw: Private<'a>,
}

/// A verification key that owns its words.
///
/// Laid out for the widest key, [`MAX_BITS`], whatever its own
/// length; [`bits`](Self::bits) says which it is.
#[derive(Clone)]
pub struct PublicKey {
    words: [u64; PUBLIC_WORDS],
    bits: usize,
}

/// A signing key that owns its words, with the public half in front.
/// Every private part is wiped on drop.
#[derive(Clone)]
pub struct PrivateKey {
    words: [u64; PRIVATE_WORDS],
    bits: usize,
}

impl<'a> PublicKeyRef<'a> {
    /// Lays out a verification key from its big-endian parts in
    /// `storage`, returning the words it took.
    ///
    /// The modulus must be odd and, with its leading zeros dropped,
    /// between [`MIN_BITS`] and [`MAX_BITS`]; anything else is
    /// [`Error::InvalidKeyLength`] with the length found. The
    /// exponent must be odd, at least 3, and fit eight bytes, which
    /// every deployed key's does. A `storage` too short is
    /// [`Error::ScratchTooSmall`] with the words wanted.
    pub fn fill(
        n: &[u8],
        e: &[u8],
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        Public::fill(n, e, storage)
    }

    /// Lays out a key from its DER `SubjectPublicKeyInfo`, as
    /// [`PublicKey::try_from_der`] reads it.
    pub fn fill_from_der(
        der: &[u8],
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        Public::fill_from_spki(der, true, storage)
    }

    /// Lays out a key from the bare PKCS#1 `RSAPublicKey`, as
    /// [`PublicKey::try_from_pkcs1`] reads it.
    pub fn fill_from_pkcs1(
        der: &[u8],
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        Public::fill_from_pkcs1(der, storage)
    }

    /// Lays out a key from a PEM block, as
    /// [`PublicKey::try_from_pem`] reads it.
    pub fn fill_from_pem(
        pem: &[u8],
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        Public::fill_from_pem(pem, true, storage)
    }

    /// The view over words a `fill` laid out. Words that do not hold
    /// a key are [`Error::InvalidPublicKey`].
    pub fn new(storage: &'a [u64]) -> Result<Self, Error> {
        Ok(PublicKeyRef {
            raw: Public::new(storage)?,
        })
    }

    /// The modulus length in bits.
    pub fn bits(&self) -> usize {
        self.raw.bits()
    }

    /// The modulus length in bytes: the length of every signature.
    pub fn modulus_len(&self) -> usize {
        self.raw.modulus_len()
    }

    /// The verification primitive; see
    /// [`PublicKey::verify_primitive`]. `out` is the modulus length.
    pub fn verify_primitive(
        &self,
        signature: &[u8],
        out: &mut [u8],
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        if !self.raw.in_range(signature) || out.len() != self.modulus_len() {
            return Err(Error::InvalidSignature);
        }
        self.raw.apply(signature, out, scratch)
    }

    /// Checks a PKCS#1 v1.5 signature; see
    /// [`PublicKey::verify_pkcs1`].
    pub fn verify_pkcs1<H: DigestInfo + Default>(
        &self,
        message: &[u8],
        signature: &[u8],
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        let len = self.modulus_len();
        let mut em = [0u8; MAX_LEN];
        let mut expected = [0u8; MAX_LEN];
        self.verify_primitive(signature, &mut em[..len], scratch)?;
        encode_pkcs1::<H>(message, &mut expected[..len])?;
        if crate::constant_time::equal(&em[..len], &expected[..len]) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Checks a PSS signature made with a salt of the digest's
    /// length; see [`PublicKey::verify_pss`].
    pub fn verify_pss<H: Hash + Default>(
        &self,
        message: &[u8],
        signature: &[u8],
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        let salt_len = size_of::<H::Output>();
        self.verify_pss_with_salt_len::<H>(
            message, signature, salt_len, scratch,
        )
    }

    /// Checks a PSS signature made with a salt of `salt_len` bytes;
    /// see [`PublicKey::verify_pss_with_salt_len`].
    pub fn verify_pss_with_salt_len<H: Hash + Default>(
        &self,
        message: &[u8],
        signature: &[u8],
        salt_len: usize,
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        let len = self.modulus_len();
        let mut em = [0u8; MAX_LEN];
        let em = &mut em[..len];
        self.verify_primitive(signature, em, scratch)?;
        let h_len = size_of::<H::Output>();
        // The encoding is one bit narrower than the modulus (RFC
        // 8017 section 8.1.2), so it is `emBits` long and takes
        // `emLen` bytes. For a modulus of 8k + 1 bits that is a byte
        // fewer than the modulus takes: the integer's top byte is
        // then no part of the encoding and has to be zero, and the
        // mask is laid over what follows it, not over it.
        let em_bits = self.bits() - 1;
        let em_len = em_bits.div_ceil(8);
        let (lead, em) = em.split_at_mut(len - em_len);
        if lead.iter().any(|&b| b != 0) {
            return Err(Error::InvalidSignature);
        }
        // `salt_len` is the caller's and may be anything, so the sum
        // is checked: wrapped, it would pass this test and index
        // past the end below.
        let needed = salt_len
            .checked_add(h_len + 2)
            .ok_or(Error::InvalidSignature)?;
        if em_len < needed {
            return Err(Error::InvalidSignature);
        }
        // EM = maskedDB || H || 0xbc, with the bits above `emBits`
        // clear: none when it fills its bytes, up to seven when the
        // modulus does not fill its top one.
        let mask = 0xffu8 >> (8 * em_len - em_bits);
        if em[em_len - 1] != 0xbc || em[0] & !mask != 0 {
            return Err(Error::InvalidSignature);
        }
        let db_len = em_len - h_len - 1;
        let (masked_db, rest) = em.split_at_mut(db_len);
        let h = &rest[..h_len];

        let mut db = [0u8; MAX_LEN];
        let db = &mut db[..db_len];
        db.copy_from_slice(masked_db);
        mgf1_xor::<H>(h, db)?;
        db[0] &= mask;

        // DB = zeros || 0x01 || salt, with the salt exactly where
        // the fixed length puts it.
        let separator = db_len - salt_len - 1;
        if db[..separator].iter().any(|&b| b != 0) || db[separator] != 0x01 {
            return Err(Error::InvalidSignature);
        }
        let salt = &db[separator + 1..];

        let mut hasher = H::default();
        hasher.update(&[0u8; 8]);
        hasher.update(H::digest(message).as_ref());
        hasher.update(salt);
        if hasher.finalize().as_ref() == h {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// The modulus, big-endian, into the front of `out`; the length
    /// written, or [`Error::OutputTooSmall`] with the length needed.
    pub fn modulus_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        let len = self.modulus_len();
        let Some(out) = out.get_mut(..len) else {
            return Err(Error::OutputTooSmall(len));
        };
        self.raw.write_modulus(out);
        Ok(len)
    }

    /// The public exponent, big-endian in eight bytes.
    pub fn exponent_bytes(&self) -> [u8; 8] {
        self.raw.exponent_bytes()
    }

    /// The key as a `SubjectPublicKeyInfo`; see
    /// [`PublicKey::der_bytes`].
    pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.spki_bytes(out)
    }

    /// The bare `RSAPublicKey`; see [`PublicKey::pkcs1_bytes`].
    pub fn pkcs1_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pkcs1_bytes(out)
    }

    /// The key as a `PUBLIC KEY` PEM block; see
    /// [`PublicKey::pem_bytes`].
    pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pem_bytes(out, false)
    }

    /// The same as an `RSA PUBLIC KEY` block, around the PKCS#1 form.
    pub fn pkcs1_pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pem_bytes(out, true)
    }
}

impl<'a> PrivateKeyRef<'a> {
    /// Lays out a signing key from its big-endian parts in
    /// `storage`, returning the words it took; see
    /// [`PrivateKey::try_new`]. `storage` must hold
    /// [`private_words`] for the modulus's bits.
    pub fn fill(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        Private::fill(n, e, d, storage)
    }

    /// Lays out a signing key with its Chinese remainder pieces; see
    /// [`PrivateKey::try_new_crt`]. The checks on the pieces need
    /// `scratch`.
    #[allow(clippy::too_many_arguments)]
    pub fn fill_crt(
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
        Private::fill_crt(n, e, d, p, q, dp, dq, qinv, storage, scratch)
    }

    /// Lays out a key from its DER PKCS#8 `PrivateKeyInfo`, as
    /// [`PrivateKey::try_from_der`] reads it.
    pub fn fill_from_der(
        der: &[u8],
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        Private::fill_from_pkcs8(der, true, storage, scratch)
    }

    /// Lays out a key from the bare PKCS#1 `RSAPrivateKey`, as
    /// [`PrivateKey::try_from_pkcs1`] reads it.
    pub fn fill_from_pkcs1(
        der: &[u8],
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        Private::fill_from_pkcs1(der, storage, scratch)
    }

    /// Lays out a key from a PEM block, as
    /// [`PrivateKey::try_from_pem`] reads it.
    pub fn fill_from_pem(
        pem: &[u8],
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        Private::fill_from_pem(pem, true, storage, scratch)
    }

    /// Generates a fresh key of `bits` in `storage`, returning the
    /// words it took; see [`PrivateKey::generate`].
    pub fn generate<R: Random>(
        rng: &mut R,
        bits: usize,
        storage: &mut [u64],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        Private::generate(rng, bits, storage, scratch)
    }

    /// The view over words a `fill` laid out. Words that do not hold
    /// a key are [`Error::InvalidPrivateKey`].
    pub fn new(storage: &'a [u64]) -> Result<Self, Error> {
        Ok(PrivateKeyRef {
            raw: Private::new(storage)?,
        })
    }

    /// The public half, as a view over the front of the same words.
    pub fn public_key(&self) -> PublicKeyRef<'a> {
        PublicKeyRef {
            raw: self.raw.public(),
        }
    }

    /// The modulus length in bits.
    pub fn bits(&self) -> usize {
        self.raw.public().bits()
    }

    /// The modulus length in bytes: the length of every signature.
    pub fn modulus_len(&self) -> usize {
        self.raw.public().modulus_len()
    }

    /// The signature primitive; see [`PrivateKey::sign_primitive`].
    /// `message` and `out` are the modulus length.
    pub fn sign_primitive(
        &self,
        message: &[u8],
        out: &mut [u8],
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        // The scheme owns this check everywhere else; the primitive
        // has no scheme above it, so it makes the check itself.
        if !self.raw.public().in_range(message)
            || out.len() != self.modulus_len()
        {
            return Err(Error::MessageTooLong);
        }
        self.raw.apply(message, out, scratch)
    }

    /// Signs with PKCS#1 v1.5 padding; see [`PrivateKey::sign_pkcs1`].
    pub fn sign_pkcs1<H: DigestInfo + Default>(
        &self,
        message: &[u8],
        scratch: &mut [u64],
    ) -> Result<Signature, Error> {
        let len = self.modulus_len();
        let mut em = [0u8; MAX_LEN];
        encode_pkcs1::<H>(message, &mut em[..len])?;
        let mut signature = Signature::zeroed(len);
        self.raw.apply(&em[..len], signature.as_mut(), scratch)?;
        Ok(signature)
    }

    /// Signs with PSS and a fresh salt of the digest's length drawn
    /// from `rng`; see [`PrivateKey::sign_pss`].
    pub fn sign_pss<H: Hash + Default, R: Random>(
        &self,
        rng: &mut R,
        message: &[u8],
        scratch: &mut [u64],
    ) -> Result<Signature, Error> {
        // A digest is the only value of the salt's length generic
        // code can make; what it held is overwritten.
        let mut salt = H::digest(&[]);
        rng.fill(salt.as_mut())?;
        let signature =
            self.sign_pss_with_salt::<H>(message, salt.as_ref(), scratch);
        salt.as_mut().zeroize();
        signature
    }

    /// Signs with PSS and the given salt; see
    /// [`PrivateKey::sign_pss_with_salt`].
    pub fn sign_pss_with_salt<H: Hash + Default>(
        &self,
        message: &[u8],
        salt: &[u8],
        scratch: &mut [u64],
    ) -> Result<Signature, Error> {
        let len = self.modulus_len();
        let h_len = size_of::<H::Output>();
        // As in verification: `emBits` is one less than the modulus,
        // and for a modulus of 8k + 1 bits the encoding is a byte
        // shorter than the modulus, behind a zero byte.
        let em_bits = self.bits() - 1;
        let em_len = em_bits.div_ceil(8);
        if em_len < h_len + salt.len() + 2 {
            return Err(Error::InvalidLength(salt.len()));
        }
        let mut whole = [0u8; MAX_LEN];
        let whole = &mut whole[..len];
        let (_, em) = whole.split_at_mut(len - em_len);
        let db_len = em_len - h_len - 1;

        // H = hash(eight zeros || mHash || salt).
        let mut hasher = H::default();
        hasher.update(&[0u8; 8]);
        hasher.update(H::digest(message).as_ref());
        hasher.update(salt);
        let h = hasher.finalize();

        // DB = zeros || 0x01 || salt, masked by MGF1 of H.
        em[db_len - salt.len() - 1] = 0x01;
        em[db_len - salt.len()..db_len].copy_from_slice(salt);
        {
            let (db, _) = em.split_at_mut(db_len);
            mgf1_xor::<H>(h.as_ref(), db)?;
        }
        // The bits above `emBits` are cleared: none when it fills
        // its bytes, up to seven when it does not.
        em[0] &= 0xffu8 >> (8 * em_len - em_bits);
        em[db_len..em_len - 1].copy_from_slice(h.as_ref());
        em[em_len - 1] = 0xbc;
        let mut signature = Signature::zeroed(len);
        self.raw.apply(whole, signature.as_mut(), scratch)?;
        Ok(signature)
    }

    /// The private exponent, big-endian, into the front of `out`;
    /// the length written, or [`Error::OutputTooSmall`] with the
    /// length needed. The caller holds a secret now, and should wipe
    /// it when done.
    pub fn d_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        let len = self.modulus_len();
        let Some(out) = out.get_mut(..len) else {
            return Err(Error::OutputTooSmall(len));
        };
        self.raw.write_d(out);
        Ok(len)
    }

    /// The length of a prime in bytes, which each Chinese remainder
    /// piece is written in.
    pub fn prime_len(&self) -> usize {
        self.raw.prime_len()
    }

    /// The Chinese remainder pieces; see [`PrivateKey::crt_bytes`].
    pub fn crt_bytes(
        &self,
        p: &mut [u8],
        q: &mut [u8],
        dp: &mut [u8],
        dq: &mut [u8],
        qinv: &mut [u8],
    ) -> Result<(), Error> {
        self.raw.crt_bytes(p, q, dp, dq, qinv)
    }

    /// The key as a PKCS#8 `PrivateKeyInfo`; see
    /// [`PrivateKey::der_bytes`].
    pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pkcs8_bytes(out)
    }

    /// The bare `RSAPrivateKey`; see [`PrivateKey::pkcs1_bytes`].
    pub fn pkcs1_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pkcs1_bytes(out)
    }

    /// The key as a `PRIVATE KEY` PEM block; see
    /// [`PrivateKey::pem_bytes`].
    pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pem_bytes(out, false)
    }

    /// The same as an `RSA PRIVATE KEY` block, around the PKCS#1
    /// form.
    pub fn pkcs1_pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pem_bytes(out, true)
    }
}

impl PublicKey {
    /// The key laid out by `fill` in a fresh array.
    fn filled(
        fill: impl FnOnce(&mut [u64]) -> Result<usize, Error>,
    ) -> Result<Self, Error> {
        let mut key = PublicKey {
            words: [0; PUBLIC_WORDS],
            bits: 0,
        };
        fill(&mut key.words)?;
        key.bits = Public::new(&key.words)?.bits();
        Ok(key)
    }

    /// The view the operations run through. The words were laid out
    /// by this type, so they hold a key of the bits it remembers.
    fn view(&self) -> PublicKeyRef<'_> {
        PublicKeyRef {
            raw: Public::over(&self.words, self.bits),
        }
    }

    /// A verification key from its big-endian parts.
    ///
    /// The modulus must be odd and, with its leading zeros dropped,
    /// between [`MIN_BITS`] and [`MAX_BITS`] bits; anything else is
    /// [`Error::InvalidKeyLength`] with the length found. Any length
    /// in that range is a key, a multiple of eight or not. The
    /// exponent must be odd, at least 3, and fit eight bytes, which
    /// every deployed key's does.
    pub fn try_new(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        Self::filled(|words| PublicKeyRef::fill(n, e, words))
    }

    /// A verification key from its DER `SubjectPublicKeyInfo` (RFC
    /// 5280), the form under `PUBLIC KEY` in a PEM file. The
    /// algorithm may be `rsaEncryption` or `id-RSASSA-PSS`; the
    /// parameters of the latter, which name a hash and a salt
    /// length, are not read, since those are chosen at each call
    /// here.
    ///
    /// The modulus is checked as [`try_new`](Self::try_new) checks
    /// it. Another algorithm's key is [`Error::WrongAlgorithm`], and
    /// anything else wrong with the bytes [`Error::InvalidEncoding`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        Self::filled(|words| PublicKeyRef::fill_from_der(der, words))
    }

    /// A verification key from the bare PKCS#1 `RSAPublicKey` (RFC
    /// 8017 A.1.1), the form under `RSA PUBLIC KEY`, which is what
    /// the `SubjectPublicKeyInfo` wraps.
    pub fn try_from_pkcs1(der: &[u8]) -> Result<Self, Error> {
        Self::filled(|words| PublicKeyRef::fill_from_pkcs1(der, words))
    }

    /// A verification key from a PEM block (RFC 7468) labelled
    /// `PUBLIC KEY` or `RSA PUBLIC KEY`, holding the matching DER
    /// form above. Whitespace and line ends are read leniently;
    /// anything else that is not exactly one well-formed block is
    /// [`Error::InvalidEncoding`].
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        Self::filled(|words| PublicKeyRef::fill_from_pem(pem, words))
    }

    /// The modulus length in bits.
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// The modulus length in bytes: the length of every signature.
    pub fn modulus_len(&self) -> usize {
        self.view().modulus_len()
    }

    /// The RSA verification primitive, RSAVP1 of RFC 8017: raises
    /// `signature` to the public exponent and writes the
    /// representative into `out`, both of the modulus length, with
    /// no padding removed and nothing checked.
    ///
    /// # This is not signature verification
    ///
    /// Raw RSA is malleable, and a representative recovered this way
    /// says nothing about who produced it until an encoding has been
    /// rebuilt and compared. Use [`verify_pkcs1`](Self::verify_pkcs1)
    /// or [`verify_pss`](Self::verify_pss) unless you are
    /// implementing a scheme those do not cover, or driving the
    /// component test suites that exercise the primitive on its own.
    ///
    /// Returns [`Error::InvalidSignature`] when the signature is at
    /// or above the modulus, or either buffer is not the modulus
    /// length, which is all the primitive refuses.
    pub fn verify_primitive(
        &self,
        signature: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut scratch = Scratch::new();
        self.view().verify_primitive(signature, out, &mut scratch.0)
    }

    /// Checks a PKCS#1 v1.5 signature over `message`.
    pub fn verify_pkcs1<H: DigestInfo + Default>(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let mut scratch = Scratch::new();
        self.view()
            .verify_pkcs1::<H>(message, signature, &mut scratch.0)
    }

    /// Checks a PSS signature over `message`, made with a salt of
    /// the digest's length, which is what [`sign_pss`] draws and
    /// what most protocols fix the length at.
    ///
    /// [`sign_pss`]: PrivateKey::sign_pss
    pub fn verify_pss<H: Hash + Default>(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let mut scratch = Scratch::new();
        self.view()
            .verify_pss::<H>(message, signature, &mut scratch.0)
    }

    /// Checks a PSS signature over `message`, made with a salt of
    /// `salt_len` bytes.
    ///
    /// The length is a parameter of the scheme, not of the
    /// signature: RFC 8017 verifies against a fixed value, and a
    /// verifier that accepts whatever length the padding claims
    /// lets a signature swap parameter sets.
    pub fn verify_pss_with_salt_len<H: Hash + Default>(
        &self,
        message: &[u8],
        signature: &[u8],
        salt_len: usize,
    ) -> Result<(), Error> {
        let mut scratch = Scratch::new();
        self.view().verify_pss_with_salt_len::<H>(
            message,
            signature,
            salt_len,
            &mut scratch.0,
        )
    }

    /// The modulus, big-endian, into the front of `out`; the length
    /// written, or [`Error::OutputTooSmall`] with the length needed.
    pub fn modulus_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.view().modulus_bytes(out)
    }

    /// The public exponent, big-endian in eight bytes.
    pub fn exponent_bytes(&self) -> [u8; 8] {
        self.view().exponent_bytes()
    }

    /// Writes the key as a `SubjectPublicKeyInfo` under
    /// `rsaEncryption` into the front of `out`, returning the
    /// length. Twice the modulus length always suffices; a buffer
    /// too small gets [`Error::OutputTooSmall`] with the exact need.
    pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.view().der_bytes(out)
    }

    /// Writes the bare `RSAPublicKey`, as [`der_bytes`](Self::der_bytes)
    /// does the wrapped one.
    pub fn pkcs1_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.view().pkcs1_bytes(out)
    }

    /// Writes the key as a `PUBLIC KEY` PEM block, ASCII with LF line
    /// ends, into the front of `out`, returning the length. Three
    /// times the modulus length always suffices.
    pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.view().pem_bytes(out)
    }

    /// The same as an `RSA PUBLIC KEY` block, around the PKCS#1 form.
    pub fn pkcs1_pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.view().pkcs1_pem_bytes(out)
    }
}

impl PrivateKey {
    /// The key laid out by `fill` in a fresh array, with the scratch
    /// the checks need.
    fn filled(
        fill: impl FnOnce(&mut [u64], &mut [u64]) -> Result<usize, Error>,
    ) -> Result<Self, Error> {
        let mut key = PrivateKey {
            words: [0; PRIVATE_WORDS],
            bits: 0,
        };
        let mut scratch = Scratch::new();
        fill(&mut key.words, &mut scratch.0)?;
        key.bits = Private::new(&key.words)?.public().bits();
        Ok(key)
    }

    /// The view the operations run through. The words were laid out
    /// by this type, so they hold a key of the bits it remembers.
    fn view(&self) -> PrivateKeyRef<'_> {
        PrivateKeyRef {
            raw: Private::over(&self.words, self.bits),
        }
    }

    /// A signing key from its big-endian parts: the public modulus
    /// and exponent, then the private exponent, which must be
    /// nonzero and below the modulus. Signing uses `d` directly; a
    /// key that carries its primes should come in through
    /// [`try_new_crt`](PrivateKey::try_new_crt) instead, which signs
    /// three times faster.
    pub fn try_new(n: &[u8], e: &[u8], d: &[u8]) -> Result<Self, Error> {
        Self::filled(|words, _| PrivateKeyRef::fill(n, e, d, words))
    }

    /// A signing key with its Chinese remainder pieces, in the order
    /// the PKCS#1 `RSAPrivateKey` structure carries them: `p` and
    /// `q`, each half the modulus's bits and within one bit of each
    /// other, the reduced exponents `dp` and `dq`, and `qinv`, the
    /// inverse of `q` modulo `p`.
    ///
    /// The pieces are checked against one another: the primes must
    /// multiply to the modulus and `qinv` must invert `q`. A wrong
    /// `dp` or `dq` cannot be caught here, and is caught instead by
    /// the check every CRT signature gets before it is released.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new_crt(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        p: &[u8],
        q: &[u8],
        dp: &[u8],
        dq: &[u8],
        qinv: &[u8],
    ) -> Result<Self, Error> {
        Self::filled(|words, scratch| {
            PrivateKeyRef::fill_crt(n, e, d, p, q, dp, dq, qinv, words, scratch)
        })
    }

    /// Generates a fresh signing key of `bits`, which must be a
    /// multiple of eight from [`MIN_BITS`] to [`MAX_BITS`], with the
    /// public exponent 65537 and every Chinese remainder piece in
    /// place. Anything else is [`Error::InvalidKeyLength`].
    ///
    /// The primes are random probable primes: trial division, then
    /// Miller-Rabin with random witnesses, with round counts read
    /// from FIPS 186-5 for random candidates of 1024 bits and up.
    /// 2048 bits is the least anyone should make a new key at;
    /// narrower ones are for interoperation and tests.
    pub fn generate<R: Random>(
        rng: &mut R,
        bits: usize,
    ) -> Result<Self, Error> {
        Self::filled(|words, scratch| {
            PrivateKeyRef::generate(rng, bits, words, scratch)
        })
    }

    /// A signing key from its DER PKCS#8 `PrivateKeyInfo` (RFC 5208;
    /// the RFC 5958 form with a public key attached reads too), the
    /// form under `PRIVATE KEY` in a PEM file. The algorithm may be
    /// `rsaEncryption` or `id-RSASSA-PSS`, as for
    /// [`PublicKey::try_from_der`].
    ///
    /// The `RSAPrivateKey` inside carries the primes, so the key
    /// comes in as if through [`try_new_crt`](Self::try_new_crt),
    /// with the same checks. Another algorithm's key is
    /// [`Error::WrongAlgorithm`], a multi-prime key
    /// [`Error::UnsupportedVersion`], and anything else wrong with
    /// the bytes [`Error::InvalidEncoding`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        Self::filled(|words, scratch| {
            PrivateKeyRef::fill_from_der(der, words, scratch)
        })
    }

    /// A signing key from the bare PKCS#1 `RSAPrivateKey` (RFC 8017
    /// A.1.2), the form under `RSA PRIVATE KEY`, which is what the
    /// `PrivateKeyInfo` wraps.
    pub fn try_from_pkcs1(der: &[u8]) -> Result<Self, Error> {
        Self::filled(|words, scratch| {
            PrivateKeyRef::fill_from_pkcs1(der, words, scratch)
        })
    }

    /// A signing key from a PEM block (RFC 7468) labelled `PRIVATE
    /// KEY` or `RSA PRIVATE KEY`, holding the matching DER form
    /// above. Whitespace and line ends are read leniently; anything
    /// else that is not exactly one well-formed block, an encrypted
    /// key included, is [`Error::InvalidEncoding`].
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        Self::filled(|words, scratch| {
            PrivateKeyRef::fill_from_pem(pem, words, scratch)
        })
    }

    /// The public half, as a key of its own.
    pub fn public_key(&self) -> PublicKey {
        let mut public = PublicKey {
            words: [0; PUBLIC_WORDS],
            bits: self.bits,
        };
        let used = public_words(self.bits);
        public.words[..used].copy_from_slice(&self.words[..used]);
        public
    }

    /// The modulus length in bits.
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// The modulus length in bytes: the length of every signature.
    pub fn modulus_len(&self) -> usize {
        self.view().modulus_len()
    }

    /// The RSA signature primitive, RSASP1 of RFC 8017: raises
    /// `message` to the private exponent, through the primes when
    /// the key carries them, into `out`, both of the modulus length,
    /// with no encoding applied.
    ///
    /// # This is not signing
    ///
    /// The input must already be a message representative that some
    /// scheme has built; handing raw data here produces something
    /// that is malleable and forgeable. Use
    /// [`sign_pss`](Self::sign_pss) or
    /// [`sign_pkcs1`](Self::sign_pkcs1) unless you are implementing a
    /// scheme those do not cover, or driving the component test
    /// suites that exercise the primitive on its own.
    ///
    /// Returns [`Error::MessageTooLong`] when the representative is
    /// at or above the modulus, or either buffer is not the modulus
    /// length. As everywhere else in the crate, a result computed
    /// through the primes is checked with the public exponent before
    /// it is returned.
    pub fn sign_primitive(
        &self,
        message: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut scratch = Scratch::new();
        self.view().sign_primitive(message, out, &mut scratch.0)
    }

    /// Signs `message` with PKCS#1 v1.5 padding.
    pub fn sign_pkcs1<H: DigestInfo + Default>(
        &self,
        message: &[u8],
    ) -> Result<Signature, Error> {
        let mut scratch = Scratch::new();
        self.view().sign_pkcs1::<H>(message, &mut scratch.0)
    }

    /// Signs `message` with PSS and a fresh salt of the digest's
    /// length, drawn from `rng`, which is what nearly every caller
    /// wants and what [`verify_pss`](PublicKey::verify_pss) expects.
    pub fn sign_pss<H: Hash + Default, R: Random>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Signature, Error> {
        let mut scratch = Scratch::new();
        self.view().sign_pss::<H, R>(rng, message, &mut scratch.0)
    }

    /// Signs `message` with PSS and the salt given: an empty one
    /// makes the signature deterministic, and a fixed one reproduces
    /// a known answer. It must leave room in the key's length for
    /// the digest and two framing bytes, or the call is
    /// [`Error::InvalidLength`] with the salt's length.
    pub fn sign_pss_with_salt<H: Hash + Default>(
        &self,
        message: &[u8],
        salt: &[u8],
    ) -> Result<Signature, Error> {
        let mut scratch = Scratch::new();
        self.view()
            .sign_pss_with_salt::<H>(message, salt, &mut scratch.0)
    }

    /// The private exponent, big-endian, into the front of `out`;
    /// the length written, or [`Error::OutputTooSmall`] with the
    /// length needed. The caller holds a secret now, and should wipe
    /// it when done.
    pub fn d_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.view().d_bytes(out)
    }

    /// The length of a prime in bytes, which each Chinese remainder
    /// piece is written in: half the modulus, rounded up.
    pub fn prime_len(&self) -> usize {
        self.view().prime_len()
    }

    /// Writes the Chinese remainder pieces, big-endian, into five
    /// buffers of [`prime_len`](Self::prime_len) bytes each. Fails
    /// with [`Error::InvalidPrivateKey`] on a key imported without
    /// them, and [`Error::InvalidLength`] on a buffer of the wrong
    /// size. The caller holds secrets now, and should wipe them when
    /// done.
    pub fn crt_bytes(
        &self,
        p: &mut [u8],
        q: &mut [u8],
        dp: &mut [u8],
        dq: &mut [u8],
        qinv: &mut [u8],
    ) -> Result<(), Error> {
        self.view().crt_bytes(p, q, dp, dq, qinv)
    }

    /// Writes the key as a `PrivateKeyInfo` under `rsaEncryption`
    /// into the front of `out`, returning the length. Five times the
    /// modulus length always suffices; a buffer too small gets
    /// [`Error::OutputTooSmall`] with the exact need.
    ///
    /// Fails with [`Error::InvalidPrivateKey`] on a key imported
    /// without its primes, as [`crt_bytes`](Self::crt_bytes) does:
    /// the structure has no place for their absence. The output is
    /// a secret, and the caller should wipe it when done.
    pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.view().der_bytes(out)
    }

    /// Writes the bare `RSAPrivateKey`, as [`der_bytes`](Self::der_bytes)
    /// does the wrapped one, with the same needs and the same
    /// refusal.
    pub fn pkcs1_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.view().pkcs1_bytes(out)
    }

    /// Writes the key as a `PRIVATE KEY` PEM block, ASCII with LF
    /// line ends, into the front of `out`, returning the length.
    /// Eight times the modulus length always suffices. The same
    /// refusal as [`der_bytes`](Self::der_bytes), and the same secret
    /// to wipe.
    pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.view().pem_bytes(out)
    }

    /// The same as an `RSA PRIVATE KEY` block, around the PKCS#1
    /// form.
    pub fn pkcs1_pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.view().pkcs1_pem_bytes(out)
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}

impl ZeroizeOnDrop for PrivateKey {}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("bits", &self.bits())
            .finish()
    }
}

impl fmt::Debug for PrivateKey {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("bits", &self.bits())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublicKeyRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeyRef")
            .field("bits", &self.bits())
            .finish()
    }
}

impl fmt::Debug for PrivateKeyRef<'_> {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyRef")
            .field("bits", &self.bits())
            .finish_non_exhaustive()
    }
}

/// The temporaries an owned key's operation uses, on the stack and
/// wiped when the operation is over.
struct Scratch([u64; SCRATCH_WORDS]);

impl Scratch {
    fn new() -> Self {
        Scratch([0; SCRATCH_WORDS])
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// EMSA-PKCS1-v1_5: `0x00 0x01 0xff.. 0x00 DigestInfo`, filling `em`
/// exactly.
fn encode_pkcs1<H: DigestInfo + Default>(
    message: &[u8],
    em: &mut [u8],
) -> Result<(), Error> {
    let len = em.len();
    let digest = H::digest(message);
    let t_len = H::PREFIX.len() + size_of::<H::Output>();
    if len < t_len + 11 {
        // The key is too narrow for this digest.
        return Err(Error::InvalidKeyLength(8 * len));
    }
    em[0] = 0x00;
    em[1] = 0x01;
    em[2..len - t_len - 1].fill(0xff);
    em[len - t_len - 1] = 0x00;
    em[len - t_len..len - size_of::<H::Output>()].copy_from_slice(H::PREFIX);
    em[len - size_of::<H::Output>()..].copy_from_slice(digest.as_ref());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::{Sha256, Sha384, Sha512};

    fn unhex<const N: usize>(hex: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(hex.len(), 2 * N);
        for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    const MSG: &[u8] = b"scytale rsa signature test message";

    /// A fixed 32-byte salt, matching the reference signatures.
    const SALT: &str =
        "65c7df7043958a926270dca4bf17f29c8ecb6e2a5dd08ecb331df85a5b4d501d";

    const N2048: &str = "\
         ba5d6c10c1d21779df565ebeba34c4e297f2d39e886edb20ff84f39522d62437\
         b8226ebbfd03aa28427c1105eb24f5aa823c25f8a34658a1e0717f0998b4f6f4\
         7eb7bb1d1747a3db256bea209b32a70f2ef5e72ef88caf8696fdb452d8abc583\
         87b0a34016c022947798efc51b2b90d4a1998ae3f267c2623f8fabc4bf7e431d\
         e3fdf8c4e3d0092ec4f921c89d0f099f36f483663a1709a88c97b60842782b11\
         c70bd6b5c22293fcef63ed6dca4bcf274255eb0d35eaf6ba1d3b6367bfeba4af\
         fdb0e35b15cead4e8f925e4809e25d603b2cec1c72c644ca7f5cb5083a75f147\
         0c9ea038935fcac5c5744156aaf70c8d771da6d2a5e802d571f07d95edfa9721";

    const D2048: &str = "\
         0e04ed162d9e6249b6b546974e669dd0f5e13c6e16915046a1321d28c0e01f05\
         5a02ad15d328ad6a2de62b59a8a0b522487dc1d57c62d454091040a0362e96cd\
         39a3149e519c0005824125f1a1fb237a0eec4ca1c9ecbb5f82883f42642e37c3\
         7737a07037c5e85406d32866496ef38c2b43e3a0d6215c0c0c0000c9e225db62\
         891cffdd88fb5121fa1d84d23852de08f44a5c2e09481cbd8d41935394b69cde\
         e6413781fc722d424bb9e52ed25d895a7f751c054ca38ef6c152be26f5186e60\
         fc800b54b7dc697c37a93effb601a46323670ad5f289c7894bb8df2a74bf271f\
         24c48d037f06551ed47ad41d60b258728397734a41c0e40b71aa60d790a6fd61";

    const V15_SHA256: &str = "\
         16ec653a7b69873aea0a15006b7fa90df5d6f1473cb5c2d0a10dda835d6cef86\
         7ee607ac3592c780ee780b48e6077559c80c36689baa6a23d7d3fed16a712de7\
         6defc4d3512b83ce1fb7d0c49fa22edc51636482604ee14431a1ea92c1df1be6\
         3ac508ed5e835a0f8c132ac4553e208a5d14922853a89ed582e2c970b5e02a7a\
         9087a0f052ca496023e40e06066046501d3a6ea6be8e88c8a3c689431a5fa0dc\
         30e4f71899bfb63af05a8cea651e3ed1bbc3bd791ddd63934e25f6710c450946\
         132a5eef050f7ca0321a1d856b333a937b24fa68dc4283fc4b6b09b6ad71cddf\
         450b1f7d4a183b7d9452c5db9c43fb90d2cb3e2c479650d514026d760f59ce13";

    const V15_SHA512: &str = "\
         1927f6ec5588b69c88f13a993a9e483d92ad5c3377d25679c9eb5db9ff01e0c3\
         4fcbb0e4054abe5883c19e328393718406c8fdd01cbdd96a5f5cc02d5ff4da02\
         517d4d2c17288938521302a56d495a41828f859299832ae242d06202a1092d83\
         9ece3c2e9ad50171c8ec83f1e56503d851967a113217cb6be5700c229942a5a8\
         181e82defdf089378bdadff6fa834a24d7600031e40e3f5ce076e6dd8b693bfe\
         118fd212e7e49b6f4cec59792baf9cab500f9f44df6b504953215abe8500eccc\
         b6b09ec76f826dc27f995627d012cdf6127131eb64518634fea9515714c300d9\
         245011176934a83fdb197465bbf3b888a68a0a13b50597931abf6afa858e0e4a";

    const PSS_SHA256_SALT32: &str = "\
         2caa1d373513dca2174700db35674f96f1093c3bafb3af899d70117fb5536bfd\
         7ff04b9dbcd1d05812b945383dd6bbcf131e2b0ea791fa026d1f96f6e9c2b8d4\
         94595ef8d8eeba40099bc54eebce75c7ee8e694e58ef3be1f385807b8b806ece\
         09412eacffeb8ab82b45d679d4060895549490d2a1cb7bbde0dc1b5ae28f9577\
         b13df8c2377d5f5c3061ab0d87356e3cbab7039c86a80538ba8324c0a27f1957\
         847267b5a3a216b5ac0c36a7f971395d545c7f4907d661c915d728f2811d097e\
         8d27fc9f0f4b83cef525d7c8e1aa9f5b8d89c7be33736f5fe22d6c4c111a54ae\
         42897e65e977fee49e5c9445c0e1cd33534683b1ad3d3d61f5d1a85c68a758d2";

    const PSS_SHA256_SALT0: &str = "\
         51074c83ad34151fc8831856759e58e429a151393ffd54675d0baf7aa14dbe31\
         79a3b4db881938bd7fd80cd4d626c7412e34daa56118be635bdb42ec17bb99ed\
         3084613bd10fe9e333c6d8eff1ea254c5a4a54d7ebcae7fa47048243b5444caa\
         c4539f1685c3628d11695244f388dfb220bc62b39ee5d562b069ed98cc000e9d\
         166609bd36c7d901568f8a1a16d4949e7c400392fb25053b08de601a7c19f0e5\
         44cb530fd3d03189229af4ece5ab9935ed6bb7f22a58788eceb7a2e8bc8c9819\
         be497a2295f2bdd4e696a64d63789070f7a0104839193d29d7ed327e8d5ad105\
         d75a69132cf1862eaba21925b51aba99c010aed0b050cfda9b78672950fc2977";

    const N1024: &str = "\
         cf2a9ef8634206418550ed3586e4f9cde5a43e54d528ac70f1424d6f9472e478\
         e17815dae8b0b3dce84522e7db2ab04f7473e0cbe4881cffd6a4d0cafb3852d4\
         34f7ef03d5de1c180dc3a175d8f47b434dd672839497c4499d5dada21ca4de6f\
         f531f0b91dd883eda6eda3384b783831e5f8c63a14733e9b428257ba4a71aa29";

    const D1024: &str = "\
         463303965890156d9b5ece5a9e80b5b352f72255fdbb201fcf68efb37922ab8f\
         d89b2810bb5bb13f1087e8e997273282620c2826ff242e6b7510f95d66de7196\
         31ca4e2977985f7479b068ac0a6fa7fbae5b2e972cbf0a7a662ec5cc4e2a43b6\
         a6a898d3a42a4ca5e7cd511c0451fcecdf01081e7a6e9ba688c06b089821df17";

    const V15_1024_SHA256: &str = "\
         139491453d895b6c59534d4301a0b732abffacc06501f3c3b2a69f0f6bcd04a0\
         e626eb143b14b1c763a4d97ee767942432784d9d6abd76a180d3bc1bd4c8476b\
         b30c4a02ed11d6c18a854dfef32c3692316649ccc4ce4e1e802f7603161df727\
         e68da996e4cf700a69720971c543eb1edac08ed60eb2dab98e05d6a1578f6715";

    const PSS_1024_SHA384_SALT32: &str = "\
         2c4d6b7546da625ae4c235e5814170542111e50afe17a6e05ba8fe90f64d6e89\
         de3880bae7ee0d3ad40f9cd45e07074b4d25a9d28c4c367c32f00b3b81fabbb1\
         fc9a26cbaa03f8127a6d095444b57e8039e58b4412e900f43e8813538158ebd6\
         0bb18c574470aa9eef2a17394bf912a352823bb7497687176063ad80e69793b5";

    const E: &[u8] = &[0x01, 0x00, 0x01];

    fn key2048() -> PrivateKey {
        PrivateKey::try_new(&unhex::<256>(N2048), E, &unhex::<256>(D2048))
            .unwrap()
    }

    fn key1024() -> PrivateKey {
        PrivateKey::try_new(&unhex::<128>(N1024), E, &unhex::<128>(D1024))
            .unwrap()
    }

    /// Signatures match an independent implementation of RFC 8017,
    /// and verify, across both paddings and two hashes.
    #[test]
    fn known_answers_2048() {
        let key = key2048();
        let public = key.public_key();
        let salt = unhex::<32>(SALT);
        assert_eq!(key.bits(), 2048);
        assert_eq!(key.modulus_len(), 256);

        let sig = key.sign_pkcs1::<Sha256>(MSG).unwrap();
        assert_eq!(sig.as_ref(), &unhex::<256>(V15_SHA256)[..]);
        assert_eq!(sig.len(), 256);
        public.verify_pkcs1::<Sha256>(MSG, sig.as_ref()).unwrap();

        let sig = key.sign_pkcs1::<Sha512>(MSG).unwrap();
        assert_eq!(sig.as_ref(), &unhex::<256>(V15_SHA512)[..]);
        public.verify_pkcs1::<Sha512>(MSG, sig.as_ref()).unwrap();

        let sig = key.sign_pss_with_salt::<Sha256>(MSG, &salt).unwrap();
        assert_eq!(sig.as_ref(), &unhex::<256>(PSS_SHA256_SALT32)[..]);
        // A 32-byte salt is the digest's length, so the plain
        // verifier takes it too.
        public.verify_pss::<Sha256>(MSG, sig.as_ref()).unwrap();
        public
            .verify_pss_with_salt_len::<Sha256>(MSG, sig.as_ref(), 32)
            .unwrap();
        // The wrong expected length is the wrong parameter set.
        assert_eq!(
            public.verify_pss_with_salt_len::<Sha256>(MSG, sig.as_ref(), 0),
            Err(Error::InvalidSignature),
        );

        let sig = key.sign_pss_with_salt::<Sha256>(MSG, &[]).unwrap();
        assert_eq!(sig.as_ref(), &unhex::<256>(PSS_SHA256_SALT0)[..]);
        public
            .verify_pss_with_salt_len::<Sha256>(MSG, sig.as_ref(), 0)
            .unwrap();
    }

    /// A second length, end to end.
    #[test]
    fn known_answers_1024() {
        let key = key1024();
        let salt = unhex::<32>(SALT);
        assert_eq!(key.bits(), 1024);

        let sig = key.sign_pkcs1::<Sha256>(MSG).unwrap();
        assert_eq!(sig.as_ref(), &unhex::<128>(V15_1024_SHA256)[..]);
        key.public_key()
            .verify_pkcs1::<Sha256>(MSG, sig.as_ref())
            .unwrap();

        let sig = key.sign_pss_with_salt::<Sha384>(MSG, &salt).unwrap();
        assert_eq!(sig.as_ref(), &unhex::<128>(PSS_1024_SHA384_SALT32)[..]);
        key.public_key()
            .verify_pss_with_salt_len::<Sha384>(MSG, sig.as_ref(), 32)
            .unwrap();
    }

    /// A salt drawn from the generator verifies under the plain
    /// verifier, and two draws give two signatures.
    #[test]
    fn a_drawn_salt_is_the_digest_length() {
        let mut rng = crate::random::CtrDrbg::from_system().unwrap();
        let key = key1024();
        let a = key.sign_pss::<Sha256, _>(&mut rng, MSG).unwrap();
        let b = key.sign_pss::<Sha256, _>(&mut rng, MSG).unwrap();
        assert_ne!(a, b);
        key.public_key()
            .verify_pss::<Sha256>(MSG, a.as_ref())
            .unwrap();
        key.public_key()
            .verify_pss::<Sha256>(MSG, b.as_ref())
            .unwrap();
    }

    #[test]
    fn rejects_tampering() {
        let key = key1024();
        let public = key.public_key();
        let v15 = key.sign_pkcs1::<Sha256>(MSG).unwrap();
        let pss = key.sign_pss_with_salt::<Sha256>(MSG, &[0x42; 16]).unwrap();

        assert_eq!(
            public.verify_pkcs1::<Sha256>(b"other message", v15.as_ref()),
            Err(Error::InvalidSignature),
        );
        assert_eq!(
            public.verify_pss_with_salt_len::<Sha256>(
                b"other message",
                pss.as_ref(),
                16
            ),
            Err(Error::InvalidSignature),
        );
        for sig in [&v15, &pss] {
            let mut bad = *sig;
            bad.as_mut()[0] ^= 1;
            assert_eq!(
                public.verify_pkcs1::<Sha256>(MSG, bad.as_ref()),
                Err(Error::InvalidSignature),
            );
            assert_eq!(
                public.verify_pss_with_salt_len::<Sha256>(
                    MSG,
                    bad.as_ref(),
                    16
                ),
                Err(Error::InvalidSignature),
            );
        }
        // The wrong hash is the wrong signature.
        assert_eq!(
            public.verify_pkcs1::<Sha384>(MSG, v15.as_ref()),
            Err(Error::InvalidSignature),
        );
        // A representative at or above the modulus is refused
        // before any arithmetic, and so is the wrong length.
        assert_eq!(
            public.verify_pss_with_salt_len::<Sha256>(MSG, &[0xff; 128], 16),
            Err(Error::InvalidSignature),
        );
        assert_eq!(
            public.verify_pkcs1::<Sha256>(MSG, &v15.as_ref()[1..]),
            Err(Error::InvalidSignature),
        );
    }

    /// The widest length is a key like the rest, and one bit past it
    /// is not a key at all.
    #[test]
    fn the_widest_length_is_a_key_like_the_rest() {
        // A modulus of the right length: top bit set, odd, and not a
        // real key, which verification never needs it to be.
        let mut n = [0xa5u8; 1024];
        n[0] |= 0x80;
        n[1023] |= 1;
        let key = PublicKey::try_new(&n, &[1, 0, 1]).expect("key");
        assert_eq!(key.bits(), MAX_BITS);
        let mut back = [0u8; 1024];
        assert_eq!(key.modulus_bytes(&mut back), Ok(1024));
        assert_eq!(back, n);

        let signature = [0x5au8; 1024];
        assert_eq!(
            key.verify_pkcs1::<Sha256>(b"message", &signature),
            Err(Error::InvalidSignature)
        );

        let mut wider = [0xa5u8; 1025];
        wider[1024] |= 1;
        assert_eq!(
            PublicKey::try_new(&wider, &[1, 0, 1]).err(),
            Some(Error::InvalidKeyLength(8200))
        );
    }

    /// A modulus need not fill its top byte: a 2049-bit key loads,
    /// reports its length, and refuses a signature like any other.
    #[test]
    fn an_odd_bit_length_is_a_key() {
        let mut n = [0x5au8; 257];
        n[0] = 0x01;
        n[256] |= 1;
        let key = PublicKey::try_new(&n, &[1, 0, 1]).expect("key");
        assert_eq!(key.bits(), 2049);
        assert_eq!(key.modulus_len(), 257);
        let mut out = [0u8; 300];
        assert_eq!(key.modulus_bytes(&mut out), Ok(257));
        assert_eq!(out[..257], n);
        assert_eq!(
            key.verify_pkcs1::<Sha256>(b"message", &[0x5a; 257]),
            Err(Error::InvalidSignature)
        );
        // Leading zeros are not part of the length.
        let mut padded = [0u8; 260];
        padded[3..].copy_from_slice(&n);
        let key = PublicKey::try_new(&padded, &[1, 0, 1]).expect("key");
        assert_eq!(key.bits(), 2049);
    }

    /// A modulus of 8k + 1 bits, where RFC 8017 makes the PSS
    /// encoding a byte shorter than the modulus: the signature is
    /// OpenSSL's, over a 1025-bit key it generated, so this is the
    /// standard's reading and not this crate's own. The mask has to
    /// be laid over the encoding and not over the zero byte ahead of
    /// it, which every length that fills its bytes cannot tell
    /// apart.
    #[test]
    fn pss_over_a_modulus_of_one_bit_past_the_byte() {
        let spki: [u8; 162] = unhex(
            "30819f300d06092a864886f70d010101050003818d00308189028181017d\
             46c9aab477b5033499e88980158ef0982e074241d54c28642d09d8bd7835\
             15b99f7f55b351576673de4d12bbd46715a3b017491a60e2f89d2bf66e46\
             c3d10ce25925ca1cd170dc057665c7b641375eb9cb2e8ef127cf1dcaf591\
             48f65587a88ed897e68c4e0d6091fece54d2965f6a444a68a4f38ec0dcef\
             6b801d29dd17ed0203010001",
        );
        let pkcs8: [u8; 637] = unhex(
            "30820279020100300d06092a864886f70d0101010500048202633082025f\
             020100028181017d46c9aab477b5033499e88980158ef0982e074241d54c\
             28642d09d8bd783515b99f7f55b351576673de4d12bbd46715a3b017491a\
             60e2f89d2bf66e46c3d10ce25925ca1cd170dc057665c7b641375eb9cb2e\
             8ef127cf1dcaf59148f65587a88ed897e68c4e0d6091fece54d2965f6a44\
             4a68a4f38ec0dcef6b801d29dd17ed020301000102818100a23bb2a7ce2e\
             797929b2ab7d8660a5f7bde927f18b6da50032cfef36a83833ee50938b6c\
             fde6089871890fa67f01bbf33b393c4f40c8250bc064ea70b5efb04d01f5\
             11c1157305ba9302d163b6c11c132878370474fd82d04dba2b2e09c9734d\
             2321f13a7cec53922ab0bf943a06a0894d12ca47a1779425f12ee196ccf7\
             9049024101ac47d64dbf25e2f8b8745f4a365e1869e7614268fd5aaa80d4\
             5d56dc8d4e3142f58f557218d41d4354892015d9ee770e19341301108e20\
             cbce968acbbaa21aa7024100e3e760b99192fed85e9a525e817a1c1ba639\
             d29efc06f18debcb5a921d21953d4673c2c0fe960b14cab77b6a4e3e9aef\
             41f1f7e7f83c01acf0fa182b50248f4b024100bc81ca13e2649ca87917cf\
             b16c88b21a3b1b960d7c266211de674f0a38b00802beeedddf208a8c6ecc\
             50a6ecb745bce559b68ffed1f89cfad7ed6f1e0901bcd5024100957654b4\
             de87aca271c87b64873d71d9a03623af2851d570e1c6c76b33b7a68c3cfc\
             062953cd4b0f23b319392a7f5c54b4c6df723e15fc7352c671bb561fe3e9\
             024100bc85b163bf81dc395dfc5715152da6ca801e11c87c275cefc860c7\
             6b73707791013cdba15bc85d40180e8b9faf5825e4bca9f8989ce19dd25e\
             96d4ef1d7e6135",
        );
        let signature_theirs: [u8; 129] = unhex(
            "007142fba28d1c89ea8d99b5a0ae20d3aa51c8761bdda3b3efec9eb79b48\
             689b15d12aac16f555b57a4dc9d9618ff06249d90297d2bf6bfba0e1cbfc\
             19eecf04aaa16913fbe7d9a040d70c8832273aeaefb17014b3e820e5c08e\
             15d276bbac78734de323bfaf325607b40fb5c02a2f8415e06c799bf3cc63\
             9cc0b713ad292c244e",
        );
        let message = b"an odd length of modulus";
        let public = PublicKey::try_from_der(&spki).expect("spki");
        assert_eq!(public.bits(), 1025);
        public
            .verify_pss::<Sha256>(message, &signature_theirs)
            .expect("OpenSSL's signature");

        // And the other way: what this signs, it verifies, and the
        // top byte of the encoding's integer stayed clear, which is
        // what lets anyone else verify it too.
        let private = PrivateKey::try_from_der(&pkcs8).expect("pkcs8");
        let signature = private
            .sign_pss_with_salt::<Sha256>(message, &[0x5a; 32])
            .expect("sign");
        public
            .verify_pss::<Sha256>(message, signature.as_ref())
            .expect("own signature");
        // With the salt fixed the signature is too, and OpenSSL
        // verified this one when the test was written.
        let expected: [u8; 129] = unhex(
            "000f25b17999c97f0cd8cdc7b3de0cfa9cd08c7754296031b5a8c26f92b5\
             d05ee95bd56aaac42fc6aca6018cc55d3d8dc386eae01939451a7c45d24d\
             5b4275718b8575dcd35524a0506b16af401faea234f48a01b1f5225f8f1d\
             adf7606e97fab3012bac53a2e9064721c07623029ceaa53339f3c66f16c9\
             7713a3c0443b52157c",
        );
        assert_eq!(signature.as_ref(), expected);

        // A salt length no encoding could hold is refused, not
        // added to until it wraps: `usize::MAX` used to pass the
        // length test and index past the end.
        for salt_len in [usize::MAX, usize::MAX - 33, usize::MAX / 2, 96] {
            assert_eq!(
                public.verify_pss_with_salt_len::<Sha256>(
                    message,
                    &signature_theirs,
                    salt_len
                ),
                Err(Error::InvalidSignature),
                "{salt_len}"
            );
        }

        let mut wrong = signature_theirs;
        wrong[64] ^= 1;
        assert_eq!(
            public.verify_pss::<Sha256>(message, &wrong),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn rejects_bad_keys() {
        let n = unhex::<128>(N1024);

        // Too short, and then even.
        assert_eq!(
            PublicKey::try_new(&n[1..], E).err(),
            Some(Error::InvalidKeyLength(1014)),
        );
        let mut even = n;
        even[127] &= 0xfe;
        assert_eq!(
            PublicKey::try_new(&even, E).err(),
            Some(Error::InvalidPublicKey),
        );

        // Even, tiny, and oversized public exponents.
        for e in [&[0x02][..], &[0x01], &[0xff; 9]] {
            assert_eq!(
                PublicKey::try_new(&n, e).err(),
                Some(Error::InvalidPublicKey),
            );
        }

        // A zero or out-of-range private exponent.
        assert_eq!(
            PrivateKey::try_new(&n, E, &[0u8; 4]).err(),
            Some(Error::InvalidPrivateKey),
        );
        assert_eq!(
            PrivateKey::try_new(&n, E, &n).err(),
            Some(Error::InvalidPrivateKey),
        );
    }

    /// Generation takes only whole bytes within the range.
    #[test]
    fn generation_checks_the_bits() {
        struct Zeros;
        impl crate::Random for Zeros {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
                out.fill(0);
                Ok(())
            }
        }
        for bits in [0, 512, 1023, 1025, 1200 + 4, MAX_BITS + 8] {
            assert_eq!(
                PrivateKey::generate(&mut Zeros, bits).err(),
                Some(Error::InvalidKeyLength(bits)),
                "{bits}"
            );
        }
    }

    /// A salt that leaves no room for the digest and framing.
    #[test]
    fn rejects_oversized_salt() {
        let key = key1024();
        let salt = [0u8; 128 - 32 - 1];
        assert!(matches!(
            key.sign_pss_with_salt::<Sha256>(MSG, &salt),
            Err(Error::InvalidLength(_)),
        ));
    }

    const P2048: &str = "\
         c04e0031d3404e9e48359b0b872df10ddab383ef8a7d3552e8160bdba70265e5\
         5e547b4fea93ff124612c55a1810e8c868b06924577437d6470326d30a7a979e\
         24c9f0e1e0db637b83a6878722342840e62c97a3ec07ebbda011b621276519e4\
         6f9bb82f65e98ed31937795b2e9eaee610bbda1ddfef977274bb295687e1dee5";

    const Q2048: &str = "\
         f817c62d739807f8e64e3a010ce43165eeb93c825875afe6351dd4b1bef7d124\
         5a9608408f93e4c17bec44644f7244c59f9ccf923875ef7a33d172cee7f245cd\
         e19285cd796f6d8479341643308405b976543b4968be72a578e25e611b7f8e76\
         dedee163025f11341f1e1d072dd890e9c2b5c58e307707267510a46d0457578d";

    const DP2048: &str = "\
         9c38c17fb895ed48387113db719da8ce1074f5218be7db81d678d279465b745b\
         b91df86f1ba9cef51167fe5b0a61f2399c927357ca93e72873d7e39a5e50e90a\
         d7e8157fea234fd5ef4541a44ded012677d691f9e0ad2e9d8583dde9610f88d1\
         42b9c60efb43997b7468d4757692029373d4a784cd7ede1165330689fd2948e1";

    const DQ2048: &str = "\
         d1bdd7afa96048ad2697cff5ff5e145d26dbb7ca42db0c20c59b38ac24d5021d\
         87effb7e0964712b1a877eb2877005b045e69e9df1d9d2e22f58cd851b16f9e8\
         bae1d2f909c72881acae5a7be752563c9b4b4eec1aff97914987a75ed58e9b74\
         e7aaea457845c3179b8f2bdf5be5116e6f4c997e427efeae869dd144d13cbe29";

    const QINV2048: &str = "\
         7066b0f24630677e6ff95fabbefc030c8723481efdd8e7d9af52e057d10f6f98\
         bd9a82b664dd1c057281a6970421a8324021125cb72f27f97b9857343e388e32\
         5bdf3aea9c167bf33468a4318fd38f8002b92bfc284074aa499587f18ddebefc\
         298a443f2ba98d20f0411d6a37f6aac042e57333e7817abd31e915795968d909";

    type CrtParts = ([u8; 128], [u8; 128], [u8; 128], [u8; 128], [u8; 128]);

    fn crt_parts_2048() -> CrtParts {
        (
            unhex::<128>(P2048),
            unhex::<128>(Q2048),
            unhex::<128>(DP2048),
            unhex::<128>(DQ2048),
            unhex::<128>(QINV2048),
        )
    }

    fn crt_key_2048() -> PrivateKey {
        let (p, q, dp, dq, qinv) = crt_parts_2048();
        PrivateKey::try_new_crt(
            &unhex::<256>(N2048),
            E,
            &unhex::<256>(D2048),
            &p,
            &q,
            &dp,
            &dq,
            &qinv,
        )
        .unwrap()
    }

    /// A CRT key produces byte-identical signatures to the plain
    /// exponent, across both paddings.
    #[test]
    fn crt_matches_plain_signing() {
        let key = crt_key_2048();
        let salt = unhex::<32>(SALT);

        let sig = key.sign_pkcs1::<Sha256>(MSG).unwrap();
        assert_eq!(sig.as_ref(), &unhex::<256>(V15_SHA256)[..]);
        key.public_key()
            .verify_pkcs1::<Sha256>(MSG, sig.as_ref())
            .unwrap();

        let sig = key.sign_pss_with_salt::<Sha256>(MSG, &salt).unwrap();
        assert_eq!(sig.as_ref(), &unhex::<256>(PSS_SHA256_SALT32)[..]);
        key.public_key()
            .verify_pss::<Sha256>(MSG, sig.as_ref())
            .unwrap();
    }

    /// Import cross-checks the pieces against one another.
    #[test]
    fn crt_rejects_inconsistent_parts() {
        let n = unhex::<256>(N2048);
        let d = unhex::<256>(D2048);
        let (p, q, dp, dq, qinv) = crt_parts_2048();
        let build = |p: &[u8], q: &[u8], dp: &[u8], dq: &[u8], qinv: &[u8]| {
            PrivateKey::try_new_crt(&n, E, &d, p, q, dp, dq, qinv).err()
        };

        // A prime that does not divide the modulus.
        let mut bad = p;
        bad[64] ^= 1;
        assert_eq!(
            build(&bad, &q, &dp, &dq, &qinv),
            Some(Error::InvalidPrivateKey)
        );
        // Swapped primes: the product still matches, qinv does not.
        assert_eq!(
            build(&q, &p, &dq, &dp, &qinv),
            Some(Error::InvalidPrivateKey)
        );
        // A wrong inverse.
        let mut bad = qinv;
        bad[64] ^= 1;
        assert_eq!(
            build(&p, &q, &dp, &dq, &bad),
            Some(Error::InvalidPrivateKey)
        );
        // The same prime twice.
        assert_eq!(
            build(&p, &p, &dp, &dp, &qinv),
            Some(Error::InvalidPrivateKey)
        );
        // A zero reduced exponent.
        assert_eq!(
            build(&p, &q, &[0u8; 4], &dq, &qinv),
            Some(Error::InvalidPrivateKey)
        );
    }

    /// A wrong dp cannot be caught at import, so the signature check
    /// catches it: nothing key-leaking is ever released.
    #[test]
    fn crt_faulty_exponent_is_caught_before_release() {
        let n = unhex::<256>(N2048);
        let d = unhex::<256>(D2048);
        let (p, q, dp, dq, qinv) = crt_parts_2048();
        // One flipped bit leaves dp in range, so import accepts it;
        // the signature it produces is wrong.
        let mut bad_dp = dp;
        bad_dp[100] ^= 1;
        let key =
            PrivateKey::try_new_crt(&n, E, &d, &p, &q, &bad_dp, &dq, &qinv)
                .unwrap();
        assert_eq!(
            key.sign_pkcs1::<Sha256>(MSG).err(),
            Some(Error::InvalidPrivateKey),
        );
    }

    /// A generated key signs, verifies, exports, and re-imports both
    /// with and without its CRT pieces, all agreeing byte for byte;
    /// at 1024 bits and at a length that is not a power of two.
    #[test]
    fn generates_working_keys() {
        use crate::random::CtrDrbg;
        let mut rng = CtrDrbg::from_system().unwrap();
        for bits in [1024, 1200] {
            let key = PrivateKey::generate(&mut rng, bits).unwrap();
            assert_eq!(key.bits(), bits);
            let len = bits / 8;
            assert_eq!(key.modulus_len(), len);
            assert_eq!(key.prime_len(), len / 2);

            let sig = key.sign_pss::<Sha256, _>(&mut rng, MSG).unwrap();
            assert_eq!(sig.len(), len);
            key.public_key()
                .verify_pss::<Sha256>(MSG, sig.as_ref())
                .unwrap();
            let sig = key.sign_pkcs1::<Sha256>(MSG).unwrap();
            key.public_key()
                .verify_pkcs1::<Sha256>(MSG, sig.as_ref())
                .unwrap();

            let mut n = [0u8; MAX_LEN];
            let mut d = [0u8; MAX_LEN];
            assert_eq!(key.public_key().modulus_bytes(&mut n), Ok(len));
            assert_eq!(key.d_bytes(&mut d), Ok(len));
            let e = key.public_key().exponent_bytes();
            assert_eq!(e, [0, 0, 0, 0, 0, 1, 0, 1]);
            let half = len / 2;
            let mut parts = [[0u8; MAX_LEN / 2]; 5];
            let [p, q, dp, dq, qinv] = &mut parts;
            key.crt_bytes(
                &mut p[..half],
                &mut q[..half],
                &mut dp[..half],
                &mut dq[..half],
                &mut qinv[..half],
            )
            .unwrap();

            // Re-imported with CRT, and as a plain exponent: all
            // three keys make the same signature, which also proves
            // d and the CRT pieces agree.
            let with_crt = PrivateKey::try_new_crt(
                &n[..len],
                &e,
                &d[..len],
                &p[..half],
                &q[..half],
                &dp[..half],
                &dq[..half],
                &qinv[..half],
            )
            .unwrap();
            let plain = PrivateKey::try_new(&n[..len], &e, &d[..len]).unwrap();
            assert_eq!(with_crt.sign_pkcs1::<Sha256>(MSG).unwrap(), sig);
            assert_eq!(plain.sign_pkcs1::<Sha256>(MSG).unwrap(), sig);
        }
    }

    /// A dead random source cannot loop forever; it fails.
    #[test]
    fn generation_fails_without_entropy() {
        struct Zeros;
        impl crate::Random for Zeros {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
                out.fill(0);
                Ok(())
            }
        }
        assert_eq!(
            PrivateKey::generate(&mut Zeros, MIN_BITS).err(),
            Some(Error::KeyGenerationFailed),
        );
    }

    /// Exporting CRT pieces from a key that has none, or into wrong
    /// buffers, is refused.
    #[test]
    fn crt_export_needs_crt_and_room() {
        let plain = key1024();
        let mut small = [0u8; 63];
        let mut buf = [[0u8; 64]; 4];
        let [ref mut a, ref mut b, ref mut c, ref mut d] = buf;
        assert_eq!(
            plain.crt_bytes(&mut small, a, b, c, d).err(),
            Some(Error::InvalidPrivateKey),
        );
        let crt_key = {
            let (p, q, dp, dq, qinv) = crt_parts_1024();
            PrivateKey::try_new_crt(
                &unhex::<128>(N1024),
                E,
                &unhex::<128>(D1024),
                &p,
                &q,
                &dp,
                &dq,
                &qinv,
            )
            .unwrap()
        };
        assert_eq!(
            crt_key.crt_bytes(&mut small, a, b, c, d).err(),
            Some(Error::InvalidLength(63)),
        );
    }

    const P1024: &str = "\
         ded94047096410d910e4b796a631463c8ba4bc51a7f51007e47d00fe74b7bacc\
         5e1bef5fa160eb536e3ffbeb13d85458fd4cfa34308b779103a15be78c936247";

    const Q1024: &str = "\
         edfc25751deed003561b8708d4403c9fff4f3d87f7f1127a82dfdb2b70bf9cb9\
         eea5a3c9db922400f7c204a31663ed1b09b8d0e62a6558db73473c7e3c85d80f";

    const DP1024: &str = "\
         52c9ccfa56ffc8ce8b5b1ce527aaa898379ca4a5854b22807c1f006e87b7f5fa\
         947fb64705b1f6dad0db8e603fc81f55cc0c7beb45999a7ad22970f62da05763";

    const DQ1024: &str = "\
         a65b8003a26cf1d3a33992e74517b24955bb1a941569db34f08f7331a69b0aff\
         9e27039b737570dd8c537fd2513080ea499d7bc9a9113750100157f41672a959";

    const QINV1024: &str = "\
         2203ff0aa7f1629991e463adfebe4629dc50aee793221bf728347fb5ab03de34\
         086cdad1fc21bbc9cbbcade52b5e77f017ac74377a8b566b4953e2d3ae47b23c";

    type CrtParts1024 = ([u8; 64], [u8; 64], [u8; 64], [u8; 64], [u8; 64]);

    fn crt_parts_1024() -> CrtParts1024 {
        (
            unhex::<64>(P1024),
            unhex::<64>(Q1024),
            unhex::<64>(DP1024),
            unhex::<64>(DQ1024),
            unhex::<64>(QINV1024),
        )
    }

    /// The 1024-bit CRT signature also matches its plain twin,
    /// covering the second length end to end.
    #[test]
    fn crt_matches_plain_signing_1024() {
        let (p, q, dp, dq, qinv) = crt_parts_1024();
        let key = PrivateKey::try_new_crt(
            &unhex::<128>(N1024),
            E,
            &unhex::<128>(D1024),
            &p,
            &q,
            &dp,
            &dq,
            &qinv,
        )
        .unwrap();
        let sig = key.sign_pkcs1::<Sha256>(MSG).unwrap();
        assert_eq!(sig.as_ref(), &unhex::<128>(V15_1024_SHA256)[..]);
    }

    /// The primitives undo one another, and the private one goes the
    /// same way with the primes as without.
    #[test]
    fn primitives_round_trip() {
        let key = key2048();
        let public = key.public_key();
        let mut m = [0u8; 256];
        m[0] = 0x01;
        m[255] = 0x42;

        let mut s = [0u8; 256];
        key.sign_primitive(&m, &mut s).unwrap();
        let mut back = [0u8; 256];
        public.verify_primitive(&s, &mut back).unwrap();
        assert_eq!(back, m);
        assert_ne!(s, m, "the primitive did nothing");

        let mut through_crt = [0u8; 256];
        crt_key_2048().sign_primitive(&m, &mut through_crt).unwrap();
        assert_eq!(through_crt, s);
    }

    /// A representative at or above the modulus is refused by both
    /// directions, which is the only input either one rejects.
    #[test]
    fn primitives_reject_out_of_range() {
        let key = key2048();
        let public = key.public_key();
        let n = unhex::<256>(N2048);
        let mut out = [0u8; 256];
        assert_eq!(
            key.sign_primitive(&n, &mut out),
            Err(Error::MessageTooLong)
        );
        assert_eq!(
            public.verify_primitive(&n, &mut out),
            Err(Error::InvalidSignature)
        );

        // One below the modulus is inside the range, so it works.
        let mut under = n;
        under[255] -= 1;
        assert!(key.sign_primitive(&under, &mut out).is_ok());
        assert!(public.verify_primitive(&under, &mut out).is_ok());
    }

    /// The scheme is built on the primitive, so a PSS signature is
    /// what the primitive gives for the encoding PSS produced.
    #[test]
    fn primitive_underlies_the_scheme() {
        let key = key2048();
        let signature = key
            .sign_pss_with_salt::<Sha256>(b"a message", &[7; 32])
            .unwrap();
        let mut em = [0u8; 256];
        key.public_key()
            .verify_primitive(signature.as_ref(), &mut em)
            .unwrap();
        // The encoded message ends in PSS's trailer byte.
        assert_eq!(em[255], 0xbc);
        let mut again = [0u8; 256];
        key.sign_primitive(&em, &mut again).unwrap();
        assert_eq!(again, signature.as_ref());
    }

    fn generated() -> PrivateKey {
        let mut rng = crate::random::CtrDrbg::from_system().unwrap();
        PrivateKey::generate(&mut rng, 1024).unwrap()
    }

    fn same_key(a: &PrivateKey, b: &PrivateKey) -> bool {
        let mut da = [0u8; MAX_LEN];
        let mut db = [0u8; MAX_LEN];
        let mut na = [0u8; MAX_LEN];
        let mut nb = [0u8; MAX_LEN];
        a.d_bytes(&mut da).unwrap();
        b.d_bytes(&mut db).unwrap();
        a.public_key().modulus_bytes(&mut na).unwrap();
        b.public_key().modulus_bytes(&mut nb).unwrap();
        da == db
            && na == nb
            && a.public_key().exponent_bytes()
                == b.public_key().exponent_bytes()
    }

    /// A key goes out through every format and comes back the same
    /// key, in both DER forms and both PEM forms, for both halves;
    /// and the wrapped forms contain the bare ones.
    #[test]
    fn formats_round_trip() {
        let key = generated();
        let public = key.public_key();
        let sig = key.sign_pkcs1::<Sha256>(MSG).unwrap();
        let mut der = [0u8; 5 * 128];
        let mut pkcs1 = [0u8; 5 * 128];
        let mut pem = [0u8; 8 * 128];

        let n = key.der_bytes(&mut der).unwrap();
        let m = key.pkcs1_bytes(&mut pkcs1).unwrap();
        assert!(der[..n].windows(m).any(|w| w == &pkcs1[..m]));
        let back = PrivateKey::try_from_der(&der[..n]).unwrap();
        assert!(same_key(&back, &key));
        assert_eq!(back.sign_pkcs1::<Sha256>(MSG).unwrap(), sig);
        let back = PrivateKey::try_from_pkcs1(&pkcs1[..m]).unwrap();
        assert!(same_key(&back, &key));
        // A key that came through the structure signs through the
        // primes it carries.
        assert_eq!(back.sign_pkcs1::<Sha256>(MSG).unwrap(), sig);

        let n = key.pem_bytes(&mut pem).unwrap();
        assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
        let back = PrivateKey::try_from_pem(&pem[..n]).unwrap();
        assert!(same_key(&back, &key));
        let n = key.pkcs1_pem_bytes(&mut pem).unwrap();
        assert!(pem.starts_with(b"-----BEGIN RSA PRIVATE KEY-----\n"));
        let back = PrivateKey::try_from_pem(&pem[..n]).unwrap();
        assert!(same_key(&back, &key));

        let n = public.der_bytes(&mut der).unwrap();
        let m = public.pkcs1_bytes(&mut pkcs1).unwrap();
        assert!(der[..n].windows(m).any(|w| w == &pkcs1[..m]));
        let mut want = [0u8; 128];
        public.modulus_bytes(&mut want).unwrap();
        for back in [
            PublicKey::try_from_der(&der[..n]).unwrap(),
            PublicKey::try_from_pkcs1(&pkcs1[..m]).unwrap(),
        ] {
            let mut got = [0u8; 128];
            back.modulus_bytes(&mut got).unwrap();
            assert_eq!(got, want);
            back.verify_pkcs1::<Sha256>(MSG, sig.as_ref()).unwrap();
        }
        let n = public.pem_bytes(&mut pem).unwrap();
        assert!(pem.starts_with(b"-----BEGIN PUBLIC KEY-----\n"));
        let back = PublicKey::try_from_pem(&pem[..n]).unwrap();
        assert_eq!(back.bits(), 1024);
        let n = public.pkcs1_pem_bytes(&mut pem).unwrap();
        assert!(pem.starts_with(b"-----BEGIN RSA PUBLIC KEY-----\n"));
        let back = PublicKey::try_from_pem(&pem[..n]).unwrap();
        assert_eq!(back.bits(), 1024);
    }

    /// An empty buffer learns the length; one byte short still
    /// fails; the exact length succeeds.
    #[test]
    fn export_reports_its_size() {
        let key = generated();
        let mut big = [0u8; 8 * 128];
        let der = key.der_bytes(&mut big).unwrap();
        assert_eq!(key.der_bytes(&mut []), Err(Error::OutputTooSmall(der)));
        assert_eq!(
            key.der_bytes(&mut big[..der - 1]),
            Err(Error::OutputTooSmall(der))
        );
        assert_eq!(key.der_bytes(&mut big[..der]), Ok(der));
        let pem = key.pem_bytes(&mut big).unwrap();
        assert_eq!(key.pem_bytes(&mut []), Err(Error::OutputTooSmall(pem)));
        assert_eq!(key.pem_bytes(&mut big[..pem]), Ok(pem));
        // The documented bounds hold with room to spare.
        assert!(der <= 5 * 128 && pem <= 8 * 128);
        let public = key.public_key();
        assert!(public.der_bytes(&mut big).unwrap() <= 2 * 128);
        assert!(public.pem_bytes(&mut big).unwrap() <= 3 * 128);
        assert_eq!(
            public.modulus_bytes(&mut big[..127]),
            Err(Error::OutputTooSmall(128))
        );
        assert_eq!(
            key.d_bytes(&mut big[..127]),
            Err(Error::OutputTooSmall(128))
        );
    }

    /// The structures have no place for a key without its primes.
    #[test]
    fn export_needs_primes() {
        let plain = key1024();
        let mut out = [0u8; 8 * 128];
        assert_eq!(plain.der_bytes(&mut out), Err(Error::InvalidPrivateKey));
        assert_eq!(plain.pkcs1_bytes(&mut out), Err(Error::InvalidPrivateKey));
        assert_eq!(plain.pem_bytes(&mut out), Err(Error::InvalidPrivateKey));
    }

    /// Signing keys may be marked either rsaEncryption or PSS;
    /// anything else is not an RSA key. A multi-prime key, trailing
    /// bytes, and a truncation are refused.
    #[test]
    fn import_refusals() {
        let key = generated();
        let mut out = [0u8; 8 * 128];
        let n = key.der_bytes(&mut out).unwrap();
        let oid_end = out[..n]
            .windows(9)
            .position(|w| w == crate::der::RSA_ENCRYPTION)
            .unwrap()
            + 8;
        out[oid_end] = 0x0a;
        PrivateKey::try_from_der(&out[..n]).unwrap();
        out[oid_end] = 0x02;
        assert_eq!(
            PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::WrongAlgorithm)
        );
        out[oid_end] = 0x01;
        assert_eq!(
            PrivateKey::try_from_der(&out[..n - 1]).err(),
            Some(Error::InvalidEncoding)
        );
        assert_eq!(
            PrivateKey::try_from_der(&out[..n + 1]).err(),
            Some(Error::InvalidEncoding)
        );
        let n = key.public_key().der_bytes(&mut out).unwrap();
        let oid_end = out[..n]
            .windows(9)
            .position(|w| w == crate::der::RSA_ENCRYPTION)
            .unwrap()
            + 8;
        out[oid_end] = 0x0a;
        PublicKey::try_from_der(&out[..n]).unwrap();
        out[oid_end] = 0x02;
        assert_eq!(
            PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::WrongAlgorithm)
        );

        // The version field of RSAPrivateKey: 1 means multi-prime.
        let n = key.pkcs1_bytes(&mut out).unwrap();
        assert_eq!(out[..7], [0x30, 0x82, out[2], out[3], 0x02, 0x01, 0x00]);
        out[6] = 1;
        assert_eq!(
            PrivateKey::try_from_pkcs1(&out[..n]).err(),
            Some(Error::UnsupportedVersion)
        );

        // A public block is not a private key, whatever it holds.
        let n = key.public_key().pem_bytes(&mut out).unwrap();
        assert_eq!(
            PrivateKey::try_from_pem(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
    }

    /// The borrowed form is the owned one over the caller's words:
    /// the same key gives the same signature, the storage sizes are
    /// what the functions say, and a scratch slice a word short is
    /// refused with the length wanted.
    #[test]
    fn the_borrowed_key_is_the_same_key() {
        let owned = crt_key_2048();
        let salt = unhex::<32>(SALT);
        let want = owned.sign_pss_with_salt::<Sha256>(MSG, &salt).unwrap();

        let (p, q, dp, dq, qinv) = crt_parts_2048();
        let mut storage = [0u64; private_words(2048)];
        let mut scratch = [0u64; scratch_words(2048)];
        let used = PrivateKeyRef::fill_crt(
            &unhex::<256>(N2048),
            E,
            &unhex::<256>(D2048),
            &p,
            &q,
            &dp,
            &dq,
            &qinv,
            &mut storage,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(used, private_words(2048));
        let key = PrivateKeyRef::new(&storage).unwrap();
        assert_eq!(key.bits(), 2048);
        let got = key
            .sign_pss_with_salt::<Sha256>(MSG, &salt, &mut scratch)
            .unwrap();
        assert_eq!(got, want);
        key.public_key()
            .verify_pss::<Sha256>(MSG, got.as_ref(), &mut scratch)
            .unwrap();

        // Short scratch, and short storage.
        let short = scratch_words(2048) - 1;
        assert_eq!(
            key.sign_pkcs1::<Sha256>(MSG, &mut scratch[..short]).err(),
            Some(Error::ScratchTooSmall(scratch_words(2048)))
        );
        assert_eq!(
            PublicKeyRef::fill(&unhex::<256>(N2048), E, &mut storage[..10])
                .err(),
            Some(Error::ScratchTooSmall(public_words(2048)))
        );
        // Words that are not a key are refused as one.
        assert!(PrivateKeyRef::new(&[0u64; 8]).is_err());
        assert!(PublicKeyRef::new(&[0u64; 8]).is_err());
    }

    /// The public view over a private key's words is the public key.
    #[test]
    fn the_public_view_shares_the_words() {
        let mut storage = [0u64; private_words(1024)];
        PrivateKeyRef::fill(
            &unhex::<128>(N1024),
            E,
            &unhex::<128>(D1024),
            &mut storage,
        )
        .unwrap();
        let key = PrivateKeyRef::new(&storage).unwrap();
        let mut scratch = [0u64; scratch_words(1024)];
        let sig = key.sign_pkcs1::<Sha256>(MSG, &mut scratch).unwrap();
        assert_eq!(sig.as_ref(), &unhex::<128>(V15_1024_SHA256)[..]);
        let public = PublicKeyRef::new(&storage[..public_words(1024)]).unwrap();
        public
            .verify_pkcs1::<Sha256>(MSG, sig.as_ref(), &mut scratch)
            .unwrap();
        assert_eq!(public.bits(), 1024);
    }
}
