//! RSA-OAEP encryption (RFC 8017): anyone encrypts to the public
//! key, and only the holder of the private key can decrypt.
//!
//! A key is a modulus `n`, the product of two secret primes, with a
//! public exponent `e` and a private exponent `d` that undo one
//! another. Anyone can raise a padded message through `e`; only the
//! key holder can bring it back through `d`.
//!
//! Only OAEP is offered as a padding: the older PKCS#1 v1.5
//! encryption cannot be decrypted safely (Bleichenbacher's oracle)
//! and is not here. The raw primitives beneath it,
//! [`encrypt_primitive`](PublicKey::encrypt_primitive) and
//! [`decrypt_primitive`](PrivateKey::decrypt_primitive), are public
//! for building a scheme this crate does not have and for the ACVP
//! component suites; they pad nothing and check nothing. And
//! OAEP is for moving keys, not data: a message must fit inside one
//! modulus less the padding, and each decryption costs a private
//! exponentiation, so encrypt a symmetric key and let a cipher carry
//! the data.
//!
//! The keys here only encrypt. RSA signatures are a different job
//! with their own keys, under [`sig::rsa`](crate::sig::rsa), and a
//! key should do one or the other: a key that both signs and
//! decrypts hands an attacker two oracles against the same secret.
//!
//! # Keys are measured in bits
//!
//! A key's length is a value, not a type: [`PrivateKey::generate`]
//! takes the number of bits, any multiple of eight from [`MIN_BITS`]
//! to [`MAX_BITS`], and an imported key is whatever length its
//! modulus is. [`bits`](PublicKey::bits) says which, and
//! [`modulus_len`](PublicKey::modulus_len) is the same in bytes,
//! which is the length of every ciphertext. A [`Ciphertext`] carries
//! its own length, so nothing has to be sized by the caller.
//!
//! Keys are imported from their integer parts, or generated fresh;
//! the accessors on both key types hand the parts back for storage,
//! and [`der_bytes`](PrivateKey::der_bytes) and
//! [`pem_bytes`](PrivateKey::pem_bytes) write the key as PKCS#8,
//! which [`try_from_der`](PrivateKey::try_from_der) and
//! [`try_from_pem`](PrivateKey::try_from_pem) read back; the public
//! half has the same four for `SubjectPublicKeyInfo`, and both have
//! the bare PKCS#1 forms as well. A key imported with its primes,
//! through [`PrivateKey::try_new_crt`], decrypts by the Chinese
//! remainder theorem, roughly three times faster, and every CRT
//! result is checked with the public exponent before use, because
//! one faulty result factors the modulus (Boneh, DeMillo and
//! Lipton).
//!
//! # Memory the caller owns
//!
//! [`PublicKey`] and [`PrivateKey`] own their words and keep an
//! operation's temporaries on the stack, about twenty-four
//! kilobytes, whatever the key's length. [`PublicKeyRef`] and
//! [`PrivateKeyRef`] are the same keys as views over a `[u64]` the
//! caller brings, with a scratch slice handed to each operation; see
//! the signature module, which lays this out in full.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::pke::rsa::PrivateKey;
//! use scytale::random::CtrDrbg;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let key = PrivateKey::generate(&mut rng, 2048)?;
//!
//! // The sender encrypts a session key to the public half.
//! let session_key = [0x42u8; 32];
//! let sealed = key
//!     .public_key()
//!     .encrypt_oaep::<Sha256, _>(&mut rng, b"", &session_key)?;
//!
//! // The key holder recovers it.
//! let mut out = [0u8; 256];
//! let n = key.decrypt_oaep::<Sha256>(b"", sealed.as_ref(), &mut out)?;
//! assert_eq!(&out[..n], &session_key);
//!
//! // Stored as PKCS#8 in PEM, the way OpenSSL writes it.
//! let mut pem = [0u8; 8 * 256];
//! let n = key.pem_bytes(&mut pem)?;
//! let key = PrivateKey::try_from_pem(&pem[..n])?;
//! assert_eq!(key.bits(), 2048);
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! The private exponentiation is a fixed sequence of limb operations
//! whose reads never depend on `d` or the primes, and unpadding
//! checks everything in one pass with one verdict: an error that
//! says *where* decryption failed gives an attacker the message one
//! query at a time (Manger's attack). Generation is the one
//! operation whose time varies with its secrets: how many candidates
//! fall to the primality tests depends on the randomness drawn.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use crate::Random;
use crate::hash::Hash;
use crate::math::rsa::{Private, Public, mgf1_xor};

pub use crate::math::rsa::{
    MAX_BITS, MIN_BITS, private_words, public_words, scratch_words,
};

/// The length of the widest ciphertext, and of the buffer behind a
/// [`Ciphertext`].
const MAX_LEN: usize = MAX_BITS / 8;

/// Words in an owned public key: enough for the widest.
const PUBLIC_WORDS: usize = public_words(MAX_BITS);

/// Words in an owned private key: enough for the widest.
const PRIVATE_WORDS: usize = private_words(MAX_BITS);

/// Scratch an owned key keeps on the stack for an operation.
const SCRATCH_WORDS: usize = scratch_words(MAX_BITS);

/// A ciphertext, as long as the key's modulus.
///
/// Held by value so that nothing has to be sized by the caller; the
/// bytes are [`as_ref`](AsRef::as_ref), and go on the wire as they
/// are.
#[derive(Clone, Copy)]
pub struct Ciphertext {
    bytes: [u8; MAX_LEN],
    len: usize,
}

impl Ciphertext {
    fn zeroed(len: usize) -> Self {
        Ciphertext {
            bytes: [0; MAX_LEN],
            len,
        }
    }

    /// The length in bytes, which is the key's
    /// [`modulus_len`](PublicKey::modulus_len).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Never: a ciphertext is at least [`MIN_BITS`] / 8 bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for Ciphertext {}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ciphertext")
            .field("len", &self.len)
            .finish()
    }
}

/// An encryption key as a view over words the caller owns; see
/// [`sig::rsa::PublicKeyRef`](crate::sig::rsa::PublicKeyRef) for
/// the shape, which is the same here.
#[derive(Clone, Copy)]
pub struct PublicKeyRef<'a> {
    raw: Public<'a>,
}

/// A decryption key as a view over words the caller owns; see
/// [`sig::rsa::PrivateKeyRef`](crate::sig::rsa::PrivateKeyRef). The
/// words are the caller's to wipe; [`PrivateKey`] does so on drop.
#[derive(Clone, Copy)]
pub struct PrivateKeyRef<'a> {
    raw: Private<'a>,
}

/// An encryption key that owns its words, laid out for the widest
/// key whatever its own length; [`bits`](Self::bits) says which.
#[derive(Clone)]
pub struct PublicKey {
    words: [u64; PUBLIC_WORDS],
    bits: usize,
}

/// A decryption key that owns its words, with the public half in
/// front. Every private part is wiped on drop.
#[derive(Clone)]
pub struct PrivateKey {
    words: [u64; PRIVATE_WORDS],
    bits: usize,
}

impl<'a> PublicKeyRef<'a> {
    /// Lays out an encryption key from its big-endian parts in
    /// `storage`, returning the words it took; see
    /// [`PublicKey::try_new`] for what is checked.
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
        Public::fill_from_spki(der, false, storage)
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
        Public::fill_from_pem(pem, false, storage)
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

    /// The modulus length in bytes: the length of every ciphertext.
    pub fn modulus_len(&self) -> usize {
        self.raw.modulus_len()
    }

    /// The encryption primitive; see
    /// [`PublicKey::encrypt_primitive`]. `message` and `out` are the
    /// modulus length.
    pub fn encrypt_primitive(
        &self,
        message: &[u8],
        out: &mut [u8],
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        if !self.raw.in_range(message) || out.len() != self.modulus_len() {
            return Err(Error::MessageTooLong);
        }
        self.raw.apply(message, out, scratch)
    }

    /// Encrypts with OAEP; see [`PublicKey::encrypt_oaep`].
    pub fn encrypt_oaep<H: Hash + Default, R: Random>(
        &self,
        rng: &mut R,
        label: &[u8],
        message: &[u8],
        scratch: &mut [u64],
    ) -> Result<Ciphertext, Error> {
        // The seed is one digest long, and a digest is the only
        // value of that length generic code can make.
        let h_len = size_of::<H::Output>();
        if self.modulus_len() < 2 * h_len + 2 {
            return Err(Error::MessageTooLong);
        }
        let mut seed = H::digest(&[]);
        rng.fill(seed.as_mut())?;
        let ciphertext =
            self.oaep_encode::<H>(seed.as_ref(), label, message, scratch);
        seed.as_mut().zeroize();
        ciphertext
    }

    /// The encoding half of OAEP, with the seed handed in so the
    /// tests can pin it.
    fn oaep_encode<H: Hash + Default>(
        &self,
        seed: &[u8],
        label: &[u8],
        message: &[u8],
        scratch: &mut [u64],
    ) -> Result<Ciphertext, Error> {
        let len = self.modulus_len();
        let h_len = size_of::<H::Output>();
        if len < 2 * h_len + 2 || message.len() > len - 2 * h_len - 2 {
            return Err(Error::MessageTooLong);
        }
        // EM = 0x00 || maskedSeed || maskedDB, where
        // DB = lHash || zeros || 0x01 || message.
        let mut em = [0u8; MAX_LEN];
        let em = &mut em[..len];
        let db_len = len - h_len - 1;
        {
            let db = &mut em[1 + h_len..];
            db[..h_len].copy_from_slice(H::digest(label).as_ref());
            db[db_len - message.len() - 1] = 0x01;
            db[db_len - message.len()..].copy_from_slice(message);
        }
        // Each half masks the other: DB under the seed's mask, then
        // the seed under the masked DB's.
        let (head, db) = em.split_at_mut(1 + h_len);
        mgf1_xor::<H>(seed, db)?;
        head[1..].copy_from_slice(seed);
        let (head, db) = em.split_at_mut(1 + h_len);
        mgf1_xor::<H>(db, &mut head[1..])?;

        // The encoded message is below the modulus by construction:
        // its first byte is zero, and a modulus of these bits has
        // its top bit within the first byte.
        let mut out = Ciphertext::zeroed(len);
        let result = self.raw.apply(em, out.as_mut(), scratch);
        em.zeroize();
        result.map(|()| out)
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
    /// Lays out a decryption key from its big-endian parts in
    /// `storage`, returning the words it took; see
    /// [`PrivateKey::try_new`].
    pub fn fill(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        storage: &mut [u64],
    ) -> Result<usize, Error> {
        Private::fill(n, e, d, storage)
    }

    /// Lays out a decryption key with its Chinese remainder pieces;
    /// see [`PrivateKey::try_new_crt`]. The checks on the pieces
    /// need `scratch`.
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
        Private::fill_from_pkcs8(der, false, storage, scratch)
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
        Private::fill_from_pem(pem, false, storage, scratch)
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

    /// The modulus length in bytes: the length of every ciphertext.
    pub fn modulus_len(&self) -> usize {
        self.raw.public().modulus_len()
    }

    /// The decryption primitive; see
    /// [`PrivateKey::decrypt_primitive`]. `ciphertext` and `out` are
    /// the modulus length.
    pub fn decrypt_primitive(
        &self,
        ciphertext: &[u8],
        out: &mut [u8],
        scratch: &mut [u64],
    ) -> Result<(), Error> {
        // The scheme owns this check everywhere else; the primitive
        // has no scheme above it, so it makes the check itself.
        if !self.raw.public().in_range(ciphertext)
            || out.len() != self.modulus_len()
        {
            return Err(Error::DecryptionFailed);
        }
        self.raw.apply(ciphertext, out, scratch)
    }

    /// Decrypts an OAEP ciphertext; see [`PrivateKey::decrypt_oaep`].
    pub fn decrypt_oaep<H: Hash + Default>(
        &self,
        label: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
        scratch: &mut [u64],
    ) -> Result<usize, Error> {
        let len = self.modulus_len();
        let h_len = size_of::<H::Output>();
        if len < 2 * h_len + 2 {
            return Err(Error::DecryptionFailed);
        }
        let longest = len - 2 * h_len - 2;
        if out.len() < longest {
            return Err(Error::OutputTooSmall(longest));
        }
        // The range check is on the public ciphertext.
        if !self.raw.public().in_range(ciphertext) {
            return Err(Error::DecryptionFailed);
        }
        let mut em = [0u8; MAX_LEN];
        let em = &mut em[..len];
        self.raw.apply(ciphertext, em, scratch)?;

        // Unmask: the seed under the masked DB, then DB under the
        // seed.
        let (head, db) = em.split_at_mut(1 + h_len);
        mgf1_xor::<H>(db, &mut head[1..])?;
        mgf1_xor::<H>(&head[1..], db)?;

        // One flag accumulates every check: the leading zero byte,
        // the label hash, and the zeros-then-0x01 frame around the
        // message.
        let mut bad = head[0];
        let lhash = H::digest(label);
        for (a, b) in db[..h_len].iter().zip(lhash.as_ref()) {
            bad |= a ^ b;
        }
        let mut looking = 1u8;
        let mut start = 0usize;
        for (i, &byte) in db.iter().enumerate().skip(h_len) {
            let is_one = eq_byte(byte, 0x01);
            let is_zero = eq_byte(byte, 0x00);
            let found = looking & is_one;
            start |= (i + 1) & usize::from(found).wrapping_neg();
            bad |= looking & !is_zero & !is_one;
            looking &= 1 - is_one;
        }
        bad |= looking;

        if bad != 0 {
            em.zeroize();
            return Err(Error::DecryptionFailed);
        }
        let message = &db[start..];
        out[..message.len()].copy_from_slice(message);
        let length = message.len();
        em.zeroize();
        Ok(length)
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

    /// An encryption key from its big-endian parts.
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

    /// An encryption key from its DER `SubjectPublicKeyInfo` (RFC
    /// 5280), the form under `PUBLIC KEY` in a PEM file. The
    /// algorithm must be `rsaEncryption`: a key marked
    /// `id-RSASSA-PSS` is a signing key, and is refused.
    ///
    /// The modulus is checked as [`try_new`](Self::try_new) checks
    /// it. Another algorithm's key, the PSS marking included, is
    /// [`Error::WrongAlgorithm`], and anything else wrong with the
    /// bytes [`Error::InvalidEncoding`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        Self::filled(|words| PublicKeyRef::fill_from_der(der, words))
    }

    /// An encryption key from the bare PKCS#1 `RSAPublicKey` (RFC
    /// 8017 A.1.1), the form under `RSA PUBLIC KEY`, which is what
    /// the `SubjectPublicKeyInfo` wraps.
    pub fn try_from_pkcs1(der: &[u8]) -> Result<Self, Error> {
        Self::filled(|words| PublicKeyRef::fill_from_pkcs1(der, words))
    }

    /// An encryption key from a PEM block (RFC 7468) labelled
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

    /// The modulus length in bytes: the length of every ciphertext.
    pub fn modulus_len(&self) -> usize {
        self.view().modulus_len()
    }

    /// The RSA encryption primitive, RSAEP of RFC 8017: raises
    /// `message` to the public exponent into `out`, both of the
    /// modulus length, with no padding applied.
    ///
    /// # This is not encryption
    ///
    /// Raw RSA is deterministic and malleable, so a message enciphered
    /// this way leaks equality and can be mauled in transit. Use
    /// [`encrypt_oaep`](Self::encrypt_oaep) unless you are
    /// implementing a scheme it does not cover, or driving the
    /// component test suites that exercise the primitive on its own.
    ///
    /// Returns [`Error::MessageTooLong`] when the representative is
    /// at or above the modulus, or either buffer is not the modulus
    /// length, which is all the primitive refuses.
    pub fn encrypt_primitive(
        &self,
        message: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut scratch = Scratch::new();
        self.view().encrypt_primitive(message, out, &mut scratch.0)
    }

    /// Encrypts `message` with OAEP, which must fit the key: at
    /// most the modulus length minus two digest lengths and two
    /// bytes. The label is rarely wanted and usually empty; whatever
    /// it is, decryption must present the same one.
    pub fn encrypt_oaep<H: Hash + Default, R: Random>(
        &self,
        rng: &mut R,
        label: &[u8],
        message: &[u8],
    ) -> Result<Ciphertext, Error> {
        let mut scratch = Scratch::new();
        self.view()
            .encrypt_oaep::<H, R>(rng, label, message, &mut scratch.0)
    }

    /// The encoding half of OAEP with the seed pinned, for the tests.
    #[cfg(test)]
    fn oaep_encode<H: Hash + Default>(
        &self,
        seed: &[u8],
        label: &[u8],
        message: &[u8],
    ) -> Result<Ciphertext, Error> {
        let mut scratch = Scratch::new();
        self.view()
            .oaep_encode::<H>(seed, label, message, &mut scratch.0)
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

    /// A decryption key from its big-endian parts: the public
    /// modulus and exponent, then the private exponent, which must
    /// be nonzero and below the modulus. A key that carries its
    /// primes should come in through
    /// [`try_new_crt`](PrivateKey::try_new_crt) instead, which
    /// decrypts three times faster.
    pub fn try_new(n: &[u8], e: &[u8], d: &[u8]) -> Result<Self, Error> {
        Self::filled(|words, _| PrivateKeyRef::fill(n, e, d, words))
    }

    /// A decryption key with its Chinese remainder pieces, in the
    /// order the PKCS#1 `RSAPrivateKey` structure carries them: `p`
    /// and `q`, each half the modulus's bits and within one bit of
    /// each other, the reduced exponents `dp` and `dq`, and `qinv`,
    /// the inverse of `q` modulo `p`.
    ///
    /// The pieces are checked against one another: the primes must
    /// multiply to the modulus and `qinv` must invert `q`. A wrong
    /// `dp` or `dq` cannot be caught here, and is caught instead by
    /// the check every CRT result gets before it is used.
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

    /// Generates a fresh decryption key of `bits`, which must be a
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

    /// A decryption key from its DER PKCS#8 `PrivateKeyInfo` (RFC
    /// 5208; the RFC 5958 form with a public key attached reads
    /// too), the form under `PRIVATE KEY` in a PEM file. The
    /// algorithm must be `rsaEncryption`, as for
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

    /// A decryption key from the bare PKCS#1 `RSAPrivateKey` (RFC
    /// 8017 A.1.2), the form under `RSA PRIVATE KEY`, which is what
    /// the `PrivateKeyInfo` wraps.
    pub fn try_from_pkcs1(der: &[u8]) -> Result<Self, Error> {
        Self::filled(|words, scratch| {
            PrivateKeyRef::fill_from_pkcs1(der, words, scratch)
        })
    }

    /// A decryption key from a PEM block (RFC 7468) labelled
    /// `PRIVATE KEY` or `RSA PRIVATE KEY`, holding the matching DER
    /// form above. Whitespace and line ends are read leniently;
    /// anything else that is not exactly one well-formed block, an
    /// encrypted key included, is [`Error::InvalidEncoding`].
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

    /// The modulus length in bytes: the length of every ciphertext.
    pub fn modulus_len(&self) -> usize {
        self.view().modulus_len()
    }

    /// The RSA decryption primitive, RSADP of RFC 8017: raises
    /// `ciphertext` to the private exponent, through the primes when
    /// the key carries them, into `out`, both of the modulus length,
    /// with no padding removed.
    ///
    /// # This is not decryption
    ///
    /// Nothing here authenticates the ciphertext or checks any
    /// padding, and a scheme built on this without care is where
    /// Bleichenbacher's and Manger's attacks live. Use
    /// [`decrypt_oaep`](Self::decrypt_oaep) unless you are
    /// implementing a scheme it does not cover, or driving the
    /// component test suites that exercise the primitive on its own.
    ///
    /// Returns [`Error::DecryptionFailed`] when the ciphertext is at
    /// or above the modulus, or either buffer is not the modulus
    /// length. As everywhere else in the crate, a result computed
    /// through the primes is checked with the public exponent before
    /// it is returned.
    pub fn decrypt_primitive(
        &self,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut scratch = Scratch::new();
        self.view()
            .decrypt_primitive(ciphertext, out, &mut scratch.0)
    }

    /// Decrypts an OAEP ciphertext made under the same hash and
    /// label, writing the message into the front of `out`, which
    /// must hold the largest message the key can carry, and
    /// returning its length.
    ///
    /// Every way the padding can be wrong is one error, found in one
    /// constant-time pass: an oracle that says *where* decryption
    /// failed gives an attacker the message one query at a time
    /// (Manger's attack), so nothing here branches on secret bytes
    /// until the single verdict.
    pub fn decrypt_oaep<H: Hash + Default>(
        &self,
        label: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut scratch = Scratch::new();
        self.view()
            .decrypt_oaep::<H>(label, ciphertext, out, &mut scratch.0)
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

/// One where the bytes are equal, zero otherwise, with no branch
/// for the comparison to leak through.
fn eq_byte(a: u8, b: u8) -> u8 {
    let x = u16::from(a ^ b);
    (x.wrapping_sub(1) >> 8) as u8 & 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::{Sha256, Sha512};

    fn unhex<const N: usize>(hex: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(hex.len(), 2 * N);
        for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

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

    const E: &[u8] = &[0x01, 0x00, 0x01];

    fn key2048() -> PrivateKey {
        PrivateKey::try_new(&unhex::<256>(N2048), E, &unhex::<256>(D2048))
            .unwrap()
    }

    fn key1024() -> PrivateKey {
        PrivateKey::try_new(&unhex::<128>(N1024), E, &unhex::<128>(D1024))
            .unwrap()
    }

    const OAEP_SEED256: &str =
        "afa64f41e1e367d9972a04d1d5ad16500c55c7dc8ad700cfd013b3249233e0ab";

    const OAEP_SHA256_NOLABEL: &str = "\
         6c873891ace82ee30335d64cb0f10e2ca182129f2fa3ef25ced68943d1267cac\
         00c5dcd316bd7d5e615e5ee315e40a8f7e7da786f7c182ce7ea72b292fff6dce\
         cde22e13bdefb0fdf1b4f84fa9c276389672d919c124f78a38fb058a9189395e\
         1fb088c86060c2f5cc6f88dc0d1deb026c6cb852f8f468369a19de86954526fc\
         fa5b729022435127ffae79364eadc61a37d8a4c546317843392581a6b3caac2c\
         961544bbceb9187df38332ad77def0ed45b5f8d3d898edede5cb4aa5687dfc50\
         1306ca3af74e20fa9f44a16ec60c0c62d5fd52bd7317f01acfb3acec81fb6c98\
         1af64549e9faa69f8917987154ca83128e66d8b16af1bd16f49ed92c996dd618";

    const OAEP_SHA256_LABEL: &str = "\
         11d42b6db867974fc4e0bf205b1f44f83d4d663b8c100c426142094b615ac840\
         847d43ee33a878185c352c9b0f76d4233e07c1c61a3927fe61f95ba7c5b1a5a8\
         9fcaecc666fbcd693ee03a056c3628ca10de3fb0a04e24cf5e4028da85740a48\
         7276ee9df78e4bdd104f671389af6c97eed1db7b43dac52e299b830d0850fb7a\
         744078202cc72ba74475ede6a9b9e3f65ac68262613962a8534cf695dd1a5328\
         f0505c4cd830d1f5acd41d98b1f6769da8b776de79f988fb12a7196328f66515\
         3f338e4216fcf5f5357c957d4220be215f7288e243c4c89ea09df6220f954a93\
         5141beda826aa5a37da12933dd0e9edaebe9adfbab5668432373f7c96ee0e81f";

    const OAEP_SHA512: &str = "\
         43f41cb0ee6164d5a4035ac86ed250408ede7a45120ec94ff7d8810d2d0b2318\
         bfb201bbee46ee795ba801b1201cc7f6b64a82ecda24f1291bd14c4382884081\
         29c5bd293dd88812d97339b341e127fa7c0cfda7f01c2a847e3bf3bcfb3488b3\
         39b84446466e07274ef6a53076f43f1c129cc4b8448d46fc3d54873d44c53788\
         ca5ca25d40b87f2e3638e0766454188513e4a10d957979116604b71a544b5b93\
         c3880005c176a19c31345caa60678a3db7983047b856489349677205fde61035\
         134006eb65da88bed184fecbf6a2db827280b2b20ae7d756ae3374eaa34adcd7\
         5ebca5f7374717ee9c41f33d497b93ab3498ef0e2e2eb94545ddf60230922228";

    const OAEP_SHA256_MAX: &str = "\
         2fdba0e5a0e0ea429e9d42c864107ebb35aa363fee342edfb2585930b56a416e\
         a5fe332d0f6dfacbe7231a4e95e2811630e3318b7d7aae07ba473d4a51d6466f\
         3335e4d220a7de0ac74b84154e28b01c6e2af8289f19ea8fa7cdd33495e3e65b\
         91b3acf26cbe96c65c6b9e1a299b76cbaacc9255acb1c451a7d5f1a1d96ce344\
         d563682db508f7f59cb2e9eb80d7fc697916871689828b42d1322e89338d31a6\
         61a5c81b72347c549a47b3468b6ba6f9973f964e796b504a79e4c0f3f502c52e\
         a09be39d95014d67bc305fb4427219e246199fe7b6b9d15c3e9ee9d013f7eea1\
         8c0360ad59294c4fa49306be07e5d7993a570c6736a5f46568c6ad32ffc6e75c";

    /// Encryption with a pinned seed matches an independent
    /// implementation, and decryption inverts it, across hashes,
    /// labels and the largest message that fits.
    #[test]
    fn oaep_known_answers() {
        let key = key2048();
        let public = key.public_key();
        let seed = unhex::<32>(OAEP_SEED256);
        let msg = b"attack at dawn";
        let mut out = [0u8; 256];
        assert_eq!(key.bits(), 2048);

        let c = public.oaep_encode::<Sha256>(&seed, b"", msg).unwrap();
        assert_eq!(c.as_ref(), &unhex::<256>(OAEP_SHA256_NOLABEL)[..]);
        assert_eq!(c.len(), 256);
        let n = key
            .decrypt_oaep::<Sha256>(b"", c.as_ref(), &mut out)
            .unwrap();
        assert_eq!(&out[..n], msg);

        let c = public
            .oaep_encode::<Sha256>(&seed, b"the label", msg)
            .unwrap();
        assert_eq!(c.as_ref(), &unhex::<256>(OAEP_SHA256_LABEL)[..]);
        let n = key
            .decrypt_oaep::<Sha256>(b"the label", c.as_ref(), &mut out)
            .unwrap();
        assert_eq!(&out[..n], msg);

        // The largest message that fits with SHA-256.
        let mut big = [0u8; 256 - 64 - 2];
        for (i, byte) in big.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let c = public.oaep_encode::<Sha256>(&seed, b"", &big).unwrap();
        assert_eq!(c.as_ref(), &unhex::<256>(OAEP_SHA256_MAX)[..]);
        let n = key
            .decrypt_oaep::<Sha256>(b"", c.as_ref(), &mut out)
            .unwrap();
        assert_eq!(&out[..n], &big[..]);
    }

    /// The SHA-512 known answer, whose seed is a digest long.
    #[test]
    fn oaep_sha512_known_answer() {
        let key = key2048();
        let seed = unhex::<64>(
            "afa64f41e1e367d9972a04d1d5ad16500c55c7dc8ad700cfd013b3249233e0ab\
             d2c83f42ff3029c16224591c041cc9081602104103cc4d6d6038e8eee227e861",
        );
        let msg = b"attack at dawn";
        let c = key
            .public_key()
            .oaep_encode::<Sha512>(&seed, b"", msg)
            .unwrap();
        assert_eq!(c.as_ref(), &unhex::<256>(OAEP_SHA512)[..]);
        let mut out = [0u8; 256];
        let n = key
            .decrypt_oaep::<Sha512>(b"", c.as_ref(), &mut out)
            .unwrap();
        assert_eq!(&out[..n], msg);
    }

    /// A fresh random seed round-trips, and an empty message is a
    /// message.
    #[test]
    fn oaep_round_trips() {
        use crate::random::CtrDrbg;
        let mut rng = CtrDrbg::from_system().unwrap();
        let key = key1024();
        let public = key.public_key();
        let mut out = [0u8; 128];
        let c = public
            .encrypt_oaep::<Sha256, _>(&mut rng, b"", b"hello")
            .unwrap();
        let n = key
            .decrypt_oaep::<Sha256>(b"", c.as_ref(), &mut out)
            .unwrap();
        assert_eq!(&out[..n], b"hello");
        let c = public
            .encrypt_oaep::<Sha256, _>(&mut rng, b"", b"")
            .unwrap();
        let n = key
            .decrypt_oaep::<Sha256>(b"", c.as_ref(), &mut out)
            .unwrap();
        assert_eq!(n, 0);
    }

    /// A generated key encrypts and decrypts, and round-trips its
    /// parts through export and CRT import, at a length that is not
    /// a power of two.
    #[test]
    fn generated_key_round_trips() {
        use crate::random::CtrDrbg;
        let mut rng = CtrDrbg::from_system().unwrap();
        let key = PrivateKey::generate(&mut rng, 1200).unwrap();
        assert_eq!(key.bits(), 1200);
        assert_eq!(key.modulus_len(), 150);
        let mut out = [0u8; 150];
        let c = key
            .public_key()
            .encrypt_oaep::<Sha256, _>(&mut rng, b"", b"session key")
            .unwrap();
        assert_eq!(c.len(), 150);
        let n = key
            .decrypt_oaep::<Sha256>(b"", c.as_ref(), &mut out)
            .unwrap();
        assert_eq!(&out[..n], b"session key");

        let mut nb = [0u8; 150];
        let mut d = [0u8; 150];
        key.public_key().modulus_bytes(&mut nb).unwrap();
        key.d_bytes(&mut d).unwrap();
        let e = key.public_key().exponent_bytes();
        let mut parts = [[0u8; 75]; 5];
        let [p, q, dp, dq, qinv] = &mut parts;
        key.crt_bytes(p, q, dp, dq, qinv).unwrap();
        let again =
            PrivateKey::try_new_crt(&nb, &e, &d, p, q, dp, dq, qinv).unwrap();
        let n = again
            .decrypt_oaep::<Sha256>(b"", c.as_ref(), &mut out)
            .unwrap();
        assert_eq!(&out[..n], b"session key");
    }

    /// Every way a ciphertext can be wrong is the same error.
    #[test]
    fn oaep_rejects_uniformly() {
        let key = key2048();
        let seed = unhex::<32>(OAEP_SEED256);
        let c = unhex::<256>(OAEP_SHA256_NOLABEL);
        let mut out = [0u8; 256];

        // A flipped bit anywhere.
        for byte in [0, 128, 255] {
            let mut bad = c;
            bad[byte] ^= 1;
            assert_eq!(
                key.decrypt_oaep::<Sha256>(b"", &bad, &mut out),
                Err(Error::DecryptionFailed),
            );
        }
        // The wrong label, and the wrong hash.
        assert_eq!(
            key.decrypt_oaep::<Sha256>(b"wrong", &c, &mut out),
            Err(Error::DecryptionFailed),
        );
        assert_eq!(
            key.decrypt_oaep::<Sha512>(b"", &c, &mut out),
            Err(Error::DecryptionFailed),
        );
        // A representative at or above the modulus, and the wrong
        // length.
        assert_eq!(
            key.decrypt_oaep::<Sha256>(b"", &[0xff; 256], &mut out),
            Err(Error::DecryptionFailed),
        );
        assert_eq!(
            key.decrypt_oaep::<Sha256>(b"", &c[1..], &mut out),
            Err(Error::DecryptionFailed),
        );
        // Too small an output buffer is its own, public error.
        assert_eq!(
            key.decrypt_oaep::<Sha256>(b"", &c, &mut [0u8; 8]),
            Err(Error::OutputTooSmall(256 - 64 - 2)),
        );
        // A message the key cannot carry.
        assert_eq!(
            key.public_key()
                .oaep_encode::<Sha256>(&seed, b"", &[0u8; 256 - 64 - 1])
                .err(),
            Some(Error::MessageTooLong),
        );
    }

    /// The primitives undo one another, and the private one is not
    /// the identity.
    #[test]
    fn primitives_round_trip() {
        let key = key2048();
        let public = key.public_key();
        let mut m = [0u8; 256];
        m[0] = 0x01;
        m[255] = 0x42;

        let mut c = [0u8; 256];
        public.encrypt_primitive(&m, &mut c).unwrap();
        assert_ne!(c, m, "the primitive did nothing");
        let mut back = [0u8; 256];
        key.decrypt_primitive(&c, &mut back).unwrap();
        assert_eq!(back, m);
    }

    /// A representative at or above the modulus is refused by both
    /// directions, each naming its own error.
    #[test]
    fn primitives_reject_out_of_range() {
        let key = key2048();
        let public = key.public_key();
        let n = unhex::<256>(N2048);
        let mut out = [0u8; 256];
        assert_eq!(
            public.encrypt_primitive(&n, &mut out),
            Err(Error::MessageTooLong)
        );
        assert_eq!(
            key.decrypt_primitive(&n, &mut out),
            Err(Error::DecryptionFailed)
        );

        let mut under = n;
        under[255] -= 1;
        assert!(public.encrypt_primitive(&under, &mut out).is_ok());
        assert!(key.decrypt_primitive(&under, &mut out).is_ok());
    }

    /// OAEP is built on the primitive: undoing the transport by hand
    /// gives the padded block OAEP encoded.
    #[test]
    fn primitive_underlies_oaep() {
        let key = key2048();
        let sealed = key
            .public_key()
            .oaep_encode::<Sha256>(&unhex::<32>(OAEP_SEED256), b"", b"hello")
            .unwrap();
        let mut em = [0u8; 256];
        key.decrypt_primitive(sealed.as_ref(), &mut em).unwrap();
        // OAEP's encoded message always has a zero leading byte.
        assert_eq!(em[0], 0);
    }

    /// A key goes through both containers and both PEM labels and
    /// decrypts what the original's public half encrypted; the
    /// public half round-trips too.
    #[test]
    fn formats_round_trip() {
        let mut rng = crate::random::CtrDrbg::from_system().unwrap();
        let key = PrivateKey::generate(&mut rng, 1024).unwrap();
        let sealed = key
            .public_key()
            .encrypt_oaep::<Sha256, _>(&mut rng, b"", b"session key")
            .unwrap();
        let mut out = [0u8; 8 * 128];
        let mut msg = [0u8; 128];
        let mut d = [0u8; 128];
        key.d_bytes(&mut d).unwrap();

        let n = key.der_bytes(&mut out).unwrap();
        let backs = [
            PrivateKey::try_from_der(&out[..n]).unwrap(),
            {
                let n = key.pkcs1_bytes(&mut out).unwrap();
                PrivateKey::try_from_pkcs1(&out[..n]).unwrap()
            },
            {
                let n = key.pem_bytes(&mut out).unwrap();
                PrivateKey::try_from_pem(&out[..n]).unwrap()
            },
            {
                let n = key.pkcs1_pem_bytes(&mut out).unwrap();
                PrivateKey::try_from_pem(&out[..n]).unwrap()
            },
        ];
        for back in &backs {
            let mut again = [0u8; 128];
            back.d_bytes(&mut again).unwrap();
            assert_eq!(again, d);
            let n = back
                .decrypt_oaep::<Sha256>(b"", sealed.as_ref(), &mut msg)
                .unwrap();
            assert_eq!(&msg[..n], b"session key");
        }

        let public = key.public_key();
        let n = public.der_bytes(&mut out).unwrap();
        let backs = [
            PublicKey::try_from_der(&out[..n]).unwrap(),
            {
                let n = public.pkcs1_bytes(&mut out).unwrap();
                PublicKey::try_from_pkcs1(&out[..n]).unwrap()
            },
            {
                let n = public.pem_bytes(&mut out).unwrap();
                PublicKey::try_from_pem(&out[..n]).unwrap()
            },
            {
                let n = public.pkcs1_pem_bytes(&mut out).unwrap();
                PublicKey::try_from_pem(&out[..n]).unwrap()
            },
        ];
        for back in &backs {
            assert_eq!(back.bits(), 1024);
            let sealed = back
                .encrypt_oaep::<Sha256, _>(&mut rng, b"", b"again")
                .unwrap();
            let n = key
                .decrypt_oaep::<Sha256>(b"", sealed.as_ref(), &mut msg)
                .unwrap();
            assert_eq!(&msg[..n], b"again");
        }
    }

    /// A key marked for PSS signing is not a decryption key, and a
    /// key without its primes cannot be written.
    #[test]
    fn pss_keys_and_plain_keys_are_refused() {
        let mut rng = crate::random::CtrDrbg::from_system().unwrap();
        let key = PrivateKey::generate(&mut rng, 1024).unwrap();
        let mut out = [0u8; 8 * 128];
        let n = key.der_bytes(&mut out).unwrap();
        let oid_end = out[..n]
            .windows(9)
            .position(|w| w == crate::der::RSA_ENCRYPTION)
            .unwrap()
            + 8;
        out[oid_end] = 0x0a;
        assert_eq!(
            PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::WrongAlgorithm)
        );
        let n = key.public_key().der_bytes(&mut out).unwrap();
        let oid_end = out[..n]
            .windows(9)
            .position(|w| w == crate::der::RSA_ENCRYPTION)
            .unwrap()
            + 8;
        out[oid_end] = 0x0a;
        assert_eq!(
            PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::WrongAlgorithm)
        );

        let plain = key1024();
        assert_eq!(plain.der_bytes(&mut out), Err(Error::InvalidPrivateKey));
        assert_eq!(plain.pem_bytes(&mut out), Err(Error::InvalidPrivateKey));
    }

    /// The borrowed form decrypts what the owned form encrypted, and
    /// the same ciphertext comes out of both for a pinned seed.
    #[test]
    fn the_borrowed_key_is_the_same_key() {
        let owned = key2048();
        let seed = unhex::<32>(OAEP_SEED256);
        let want = owned
            .public_key()
            .oaep_encode::<Sha256>(&seed, b"", b"hello")
            .unwrap();

        let mut storage = [0u64; private_words(2048)];
        let mut scratch = [0u64; scratch_words(2048)];
        PrivateKeyRef::fill(
            &unhex::<256>(N2048),
            E,
            &unhex::<256>(D2048),
            &mut storage,
        )
        .unwrap();
        let key = PrivateKeyRef::new(&storage).unwrap();
        let got = key
            .public_key()
            .oaep_encode::<Sha256>(&seed, b"", b"hello", &mut scratch)
            .unwrap();
        assert_eq!(got, want);
        let mut out = [0u8; 256];
        let n = key
            .decrypt_oaep::<Sha256>(b"", got.as_ref(), &mut out, &mut scratch)
            .unwrap();
        assert_eq!(&out[..n], b"hello");
        assert_eq!(
            key.decrypt_oaep::<Sha256>(
                b"",
                got.as_ref(),
                &mut out,
                &mut [0; 8]
            )
            .err(),
            Some(Error::ScratchTooSmall(scratch_words(2048)))
        );
    }
}
