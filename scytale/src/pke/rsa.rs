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
//! The width of a key is part of its type: [`Rsa2048PrivateKey`]
//! holds a 2048-bit modulus, and the general [`PrivateKey`] takes
//! the limb and byte counts for any other width, with no ceiling.
//! Keys are imported from their integer parts, or generated fresh by
//! [`PrivateKey::generate`]; the accessors on both key types hand
//! the parts back for storage, and [`der_bytes`](PrivateKey::der_bytes)
//! and [`pem_bytes`](PrivateKey::pem_bytes) write the key as PKCS#8,
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
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::pke::rsa::Rsa2048PrivateKey;
//! use scytale::random::{Rng, System};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let key = Rsa2048PrivateKey::generate(&mut rng)?;
//!
//! // The sender encrypts a session key to the public half.
//! let session_key = [0x42u8; 32];
//! let sealed = key
//!     .public_key()
//!     .encrypt_oaep::<Sha256, _>(&mut rng, b"", &session_key)?;
//!
//! // The key holder recovers it.
//! let mut out = [0u8; 256];
//! let n = key.decrypt_oaep::<Sha256>(b"", &sealed, &mut out)?;
//! assert_eq!(&out[..n], &session_key);
//!
//! // Stored as PKCS#8 in PEM, the way OpenSSL writes it.
//! let mut pem = [0u8; 8 * 256];
//! let n = key.pem_bytes(&mut pem)?;
//! let key = Rsa2048PrivateKey::try_from_pem(&pem[..n])?;
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
//! query at a time (Manger's attack).

use zeroize::Zeroize;

use crate::cipher::Block;
use crate::hash::Hash;
use crate::math::rsa::{mgf1_xor, Private, Public};
use crate::math::uint::Uint;
use crate::random::Random;
use crate::Error;

/// An RSA encryption key of `LIMBS` 64-bit words; `BYTES` is the
/// same width in bytes, 8 times `LIMBS`, and is the length of every
/// ciphertext. The width aliases below fill both in.
pub struct PublicKey<const LIMBS: usize, const BYTES: usize> {
    raw: Public<LIMBS, BYTES>,
}

/// An RSA decryption key. The public half rides along, and every
/// private part is wiped on drop.
///
/// `HALF` is the width of one prime, half of `LIMBS`; the aliases
/// fill it in. It is a parameter only because the language cannot
/// yet derive it.
pub struct PrivateKey<const LIMBS: usize, const BYTES: usize, const HALF: usize>
{
    public: PublicKey<LIMBS, BYTES>,
    raw: Private<LIMBS, BYTES, HALF>,
}

/// A 2048-bit encryption key.
pub type Rsa2048PublicKey = PublicKey<32, 256>;
/// A 2048-bit decryption key.
pub type Rsa2048PrivateKey = PrivateKey<32, 256, 16>;
/// A 3072-bit encryption key.
pub type Rsa3072PublicKey = PublicKey<48, 384>;
/// A 3072-bit decryption key.
pub type Rsa3072PrivateKey = PrivateKey<48, 384, 24>;
/// A 4096-bit encryption key.
pub type Rsa4096PublicKey = PublicKey<64, 512>;
/// A 4096-bit decryption key.
pub type Rsa4096PrivateKey = PrivateKey<64, 512, 32>;
/// A 1024-bit encryption key: legacy interoperation only, too small
/// for new uses.
pub type Rsa1024PublicKey = PublicKey<16, 128>;
/// A 1024-bit decryption key: legacy interoperation only.
pub type Rsa1024PrivateKey = PrivateKey<16, 128, 8>;

impl<const LIMBS: usize, const BYTES: usize> PublicKey<LIMBS, BYTES> {
    /// An encryption key from its big-endian parts.
    ///
    /// The modulus must be exactly the type's width, top bit set,
    /// and odd. The exponent must be odd, at least 3, and fit eight
    /// bytes, which every deployed key's does.
    pub fn try_new(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            raw: Public::try_new(n, e)?,
        })
    }

    /// The RSA encryption primitive, RSAEP of RFC 8017: raises
    /// `message` to the public exponent, with no padding applied.
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
    /// at or above the modulus, which is the only input the primitive
    /// refuses.
    pub fn encrypt_primitive(
        &self,
        message: &[u8; BYTES],
    ) -> Result<[u8; BYTES], Error> {
        self.raw.apply(message).ok_or(Error::MessageTooLong)
    }

    /// Encrypts `message` with OAEP, which must fit the key: at
    /// most the width minus two digest lengths and two bytes. The
    /// label is rarely wanted and usually empty; whatever it is,
    /// decryption must present the same one.
    pub fn encrypt_oaep<H: Hash, R: Random>(
        &self,
        rng: &mut R,
        label: &[u8],
        message: &[u8],
    ) -> Result<[u8; BYTES], Error> {
        let mut seed = H::Output::ZERO;
        rng.fill(seed.as_mut())?;
        let ciphertext = self.oaep_encode::<H>(seed.as_ref(), label, message);
        seed.as_mut().zeroize();
        ciphertext
    }

    /// The encoding half of OAEP, with the seed handed in so the
    /// tests can pin it.
    fn oaep_encode<H: Hash>(
        &self,
        seed: &[u8],
        label: &[u8],
        message: &[u8],
    ) -> Result<[u8; BYTES], Error> {
        let h_len = H::Output::SIZE;
        if BYTES < 2 * h_len + 2 || message.len() > BYTES - 2 * h_len - 2 {
            return Err(Error::MessageTooLong);
        }
        // EM = 0x00 || maskedSeed || maskedDB, where
        // DB = lHash || zeros || 0x01 || message.
        let mut em = [0u8; BYTES];
        let db_len = BYTES - h_len - 1;
        {
            let db = &mut em[1 + h_len..];
            db[..h_len].copy_from_slice(H::digest(label)?.as_ref());
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

        // The encoded message is below the modulus by construction,
        // so the public operation cannot refuse it.
        let out = self.raw.apply(&em).ok_or(Error::MessageTooLong);
        em.zeroize();
        out
    }

    /// The modulus, big-endian.
    pub fn modulus_bytes(&self) -> [u8; BYTES] {
        self.raw.modulus_bytes()
    }

    /// The public exponent, big-endian in eight bytes.
    pub fn exponent_bytes(&self) -> [u8; 8] {
        self.raw.exponent_bytes()
    }

    /// An encryption key from its DER `SubjectPublicKeyInfo` (RFC
    /// 5280), the form under `PUBLIC KEY` in a PEM file. The algorithm must be
    /// `rsaEncryption`: a key marked `id-RSASSA-PSS` is a signing
    /// key, and is refused.
    ///
    /// The modulus must be the type's width, as with
    /// [`try_new`](Self::try_new); anything else wrong with the
    /// bytes is [`Error::InvalidEncoding`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            raw: Public::from_spki(der, false)?,
        })
    }

    /// Writes the key as a `SubjectPublicKeyInfo` under
    /// `rsaEncryption` into the front of `out`, returning the
    /// length. `2 * BYTES` always suffices; a buffer too small gets
    /// [`Error::OutputTooSmall`] with the exact need.
    pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.spki_bytes(out)
    }

    /// An encryption key from the bare PKCS#1 `RSAPublicKey` (RFC 8017
    /// A.1.1), the form under `RSA PUBLIC KEY`, which is what the
    /// `SubjectPublicKeyInfo` wraps.
    pub fn try_from_pkcs1(der: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            raw: Public::from_pkcs1(der)?,
        })
    }

    /// Writes the bare `RSAPublicKey`, as [`der_bytes`](Self::der_bytes)
    /// does the wrapped one.
    pub fn pkcs1_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pkcs1_bytes(out)
    }

    /// An encryption key from a PEM block (RFC 7468) labelled `PUBLIC KEY`
    /// or `RSA PUBLIC KEY`, holding the matching DER form above.
    /// Whitespace and line ends are read leniently; anything else
    /// that is not exactly one well-formed block is
    /// [`Error::InvalidEncoding`].
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            raw: Public::from_pem(pem, false)?,
        })
    }

    /// Writes the key as a `PUBLIC KEY` PEM block, ASCII with LF line
    /// ends, into the front of `out`, returning the length.
    /// `3 * BYTES` always suffices.
    pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pem_bytes(out, false)
    }

    /// The same as an `RSA PUBLIC KEY` block, around the PKCS#1 form.
    pub fn pkcs1_pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pem_bytes(out, true)
    }
}

impl<const LIMBS: usize, const BYTES: usize, const HALF: usize>
    PrivateKey<LIMBS, BYTES, HALF>
{
    /// A decryption key from its big-endian parts: the public
    /// modulus and exponent, then the private exponent, which must
    /// be nonzero and below the modulus. A key that carries its
    /// primes should come in through
    /// [`try_new_crt`](PrivateKey::try_new_crt) instead.
    pub fn try_new(n: &[u8], e: &[u8], d: &[u8]) -> Result<Self, Error> {
        let public = PublicKey::try_new(n, e)?;
        let raw = Private::try_new(&public.raw, d)?;
        Ok(PrivateKey { public, raw })
    }

    /// A decryption key with its Chinese remainder pieces, in the
    /// order the PKCS#1 `RSAPrivateKey` structure carries them: `p`
    /// and `q` exactly half the modulus wide with their top bits
    /// set, the reduced exponents `dp` and `dq`, and `qinv`, the
    /// inverse of `q` modulo `p`.
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
        let public = PublicKey::try_new(n, e)?;
        let raw = Private::try_new_crt(&public.raw, d, p, q, dp, dq, qinv)?;
        Ok(PrivateKey { public, raw })
    }

    /// The public half.
    pub fn public_key(&self) -> &PublicKey<LIMBS, BYTES> {
        &self.public
    }

    /// Generates a fresh decryption key, with the public exponent
    /// 65537 and every Chinese remainder piece in place.
    ///
    /// The primes are random probable primes: trial division, then
    /// Miller-Rabin with random witnesses, with round counts read
    /// from FIPS 186-5 for random candidates of 1024 bits and up.
    /// Widths below [`Rsa2048PrivateKey`] are for interoperation
    /// and tests, not for new keys. Generation is the one operation
    /// here whose time varies with its secrets: how many candidates
    /// fall to the primality tests depends on the randomness drawn.
    pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
        let (public, raw) = Private::generate(rng)?;
        Ok(PrivateKey {
            public: PublicKey { raw: public },
            raw,
        })
    }

    /// The private exponent, big-endian. The caller holds a secret
    /// now, and should wipe it when done.
    pub fn d_bytes(&self) -> [u8; BYTES] {
        self.raw.d_bytes()
    }

    /// Writes the Chinese remainder pieces, big-endian, into five
    /// buffers of half the modulus width each. Fails with
    /// [`Error::InvalidPrivateKey`] on a key imported without them,
    /// and [`Error::InvalidLength`] on a buffer of the wrong size.
    /// The caller holds secrets now, and should wipe them when done.
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

    /// A decryption key from its DER PKCS#8 `PrivateKeyInfo` (RFC 5208;
    /// the RFC 5958 form with a public key attached reads too), the
    /// form under `PRIVATE KEY` in a PEM file. The algorithm must be
    /// `rsaEncryption`, as for [`PublicKey::try_from_der`].
    ///
    /// The `RSAPrivateKey` inside carries the primes, so the key
    /// comes in as if through [`try_new_crt`](Self::try_new_crt),
    /// with the same checks. A multi-prime key, or anything else
    /// wrong with the bytes, is [`Error::InvalidEncoding`]; a
    /// modulus of another width is [`Error::InvalidKeyLength`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        let (public, raw) = Private::from_pkcs8(der, false)?;
        Ok(PrivateKey {
            public: PublicKey { raw: public },
            raw,
        })
    }

    /// Writes the key as a `PrivateKeyInfo` under `rsaEncryption`
    /// into the front of `out`, returning the length. `5 * BYTES`
    /// suffices for any key of 1024 bits or more; a buffer too
    /// small gets [`Error::OutputTooSmall`] with the exact need.
    ///
    /// Fails with [`Error::InvalidPrivateKey`] on a key imported
    /// without its primes, as [`crt_bytes`](Self::crt_bytes) does:
    /// the structure has no place for their absence. The output is
    /// a secret, and the caller should wipe it when done.
    pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pkcs8_bytes(&self.public.raw, out)
    }

    /// A decryption key from the bare PKCS#1 `RSAPrivateKey` (RFC 8017
    /// A.1.2), the form under `RSA PRIVATE KEY`, which is what the
    /// `PrivateKeyInfo` wraps.
    pub fn try_from_pkcs1(der: &[u8]) -> Result<Self, Error> {
        let (public, raw) = Private::from_pkcs1(der)?;
        Ok(PrivateKey {
            public: PublicKey { raw: public },
            raw,
        })
    }

    /// Writes the bare `RSAPrivateKey`, as [`der_bytes`](Self::der_bytes)
    /// does the wrapped one, with the same needs and the same
    /// refusal.
    pub fn pkcs1_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pkcs1_bytes(&self.public.raw, out)
    }

    /// A decryption key from a PEM block (RFC 7468) labelled `PRIVATE KEY`
    /// or `RSA PRIVATE KEY`, holding the matching DER form above.
    /// Whitespace and line ends are read leniently; anything else
    /// that is not exactly one well-formed block, an encrypted key
    /// included, is [`Error::InvalidEncoding`].
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        let (public, raw) = Private::from_pem(pem, false)?;
        Ok(PrivateKey {
            public: PublicKey { raw: public },
            raw,
        })
    }

    /// Writes the key as a `PRIVATE KEY` PEM block, ASCII with LF
    /// line ends, into the front of `out`, returning the length.
    /// `8 * BYTES` suffices for any key of 1024 bits or more. The
    /// same refusal as [`der_bytes`](Self::der_bytes), and the same
    /// secret to wipe.
    pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pem_bytes(&self.public.raw, out, false)
    }

    /// The same as an `RSA PRIVATE KEY` block, around the PKCS#1
    /// form.
    pub fn pkcs1_pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.pem_bytes(&self.public.raw, out, true)
    }

    /// The RSA decryption primitive, RSADP of RFC 8017: raises
    /// `ciphertext` to the private exponent, through the primes when
    /// the key carries them, with no padding removed.
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
    /// or above the modulus. As everywhere else in the crate, a
    /// result computed through the primes is checked with the public
    /// exponent before it is returned.
    pub fn decrypt_primitive(
        &self,
        ciphertext: &[u8; BYTES],
    ) -> Result<[u8; BYTES], Error> {
        // The scheme owns this check everywhere else; the primitive
        // has no scheme above it, so it makes the check itself.
        if !self.public.raw.in_range(ciphertext) {
            return Err(Error::DecryptionFailed);
        }
        self.raw.apply(&self.public.raw, ciphertext)
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
    pub fn decrypt_oaep<H: Hash>(
        &self,
        label: &[u8],
        ciphertext: &[u8; BYTES],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let h_len = H::Output::SIZE;
        if BYTES < 2 * h_len + 2 {
            return Err(Error::DecryptionFailed);
        }
        let longest = BYTES - 2 * h_len - 2;
        if out.len() < longest {
            return Err(Error::OutputTooSmall(longest));
        }
        // The range check is on the public ciphertext.
        let c = Uint::<LIMBS>::from_be_bytes(ciphertext);
        if c.less_than(self.public.raw.m.modulus()) == 0 {
            return Err(Error::DecryptionFailed);
        }
        let mut em = self.raw.apply(&self.public.raw, ciphertext)?;

        // Unmask: the seed under the masked DB, then DB under the
        // seed.
        let (head, db) = em.split_at_mut(1 + h_len);
        mgf1_xor::<H>(db, &mut head[1..])?;
        mgf1_xor::<H>(&head[1..], db)?;

        // One flag accumulates every check: the leading zero byte,
        // the label hash, and the zeros-then-0x01 frame around the
        // message.
        let mut bad = head[0];
        let lhash = H::digest(label)?;
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

    const N2048: &str =
        "ba5d6c10c1d21779df565ebeba34c4e297f2d39e886edb20ff84f39522d62437\
         b8226ebbfd03aa28427c1105eb24f5aa823c25f8a34658a1e0717f0998b4f6f4\
         7eb7bb1d1747a3db256bea209b32a70f2ef5e72ef88caf8696fdb452d8abc583\
         87b0a34016c022947798efc51b2b90d4a1998ae3f267c2623f8fabc4bf7e431d\
         e3fdf8c4e3d0092ec4f921c89d0f099f36f483663a1709a88c97b60842782b11\
         c70bd6b5c22293fcef63ed6dca4bcf274255eb0d35eaf6ba1d3b6367bfeba4af\
         fdb0e35b15cead4e8f925e4809e25d603b2cec1c72c644ca7f5cb5083a75f147\
         0c9ea038935fcac5c5744156aaf70c8d771da6d2a5e802d571f07d95edfa9721";

    const D2048: &str =
        "0e04ed162d9e6249b6b546974e669dd0f5e13c6e16915046a1321d28c0e01f05\
         5a02ad15d328ad6a2de62b59a8a0b522487dc1d57c62d454091040a0362e96cd\
         39a3149e519c0005824125f1a1fb237a0eec4ca1c9ecbb5f82883f42642e37c3\
         7737a07037c5e85406d32866496ef38c2b43e3a0d6215c0c0c0000c9e225db62\
         891cffdd88fb5121fa1d84d23852de08f44a5c2e09481cbd8d41935394b69cde\
         e6413781fc722d424bb9e52ed25d895a7f751c054ca38ef6c152be26f5186e60\
         fc800b54b7dc697c37a93effb601a46323670ad5f289c7894bb8df2a74bf271f\
         24c48d037f06551ed47ad41d60b258728397734a41c0e40b71aa60d790a6fd61";

    const N1024: &str =
        "cf2a9ef8634206418550ed3586e4f9cde5a43e54d528ac70f1424d6f9472e478\
         e17815dae8b0b3dce84522e7db2ab04f7473e0cbe4881cffd6a4d0cafb3852d4\
         34f7ef03d5de1c180dc3a175d8f47b434dd672839497c4499d5dada21ca4de6f\
         f531f0b91dd883eda6eda3384b783831e5f8c63a14733e9b428257ba4a71aa29";

    const D1024: &str =
        "463303965890156d9b5ece5a9e80b5b352f72255fdbb201fcf68efb37922ab8f\
         d89b2810bb5bb13f1087e8e997273282620c2826ff242e6b7510f95d66de7196\
         31ca4e2977985f7479b068ac0a6fa7fbae5b2e972cbf0a7a662ec5cc4e2a43b6\
         a6a898d3a42a4ca5e7cd511c0451fcecdf01081e7a6e9ba688c06b089821df17";

    const E: &[u8] = &[0x01, 0x00, 0x01];

    fn key2048() -> Rsa2048PrivateKey {
        PrivateKey::try_new(&unhex::<256>(N2048), E, &unhex::<256>(D2048))
            .unwrap()
    }

    fn key1024() -> Rsa1024PrivateKey {
        PrivateKey::try_new(&unhex::<128>(N1024), E, &unhex::<128>(D1024))
            .unwrap()
    }

    const OAEP_SEED256: &str =
        "afa64f41e1e367d9972a04d1d5ad16500c55c7dc8ad700cfd013b3249233e0ab";

    const OAEP_SHA256_NOLABEL: &str =
        "6c873891ace82ee30335d64cb0f10e2ca182129f2fa3ef25ced68943d1267cac\
         00c5dcd316bd7d5e615e5ee315e40a8f7e7da786f7c182ce7ea72b292fff6dce\
         cde22e13bdefb0fdf1b4f84fa9c276389672d919c124f78a38fb058a9189395e\
         1fb088c86060c2f5cc6f88dc0d1deb026c6cb852f8f468369a19de86954526fc\
         fa5b729022435127ffae79364eadc61a37d8a4c546317843392581a6b3caac2c\
         961544bbceb9187df38332ad77def0ed45b5f8d3d898edede5cb4aa5687dfc50\
         1306ca3af74e20fa9f44a16ec60c0c62d5fd52bd7317f01acfb3acec81fb6c98\
         1af64549e9faa69f8917987154ca83128e66d8b16af1bd16f49ed92c996dd618";

    const OAEP_SHA256_LABEL: &str =
        "11d42b6db867974fc4e0bf205b1f44f83d4d663b8c100c426142094b615ac840\
         847d43ee33a878185c352c9b0f76d4233e07c1c61a3927fe61f95ba7c5b1a5a8\
         9fcaecc666fbcd693ee03a056c3628ca10de3fb0a04e24cf5e4028da85740a48\
         7276ee9df78e4bdd104f671389af6c97eed1db7b43dac52e299b830d0850fb7a\
         744078202cc72ba74475ede6a9b9e3f65ac68262613962a8534cf695dd1a5328\
         f0505c4cd830d1f5acd41d98b1f6769da8b776de79f988fb12a7196328f66515\
         3f338e4216fcf5f5357c957d4220be215f7288e243c4c89ea09df6220f954a93\
         5141beda826aa5a37da12933dd0e9edaebe9adfbab5668432373f7c96ee0e81f";

    const OAEP_SHA512: &str =
        "43f41cb0ee6164d5a4035ac86ed250408ede7a45120ec94ff7d8810d2d0b2318\
         bfb201bbee46ee795ba801b1201cc7f6b64a82ecda24f1291bd14c4382884081\
         29c5bd293dd88812d97339b341e127fa7c0cfda7f01c2a847e3bf3bcfb3488b3\
         39b84446466e07274ef6a53076f43f1c129cc4b8448d46fc3d54873d44c53788\
         ca5ca25d40b87f2e3638e0766454188513e4a10d957979116604b71a544b5b93\
         c3880005c176a19c31345caa60678a3db7983047b856489349677205fde61035\
         134006eb65da88bed184fecbf6a2db827280b2b20ae7d756ae3374eaa34adcd7\
         5ebca5f7374717ee9c41f33d497b93ab3498ef0e2e2eb94545ddf60230922228";

    const OAEP_SHA256_MAX: &str =
        "2fdba0e5a0e0ea429e9d42c864107ebb35aa363fee342edfb2585930b56a416e\
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

        let c = public.oaep_encode::<Sha256>(&seed, b"", msg).unwrap();
        assert_eq!(c, unhex::<256>(OAEP_SHA256_NOLABEL));
        let n = key.decrypt_oaep::<Sha256>(b"", &c, &mut out).unwrap();
        assert_eq!(&out[..n], msg);

        let c = public
            .oaep_encode::<Sha256>(&seed, b"the label", msg)
            .unwrap();
        assert_eq!(c, unhex::<256>(OAEP_SHA256_LABEL));
        let n = key
            .decrypt_oaep::<Sha256>(b"the label", &c, &mut out)
            .unwrap();
        assert_eq!(&out[..n], msg);

        // The largest message that fits with SHA-256.
        let mut big = [0u8; 256 - 64 - 2];
        for (i, byte) in big.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let c = public.oaep_encode::<Sha256>(&seed, b"", &big).unwrap();
        assert_eq!(c, unhex::<256>(OAEP_SHA256_MAX));
        let n = key.decrypt_oaep::<Sha256>(b"", &c, &mut out).unwrap();
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
        assert_eq!(c, unhex::<256>(OAEP_SHA512));
        let mut out = [0u8; 256];
        let n = key.decrypt_oaep::<Sha512>(b"", &c, &mut out).unwrap();
        assert_eq!(&out[..n], msg);
    }

    /// A fresh random seed round-trips, and an empty message is a
    /// message.
    #[test]
    fn oaep_round_trips() {
        use crate::random::{Rng, System};
        let mut rng = Rng::try_new(System::try_new().unwrap()).unwrap();
        let key = key1024();
        let public = key.public_key();
        let mut out = [0u8; 128];
        let c = public
            .encrypt_oaep::<Sha256, _>(&mut rng, b"", b"hello")
            .unwrap();
        let n = key.decrypt_oaep::<Sha256>(b"", &c, &mut out).unwrap();
        assert_eq!(&out[..n], b"hello");
        let c = public
            .encrypt_oaep::<Sha256, _>(&mut rng, b"", b"")
            .unwrap();
        let n = key.decrypt_oaep::<Sha256>(b"", &c, &mut out).unwrap();
        assert_eq!(n, 0);
    }

    /// A generated key encrypts and decrypts, and round-trips its
    /// parts through export and CRT import.
    #[test]
    fn generated_key_round_trips() {
        use crate::random::{Rng, System};
        let mut rng = Rng::try_new(System::try_new().unwrap()).unwrap();
        let key = Rsa1024PrivateKey::generate(&mut rng).unwrap();
        let mut out = [0u8; 128];
        let c = key
            .public_key()
            .encrypt_oaep::<Sha256, _>(&mut rng, b"", b"session key")
            .unwrap();
        let n = key.decrypt_oaep::<Sha256>(b"", &c, &mut out).unwrap();
        assert_eq!(&out[..n], b"session key");

        let nb = key.public_key().modulus_bytes();
        let e = key.public_key().exponent_bytes();
        let d = key.d_bytes();
        let mut p = [0u8; 64];
        let mut q = [0u8; 64];
        let mut dp = [0u8; 64];
        let mut dq = [0u8; 64];
        let mut qinv = [0u8; 64];
        key.crt_bytes(&mut p, &mut q, &mut dp, &mut dq, &mut qinv)
            .unwrap();
        let again = Rsa1024PrivateKey::try_new_crt(
            &nb, &e, &d, &p, &q, &dp, &dq, &qinv,
        )
        .unwrap();
        let n = again.decrypt_oaep::<Sha256>(b"", &c, &mut out).unwrap();
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
        // A representative at or above the modulus.
        assert_eq!(
            key.decrypt_oaep::<Sha256>(b"", &[0xff; 256], &mut out),
            Err(Error::DecryptionFailed),
        );
        // Too small an output buffer is its own, public error.
        assert_eq!(
            key.decrypt_oaep::<Sha256>(b"", &c, &mut [0u8; 8]),
            Err(Error::OutputTooSmall(256 - 64 - 2)),
        );
        // A message the key cannot carry.
        assert_eq!(
            key.public_key().oaep_encode::<Sha256>(
                &seed,
                b"",
                &[0u8; 256 - 64 - 1],
            ),
            Err(Error::MessageTooLong),
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

        let c = public.encrypt_primitive(&m).unwrap();
        assert_ne!(c, m, "the primitive did nothing");
        assert_eq!(key.decrypt_primitive(&c).unwrap(), m);
    }

    /// A representative at or above the modulus is refused by both
    /// directions, each naming its own error.
    #[test]
    fn primitives_reject_out_of_range() {
        let key = key2048();
        let public = key.public_key();
        let n = unhex::<256>(N2048);
        assert_eq!(public.encrypt_primitive(&n), Err(Error::MessageTooLong));
        assert_eq!(key.decrypt_primitive(&n), Err(Error::DecryptionFailed));

        let mut under = n;
        under[255] -= 1;
        assert!(public.encrypt_primitive(&under).is_ok());
        assert!(key.decrypt_primitive(&under).is_ok());
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
        let em = key.decrypt_primitive(&sealed).unwrap();
        // OAEP's encoded message always has a zero leading byte.
        assert_eq!(em[0], 0);
    }

    /// A key goes through both containers and both PEM labels and
    /// decrypts what the original's public half encrypted; the
    /// public half round-trips too.
    #[test]
    fn formats_round_trip() {
        let mut rng = crate::random::Rng::try_new(
            crate::random::System::try_new().unwrap(),
        )
        .unwrap();
        let key = Rsa1024PrivateKey::generate(&mut rng).unwrap();
        let sealed = key
            .public_key()
            .encrypt_oaep::<Sha256, _>(&mut rng, b"", b"session key")
            .unwrap();
        let mut out = [0u8; 8 * 128];
        let mut msg = [0u8; 128];

        let n = key.der_bytes(&mut out).unwrap();
        let backs = [
            Rsa1024PrivateKey::try_from_der(&out[..n]).unwrap(),
            {
                let n = key.pkcs1_bytes(&mut out).unwrap();
                Rsa1024PrivateKey::try_from_pkcs1(&out[..n]).unwrap()
            },
            {
                let n = key.pem_bytes(&mut out).unwrap();
                Rsa1024PrivateKey::try_from_pem(&out[..n]).unwrap()
            },
            {
                let n = key.pkcs1_pem_bytes(&mut out).unwrap();
                Rsa1024PrivateKey::try_from_pem(&out[..n]).unwrap()
            },
        ];
        for back in &backs {
            assert_eq!(back.d_bytes(), key.d_bytes());
            let n =
                back.decrypt_oaep::<Sha256>(b"", &sealed, &mut msg).unwrap();
            assert_eq!(&msg[..n], b"session key");
        }

        let public = key.public_key();
        let n = public.der_bytes(&mut out).unwrap();
        let backs = [
            Rsa1024PublicKey::try_from_der(&out[..n]).unwrap(),
            {
                let n = public.pkcs1_bytes(&mut out).unwrap();
                Rsa1024PublicKey::try_from_pkcs1(&out[..n]).unwrap()
            },
            {
                let n = public.pem_bytes(&mut out).unwrap();
                Rsa1024PublicKey::try_from_pem(&out[..n]).unwrap()
            },
            {
                let n = public.pkcs1_pem_bytes(&mut out).unwrap();
                Rsa1024PublicKey::try_from_pem(&out[..n]).unwrap()
            },
        ];
        for back in &backs {
            assert_eq!(back.modulus_bytes(), public.modulus_bytes());
            let sealed = back
                .encrypt_oaep::<Sha256, _>(&mut rng, b"", b"again")
                .unwrap();
            let n = key.decrypt_oaep::<Sha256>(b"", &sealed, &mut msg).unwrap();
            assert_eq!(&msg[..n], b"again");
        }
    }

    /// A key marked for PSS signing is not a decryption key, and a
    /// key without its primes cannot be written.
    #[test]
    fn pss_keys_and_plain_keys_are_refused() {
        let mut rng = crate::random::Rng::try_new(
            crate::random::System::try_new().unwrap(),
        )
        .unwrap();
        let key = Rsa1024PrivateKey::generate(&mut rng).unwrap();
        let mut out = [0u8; 8 * 128];
        let n = key.der_bytes(&mut out).unwrap();
        let oid_end = out[..n]
            .windows(9)
            .position(|w| w == crate::der::RSA_ENCRYPTION)
            .unwrap()
            + 8;
        out[oid_end] = 0x0a;
        assert_eq!(
            Rsa1024PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
        let n = key.public_key().der_bytes(&mut out).unwrap();
        let oid_end = out[..n]
            .windows(9)
            .position(|w| w == crate::der::RSA_ENCRYPTION)
            .unwrap()
            + 8;
        out[oid_end] = 0x0a;
        assert_eq!(
            Rsa1024PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );

        let plain = key1024();
        assert_eq!(plain.der_bytes(&mut out), Err(Error::InvalidPrivateKey));
        assert_eq!(plain.pem_bytes(&mut out), Err(Error::InvalidPrivateKey));
    }
}
