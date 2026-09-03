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
//! The width of a key is part of its type: [`Rsa2048PrivateKey`]
//! holds a 2048-bit modulus, and the general [`PrivateKey`] takes
//! the limb and byte counts for any other width, with no ceiling.
//! Keys are imported from their integer parts, or generated fresh
//! by [`PrivateKey::generate`], which fixes the public exponent at
//! 65537 and derives every Chinese remainder piece; the accessors
//! on both key types hand the parts back for storage.
//!
//! Keys also read and write the formats everything else stores
//! them in: a public key as a DER `SubjectPublicKeyInfo` and a
//! private key as PKCS#8, through [`try_from_der`] and
//! [`der_bytes`] on each type, the bare PKCS#1 structures inside
//! those through `try_from_pkcs1` and `pkcs1_bytes`, and any of
//! them in PEM through `try_from_pem` and the `pem_bytes` pair. A
//! signing key may be marked `rsaEncryption` or `id-RSASSA-PSS`
//! when it comes in, and goes out as the former.
//!
//! [`try_from_der`]: PrivateKey::try_from_der
//! [`der_bytes`]: PrivateKey::der_bytes
//!
//! Generation is the one operation here whose time varies with its
//! secrets: how many candidates fall to the primality tests depends
//! on the randomness drawn, as it does in every implementation. The
//! arithmetic under each candidate is still fixed-sequence.
//!
//! A key imported with its primes, through
//! [`PrivateKey::try_new_crt`], signs by the Chinese remainder
//! theorem: two half-width exponentiations in place of one full one,
//! roughly three times faster. Every CRT signature is checked with
//! the public exponent before release, because a wrong result there
//! is not merely wrong: one faulty CRT signature factors the modulus
//! (Boneh, DeMillo and Lipton), so nothing unchecked ever leaves.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::sig::rsa::{Rsa1024PrivateKey, Rsa1024PublicKey};
//!
//! # fn unhex<const N: usize>(hex: &str) -> [u8; N] {
//! #     let mut out = [0u8; N];
//! #     for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
//! #         let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
//! #         let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
//! #         *byte = hi << 4 | lo;
//! #     }
//! #     out
//! # }
//! # fn main() -> Result<(), scytale::Error> {
//! # let n = unhex::<128>(concat!(
//! #     "cf2a9ef8634206418550ed3586e4f9cde5a43e54d528ac70f1424d6f9472e478",
//! #     "e17815dae8b0b3dce84522e7db2ab04f7473e0cbe4881cffd6a4d0cafb3852d4",
//! #     "34f7ef03d5de1c180dc3a175d8f47b434dd672839497c4499d5dada21ca4de6f",
//! #     "f531f0b91dd883eda6eda3384b783831e5f8c63a14733e9b428257ba4a71aa29",
//! # ));
//! # let d = unhex::<128>(concat!(
//! #     "463303965890156d9b5ece5a9e80b5b352f72255fdbb201fcf68efb37922ab8f",
//! #     "d89b2810bb5bb13f1087e8e997273282620c2826ff242e6b7510f95d66de7196",
//! #     "31ca4e2977985f7479b068ac0a6fa7fbae5b2e972cbf0a7a662ec5cc4e2a43b6",
//! #     "a6a898d3a42a4ca5e7cd511c0451fcecdf01081e7a6e9ba688c06b089821df17",
//! # ));
//! // n, e and d imported from wherever the key lives.
//! let key = Rsa1024PrivateKey::try_new(&n, &[0x01, 0x00, 0x01], &d)?;
//!
//! // A fresh random salt of the digest's length is the usual
//! // choice; an empty salt makes the signature deterministic.
//! let salt = [0x5a; 32];
//! let signature = key.sign_pss::<Sha256>(b"the message", &salt)?;
//! let public = key.public_key();
//! public.verify_pss::<Sha256>(b"the message", &signature, salt.len())?;
//!
//! // The public half in the form a certificate or a peer expects.
//! let mut der = [0u8; 2 * 128];
//! let n = public.der_bytes(&mut der)?;
//! let public = Rsa1024PublicKey::try_from_der(&der[..n])?;
//! public.verify_pss::<Sha256>(b"the message", &signature, salt.len())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! The private exponentiation is a fixed sequence of limb operations
//! whose reads never depend on `d` or the primes. Verification, and
//! the padding checks on both sides, handle only public values.

use crate::cipher::Block;
use crate::hash::Hash;
use crate::math::rsa::{mgf1_xor, Private, Public};
use crate::random::Random;
use crate::Error;

/// A hash that PKCS#1 v1.5 can name: one with a DER `DigestInfo`
/// prefix. All the SHA-2 and SHA-3 digests have one, under the one
/// NIST arc; PSS needs no such name and takes any [`Hash`].
pub trait DigestInfo: Hash {
    /// The final byte of the OID 2.16.840.1.101.3.4.2.x.
    const OID: u8;
}

macro_rules! digest_info {
    ($($hash:ty => $oid:expr,)*) => {
        $(impl DigestInfo for $hash {
            const OID: u8 = $oid;
        })*
    };
}

digest_info! {
    crate::hash::sha2::Sha224 => 4,
    crate::hash::sha2::Sha256 => 1,
    crate::hash::sha2::Sha384 => 2,
    crate::hash::sha2::Sha512 => 3,
    crate::hash::sha2::Sha512_224 => 5,
    crate::hash::sha2::Sha512_256 => 6,
    crate::hash::sha3::Sha3_224 => 7,
    crate::hash::sha3::Sha3_256 => 8,
    crate::hash::sha3::Sha3_384 => 9,
    crate::hash::sha3::Sha3_512 => 10,
}

/// The 19 bytes of DER in front of the digest: two SEQUENCEs, the
/// algorithm's OID, a NULL, and the OCTET STRING header.
fn digest_info_prefix(oid: u8, digest_len: usize) -> [u8; 19] {
    [
        0x30,
        0x11 + digest_len as u8,
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
        oid,
        0x05,
        0x00,
        0x04,
        digest_len as u8,
    ]
}

/// An RSA verification key of `LIMBS` 64-bit words; `BYTES` is the
/// same width in bytes, 8 times `LIMBS`, and is the length of every
/// signature. The width aliases below fill both in.
pub struct PublicKey<const LIMBS: usize, const BYTES: usize> {
    raw: Public<LIMBS, BYTES>,
}

/// An RSA signing key. The public half rides along, and every
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

/// A 2048-bit verification key.
pub type Rsa2048PublicKey = PublicKey<32, 256>;
/// A 2048-bit signing key.
pub type Rsa2048PrivateKey = PrivateKey<32, 256, 16>;
/// A 3072-bit verification key.
pub type Rsa3072PublicKey = PublicKey<48, 384>;
/// A 3072-bit signing key.
pub type Rsa3072PrivateKey = PrivateKey<48, 384, 24>;
/// A 4096-bit verification key.
pub type Rsa4096PublicKey = PublicKey<64, 512>;
/// A 4096-bit signing key.
pub type Rsa4096PrivateKey = PrivateKey<64, 512, 32>;
/// A 1024-bit verification key: legacy interoperation only, too
/// small for new uses.
pub type Rsa1024PublicKey = PublicKey<16, 128>;
/// A 1024-bit signing key: legacy interoperation only.
pub type Rsa1024PrivateKey = PrivateKey<16, 128, 8>;

impl<const LIMBS: usize, const BYTES: usize> PublicKey<LIMBS, BYTES> {
    /// A verification key from its big-endian parts.
    ///
    /// The modulus must be exactly the type's width, top bit set,
    /// and odd. The exponent must be odd, at least 3, and fit eight
    /// bytes, which every deployed key's does.
    pub fn try_new(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            raw: Public::try_new(n, e)?,
        })
    }

    /// The RSA verification primitive, RSAVP1 of RFC 8017: raises
    /// `signature` to the public exponent and hands back the
    /// representative, with no padding removed and nothing checked.
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
    /// or above the modulus, which is the only input the primitive
    /// refuses.
    pub fn verify_primitive(
        &self,
        signature: &[u8; BYTES],
    ) -> Result<[u8; BYTES], Error> {
        self.raw.apply(signature).ok_or(Error::InvalidSignature)
    }

    /// Checks a PKCS#1 v1.5 signature over `message`.
    pub fn verify_pkcs1<H: DigestInfo>(
        &self,
        message: &[u8],
        signature: &[u8; BYTES],
    ) -> Result<(), Error> {
        let em = self.raw.apply(signature).ok_or(Error::InvalidSignature)?;
        let mut expected = [0u8; BYTES];
        encode_pkcs1::<H, BYTES>(message, &mut expected)?;
        if em == expected {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Checks a PSS signature over `message`, made with a salt of
    /// `salt_len` bytes.
    ///
    /// The length is a parameter of the scheme, not of the
    /// signature: RFC 8017 verifies against a fixed value, and a
    /// verifier that accepts whatever length the padding claims
    /// lets a signature swap parameter sets. Most protocols fix it
    /// at the digest length.
    pub fn verify_pss<H: Hash>(
        &self,
        message: &[u8],
        signature: &[u8; BYTES],
        salt_len: usize,
    ) -> Result<(), Error> {
        let mut em =
            self.raw.apply(signature).ok_or(Error::InvalidSignature)?;
        let h_len = H::Output::SIZE;
        if BYTES < h_len + salt_len + 2 {
            return Err(Error::InvalidSignature);
        }
        // EM = maskedDB || H || 0xbc, with the top bit clear because
        // the encoding is one bit narrower than the modulus.
        if em[BYTES - 1] != 0xbc || em[0] >> 7 != 0 {
            return Err(Error::InvalidSignature);
        }
        let db_len = BYTES - h_len - 1;
        let (masked_db, rest) = em.split_at_mut(db_len);
        let h = &rest[..h_len];

        let mut db = [0u8; BYTES];
        let db = &mut db[..db_len];
        db.copy_from_slice(masked_db);
        mgf1_xor::<H>(h, db)?;
        db[0] &= 0x7f;

        // DB = zeros || 0x01 || salt, with the salt exactly where
        // the fixed length puts it.
        let separator = db_len - salt_len - 1;
        if db[..separator].iter().any(|&b| b != 0) || db[separator] != 0x01 {
            return Err(Error::InvalidSignature);
        }
        let salt = &db[separator + 1..];

        let mut hasher = H::try_new()?;
        hasher.update(&[0u8; 8]);
        hasher.update(H::digest(message)?.as_ref());
        hasher.update(salt);
        if hasher.finalize().as_ref() == h {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// The modulus, big-endian.
    pub fn modulus_bytes(&self) -> [u8; BYTES] {
        self.raw.modulus_bytes()
    }

    /// The public exponent, big-endian in eight bytes.
    pub fn exponent_bytes(&self) -> [u8; 8] {
        self.raw.exponent_bytes()
    }

    /// A verification key from its DER `SubjectPublicKeyInfo` (RFC
    /// 5280), the form under `PUBLIC KEY` in a PEM file. The algorithm may be
    /// `rsaEncryption` or `id-RSASSA-PSS`; the parameters of the
    /// latter, which name a hash and a salt length, are not read,
    /// since those are chosen at each call here.
    ///
    /// The modulus must be the type's width, as with
    /// [`try_new`](Self::try_new); anything else wrong with the
    /// bytes is [`Error::InvalidEncoding`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            raw: Public::from_spki(der, true)?,
        })
    }

    /// Writes the key as a `SubjectPublicKeyInfo` under
    /// `rsaEncryption` into the front of `out`, returning the
    /// length. `2 * BYTES` always suffices; a buffer too small gets
    /// [`Error::OutputTooSmall`] with the exact need.
    pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.raw.spki_bytes(out)
    }

    /// A verification key from the bare PKCS#1 `RSAPublicKey` (RFC 8017
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

    /// A verification key from a PEM block (RFC 7468) labelled `PUBLIC KEY`
    /// or `RSA PUBLIC KEY`, holding the matching DER form above.
    /// Whitespace and line ends are read leniently; anything else
    /// that is not exactly one well-formed block is
    /// [`Error::InvalidEncoding`].
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            raw: Public::from_pem(pem, true)?,
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
    /// A signing key from its big-endian parts: the public modulus
    /// and exponent, then the private exponent, which must be
    /// nonzero and below the modulus. Signing uses `d` directly; a
    /// key that carries its primes should come in through
    /// [`try_new_crt`](PrivateKey::try_new_crt) instead.
    pub fn try_new(n: &[u8], e: &[u8], d: &[u8]) -> Result<Self, Error> {
        let public = PublicKey::try_new(n, e)?;
        let raw = Private::try_new(&public.raw, d)?;
        Ok(PrivateKey { public, raw })
    }

    /// A signing key with its Chinese remainder pieces, in the order
    /// the PKCS#1 `RSAPrivateKey` structure carries them: `p` and
    /// `q` exactly half the modulus wide with their top bits set,
    /// the reduced exponents `dp` and `dq`, and `qinv`, the inverse
    /// of `q` modulo `p`.
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
        let public = PublicKey::try_new(n, e)?;
        let raw = Private::try_new_crt(&public.raw, d, p, q, dp, dq, qinv)?;
        Ok(PrivateKey { public, raw })
    }

    /// The public half.
    pub fn public_key(&self) -> &PublicKey<LIMBS, BYTES> {
        &self.public
    }

    /// The RSA signature primitive, RSASP1 of RFC 8017: raises
    /// `message` to the private exponent, through the primes when
    /// the key carries them, with no encoding applied.
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
    /// at or above the modulus. As everywhere else in the crate, a
    /// result computed through the primes is checked with the public
    /// exponent before it is returned.
    pub fn sign_primitive(
        &self,
        message: &[u8; BYTES],
    ) -> Result<[u8; BYTES], Error> {
        // The scheme owns this check everywhere else; the primitive
        // has no scheme above it, so it makes the check itself.
        if !self.public.raw.in_range(message) {
            return Err(Error::MessageTooLong);
        }
        self.raw.apply(&self.public.raw, message)
    }

    /// Signs `message` with PKCS#1 v1.5 padding.
    pub fn sign_pkcs1<H: DigestInfo>(
        &self,
        message: &[u8],
    ) -> Result<[u8; BYTES], Error> {
        let mut em = [0u8; BYTES];
        encode_pkcs1::<H, BYTES>(message, &mut em)?;
        self.raw.apply(&self.public.raw, &em)
    }

    /// Signs `message` with PSS.
    ///
    /// The salt is the caller's: a fresh random string of the
    /// digest's length is the usual choice, and an empty salt gives
    /// a deterministic signature. It must leave room in the key's
    /// width for the digest and two framing bytes.
    pub fn sign_pss<H: Hash>(
        &self,
        message: &[u8],
        salt: &[u8],
    ) -> Result<[u8; BYTES], Error> {
        let h_len = H::Output::SIZE;
        if BYTES < h_len + salt.len() + 2 {
            return Err(Error::InvalidLength(salt.len()));
        }
        let mut em = [0u8; BYTES];
        let db_len = BYTES - h_len - 1;

        // H = hash(eight zeros || mHash || salt).
        let mut hasher = H::try_new()?;
        hasher.update(&[0u8; 8]);
        hasher.update(H::digest(message)?.as_ref());
        hasher.update(salt);
        let h = hasher.finalize();

        // DB = zeros || 0x01 || salt, masked by MGF1 of H.
        em[db_len - salt.len() - 1] = 0x01;
        em[db_len - salt.len()..db_len].copy_from_slice(salt);
        {
            let (db, _) = em.split_at_mut(db_len);
            mgf1_xor::<H>(h.as_ref(), db)?;
        }
        // One bit narrower than the modulus.
        em[0] &= 0x7f;
        em[db_len..BYTES - 1].copy_from_slice(h.as_ref());
        em[BYTES - 1] = 0xbc;
        self.raw.apply(&self.public.raw, &em)
    }

    /// Generates a fresh signing key, with the public exponent 65537
    /// and every Chinese remainder piece in place.
    ///
    /// The primes are random probable primes: trial division, then
    /// Miller-Rabin with random witnesses, with round counts read
    /// from FIPS 186-5 for random candidates of 1024 bits and up.
    /// Widths below [`Rsa2048PrivateKey`] are for interoperation
    /// and tests, not for new keys.
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

    /// A signing key from its DER PKCS#8 `PrivateKeyInfo` (RFC 5208;
    /// the RFC 5958 form with a public key attached reads too), the
    /// form under `PRIVATE KEY` in a PEM file. The algorithm may be
    /// `rsaEncryption` or `id-RSASSA-PSS`, as for
    /// [`PublicKey::try_from_der`].
    ///
    /// The `RSAPrivateKey` inside carries the primes, so the key
    /// comes in as if through [`try_new_crt`](Self::try_new_crt),
    /// with the same checks. A multi-prime key, or anything else
    /// wrong with the bytes, is [`Error::InvalidEncoding`]; a
    /// modulus of another width is [`Error::InvalidKeyLength`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        let (public, raw) = Private::from_pkcs8(der, true)?;
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

    /// A signing key from the bare PKCS#1 `RSAPrivateKey` (RFC 8017
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

    /// A signing key from a PEM block (RFC 7468) labelled `PRIVATE KEY`
    /// or `RSA PRIVATE KEY`, holding the matching DER form above.
    /// Whitespace and line ends are read leniently; anything else
    /// that is not exactly one well-formed block, an encrypted key
    /// included, is [`Error::InvalidEncoding`].
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        let (public, raw) = Private::from_pem(pem, true)?;
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
}

/// EMSA-PKCS1-v1_5: `0x00 0x01 0xff.. 0x00 DigestInfo`, filling the
/// buffer exactly.
fn encode_pkcs1<H: DigestInfo, const BYTES: usize>(
    message: &[u8],
    em: &mut [u8; BYTES],
) -> Result<(), Error> {
    let digest = H::digest(message)?;
    let t_len = 19 + H::Output::SIZE;
    if BYTES < t_len + 11 {
        // The key is too narrow for this digest.
        return Err(Error::InvalidKeyLength(BYTES));
    }
    em[0] = 0x00;
    em[1] = 0x01;
    em[2..BYTES - t_len - 1].fill(0xff);
    em[BYTES - t_len - 1] = 0x00;
    let prefix = digest_info_prefix(H::OID, H::Output::SIZE);
    em[BYTES - t_len..BYTES - H::Output::SIZE].copy_from_slice(&prefix);
    em[BYTES - H::Output::SIZE..].copy_from_slice(digest.as_ref());
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

    const V15_SHA256: &str =
        "16ec653a7b69873aea0a15006b7fa90df5d6f1473cb5c2d0a10dda835d6cef86\
         7ee607ac3592c780ee780b48e6077559c80c36689baa6a23d7d3fed16a712de7\
         6defc4d3512b83ce1fb7d0c49fa22edc51636482604ee14431a1ea92c1df1be6\
         3ac508ed5e835a0f8c132ac4553e208a5d14922853a89ed582e2c970b5e02a7a\
         9087a0f052ca496023e40e06066046501d3a6ea6be8e88c8a3c689431a5fa0dc\
         30e4f71899bfb63af05a8cea651e3ed1bbc3bd791ddd63934e25f6710c450946\
         132a5eef050f7ca0321a1d856b333a937b24fa68dc4283fc4b6b09b6ad71cddf\
         450b1f7d4a183b7d9452c5db9c43fb90d2cb3e2c479650d514026d760f59ce13";

    const V15_SHA512: &str =
        "1927f6ec5588b69c88f13a993a9e483d92ad5c3377d25679c9eb5db9ff01e0c3\
         4fcbb0e4054abe5883c19e328393718406c8fdd01cbdd96a5f5cc02d5ff4da02\
         517d4d2c17288938521302a56d495a41828f859299832ae242d06202a1092d83\
         9ece3c2e9ad50171c8ec83f1e56503d851967a113217cb6be5700c229942a5a8\
         181e82defdf089378bdadff6fa834a24d7600031e40e3f5ce076e6dd8b693bfe\
         118fd212e7e49b6f4cec59792baf9cab500f9f44df6b504953215abe8500eccc\
         b6b09ec76f826dc27f995627d012cdf6127131eb64518634fea9515714c300d9\
         245011176934a83fdb197465bbf3b888a68a0a13b50597931abf6afa858e0e4a";

    const PSS_SHA256_SALT32: &str =
        "2caa1d373513dca2174700db35674f96f1093c3bafb3af899d70117fb5536bfd\
         7ff04b9dbcd1d05812b945383dd6bbcf131e2b0ea791fa026d1f96f6e9c2b8d4\
         94595ef8d8eeba40099bc54eebce75c7ee8e694e58ef3be1f385807b8b806ece\
         09412eacffeb8ab82b45d679d4060895549490d2a1cb7bbde0dc1b5ae28f9577\
         b13df8c2377d5f5c3061ab0d87356e3cbab7039c86a80538ba8324c0a27f1957\
         847267b5a3a216b5ac0c36a7f971395d545c7f4907d661c915d728f2811d097e\
         8d27fc9f0f4b83cef525d7c8e1aa9f5b8d89c7be33736f5fe22d6c4c111a54ae\
         42897e65e977fee49e5c9445c0e1cd33534683b1ad3d3d61f5d1a85c68a758d2";

    const PSS_SHA256_SALT0: &str =
        "51074c83ad34151fc8831856759e58e429a151393ffd54675d0baf7aa14dbe31\
         79a3b4db881938bd7fd80cd4d626c7412e34daa56118be635bdb42ec17bb99ed\
         3084613bd10fe9e333c6d8eff1ea254c5a4a54d7ebcae7fa47048243b5444caa\
         c4539f1685c3628d11695244f388dfb220bc62b39ee5d562b069ed98cc000e9d\
         166609bd36c7d901568f8a1a16d4949e7c400392fb25053b08de601a7c19f0e5\
         44cb530fd3d03189229af4ece5ab9935ed6bb7f22a58788eceb7a2e8bc8c9819\
         be497a2295f2bdd4e696a64d63789070f7a0104839193d29d7ed327e8d5ad105\
         d75a69132cf1862eaba21925b51aba99c010aed0b050cfda9b78672950fc2977";

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

    const V15_1024_SHA256: &str =
        "139491453d895b6c59534d4301a0b732abffacc06501f3c3b2a69f0f6bcd04a0\
         e626eb143b14b1c763a4d97ee767942432784d9d6abd76a180d3bc1bd4c8476b\
         b30c4a02ed11d6c18a854dfef32c3692316649ccc4ce4e1e802f7603161df727\
         e68da996e4cf700a69720971c543eb1edac08ed60eb2dab98e05d6a1578f6715";

    const PSS_1024_SHA384_SALT32: &str =
        "2c4d6b7546da625ae4c235e5814170542111e50afe17a6e05ba8fe90f64d6e89\
         de3880bae7ee0d3ad40f9cd45e07074b4d25a9d28c4c367c32f00b3b81fabbb1\
         fc9a26cbaa03f8127a6d095444b57e8039e58b4412e900f43e8813538158ebd6\
         0bb18c574470aa9eef2a17394bf912a352823bb7497687176063ad80e69793b5";

    const E: &[u8] = &[0x01, 0x00, 0x01];

    fn key2048() -> Rsa2048PrivateKey {
        PrivateKey::try_new(&unhex::<256>(N2048), E, &unhex::<256>(D2048))
            .unwrap()
    }

    fn key1024() -> Rsa1024PrivateKey {
        PrivateKey::try_new(&unhex::<128>(N1024), E, &unhex::<128>(D1024))
            .unwrap()
    }

    /// Signatures match an independent implementation of RFC 8017,
    /// and verify, across both paddings and two hashes.
    #[test]
    fn known_answers_2048() {
        let key = key2048();
        let salt = unhex::<32>(SALT);

        let sig = key.sign_pkcs1::<Sha256>(MSG).unwrap();
        assert_eq!(sig, unhex::<256>(V15_SHA256));
        key.public_key().verify_pkcs1::<Sha256>(MSG, &sig).unwrap();

        let sig = key.sign_pkcs1::<Sha512>(MSG).unwrap();
        assert_eq!(sig, unhex::<256>(V15_SHA512));
        key.public_key().verify_pkcs1::<Sha512>(MSG, &sig).unwrap();

        let sig = key.sign_pss::<Sha256>(MSG, &salt).unwrap();
        assert_eq!(sig, unhex::<256>(PSS_SHA256_SALT32));
        key.public_key()
            .verify_pss::<Sha256>(MSG, &sig, 32)
            .unwrap();
        // The wrong expected length is the wrong parameter set.
        assert_eq!(
            key.public_key().verify_pss::<Sha256>(MSG, &sig, 0),
            Err(Error::InvalidSignature),
        );

        let sig = key.sign_pss::<Sha256>(MSG, &[]).unwrap();
        assert_eq!(sig, unhex::<256>(PSS_SHA256_SALT0));
        key.public_key().verify_pss::<Sha256>(MSG, &sig, 0).unwrap();
    }

    /// A second width exercises different const parameters end to
    /// end.
    #[test]
    fn known_answers_1024() {
        let key = key1024();
        let salt = unhex::<32>(SALT);

        let sig = key.sign_pkcs1::<Sha256>(MSG).unwrap();
        assert_eq!(sig, unhex::<128>(V15_1024_SHA256));
        key.public_key().verify_pkcs1::<Sha256>(MSG, &sig).unwrap();

        let sig = key.sign_pss::<Sha384>(MSG, &salt).unwrap();
        assert_eq!(sig, unhex::<128>(PSS_1024_SHA384_SALT32));
        key.public_key()
            .verify_pss::<Sha384>(MSG, &sig, 32)
            .unwrap();
    }

    #[test]
    fn rejects_tampering() {
        let key = key1024();
        let public = key.public_key();
        let v15 = key.sign_pkcs1::<Sha256>(MSG).unwrap();
        let pss = key.sign_pss::<Sha256>(MSG, &[0x42; 16]).unwrap();

        assert_eq!(
            public.verify_pkcs1::<Sha256>(b"other message", &v15),
            Err(Error::InvalidSignature),
        );
        assert_eq!(
            public.verify_pss::<Sha256>(b"other message", &pss, 16),
            Err(Error::InvalidSignature),
        );
        for sig in [&v15, &pss] {
            let mut bad = *sig;
            bad[0] ^= 1;
            assert_eq!(
                public.verify_pkcs1::<Sha256>(MSG, &bad),
                Err(Error::InvalidSignature),
            );
            assert_eq!(
                public.verify_pss::<Sha256>(MSG, &bad, 16),
                Err(Error::InvalidSignature),
            );
        }
        // The wrong hash is the wrong signature.
        assert_eq!(
            public.verify_pkcs1::<Sha384>(MSG, &v15),
            Err(Error::InvalidSignature),
        );
        // A representative at or above the modulus is refused
        // before any arithmetic.
        let too_big = [0xffu8; 128];
        assert_eq!(
            public.verify_pss::<Sha256>(MSG, &too_big, 16),
            Err(Error::InvalidSignature),
        );
    }

    #[test]
    fn rejects_bad_keys() {
        let n = unhex::<128>(N1024);
        let d = unhex::<128>(D1024);

        // Wrong length, top bit clear, and even moduli.
        assert!(matches!(
            Rsa1024PublicKey::try_new(&n[1..], E),
            Err(Error::InvalidKeyLength(127)),
        ));
        let mut low_top = n;
        low_top[0] = 0x01;
        assert!(matches!(
            Rsa1024PublicKey::try_new(&low_top, E),
            Err(Error::InvalidKeyLength(_)),
        ));
        let mut even = n;
        even[127] &= 0xfe;
        assert!(matches!(
            Rsa1024PublicKey::try_new(&even, E),
            Err(Error::InvalidPublicKey),
        ));

        // Even, tiny, and oversized public exponents.
        for e in [&[0x02][..], &[0x01], &[0xff; 9]] {
            assert!(matches!(
                Rsa1024PublicKey::try_new(&n, e),
                Err(Error::InvalidPublicKey),
            ));
        }

        // A zero or out-of-range private exponent.
        assert!(matches!(
            Rsa1024PrivateKey::try_new(&n, E, &[0u8; 4]),
            Err(Error::InvalidPrivateKey),
        ));
        assert!(matches!(
            Rsa1024PrivateKey::try_new(&n, E, &n),
            Err(Error::InvalidPrivateKey),
        ));
        let _ = d;
    }

    /// A salt that leaves no room for the digest and framing.
    #[test]
    fn rejects_oversized_salt() {
        let key = key1024();
        let salt = [0u8; 128 - 32 - 1];
        assert!(matches!(
            key.sign_pss::<Sha256>(MSG, &salt),
            Err(Error::InvalidLength(_)),
        ));
    }

    const P2048: &str =
        "c04e0031d3404e9e48359b0b872df10ddab383ef8a7d3552e8160bdba70265e5\
         5e547b4fea93ff124612c55a1810e8c868b06924577437d6470326d30a7a979e\
         24c9f0e1e0db637b83a6878722342840e62c97a3ec07ebbda011b621276519e4\
         6f9bb82f65e98ed31937795b2e9eaee610bbda1ddfef977274bb295687e1dee5";

    const Q2048: &str =
        "f817c62d739807f8e64e3a010ce43165eeb93c825875afe6351dd4b1bef7d124\
         5a9608408f93e4c17bec44644f7244c59f9ccf923875ef7a33d172cee7f245cd\
         e19285cd796f6d8479341643308405b976543b4968be72a578e25e611b7f8e76\
         dedee163025f11341f1e1d072dd890e9c2b5c58e307707267510a46d0457578d";

    const DP2048: &str =
        "9c38c17fb895ed48387113db719da8ce1074f5218be7db81d678d279465b745b\
         b91df86f1ba9cef51167fe5b0a61f2399c927357ca93e72873d7e39a5e50e90a\
         d7e8157fea234fd5ef4541a44ded012677d691f9e0ad2e9d8583dde9610f88d1\
         42b9c60efb43997b7468d4757692029373d4a784cd7ede1165330689fd2948e1";

    const DQ2048: &str =
        "d1bdd7afa96048ad2697cff5ff5e145d26dbb7ca42db0c20c59b38ac24d5021d\
         87effb7e0964712b1a877eb2877005b045e69e9df1d9d2e22f58cd851b16f9e8\
         bae1d2f909c72881acae5a7be752563c9b4b4eec1aff97914987a75ed58e9b74\
         e7aaea457845c3179b8f2bdf5be5116e6f4c997e427efeae869dd144d13cbe29";

    const QINV2048: &str =
        "7066b0f24630677e6ff95fabbefc030c8723481efdd8e7d9af52e057d10f6f98\
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

    fn crt_key_2048() -> Rsa2048PrivateKey {
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
        assert_eq!(sig, unhex::<256>(V15_SHA256));
        key.public_key().verify_pkcs1::<Sha256>(MSG, &sig).unwrap();

        let sig = key.sign_pss::<Sha256>(MSG, &salt).unwrap();
        assert_eq!(sig, unhex::<256>(PSS_SHA256_SALT32));
        key.public_key()
            .verify_pss::<Sha256>(MSG, &sig, 32)
            .unwrap();
    }

    /// Import cross-checks the pieces against one another.
    #[test]
    fn crt_rejects_inconsistent_parts() {
        let n = unhex::<256>(N2048);
        let d = unhex::<256>(D2048);
        let (p, q, dp, dq, qinv) = crt_parts_2048();
        let build = |p: &[u8], q: &[u8], dp: &[u8], dq: &[u8], qinv: &[u8]| {
            Rsa2048PrivateKey::try_new_crt(&n, E, &d, p, q, dp, dq, qinv)
        };

        // A prime that does not divide the modulus.
        let mut bad = p;
        bad[64] ^= 1;
        assert!(matches!(
            build(&bad, &q, &dp, &dq, &qinv),
            Err(Error::InvalidPrivateKey),
        ));
        // Swapped primes: the product still matches, qinv does not.
        assert!(matches!(
            build(&q, &p, &dq, &dp, &qinv),
            Err(Error::InvalidPrivateKey),
        ));
        // A wrong inverse.
        let mut bad = qinv;
        bad[64] ^= 1;
        assert!(matches!(
            build(&p, &q, &dp, &dq, &bad),
            Err(Error::InvalidPrivateKey),
        ));
        // The same prime twice.
        assert!(matches!(
            build(&p, &p, &dp, &dp, &qinv),
            Err(Error::InvalidPrivateKey),
        ));
        // A zero reduced exponent.
        assert!(matches!(
            build(&p, &q, &[0u8; 4], &dq, &qinv),
            Err(Error::InvalidPrivateKey),
        ));
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
        let key = Rsa2048PrivateKey::try_new_crt(
            &n, E, &d, &p, &q, &bad_dp, &dq, &qinv,
        )
        .unwrap();
        assert!(matches!(
            key.sign_pkcs1::<Sha256>(MSG),
            Err(Error::InvalidPrivateKey),
        ));
    }

    /// A generated key signs, verifies, exports, and re-imports both
    /// with and without its CRT pieces, all agreeing byte for byte.
    #[test]
    fn generates_working_keys() {
        use crate::random::{Rng, System};
        let mut rng = Rng::try_new(System::try_new().unwrap()).unwrap();
        let key = Rsa1024PrivateKey::generate(&mut rng).unwrap();

        let sig = key.sign_pss::<Sha256>(MSG, &[7u8; 16]).unwrap();
        key.public_key()
            .verify_pss::<Sha256>(MSG, &sig, 16)
            .unwrap();
        let sig = key.sign_pkcs1::<Sha256>(MSG).unwrap();
        key.public_key().verify_pkcs1::<Sha256>(MSG, &sig).unwrap();

        let n = key.public_key().modulus_bytes();
        let e = key.public_key().exponent_bytes();
        assert_eq!(e, [0, 0, 0, 0, 0, 1, 0, 1]);
        let d = key.d_bytes();
        let mut p = [0u8; 64];
        let mut q = [0u8; 64];
        let mut dp = [0u8; 64];
        let mut dq = [0u8; 64];
        let mut qinv = [0u8; 64];
        key.crt_bytes(&mut p, &mut q, &mut dp, &mut dq, &mut qinv)
            .unwrap();

        // Re-imported with CRT, and as a plain exponent: all three
        // keys make the same signature, which also proves d and the
        // CRT pieces agree.
        let with_crt =
            Rsa1024PrivateKey::try_new_crt(&n, &e, &d, &p, &q, &dp, &dq, &qinv)
                .unwrap();
        let plain = Rsa1024PrivateKey::try_new(&n, &e, &d).unwrap();
        assert_eq!(with_crt.sign_pkcs1::<Sha256>(MSG).unwrap(), sig);
        assert_eq!(plain.sign_pkcs1::<Sha256>(MSG).unwrap(), sig);
    }

    /// A dead random source cannot loop forever; it fails. The tiny
    /// width keeps the capped search cheap.
    #[test]
    fn generation_fails_without_entropy() {
        struct Zeros;
        impl crate::random::Random for Zeros {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
                out.fill(0);
                Ok(())
            }
        }
        assert!(matches!(
            PrivateKey::<2, 16, 1>::generate(&mut Zeros),
            Err(Error::KeyGenerationFailed),
        ));
    }

    /// Exporting CRT pieces from a key that has none, or into wrong
    /// buffers, is refused.
    #[test]
    fn crt_export_needs_crt_and_room() {
        let key = key1024();
        let plain = Rsa1024PrivateKey::try_new(
            &unhex::<128>(N1024),
            E,
            &unhex::<128>(D1024),
        )
        .unwrap();
        let mut small = [0u8; 63];
        let mut buf = [[0u8; 64]; 4];
        let [ref mut a, ref mut b, ref mut c, ref mut d] = buf;
        assert!(matches!(
            plain.crt_bytes(&mut small, a, b, c, d),
            Err(Error::InvalidPrivateKey),
        ));
        let crt_key = {
            let (p, q, dp, dq, qinv) = crt_parts_1024();
            Rsa1024PrivateKey::try_new_crt(
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
        assert!(matches!(
            crt_key.crt_bytes(&mut small, a, b, c, d),
            Err(Error::InvalidLength(63)),
        ));
        let _ = key;
    }

    const P1024: &str =
        "ded94047096410d910e4b796a631463c8ba4bc51a7f51007e47d00fe74b7bacc\
         5e1bef5fa160eb536e3ffbeb13d85458fd4cfa34308b779103a15be78c936247";

    const Q1024: &str =
        "edfc25751deed003561b8708d4403c9fff4f3d87f7f1127a82dfdb2b70bf9cb9\
         eea5a3c9db922400f7c204a31663ed1b09b8d0e62a6558db73473c7e3c85d80f";

    const DP1024: &str =
        "52c9ccfa56ffc8ce8b5b1ce527aaa898379ca4a5854b22807c1f006e87b7f5fa\
         947fb64705b1f6dad0db8e603fc81f55cc0c7beb45999a7ad22970f62da05763";

    const DQ1024: &str =
        "a65b8003a26cf1d3a33992e74517b24955bb1a941569db34f08f7331a69b0aff\
         9e27039b737570dd8c537fd2513080ea499d7bc9a9113750100157f41672a959";

    const QINV1024: &str =
        "2203ff0aa7f1629991e463adfebe4629dc50aee793221bf728347fb5ab03de34\
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
    /// covering the second width end to end.
    #[test]
    fn crt_matches_plain_signing_1024() {
        let (p, q, dp, dq, qinv) = crt_parts_1024();
        let key = Rsa1024PrivateKey::try_new_crt(
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
        assert_eq!(sig, unhex::<128>(V15_1024_SHA256));
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

        let s = key.sign_primitive(&m).unwrap();
        assert_eq!(public.verify_primitive(&s).unwrap(), m);
        assert_ne!(s, m, "the primitive did nothing");

        assert_eq!(crt_key_2048().sign_primitive(&m).unwrap(), s);
    }

    /// A representative at or above the modulus is refused by both
    /// directions, which is the only input either one rejects.
    #[test]
    fn primitives_reject_out_of_range() {
        let key = key2048();
        let public = key.public_key();
        let n = unhex::<256>(N2048);
        assert_eq!(key.sign_primitive(&n), Err(Error::MessageTooLong));
        assert_eq!(public.verify_primitive(&n), Err(Error::InvalidSignature));

        // One below the modulus is inside the range, so it works.
        let mut under = n;
        under[255] -= 1;
        assert!(key.sign_primitive(&under).is_ok());
        assert!(public.verify_primitive(&under).is_ok());
    }

    /// The scheme is built on the primitive, so a PSS signature is
    /// what the primitive gives for the encoding PSS produced.
    #[test]
    fn primitive_underlies_the_scheme() {
        let key = key2048();
        let signature = key.sign_pss::<Sha256>(b"a message", &[7; 32]).unwrap();
        let em = key.public_key().verify_primitive(&signature).unwrap();
        // The encoded message ends in PSS's trailer byte.
        assert_eq!(em[255], 0xbc);
        assert_eq!(key.sign_primitive(&em).unwrap(), signature);
    }

    fn generated() -> Rsa1024PrivateKey {
        let mut rng = crate::random::Rng::try_new(
            crate::random::System::try_new().unwrap(),
        )
        .unwrap();
        Rsa1024PrivateKey::generate(&mut rng).unwrap()
    }

    fn same_key(a: &Rsa1024PrivateKey, b: &Rsa1024PrivateKey) -> bool {
        a.d_bytes() == b.d_bytes()
            && a.public_key().modulus_bytes() == b.public_key().modulus_bytes()
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
        let back = Rsa1024PrivateKey::try_from_der(&der[..n]).unwrap();
        assert!(same_key(&back, &key));
        assert_eq!(back.sign_pkcs1::<Sha256>(MSG).unwrap(), sig);
        let back = Rsa1024PrivateKey::try_from_pkcs1(&pkcs1[..m]).unwrap();
        assert!(same_key(&back, &key));
        // A key that came through the structure signs through the
        // primes it carries.
        assert_eq!(back.sign_pkcs1::<Sha256>(MSG).unwrap(), sig);

        let n = key.pem_bytes(&mut pem).unwrap();
        assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
        let back = Rsa1024PrivateKey::try_from_pem(&pem[..n]).unwrap();
        assert!(same_key(&back, &key));
        let n = key.pkcs1_pem_bytes(&mut pem).unwrap();
        assert!(pem.starts_with(b"-----BEGIN RSA PRIVATE KEY-----\n"));
        let back = Rsa1024PrivateKey::try_from_pem(&pem[..n]).unwrap();
        assert!(same_key(&back, &key));

        let n = public.der_bytes(&mut der).unwrap();
        let m = public.pkcs1_bytes(&mut pkcs1).unwrap();
        assert!(der[..n].windows(m).any(|w| w == &pkcs1[..m]));
        for back in [
            Rsa1024PublicKey::try_from_der(&der[..n]).unwrap(),
            Rsa1024PublicKey::try_from_pkcs1(&pkcs1[..m]).unwrap(),
        ] {
            assert_eq!(back.modulus_bytes(), public.modulus_bytes());
            back.verify_pkcs1::<Sha256>(MSG, &sig).unwrap();
        }
        let n = public.pem_bytes(&mut pem).unwrap();
        assert!(pem.starts_with(b"-----BEGIN PUBLIC KEY-----\n"));
        let back = Rsa1024PublicKey::try_from_pem(&pem[..n]).unwrap();
        assert_eq!(back.modulus_bytes(), public.modulus_bytes());
        let n = public.pkcs1_pem_bytes(&mut pem).unwrap();
        assert!(pem.starts_with(b"-----BEGIN RSA PUBLIC KEY-----\n"));
        let back = Rsa1024PublicKey::try_from_pem(&pem[..n]).unwrap();
        assert_eq!(back.modulus_bytes(), public.modulus_bytes());
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

    /// The width is the type's, as when importing from parts.
    #[test]
    fn import_checks_the_width() {
        let key = generated();
        let mut out = [0u8; 8 * 128];
        let n = key.der_bytes(&mut out).unwrap();
        assert_eq!(
            Rsa2048PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidKeyLength(128))
        );
        let n = key.public_key().der_bytes(&mut out).unwrap();
        assert_eq!(
            Rsa2048PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidKeyLength(128))
        );
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
        Rsa1024PrivateKey::try_from_der(&out[..n]).unwrap();
        out[oid_end] = 0x02;
        assert_eq!(
            Rsa1024PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
        out[oid_end] = 0x01;
        assert_eq!(
            Rsa1024PrivateKey::try_from_der(&out[..n - 1]).err(),
            Some(Error::InvalidEncoding)
        );
        assert_eq!(
            Rsa1024PrivateKey::try_from_der(&out[..n + 1]).err(),
            Some(Error::InvalidEncoding)
        );
        let n = key.public_key().der_bytes(&mut out).unwrap();
        let oid_end = out[..n]
            .windows(9)
            .position(|w| w == crate::der::RSA_ENCRYPTION)
            .unwrap()
            + 8;
        out[oid_end] = 0x0a;
        Rsa1024PublicKey::try_from_der(&out[..n]).unwrap();
        out[oid_end] = 0x02;
        assert_eq!(
            Rsa1024PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );

        // The version field of RSAPrivateKey: 1 means multi-prime.
        let n = key.pkcs1_bytes(&mut out).unwrap();
        assert_eq!(out[..7], [0x30, 0x82, out[2], out[3], 0x02, 0x01, 0x00]);
        out[6] = 1;
        assert_eq!(
            Rsa1024PrivateKey::try_from_pkcs1(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );

        // A public block is not a private key, whatever it holds.
        let n = key.public_key().pem_bytes(&mut out).unwrap();
        assert_eq!(
            Rsa1024PrivateKey::try_from_pem(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
    }
}
