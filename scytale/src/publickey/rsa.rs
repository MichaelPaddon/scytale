//! RSA (RFC 8017): PSS and PKCS#1 v1.5 signatures, and OAEP
//! encryption.
//!
//! A key is a modulus `n`, the product of two secret primes, with a
//! public exponent `e` and a private exponent `d` that undo one
//! another. Signing raises an encoding of the message's digest to
//! `d`; anyone can raise the signature back through `e` and compare.
//! Encryption runs the other way: anyone can raise a padded message
//! through `e`, and only the key holder can bring it back.
//!
//! Two signature encodings are in use. PSS is the modern one, with a
//! security argument and a salt; PKCS#1 v1.5 is the fixed padding
//! that most deployed certificates still carry. Sign with PSS unless
//! a protocol demands otherwise; verify whichever the peer sends.
//! For encryption there is only OAEP here: the older PKCS#1 v1.5
//! encryption cannot be decrypted safely (Bleichenbacher's oracle)
//! and is not offered.
//!
//! Use a key for one job. A key that both signs and decrypts hands
//! an attacker two oracles against the same secret, and proofs for
//! either scheme assume it has the key to itself.
//!
//! The width of a key is part of its type: [`Rsa2048PrivateKey`]
//! holds a 2048-bit modulus, and the general [`PrivateKey`] takes
//! the limb and byte counts for any other width, with no ceiling.
//! Keys are imported from their integer parts, or generated fresh
//! by [`PrivateKey::generate`], which fixes the public exponent at
//! 65537 and derives every Chinese remainder piece; the accessors
//! on both key types hand the parts back for storage.
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
//! use scytale::publickey::rsa::Rsa1024PrivateKey;
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
//! key.public_key().verify_pss::<Sha256>(b"the message", &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! The private exponentiation is a fixed sequence of limb operations
//! whose reads never depend on `d` or the primes. Verification, and
//! the padding checks on both sides, handle only public values.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash::Hash;
use crate::math::montgomery::Montgomery;
use crate::math::uint::Uint;
use crate::random::Random;
use crate::symmetric::Block;
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

/// An RSA public key of `LIMBS` 64-bit words; `BYTES` is the same
/// width in bytes, 8 times `LIMBS`, and is the length of every
/// signature. The width aliases below fill both in.
pub struct PublicKey<const LIMBS: usize, const BYTES: usize> {
    m: Montgomery<LIMBS>,
    e: Uint<1>,
}

/// An RSA private key. The public half rides along, and every
/// private part is wiped on drop.
///
/// `HALF` is the width of one prime, half of `LIMBS`; the aliases
/// fill it in. It is a parameter only because the language cannot
/// yet derive it.
pub struct PrivateKey<const LIMBS: usize, const BYTES: usize, const HALF: usize>
{
    public: PublicKey<LIMBS, BYTES>,
    d: Uint<LIMBS>,
    crt: Option<Crt<HALF>>,
}

/// The Chinese remainder pieces of a private key.
struct Crt<const HALF: usize> {
    p: Montgomery<HALF>,
    q: Montgomery<HALF>,
    dp: Uint<HALF>,
    dq: Uint<HALF>,
    /// `q^-1 mod p`.
    qinv: Uint<HALF>,
}

/// A 2048-bit public key.
pub type Rsa2048PublicKey = PublicKey<32, 256>;
/// A 2048-bit private key.
pub type Rsa2048PrivateKey = PrivateKey<32, 256, 16>;
/// A 3072-bit public key.
pub type Rsa3072PublicKey = PublicKey<48, 384>;
/// A 3072-bit private key.
pub type Rsa3072PrivateKey = PrivateKey<48, 384, 24>;
/// A 4096-bit public key.
pub type Rsa4096PublicKey = PublicKey<64, 512>;
/// A 4096-bit private key.
pub type Rsa4096PrivateKey = PrivateKey<64, 512, 32>;
/// A 1024-bit public key: legacy interoperation only, too small for
/// new uses.
pub type Rsa1024PublicKey = PublicKey<16, 128>;
/// A 1024-bit private key: legacy interoperation only.
pub type Rsa1024PrivateKey = PrivateKey<16, 128, 8>;

impl<const LIMBS: usize, const BYTES: usize> PublicKey<LIMBS, BYTES> {
    /// A public key from its big-endian parts.
    ///
    /// The modulus must be exactly the type's width, top bit set,
    /// and odd. The exponent must be odd, at least 3, and fit eight
    /// bytes, which every deployed key's does.
    pub fn try_new(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        // A mismatched pair of const parameters is a bug at the
        // definition of an alias, not a runtime condition.
        assert_eq!(8 * LIMBS, BYTES, "BYTES must be 8 * LIMBS");
        if n.len() != BYTES {
            return Err(Error::InvalidKeyLength(n.len()));
        }
        let n = Uint::<LIMBS>::from_be_bytes(n);
        if n.0[LIMBS - 1] >> 63 == 0 {
            return Err(Error::InvalidKeyLength(BYTES));
        }
        let m = Montgomery::new(n).ok_or(Error::InvalidPublicKey)?;

        let e_bytes = strip_leading_zeros(e);
        if e_bytes.len() > 8 {
            return Err(Error::InvalidPublicKey);
        }
        let e = Uint::<1>::from_be_bytes(e_bytes);
        if !e.is_odd() || e.0[0] < 3 {
            return Err(Error::InvalidPublicKey);
        }
        Ok(PublicKey { m, e })
    }

    /// Checks a PKCS#1 v1.5 signature over `message`.
    pub fn verify_pkcs1<H: DigestInfo>(
        &self,
        message: &[u8],
        signature: &[u8; BYTES],
    ) -> Result<(), Error> {
        let em = self.undo(signature)?;
        let mut expected = [0u8; BYTES];
        encode_pkcs1::<H, BYTES>(message, &mut expected)?;
        if em == expected {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Checks a PSS signature over `message`.
    ///
    /// The salt length is read from the padding rather than fixed in
    /// advance, so any length the key's width allows is accepted.
    pub fn verify_pss<H: Hash>(
        &self,
        message: &[u8],
        signature: &[u8; BYTES],
    ) -> Result<(), Error> {
        let mut em = self.undo(signature)?;
        let h_len = H::Output::SIZE;
        if BYTES < h_len + 2 {
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

        // DB = zeros || 0x01 || salt; the 0x01 marks where the salt
        // starts, which is how its length travels.
        let one_at = db
            .iter()
            .position(|&b| b != 0)
            .ok_or(Error::InvalidSignature)?;
        if db[one_at] != 0x01 {
            return Err(Error::InvalidSignature);
        }
        let salt = &db[one_at + 1..];

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
        let mut out = [0u8; BYTES];
        self.m.modulus().to_be_bytes(&mut out);
        out
    }

    /// The public exponent, big-endian in eight bytes.
    pub fn exponent_bytes(&self) -> [u8; 8] {
        self.e.0[0].to_be_bytes()
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

        let m = Uint::<LIMBS>::from_be_bytes(&em);
        let c = self.m.modexp(&m, &self.e);
        let mut out = [0u8; BYTES];
        c.to_be_bytes(&mut out);
        em.zeroize();
        Ok(out)
    }

    /// The public operation: the signature back through `e`, as
    /// encoded-message bytes.
    fn undo(&self, signature: &[u8; BYTES]) -> Result<[u8; BYTES], Error> {
        let s = Uint::<LIMBS>::from_be_bytes(signature);
        if s.less_than(self.m.modulus()) == 0 {
            return Err(Error::InvalidSignature);
        }
        let em = self.m.modexp(&s, &self.e);
        let mut out = [0u8; BYTES];
        em.to_be_bytes(&mut out);
        Ok(out)
    }
}

impl<const LIMBS: usize, const BYTES: usize, const HALF: usize>
    PrivateKey<LIMBS, BYTES, HALF>
{
    /// A private key from its big-endian parts: the public modulus
    /// and exponent, then the private exponent, which must be
    /// nonzero and below the modulus. Signing uses `d` directly; a
    /// key that carries its primes should come in through
    /// [`try_new_crt`](PrivateKey::try_new_crt) instead.
    pub fn try_new(n: &[u8], e: &[u8], d: &[u8]) -> Result<Self, Error> {
        assert_eq!(2 * HALF, LIMBS, "HALF must be LIMBS / 2");
        let public = PublicKey::try_new(n, e)?;
        if d.len() > BYTES {
            return Err(Error::InvalidPrivateKey);
        }
        let d = Uint::<LIMBS>::from_be_bytes(d);
        if d.is_zero() || d.less_than(public.m.modulus()) == 0 {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(PrivateKey {
            public,
            d,
            crt: None,
        })
    }

    /// A private key with its Chinese remainder pieces, in the order
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
        let mut key = Self::try_new(n, e, d)?;

        let half = |part: &[u8]| -> Result<Uint<HALF>, Error> {
            if part.len() > BYTES / 2 {
                return Err(Error::InvalidPrivateKey);
            }
            Ok(Uint::from_be_bytes(part))
        };
        let p_value = half(p)?;
        let q_value = half(q)?;
        // Top bits set, so each prime is exactly half the width,
        // which the reduction of `q` modulo `p` below relies on.
        if p_value.0[HALF - 1] >> 63 == 0 || q_value.0[HALF - 1] >> 63 == 0 {
            return Err(Error::InvalidPrivateKey);
        }
        let (difference, _) = p_value.sub_borrow(&q_value);
        if difference.is_zero() {
            return Err(Error::InvalidPrivateKey);
        }
        if p_value.mul_wide::<LIMBS>(&q_value).0 != key.public.m.modulus().0 {
            return Err(Error::InvalidPrivateKey);
        }
        let p = Montgomery::new(p_value).ok_or(Error::InvalidPrivateKey)?;
        let q = Montgomery::new(q_value).ok_or(Error::InvalidPrivateKey)?;

        let dp = half(dp)?;
        let dq = half(dq)?;
        let qinv = half(qinv)?;
        if dp.is_zero()
            || dp.less_than(p.modulus()) == 0
            || dq.is_zero()
            || dq.less_than(q.modulus()) == 0
            || qinv.is_zero()
            || qinv.less_than(p.modulus()) == 0
        {
            return Err(Error::InvalidPrivateKey);
        }
        // qinv really must invert q; a wrong value here would only
        // surface as every signature failing its final check.
        let q_mod_p = reduce_once_mod(q.modulus(), p.modulus());
        if p.mulmod(&qinv, &q_mod_p).0 != Uint::<HALF>::one().0 {
            return Err(Error::InvalidPrivateKey);
        }

        key.crt = Some(Crt { p, q, dp, dq, qinv });
        Ok(key)
    }

    /// The public half.
    pub fn public_key(&self) -> &PublicKey<LIMBS, BYTES> {
        &self.public
    }

    /// Signs `message` with PKCS#1 v1.5 padding.
    pub fn sign_pkcs1<H: DigestInfo>(
        &self,
        message: &[u8],
    ) -> Result<[u8; BYTES], Error> {
        let mut em = [0u8; BYTES];
        encode_pkcs1::<H, BYTES>(message, &mut em)?;
        self.apply(&em)
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
        self.apply(&em)
    }

    /// Generates a fresh key, with the public exponent 65537 and
    /// every Chinese remainder piece in place.
    ///
    /// The primes are random probable primes: trial division, then
    /// Miller-Rabin with random witnesses, with round counts read
    /// from FIPS 186-5 for random candidates of 1024 bits and up.
    /// Widths below [`Rsa2048PrivateKey`] are for interoperation
    /// and tests, not for new keys.
    pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
        assert_eq!(2 * HALF, LIMBS, "HALF must be LIMBS / 2");
        const E_WORD: u64 = 65537;

        let mut p = probable_prime::<HALF, R>(rng)?;
        let mut q = Uint::<HALF>::ZERO;
        let mut found = false;
        for _ in 0..64 {
            q = probable_prime::<HALF, R>(rng)?;
            // FIPS 186-5: the primes must not be close, or Fermat
            // factoring splits the modulus.
            let (a, borrow) = p.sub_borrow(&q);
            let mut difference = a;
            difference.cmov(&q.sub_borrow(&p).0, borrow);
            if difference.bit_length() > (64 * HALF).saturating_sub(100) {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::KeyGenerationFailed);
        }

        let n = p.mul_wide::<LIMBS>(&q);

        // phi = (p-1)(q-1) = n - p - q + 1; no borrow can happen.
        let phi = n
            .sub_borrow(&p.widen())
            .0
            .sub_borrow(&q.widen())
            .0
            .add_carry(&Uint::one())
            .0;

        // d = (1 + k * phi) / e for the k that makes the division
        // exact: k = -phi^-1 mod e. The whole inversion happens in
        // one word, because e does.
        let phi_mod_e = phi.rem_word(E_WORD);
        let k = E_WORD - inv_mod_word(phi_mod_e, E_WORD);
        let (k_phi, top) = phi.mul_word(k);
        let (with_one, carry) = k_phi.add_carry(&Uint::one());
        let (mut d, remainder) = with_one.div_rem_word(top + carry, E_WORD);
        debug_assert_eq!(remainder, 0);

        // The Chinese remainder pieces. p is prime, so the inverse
        // of q is a Fermat power, and the exponentiations that need
        // an even modulus are plain bit-by-bit remainders instead.
        let mut p_minus_1 = p.sub_borrow(&Uint::one()).0;
        let mut q_minus_1 = q.sub_borrow(&Uint::one()).0;
        let mut dp = d.rem_wide::<HALF>(&p_minus_1);
        let mut dq = d.rem_wide::<HALF>(&q_minus_1);
        let mont_p = Montgomery::new(p).ok_or(Error::KeyGenerationFailed)?;
        let q_mod_p = reduce_once_mod(&q, &p);
        let mut p_minus_2 = p.sub_borrow(&Uint::from_limbs(&[2])).0;
        let mut qinv = mont_p.modexp(&q_mod_p, &p_minus_2);

        // Out through bytes and back through try_new_crt, so a
        // generated key passes exactly the checks an imported one
        // does.
        let mut n_bytes = [0u8; BYTES];
        n.to_be_bytes(&mut n_bytes);
        let mut d_bytes = [0u8; BYTES];
        d.to_be_bytes(&mut d_bytes);
        let mut halves = [[0u8; BYTES]; 5];
        for (buf, value) in halves.iter_mut().zip([p, q, dp, dq, qinv]) {
            value.to_be_bytes(&mut buf[..BYTES / 2]);
        }
        let key = Self::try_new_crt(
            &n_bytes,
            &E_WORD.to_be_bytes(),
            &d_bytes,
            &halves[0][..BYTES / 2],
            &halves[1][..BYTES / 2],
            &halves[2][..BYTES / 2],
            &halves[3][..BYTES / 2],
            &halves[4][..BYTES / 2],
        );

        p.zeroize();
        q.zeroize();
        d.zeroize();
        dp.zeroize();
        dq.zeroize();
        qinv.zeroize();
        p_minus_1.zeroize();
        q_minus_1.zeroize();
        p_minus_2.zeroize();
        d_bytes.zeroize();
        for buf in halves.iter_mut() {
            buf.zeroize();
        }
        key
    }

    /// The private exponent, big-endian. The caller holds a secret
    /// now, and should wipe it when done.
    pub fn d_bytes(&self) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        self.d.to_be_bytes(&mut out);
        out
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
        let crt = self.crt.as_ref().ok_or(Error::InvalidPrivateKey)?;
        for out in [&p, &q, &dp, &dq, &qinv] {
            if out.len() != BYTES / 2 {
                return Err(Error::InvalidLength(out.len()));
            }
        }
        crt.p.modulus().to_be_bytes(p);
        crt.q.modulus().to_be_bytes(q);
        crt.dp.to_be_bytes(dp);
        crt.dq.to_be_bytes(dq);
        crt.qinv.to_be_bytes(qinv);
        Ok(())
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
        if c.less_than(self.public.m.modulus()) == 0 {
            return Err(Error::DecryptionFailed);
        }
        let mut em = self.apply(ciphertext)?;

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

    /// The private operation: the encoded message through `d`, or
    /// through the primes when the key carries them.
    fn apply(&self, em: &[u8; BYTES]) -> Result<[u8; BYTES], Error> {
        let m = Uint::<LIMBS>::from_be_bytes(em);
        let s = match &self.crt {
            Some(crt) => {
                let s = crt.apply(&m);
                // One faulty CRT signature factors the modulus, so
                // check with the public exponent before anything
                // leaves. This also catches a wrong dp or dq, which
                // import cannot.
                if self.public.m.modexp(&s, &self.public.e).0 != m.0 {
                    return Err(Error::InvalidPrivateKey);
                }
                s
            }
            None => self.public.m.modexp(&m, &self.d),
        };
        let mut out = [0u8; BYTES];
        s.to_be_bytes(&mut out);
        Ok(out)
    }
}

impl<const HALF: usize> Crt<HALF> {
    /// Garner's recombination: exponentiate modulo each prime, then
    /// lift: `s = sq + q * (qinv * (sp - sq) mod p)`, which is below
    /// `p * q` with no final reduction.
    fn apply<const LIMBS: usize>(&self, m: &Uint<LIMBS>) -> Uint<LIMBS> {
        let lo = Uint::<HALF>::from_limbs(&m.0[..HALF]);
        let hi = Uint::<HALF>::from_limbs(&m.0[HALF..]);
        let mut mp = self.p.reduce_wide(&lo, &hi);
        let mut mq = self.q.reduce_wide(&lo, &hi);
        let mut sp = self.p.modexp(&mp, &self.dp);
        let mut sq = self.q.modexp(&mq, &self.dq);

        let sq_mod_p = reduce_once_mod(&sq, self.p.modulus());
        let mut difference = sp.sub_mod(&sq_mod_p, self.p.modulus());
        let mut h = self.p.mulmod(&self.qinv, &difference);
        let (s, carry) = self
            .q
            .modulus()
            .mul_wide::<LIMBS>(&h)
            .add_carry(&sq.widen());
        debug_assert_eq!(carry, 0);

        mp.zeroize();
        mq.zeroize();
        sp.zeroize();
        sq.zeroize();
        difference.zeroize();
        h.zeroize();
        s
    }
}

/// Draws random candidates until one survives trial division and
/// Miller-Rabin. The cap on attempts is FIPS 186-5's, and failing it
/// means the random source is not producing usable candidates.
fn probable_prime<const HALF: usize, R: Random>(
    rng: &mut R,
) -> Result<Uint<HALF>, Error> {
    for _ in 0..5 * 64 * HALF {
        let mut limbs = [0u64; HALF];
        for limb in limbs.iter_mut() {
            let mut bytes = [0u8; 8];
            rng.fill(&mut bytes)?;
            *limb = u64::from_le_bytes(bytes);
        }
        // Odd, and with the top two bits set so the product of two
        // candidates fills the modulus width exactly.
        limbs[0] |= 1;
        limbs[HALF - 1] |= 3 << 62;
        let mut candidate = Uint(limbs);
        limbs.zeroize();

        // Trial division by every odd number to 2000; the composite
        // divisors are redundant but harmless, and the loop stays
        // two lines.
        let mut divisor = 3u64;
        let mut composite = false;
        while divisor < 2000 {
            if candidate.rem_word(divisor) == 0 {
                composite = true;
                break;
            }
            divisor += 2;
        }
        // A prime congruent to 1 mod e would make e share a factor
        // with phi, and no d would exist.
        if composite || candidate.rem_word(65537) == 1 {
            candidate.zeroize();
            continue;
        }
        if miller_rabin(&candidate, rng)? {
            return Ok(candidate);
        }
        candidate.zeroize();
    }
    Err(Error::KeyGenerationFailed)
}

/// Miller-Rabin with random witnesses. Eight rounds: FIPS 186-5
/// table B.1 asks for at most five on random candidates of 1024
/// bits, and the extras are margin for the narrower legacy widths.
fn miller_rabin<const HALF: usize, R: Random>(
    candidate: &Uint<HALF>,
    rng: &mut R,
) -> Result<bool, Error> {
    let m = Montgomery::new(*candidate).ok_or(Error::KeyGenerationFailed)?;
    let one = Uint::<HALF>::one();
    let minus_one = candidate.sub_borrow(&one).0;
    // candidate - 1 = 2^s * t with t odd.
    let s = minus_one.trailing_zeros();
    let mut t = minus_one.shr(s);

    'witness: for _ in 0..8 {
        // A random witness below the candidate: clearing the top
        // bit is enough, since the candidate has it set, and tiny
        // witnesses are nudged to two.
        let mut limbs = [0u64; HALF];
        for limb in limbs.iter_mut() {
            let mut bytes = [0u8; 8];
            rng.fill(&mut bytes)?;
            *limb = u64::from_le_bytes(bytes);
        }
        limbs[HALF - 1] &= !(1 << 63);
        let mut a = Uint(limbs);
        limbs.zeroize();
        if a.bit_length() < 2 {
            a = Uint::from_limbs(&[2]);
        }

        let mut x = m.modexp(&a, &t);
        if x.0 == one.0 || x.0 == minus_one.0 {
            continue;
        }
        for _ in 1..s {
            x = m.mulmod(&x, &x);
            if x.0 == minus_one.0 {
                continue 'witness;
            }
        }
        t.zeroize();
        return Ok(false);
    }
    t.zeroize();
    Ok(true)
}

/// The inverse of `a` modulo `m`, by the extended Euclidean
/// algorithm in one word; `a` and `m` must be coprime.
fn inv_mod_word(a: u64, m: u64) -> u64 {
    let (mut t, mut new_t) = (0i128, 1i128);
    let (mut r, mut new_r) = (i128::from(m), i128::from(a));
    while new_r != 0 {
        let quotient = r / new_r;
        (t, new_t) = (new_t, t - quotient * new_t);
        (r, new_r) = (new_r, r - quotient * new_r);
    }
    debug_assert_eq!(r, 1, "not coprime");
    ((t % i128::from(m) + i128::from(m)) % i128::from(m)) as u64
}

/// The remainder of `value` modulo `n`, where `value` is known to be
/// below `2n`: one conditional subtraction.
fn reduce_once_mod<const LIMBS: usize>(
    value: &Uint<LIMBS>,
    n: &Uint<LIMBS>,
) -> Uint<LIMBS> {
    let (reduced, borrow) = value.sub_borrow(n);
    let mut out = reduced;
    out.cmov(value, borrow);
    out
}

impl<const HALF: usize> Zeroize for Crt<HALF> {
    fn zeroize(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
    }
}

impl<const LIMBS: usize, const BYTES: usize, const HALF: usize> Drop
    for PrivateKey<LIMBS, BYTES, HALF>
{
    fn drop(&mut self) {
        self.d.zeroize();
        if let Some(crt) = &mut self.crt {
            crt.zeroize();
        }
    }
}

impl<const LIMBS: usize, const BYTES: usize, const HALF: usize> ZeroizeOnDrop
    for PrivateKey<LIMBS, BYTES, HALF>
{
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

/// MGF1: xors `out` with the counter-indexed digests of `seed`, as
/// RFC 8017 appendix B.2.1 defines the mask.
fn mgf1_xor<H: Hash>(seed: &[u8], out: &mut [u8]) -> Result<(), Error> {
    for (counter, chunk) in (0u32..).zip(out.chunks_mut(H::Output::SIZE)) {
        let mut hasher = H::try_new()?;
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        let mask = hasher.finalize();
        for (byte, mask) in chunk.iter_mut().zip(mask.as_ref()) {
            *byte ^= mask;
        }
    }
    Ok(())
}

/// One where the bytes are equal, zero otherwise, with no branch
/// for the comparison to leak through.
fn eq_byte(a: u8, b: u8) -> u8 {
    let x = u16::from(a ^ b);
    (x.wrapping_sub(1) >> 8) as u8 & 1
}

/// The value without its leading zero bytes.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
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
        key.public_key().verify_pss::<Sha256>(MSG, &sig).unwrap();

        let sig = key.sign_pss::<Sha256>(MSG, &[]).unwrap();
        assert_eq!(sig, unhex::<256>(PSS_SHA256_SALT0));
        key.public_key().verify_pss::<Sha256>(MSG, &sig).unwrap();
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
        key.public_key().verify_pss::<Sha384>(MSG, &sig).unwrap();
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
            public.verify_pss::<Sha256>(b"other message", &pss),
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
                public.verify_pss::<Sha256>(MSG, &bad),
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
            public.verify_pss::<Sha256>(MSG, &too_big),
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
        key.public_key().verify_pss::<Sha256>(MSG, &sig).unwrap();
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
        key.public_key().verify_pss::<Sha256>(MSG, &sig).unwrap();
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
}
