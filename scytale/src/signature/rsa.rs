//! RSA signatures (RFC 8017): RSASSA-PSS and RSASSA-PKCS1-v1_5.
//!
//! A key is a modulus `n`, the product of two secret primes, with a
//! public exponent `e` and a private exponent `d` that undo one
//! another. Signing raises an encoding of the message's digest to
//! `d`; anyone can raise the signature back through `e` and compare.
//!
//! Two encodings are in use. PSS is the modern one, with a security
//! argument and a salt; PKCS#1 v1.5 is the fixed padding that most
//! deployed certificates still carry. Sign with PSS unless a
//! protocol demands otherwise; verify whichever the peer sends.
//!
//! The width of a key is part of its type: [`Rsa2048PrivateKey`]
//! holds a 2048-bit modulus, and the general [`PrivateKey`] takes
//! the limb and byte counts for any other width, with no ceiling.
//! Keys are imported from their integer parts; generating fresh
//! ones is not offered yet, and neither is CRT acceleration, so
//! signing costs one full-width exponentiation.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::signature::rsa::Rsa1024PrivateKey;
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
//! whose reads never depend on `d`; see
//! [`math`](crate::math). Verification, and the padding checks on
//! both sides, handle only public values.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash::Hash;
use crate::math::montgomery::Montgomery;
use crate::math::uint::Uint;
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

/// An RSA private key. The public half rides along, and the private
/// exponent is wiped on drop.
pub struct PrivateKey<const LIMBS: usize, const BYTES: usize> {
    public: PublicKey<LIMBS, BYTES>,
    d: Uint<LIMBS>,
}

/// A 2048-bit public key.
pub type Rsa2048PublicKey = PublicKey<32, 256>;
/// A 2048-bit private key.
pub type Rsa2048PrivateKey = PrivateKey<32, 256>;
/// A 3072-bit public key.
pub type Rsa3072PublicKey = PublicKey<48, 384>;
/// A 3072-bit private key.
pub type Rsa3072PrivateKey = PrivateKey<48, 384>;
/// A 4096-bit public key.
pub type Rsa4096PublicKey = PublicKey<64, 512>;
/// A 4096-bit private key.
pub type Rsa4096PrivateKey = PrivateKey<64, 512>;
/// A 1024-bit public key: legacy interoperation only, too small for
/// new uses.
pub type Rsa1024PublicKey = PublicKey<16, 128>;
/// A 1024-bit private key: legacy interoperation only.
pub type Rsa1024PrivateKey = PrivateKey<16, 128>;

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

impl<const LIMBS: usize, const BYTES: usize> PrivateKey<LIMBS, BYTES> {
    /// A private key from its big-endian parts: the public modulus
    /// and exponent, then the private exponent, which must be
    /// nonzero and below the modulus.
    pub fn try_new(n: &[u8], e: &[u8], d: &[u8]) -> Result<Self, Error> {
        let public = PublicKey::try_new(n, e)?;
        if d.len() > BYTES {
            return Err(Error::InvalidPrivateKey);
        }
        let d = Uint::<LIMBS>::from_be_bytes(d);
        if d.is_zero() || d.less_than(public.m.modulus()) == 0 {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(PrivateKey { public, d })
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
        Ok(self.apply(&em))
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
        Ok(self.apply(&em))
    }

    /// The private operation: the encoded message through `d`.
    fn apply(&self, em: &[u8; BYTES]) -> [u8; BYTES] {
        let m = Uint::<LIMBS>::from_be_bytes(em);
        let s = self.public.m.modexp(&m, &self.d);
        let mut out = [0u8; BYTES];
        s.to_be_bytes(&mut out);
        out
    }
}

impl<const LIMBS: usize, const BYTES: usize> Drop for PrivateKey<LIMBS, BYTES> {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

impl<const LIMBS: usize, const BYTES: usize> ZeroizeOnDrop
    for PrivateKey<LIMBS, BYTES>
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
}
