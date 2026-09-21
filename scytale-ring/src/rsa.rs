//! RSA signatures: PKCS#1 v1.5 and PSS.
//!
//! Keys that sign are held to ring's rules, which are stricter than
//! scytale's: 2048 to 4096 bits, primes a multiple of 512 bits, and a
//! public exponent of at least 65537. Keys that only verify may be
//! anything from the parameters' minimum up to 8192 bits.

use core::fmt;

use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{Sha256, Sha384, Sha512};
use scytale::sig::rsa;

use crate::digest::{self, Id};
use crate::error::{self, KeyRejected};
use crate::rand::{self, Bridge};
use crate::signature::{self, VerificationAlgorithm};

/// The largest modulus a verifying key may have.
const PUBLIC_MAX_BITS: usize = 8192;

/// The bounds on a signing key's modulus.
const PRIVATE_MIN_BITS: usize = 2048;
const PRIVATE_MAX_BITS: usize = 4096;

/// The smallest public exponent a signing key may have.
const PRIVATE_MIN_EXPONENT: u64 = 65537;

/// Runs `$body` with `$h` bound to the scytale hash `$id` names.
macro_rules! by_hash {
    ($id:expr, $h:ident => $body:expr) => {
        match $id {
            Id::SHA1 => {
                type $h = Sha1;
                $body
            }
            Id::SHA256 => {
                type $h = Sha256;
                $body
            }
            Id::SHA384 => {
                type $h = Sha384;
                $body
            }
            Id::SHA512 => {
                type $h = Sha512;
                $body
            }
            // No padding static names this hash, so none can reach
            // here.
            Id::SHA512_256 => unreachable!("RSA over SHA-512/256"),
        }
    };
}

/// A modulus's length as ring measures it: in whole bytes, so that a
/// modulus a few bits short of a boundary still counts as reaching it.
fn bits_rounded_up(bits: usize) -> usize {
    bits.div_ceil(8) * 8
}

pub(crate) mod padding {
    use super::*;

    /// Which padding, over which hash.
    #[derive(Clone, Copy)]
    pub enum Scheme {
        Pkcs1(&'static digest::Algorithm),
        Pss(&'static digest::Algorithm),
    }

    /// A padding scheme. Sealed: the only values are the `static`s.
    pub trait Padding:
        'static + Sync + crate::sealed::Sealed + fmt::Debug
    {
        /// The hash the message is digested with.
        fn digest_alg(&self) -> &'static digest::Algorithm;

        /// How to sign and verify with it.
        fn scheme(&self) -> Scheme;
    }

    /// PKCS#1 v1.5 padding (RFC 8017, section 8.2).
    pub struct PKCS1 {
        pub(crate) digest_alg: &'static digest::Algorithm,
    }

    /// PSS padding (RFC 8017, section 8.1), with MGF1 over the same
    /// hash and a salt as long as the digest.
    // ring's name for it.
    #[allow(clippy::upper_case_acronyms)]
    pub struct PSS {
        pub(crate) digest_alg: &'static digest::Algorithm,
    }

    impl fmt::Debug for PKCS1 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("PKCS1")
                .field("digest_alg", self.digest_alg)
                .finish()
        }
    }

    impl fmt::Debug for PSS {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("PSS")
                .field("digest_alg", self.digest_alg)
                .finish()
        }
    }

    impl crate::sealed::Sealed for PKCS1 {}
    impl crate::sealed::Sealed for PSS {}

    impl Padding for PKCS1 {
        fn digest_alg(&self) -> &'static digest::Algorithm {
            self.digest_alg
        }

        fn scheme(&self) -> Scheme {
            Scheme::Pkcs1(self.digest_alg)
        }
    }

    impl Padding for PSS {
        fn digest_alg(&self) -> &'static digest::Algorithm {
            self.digest_alg
        }

        fn scheme(&self) -> Scheme {
            Scheme::Pss(self.digest_alg)
        }
    }

    impl RsaEncoding for PKCS1 {}
    impl RsaEncoding for PSS {}

    pub(crate) static RSA_PKCS1_SHA1_FOR_LEGACY_USE_ONLY: PKCS1 = PKCS1 {
        digest_alg: &digest::SHA1_FOR_LEGACY_USE_ONLY,
    };
}

use padding::{PKCS1, PSS, Padding, Scheme};

/// A padding scheme a key can sign with.
pub trait RsaEncoding: Padding {}

/// PKCS#1 v1.5 padding with SHA-256.
pub static RSA_PKCS1_SHA256: PKCS1 = PKCS1 {
    digest_alg: &digest::SHA256,
};

/// PKCS#1 v1.5 padding with SHA-384.
pub static RSA_PKCS1_SHA384: PKCS1 = PKCS1 {
    digest_alg: &digest::SHA384,
};

/// PKCS#1 v1.5 padding with SHA-512.
pub static RSA_PKCS1_SHA512: PKCS1 = PKCS1 {
    digest_alg: &digest::SHA512,
};

/// PSS padding with SHA-256.
pub static RSA_PSS_SHA256: PSS = PSS {
    digest_alg: &digest::SHA256,
};

/// PSS padding with SHA-384.
pub static RSA_PSS_SHA384: PSS = PSS {
    digest_alg: &digest::SHA384,
};

/// PSS padding with SHA-512.
pub static RSA_PSS_SHA512: PSS = PSS {
    digest_alg: &digest::SHA512,
};

/// A way to verify: a padding scheme and the smallest modulus
/// accepted.
pub struct RsaParameters {
    padding_alg: &'static dyn Padding,
    min_bits: usize,
}

impl fmt::Debug for RsaParameters {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RsaParameters")
            .field("padding_alg", &self.padding_alg)
            .field("min_bits", &self.min_bits)
            .finish()
    }
}

impl crate::sealed::Sealed for RsaParameters {}

impl VerificationAlgorithm for RsaParameters {
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        let key =
            rsa::PublicKey::try_from_pkcs1(public_key.as_slice_less_safe())
                .map_err(error::erase)?;
        verify_with(
            self,
            &key,
            msg.as_slice_less_safe(),
            signature.as_slice_less_safe(),
        )
    }
}

fn verify_with(
    params: &RsaParameters,
    key: &rsa::PublicKey,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), error::Unspecified> {
    let bits = bits_rounded_up(key.bits());
    if bits < params.min_bits || key.bits() > PUBLIC_MAX_BITS {
        return Err(error::Unspecified);
    }
    let checked = match params.padding_alg.scheme() {
        Scheme::Pkcs1(d) => {
            by_hash!(d.id, H => key.verify_pkcs1::<H>(msg, signature))
        }
        Scheme::Pss(d) => {
            by_hash!(d.id, H => key.verify_pss::<H>(msg, signature))
        }
    };
    checked.map_err(error::erase)
}

macro_rules! rsa_params {
    ($name:ident, $min:expr, $padding:expr, $doc:literal) => {
        #[doc = $doc]
        pub static $name: RsaParameters = RsaParameters {
            padding_alg: $padding,
            min_bits: $min,
        };
    };
}

rsa_params!(
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    1024,
    &padding::RSA_PKCS1_SHA1_FOR_LEGACY_USE_ONLY,
    "PKCS#1 v1.5 with SHA-1, keys of 1024 to 8192 bits."
);
rsa_params!(
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    2048,
    &padding::RSA_PKCS1_SHA1_FOR_LEGACY_USE_ONLY,
    "PKCS#1 v1.5 with SHA-1, keys of 2048 to 8192 bits."
);
rsa_params!(
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    1024,
    &RSA_PKCS1_SHA256,
    "PKCS#1 v1.5 with SHA-256, keys of 1024 to 8192 bits."
);
rsa_params!(
    RSA_PKCS1_2048_8192_SHA256,
    2048,
    &RSA_PKCS1_SHA256,
    "PKCS#1 v1.5 with SHA-256, keys of 2048 to 8192 bits."
);
rsa_params!(
    RSA_PKCS1_2048_8192_SHA384,
    2048,
    &RSA_PKCS1_SHA384,
    "PKCS#1 v1.5 with SHA-384, keys of 2048 to 8192 bits."
);
rsa_params!(
    RSA_PKCS1_2048_8192_SHA512,
    2048,
    &RSA_PKCS1_SHA512,
    "PKCS#1 v1.5 with SHA-512, keys of 2048 to 8192 bits."
);
rsa_params!(
    RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    1024,
    &RSA_PKCS1_SHA512,
    "PKCS#1 v1.5 with SHA-512, keys of 1024 to 8192 bits."
);
rsa_params!(
    RSA_PKCS1_3072_8192_SHA384,
    3072,
    &RSA_PKCS1_SHA384,
    "PKCS#1 v1.5 with SHA-384, keys of 3072 to 8192 bits."
);
rsa_params!(
    RSA_PSS_2048_8192_SHA256,
    2048,
    &RSA_PSS_SHA256,
    "PSS with SHA-256, keys of 2048 to 8192 bits."
);
rsa_params!(
    RSA_PSS_2048_8192_SHA384,
    2048,
    &RSA_PSS_SHA384,
    "PSS with SHA-384, keys of 2048 to 8192 bits."
);
rsa_params!(
    RSA_PSS_2048_8192_SHA512,
    2048,
    &RSA_PSS_SHA512,
    "PSS with SHA-512, keys of 2048 to 8192 bits."
);

/// The longest DER `RSAPublicKey`: an 8192-bit modulus, an eight-byte
/// exponent, and the headers around them.
const PUBLIC_KEY_DER_MAX: usize = PUBLIC_MAX_BITS / 8 + 32;

/// A public key, as its DER `RSAPublicKey`.
#[derive(Clone)]
pub struct PublicKey {
    der: [u8; PUBLIC_KEY_DER_MAX],
    len: usize,
    modulus_len: usize,
}

impl PublicKey {
    fn from_scytale(key: &rsa::PublicKey) -> Result<Self, KeyRejected> {
        let mut der = [0u8; PUBLIC_KEY_DER_MAX];
        let len = key
            .pkcs1_bytes(&mut der)
            .map_err(|_| KeyRejected::unexpected_error())?;
        Ok(PublicKey {
            der,
            len,
            modulus_len: key.modulus_len(),
        })
    }

    /// The length of the modulus in bytes, which is also the length of
    /// every signature.
    pub fn modulus_len(&self) -> usize {
        self.modulus_len
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.der[..self.len]
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        crate::debug::write_hex_tuple(f, "PublicKey", self.as_ref())
    }
}

/// A key pair that signs.
pub struct KeyPair {
    private: rsa::PrivateKey,
    public: PublicKey,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RsaKeyPair")
            .field("public", &self.public)
            .finish()
    }
}

impl KeyPair {
    /// A key pair from its PKCS#8 `PrivateKeyInfo`.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        let key = rsa::PrivateKey::try_from_der(pkcs8)
            .map_err(KeyRejected::from_scytale)?;
        Self::checked(key)
    }

    /// A key pair from its PKCS#1 `RSAPrivateKey`.
    pub fn from_der(input: &[u8]) -> Result<Self, KeyRejected> {
        let key = rsa::PrivateKey::try_from_pkcs1(input)
            .map_err(KeyRejected::from_scytale)?;
        Self::checked(key)
    }

    /// Holds a key scytale accepted to the rules ring signs with.
    fn checked(private: rsa::PrivateKey) -> Result<Self, KeyRejected> {
        let bits = private.bits();
        if bits_rounded_up(bits) < PRIVATE_MIN_BITS {
            return Err(KeyRejected::too_small());
        }
        if bits > PRIVATE_MAX_BITS {
            return Err(KeyRejected::too_large());
        }
        let public = private.public_key();
        let e = u64::from_be_bytes(public.exponent_bytes());
        if e < PRIVATE_MIN_EXPONENT {
            return Err(KeyRejected::too_small());
        }
        // Each prime is half the modulus; ring asks that to be a whole
        // number of 512-bit steps.
        if !bits.div_ceil(2).is_multiple_of(512) {
            return Err(
                KeyRejected::private_modulus_len_not_multiple_of_512_bits(),
            );
        }
        Ok(KeyPair {
            public: PublicKey::from_scytale(&public)?,
            private,
        })
    }

    /// The public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The length of the modulus in bytes.
    #[deprecated = "Use `public().modulus_len()`"]
    pub fn public_modulus_len(&self) -> usize {
        self.public.modulus_len()
    }

    /// Signs `msg` into `signature`, which must be exactly
    /// [`modulus_len`](PublicKey::modulus_len) bytes. `rng` supplies
    /// the salt for PSS and is not used for PKCS#1 v1.5.
    pub fn sign(
        &self,
        padding_alg: &'static dyn RsaEncoding,
        rng: &dyn rand::SecureRandom,
        msg: &[u8],
        signature: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        if signature.len() != self.public.modulus_len() {
            return Err(error::Unspecified);
        }
        let key = &self.private;
        let made = match padding_alg.scheme() {
            Scheme::Pkcs1(d) => {
                by_hash!(d.id, H => key.sign_pkcs1::<H>(msg))
            }
            Scheme::Pss(d) => {
                let mut rng = Bridge(rng);
                by_hash!(d.id, H => key.sign_pss::<H, _>(&mut rng, msg))
            }
        }
        .map_err(error::erase)?;
        signature.copy_from_slice(made.as_ref());
        Ok(())
    }
}

impl signature::KeyPair for KeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        self.public()
    }
}

/// A public key as its modulus and exponent, big-endian.
#[derive(Clone, Copy)]
pub struct PublicKeyComponents<B> {
    /// The modulus.
    pub n: B,
    /// The public exponent.
    pub e: B,
}

impl<B> fmt::Debug for PublicKeyComponents<B>
where
    B: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PublicKeyComponents")
            .field("n", &crate::debug::HexStr(self.n.as_ref()))
            .field("e", &crate::debug::HexStr(self.e.as_ref()))
            .finish()
    }
}

impl<B> PublicKeyComponents<B>
where
    B: AsRef<[u8]>,
{
    /// Verifies `signature` over `message` with `params`.
    pub fn verify(
        &self,
        params: &RsaParameters,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), error::Unspecified> {
        let key = rsa::PublicKey::try_new(self.n.as_ref(), self.e.as_ref())
            .map_err(error::erase)?;
        verify_with(params, &key, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_lengths_are_counted_in_whole_bytes() {
        assert_eq!(bits_rounded_up(2048), 2048);
        assert_eq!(bits_rounded_up(2041), 2048);
        assert_eq!(bits_rounded_up(2040), 2040);
    }
}
