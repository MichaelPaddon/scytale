//! Signatures: Ed25519, ECDSA over P-256 and P-384, and RSA.
//!
//! Verification goes through [`UnparsedPublicKey`] and a `static`
//! naming the algorithm. Signing goes through a key pair type per
//! algorithm.

use core::fmt;

use scytale::Key;
use scytale::hash::sha2::{Sha256, Sha384};
use scytale::sig::ecdsa::{p256, p384};
use scytale::sig::ed25519;

use crate::debug::HexStr;
use crate::error::{self, KeyRejected};
use crate::{rand, sealed};

pub use crate::rsa::{
    PublicKeyComponents as RsaPublicKeyComponents,
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
    RsaEncoding, RsaParameters,
};

/// A key pair that signs with RSA.
pub type RsaKeyPair = crate::rsa::KeyPair;

/// The longest signature a key pair here returns: an ASN.1 ECDSA
/// signature over P-384, both integers with a leading zero.
const MAX_LEN: usize = 1 + 2 + 2 * (1 + 1 + 1 + 48);

/// A signature a key pair made.
#[derive(Clone, Copy)]
pub struct Signature {
    value: [u8; MAX_LEN],
    len: usize,
}

impl Signature {
    fn new(bytes: &[u8]) -> Self {
        let mut value = [0u8; MAX_LEN];
        value[..bytes.len()].copy_from_slice(bytes);
        Signature {
            value,
            len: bytes.len(),
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.value[..self.len]
    }
}

/// A key pair, with the public half it hands out.
pub trait KeyPair: fmt::Debug + Send + Sized + Sync {
    /// The public key's type.
    type PublicKey: AsRef<[u8]> + fmt::Debug + Clone + Send + Sized + Sync;

    /// The public key.
    fn public_key(&self) -> &Self::PublicKey;
}

/// A signature algorithm that verifies. Sealed: the only values are the
/// `static`s here.
pub trait VerificationAlgorithm: fmt::Debug + Sync + sealed::Sealed {
    /// Checks `signature` over `msg` under `public_key`.
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified>;
}

/// A public key and the algorithm to verify with it, not yet checked.
#[derive(Clone, Copy)]
pub struct UnparsedPublicKey<B> {
    algorithm: &'static dyn VerificationAlgorithm,
    bytes: B,
}

impl<B> AsRef<[u8]> for UnparsedPublicKey<B>
where
    B: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<B: fmt::Debug> fmt::Debug for UnparsedPublicKey<B>
where
    B: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UnparsedPublicKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &HexStr(self.bytes.as_ref()))
            .finish()
    }
}

impl<B> UnparsedPublicKey<B> {
    /// A key for `algorithm`.
    #[inline]
    pub fn new(
        algorithm: &'static dyn VerificationAlgorithm,
        bytes: B,
    ) -> Self {
        Self { algorithm, bytes }
    }

    /// Checks `signature` over `message`.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), error::Unspecified>
    where
        B: AsRef<[u8]>,
    {
        self.algorithm.verify(
            untrusted::Input::from(self.bytes.as_ref()),
            untrusted::Input::from(message),
            untrusted::Input::from(signature),
        )
    }
}

// Ed25519.

/// The length of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LEN: usize = ed25519::PUBLIC_KEY_SIZE;

/// Ed25519 verification parameters.
pub struct EdDSAParameters;

impl fmt::Debug for EdDSAParameters {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // ring's own spelling, which its tests compare against.
        f.write_str("ring::signature::ED25519")
    }
}

/// Ed25519 (RFC 8032).
pub static ED25519: EdDSAParameters = EdDSAParameters;

impl sealed::Sealed for EdDSAParameters {}

impl VerificationAlgorithm for EdDSAParameters {
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        let public_key: &[u8; ED25519_PUBLIC_KEY_LEN] =
            public_key.as_slice_less_safe().try_into()?;
        let signature: &[u8; ed25519::SIGNATURE_SIZE] =
            signature.as_slice_less_safe().try_into()?;
        ed25519::PublicKey::new(public_key)
            .verify(msg.as_slice_less_safe(), signature)
            .map_err(error::erase)
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy)]
pub struct Ed25519PublicKey([u8; ED25519_PUBLIC_KEY_LEN]);

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        crate::debug::write_hex_tuple(f, "PublicKey", &self.0)
    }
}

/// An Ed25519 key pair.
pub struct Ed25519KeyPair {
    private: ed25519::PrivateKey,
    public_key: Ed25519PublicKey,
}

impl fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Ed25519KeyPair {
    fn from_private(private: ed25519::PrivateKey) -> Self {
        let public_key = Ed25519PublicKey(private.public_key().bytes());
        Ed25519KeyPair {
            private,
            public_key,
        }
    }

    /// A key pair from PKCS#8, version 1 or 2. A public key carried in
    /// version 2 is checked against the seed.
    pub fn from_pkcs8_maybe_unchecked(
        pkcs8: &[u8],
    ) -> Result<Self, KeyRejected> {
        ed25519::PrivateKey::try_from_der(pkcs8)
            .map(Self::from_private)
            .map_err(KeyRejected::from_scytale)
    }

    /// A key pair from its 32-byte seed.
    pub fn from_seed_unchecked(seed: &[u8]) -> Result<Self, KeyRejected> {
        let seed = Key::<[u8; ed25519::KEY_SIZE]>::try_from(seed)
            .map_err(|_| KeyRejected::invalid_encoding())?;
        Ok(Self::from_private(ed25519::PrivateKey::new(&seed)))
    }

    /// A key pair from its seed, checked against the public key the
    /// caller holds for it.
    pub fn from_seed_and_public_key(
        seed: &[u8],
        public_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        let pair = Self::from_seed_unchecked(seed)?;
        let public_key: &[u8; ED25519_PUBLIC_KEY_LEN] =
            public_key
                .try_into()
                .map_err(|_| KeyRejected::invalid_encoding())?;
        if pair.public_key.0 != *public_key {
            return Err(KeyRejected::inconsistent_components());
        }
        Ok(pair)
    }

    /// Signs `msg`.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature::new(&self.private.sign(msg))
    }
}

impl KeyPair for Ed25519KeyPair {
    type PublicKey = Ed25519PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

// ECDSA.

#[derive(Clone, Copy, Eq, PartialEq)]
enum Curve {
    P256,
    P384,
}

#[derive(Clone, Copy)]
enum Hash {
    Sha256,
    Sha384,
}

/// Which ECDSA verification a `static` is, and what [`Debug`] prints.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
enum VerifyId {
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA384_ASN1,
    ECDSA_P384_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_FIXED,
}

/// ECDSA verification over a curve, a hash and a signature format.
pub struct EcdsaVerificationAlgorithm {
    id: VerifyId,
    curve: Curve,
    hash: Hash,
    asn1: bool,
}

impl fmt::Debug for EcdsaVerificationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.id, f)
    }
}

impl sealed::Sealed for EcdsaVerificationAlgorithm {}

/// An uncompressed point of exactly the curve's length. scytale also
/// takes compressed points; ring does not.
fn uncompressed(bytes: &[u8], len: usize) -> Result<&[u8], error::Unspecified> {
    match bytes.first() {
        Some(0x04) if bytes.len() == len => Ok(bytes),
        _ => Err(error::Unspecified),
    }
}

impl VerificationAlgorithm for EcdsaVerificationAlgorithm {
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        let public_key = public_key.as_slice_less_safe();
        let msg = msg.as_slice_less_safe();
        let signature = signature.as_slice_less_safe();
        macro_rules! verify {
            ($curve:ident) => {{
                let point = uncompressed(public_key, $curve::PUBLIC_KEY_SIZE)?;
                let key = $curve::PublicKey::try_from_sec1(point)
                    .map_err(error::erase)?;
                let sig = if self.asn1 {
                    $curve::signature_from_der(signature)
                        .map_err(error::erase)?
                } else {
                    *<&[u8; $curve::SIGNATURE_SIZE]>::try_from(signature)?
                };
                match self.hash {
                    Hash::Sha256 => key.verify::<Sha256>(msg, &sig),
                    Hash::Sha384 => key.verify::<Sha384>(msg, &sig),
                }
                .map_err(error::erase)
            }};
        }
        match self.curve {
            Curve::P256 => verify!(p256),
            Curve::P384 => verify!(p384),
        }
    }
}

macro_rules! ecdsa_verify {
    ($name:ident, $curve:ident, $hash:ident, $asn1:expr, $doc:literal) => {
        #[doc = $doc]
        pub static $name: EcdsaVerificationAlgorithm =
            EcdsaVerificationAlgorithm {
                id: VerifyId::$name,
                curve: Curve::$curve,
                hash: Hash::$hash,
                asn1: $asn1,
            };
    };
}

ecdsa_verify!(
    ECDSA_P256_SHA256_ASN1,
    P256,
    Sha256,
    true,
    "ECDSA over P-256 with SHA-256, signatures in ASN.1 DER."
);
ecdsa_verify!(
    ECDSA_P256_SHA256_FIXED,
    P256,
    Sha256,
    false,
    "ECDSA over P-256 with SHA-256, signatures as `r || s`."
);
ecdsa_verify!(
    ECDSA_P256_SHA384_ASN1,
    P256,
    Sha384,
    true,
    "ECDSA over P-256 with SHA-384, signatures in ASN.1 DER."
);
ecdsa_verify!(
    ECDSA_P384_SHA256_ASN1,
    P384,
    Sha256,
    true,
    "ECDSA over P-384 with SHA-256, signatures in ASN.1 DER."
);
ecdsa_verify!(
    ECDSA_P384_SHA384_ASN1,
    P384,
    Sha384,
    true,
    "ECDSA over P-384 with SHA-384, signatures in ASN.1 DER."
);
ecdsa_verify!(
    ECDSA_P384_SHA384_FIXED,
    P384,
    Sha384,
    false,
    "ECDSA over P-384 with SHA-384, signatures as `r || s`."
);

/// Which ECDSA signing a `static` is, and what [`Debug`] prints.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignId {
    ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING,
}

/// ECDSA signing over a curve, its hash and a signature format.
pub struct EcdsaSigningAlgorithm {
    id: SignId,
    curve: Curve,
    asn1: bool,
}

impl fmt::Debug for EcdsaSigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.id, f)
    }
}

impl PartialEq for EcdsaSigningAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for EcdsaSigningAlgorithm {}

impl sealed::Sealed for EcdsaSigningAlgorithm {}

macro_rules! ecdsa_sign {
    ($name:ident, $curve:ident, $asn1:expr, $doc:literal) => {
        #[doc = $doc]
        pub static $name: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
            id: SignId::$name,
            curve: Curve::$curve,
            asn1: $asn1,
        };
    };
}

ecdsa_sign!(
    ECDSA_P256_SHA256_FIXED_SIGNING,
    P256,
    false,
    "ECDSA over P-256 with SHA-256, signing `r || s`."
);
ecdsa_sign!(
    ECDSA_P384_SHA384_FIXED_SIGNING,
    P384,
    false,
    "ECDSA over P-384 with SHA-384, signing `r || s`."
);
ecdsa_sign!(
    ECDSA_P256_SHA256_ASN1_SIGNING,
    P256,
    true,
    "ECDSA over P-256 with SHA-256, signing ASN.1 DER."
);
ecdsa_sign!(
    ECDSA_P384_SHA384_ASN1_SIGNING,
    P384,
    true,
    "ECDSA over P-384 with SHA-384, signing ASN.1 DER."
);

/// The longest ECDSA public key: an uncompressed P-384 point.
const EC_PUBLIC_KEY_MAX: usize = p384::PUBLIC_KEY_SIZE;

/// An ECDSA public key, as an uncompressed point.
#[derive(Clone, Copy)]
pub struct EcdsaPublicKey {
    bytes: [u8; EC_PUBLIC_KEY_MAX],
    len: usize,
}

impl EcdsaPublicKey {
    fn new(point: &[u8]) -> Self {
        let mut bytes = [0u8; EC_PUBLIC_KEY_MAX];
        bytes[..point.len()].copy_from_slice(point);
        EcdsaPublicKey {
            bytes,
            len: point.len(),
        }
    }
}

impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        crate::debug::write_hex_tuple(f, "PublicKey", self.as_ref())
    }
}

enum EcdsaPrivate {
    P256(p256::PrivateKey),
    P384(p384::PrivateKey),
}

/// An ECDSA key pair.
///
/// Its signatures are deterministic (RFC 6979). ring's are randomised;
/// both verify the same, but the bytes differ.
pub struct EcdsaKeyPair {
    private: EcdsaPrivate,
    public_key: EcdsaPublicKey,
    alg: &'static EcdsaSigningAlgorithm,
}

impl fmt::Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EcdsaKeyPair")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl EcdsaKeyPair {
    fn from_private(
        alg: &'static EcdsaSigningAlgorithm,
        private: EcdsaPrivate,
    ) -> Self {
        let public_key = match &private {
            EcdsaPrivate::P256(k) => {
                EcdsaPublicKey::new(&k.public_key().sec1_bytes())
            }
            EcdsaPrivate::P384(k) => {
                EcdsaPublicKey::new(&k.public_key().sec1_bytes())
            }
        };
        EcdsaKeyPair {
            private,
            public_key,
            alg,
        }
    }

    /// A key pair from PKCS#8 on the algorithm's curve. A public key
    /// carried in it is checked against the private one.
    pub fn from_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
        _rng: &dyn rand::SecureRandom,
    ) -> Result<Self, KeyRejected> {
        let private =
            match alg.curve {
                Curve::P256 => p256::PrivateKey::try_from_der(pkcs8)
                    .map(EcdsaPrivate::P256),
                Curve::P384 => p384::PrivateKey::try_from_der(pkcs8)
                    .map(EcdsaPrivate::P384),
            }
            .map_err(KeyRejected::from_scytale)?;
        Ok(Self::from_private(alg, private))
    }

    /// A key pair from the private scalar, big-endian, and the public
    /// key as an uncompressed point, which must agree.
    pub fn from_private_key_and_public_key(
        alg: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
        _rng: &dyn rand::SecureRandom,
    ) -> Result<Self, KeyRejected> {
        macro_rules! load {
            ($curve:ident, $arm:ident) => {{
                let scalar: &[u8; $curve::KEY_SIZE] = private_key
                    .try_into()
                    .map_err(|_| KeyRejected::invalid_encoding())?;
                $curve::PrivateKey::try_new(scalar)
                    .map(EcdsaPrivate::$arm)
                    .map_err(|_| KeyRejected::invalid_component())?
            }};
        }
        let private = match alg.curve {
            Curve::P256 => load!(p256, P256),
            Curve::P384 => load!(p384, P384),
        };
        let pair = Self::from_private(alg, private);
        if pair.public_key.as_ref() != public_key {
            return Err(KeyRejected::inconsistent_components());
        }
        Ok(pair)
    }

    /// Signs `message`. `rng` is accepted for ring's signature and not
    /// used: the nonce comes from the key and the message.
    pub fn sign(
        &self,
        _rng: &dyn rand::SecureRandom,
        message: &[u8],
    ) -> Result<Signature, error::Unspecified> {
        macro_rules! sign {
            ($curve:ident, $key:expr, $hash:ty) => {{
                let fixed =
                    $key.sign::<$hash>(message).map_err(error::erase)?;
                if self.alg.asn1 {
                    let mut der = [0u8; MAX_LEN];
                    let len = $curve::signature_der(&fixed, &mut der)
                        .map_err(error::erase)?;
                    Ok(Signature::new(&der[..len]))
                } else {
                    Ok(Signature::new(&fixed))
                }
            }};
        }
        match &self.private {
            EcdsaPrivate::P256(k) => sign!(p256, k, Sha256),
            EcdsaPrivate::P384(k) => sign!(p384, k, Sha384),
        }
    }
}

impl KeyPair for EcdsaKeyPair {
    type PublicKey = EcdsaPublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

#[cfg(test)]
mod tests;
