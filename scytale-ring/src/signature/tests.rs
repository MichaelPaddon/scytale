//! Keys and signatures in `testdata` were made with OpenSSL 3.5, so
//! each test here checks agreement with an implementation other than
//! the one underneath.

use super::*;

extern crate std;
use std::format;
use std::vec::Vec;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

const MSG: &[u8] = include_bytes!("testdata/msg");

// RFC 8032 section 7.1, test 1.
#[test]
fn ed25519_gives_the_published_signature() {
    let seed = hex("9d61b19deffd5a60ba844af492ec2cc4\
         4449c5697b326919703bac031cae7f60");
    let public = hex("d75a980182b10ab7d54bfed3c964073a\
         0ee172f3daa62325af021a68f707511a");
    let pair =
        Ed25519KeyPair::from_seed_and_public_key(&seed, &public).expect("pair");
    let sig = pair.sign(b"");
    assert_eq!(
        sig.as_ref(),
        &hex("e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b")[..]
    );
    let key = UnparsedPublicKey::new(&ED25519, &public);
    key.verify(b"", sig.as_ref()).expect("verify");
    assert!(key.verify(b"x", sig.as_ref()).is_err());
    assert!(key.verify(b"", &sig.as_ref()[1..]).is_err());

    let mut other = public.clone();
    other[0] ^= 1;
    let e = Ed25519KeyPair::from_seed_and_public_key(&seed, &other)
        .expect_err("a public key of another seed");
    assert_eq!(format!("{e}"), "InconsistentComponents");
}

#[test]
fn ed25519_prints_as_ring_prints_it() {
    let key = UnparsedPublicKey::new(&ED25519, [0x01u8, 0x02, 0x03]);
    assert_eq!(
        format!("{key:?}"),
        concat!(
            "UnparsedPublicKey { algorithm: ring::signature::ED25519, ",
            "bytes: \"010203\" }"
        )
    );
    let pair = Ed25519KeyPair::from_seed_unchecked(&[0u8; 32]).expect("pair");
    assert_eq!(
        format!("{pair:?}"),
        format!("Ed25519KeyPair {{ public_key: {:?} }}", pair.public_key())
    );
    assert!(format!("{:?}", pair.public_key()).starts_with("PublicKey(\""));
    assert!(Ed25519KeyPair::from_seed_unchecked(&[0u8; 31]).is_err());
}

#[test]
fn ecdsa_verifies_what_openssl_signed() {
    let public = include_bytes!("testdata/p256.pub");
    let sig = include_bytes!("testdata/p256_sha256.sig");
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public[..]);
    key.verify(MSG, sig).expect("verify");
    assert!(key.verify(b"other", sig).is_err());
    // The same signature under the wrong hash, and on the wrong curve.
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA384_ASN1, &public[..]);
    assert!(key.verify(MSG, sig).is_err());
    let key = UnparsedPublicKey::new(&ECDSA_P384_SHA256_ASN1, &public[..]);
    assert!(key.verify(MSG, sig).is_err());
}

#[test]
fn ecdsa_refuses_a_compressed_point() {
    let public = include_bytes!("testdata/p256.pub");
    let sig = include_bytes!("testdata/p256_sha256.sig");
    let mut compressed = public[..33].to_vec();
    compressed[0] = 0x02 | (public[64] & 1);
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &compressed);
    assert!(key.verify(MSG, sig).is_err());
}

fn ecdsa_signs_and_verifies(
    signing: &'static EcdsaSigningAlgorithm,
    verifying: &'static EcdsaVerificationAlgorithm,
    pkcs8: &[u8],
) {
    let rng = rand::SystemRandom::new();
    let pair = EcdsaKeyPair::from_pkcs8(signing, pkcs8, &rng).expect("pair");
    let sig = pair.sign(&rng, MSG).expect("sign");
    let key = UnparsedPublicKey::new(verifying, pair.public_key().as_ref());
    key.verify(MSG, sig.as_ref()).expect("verify");
    assert!(key.verify(b"other", sig.as_ref()).is_err());
}

#[test]
fn ecdsa_signs_what_it_verifies_in_both_formats() {
    let p256 = include_bytes!("testdata/p256.p8");
    ecdsa_signs_and_verifies(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &ECDSA_P256_SHA256_ASN1,
        p256,
    );
    ecdsa_signs_and_verifies(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &ECDSA_P256_SHA256_FIXED,
        p256,
    );

    let p384 = include_bytes!("testdata/p384.p8");
    ecdsa_signs_and_verifies(
        &ECDSA_P384_SHA384_ASN1_SIGNING,
        &ECDSA_P384_SHA384_ASN1,
        p384,
    );
    ecdsa_signs_and_verifies(
        &ECDSA_P384_SHA384_FIXED_SIGNING,
        &ECDSA_P384_SHA384_FIXED,
        p384,
    );
}

#[test]
fn an_ecdsa_key_for_another_curve_is_refused() {
    let rng = rand::SystemRandom::new();
    let p256 = include_bytes!("testdata/p256.p8");
    assert!(
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, p256, &rng)
            .is_err()
    );
}

#[test]
fn an_ecdsa_pair_must_agree_with_itself() {
    let rng = rand::SystemRandom::new();
    let p256 = include_bytes!("testdata/p256.p8");
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, p256, &rng)
            .expect("pair");
    let mut wrong = pair.public_key().as_ref().to_vec();
    wrong[40] ^= 1;
    let scalar = [0x42u8; 32];
    let e = EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &scalar,
        &wrong,
        &rng,
    )
    .expect_err("mismatch");
    assert_eq!(format!("{e}"), "InconsistentComponents");
    assert_eq!(
        format!("{pair:?}"),
        format!("EcdsaKeyPair {{ public_key: {:?} }}", pair.public_key())
    );
}

#[test]
fn rsa_verifies_what_openssl_signed() {
    let public = include_bytes!("testdata/rsa2048.pub");
    let pkcs1 = include_bytes!("testdata/rsa2048_pkcs1_sha256.sig");
    let pss = include_bytes!("testdata/rsa2048_pss_sha384.sig");

    let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public[..]);
    key.verify(MSG, pkcs1).expect("pkcs1");
    assert!(key.verify(b"other", pkcs1).is_err());
    assert!(key.verify(MSG, &pkcs1[1..]).is_err());

    let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, &public[..]);
    key.verify(MSG, pss).expect("pss");
    let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &public[..]);
    assert!(key.verify(MSG, pss).is_err());

    // Too small for the 3072-bit minimum.
    let key = UnparsedPublicKey::new(&RSA_PKCS1_3072_8192_SHA384, &public[..]);
    assert!(key.verify(MSG, pkcs1).is_err());
}

#[test]
fn rsa_signs_what_it_verifies() {
    let rng = rand::SystemRandom::new();
    let pair = RsaKeyPair::from_pkcs8(include_bytes!("testdata/rsa2048.p8"))
        .expect("pair");
    let same = RsaKeyPair::from_der(include_bytes!("testdata/rsa2048.pkcs1"))
        .expect("pkcs1");
    assert_eq!(pair.public().as_ref(), same.public().as_ref());
    assert_eq!(
        pair.public().as_ref(),
        &include_bytes!("testdata/rsa2048.pub")[..]
    );
    assert_eq!(pair.public().modulus_len(), 256);

    // PKCS#1 v1.5 is deterministic, so it gives OpenSSL's bytes.
    let mut sig = [0u8; 256];
    pair.sign(&RSA_PKCS1_SHA256, &rng, MSG, &mut sig)
        .expect("sign");
    assert_eq!(
        &sig[..],
        &include_bytes!("testdata/rsa2048_pkcs1_sha256.sig")[..]
    );

    for (encoding, verifying) in [
        (
            &RSA_PSS_SHA256 as &'static dyn RsaEncoding,
            &RSA_PSS_2048_8192_SHA256,
        ),
        (&RSA_PSS_SHA512, &RSA_PSS_2048_8192_SHA512),
        (&RSA_PKCS1_SHA384, &RSA_PKCS1_2048_8192_SHA384),
    ] {
        pair.sign(encoding, &rng, MSG, &mut sig).expect("sign");
        UnparsedPublicKey::new(verifying, pair.public().as_ref())
            .verify(MSG, &sig)
            .expect("verify");
    }

    // The buffer must be exactly one modulus long.
    assert!(
        pair.sign(&RSA_PKCS1_SHA256, &rng, MSG, &mut [0u8; 255])
            .is_err()
    );
    assert_eq!(
        format!("{pair:?}"),
        format!("RsaKeyPair {{ public: {:?} }}", pair.public_key())
    );
}

#[test]
fn rsa_signing_keys_are_held_to_rings_rules() {
    let reason = |der: &[u8]| {
        format!("{}", RsaKeyPair::from_pkcs8(der).expect_err("refused"))
    };
    assert_eq!(reason(include_bytes!("testdata/rsa1024.p8")), "TooSmall");
    assert_eq!(reason(include_bytes!("testdata/rsa2048_e3.p8")), "TooSmall");
    assert_eq!(
        reason(include_bytes!("testdata/rsa2560.p8")),
        "PrivateModulusLenNotMultipleOf512Bits"
    );
    assert_eq!(reason(b"invalid"), "InvalidEncoding");
    RsaKeyPair::from_pkcs8(include_bytes!("testdata/rsa3072.p8"))
        .expect("3072");
    RsaKeyPair::from_pkcs8(include_bytes!("testdata/rsa4096.p8"))
        .expect("4096");
}

#[test]
fn rsa_components_verify_as_the_der_key_does() {
    let rng = rand::SystemRandom::new();
    let pair = RsaKeyPair::from_pkcs8(include_bytes!("testdata/rsa3072.p8"))
        .expect("pair");
    let mut sig = [0u8; 384];
    pair.sign(&RSA_PKCS1_SHA384, &rng, MSG, &mut sig)
        .expect("sign");
    let public = include_bytes!("testdata/rsa3072.pub");
    UnparsedPublicKey::new(&RSA_PKCS1_3072_8192_SHA384, &public[..])
        .verify(MSG, &sig)
        .expect("der");
}

/// Everything rustls stores in a `Send + Sync` object.
#[test]
fn keys_can_cross_threads() {
    fn both<T: Send + Sync>() {}
    both::<EcdsaKeyPair>();
    both::<Ed25519KeyPair>();
    both::<RsaKeyPair>();
    both::<&'static dyn RsaEncoding>();
    both::<&'static dyn VerificationAlgorithm>();
    both::<UnparsedPublicKey<&[u8]>>();
}
