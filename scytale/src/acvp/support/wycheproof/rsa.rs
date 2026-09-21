//! Wycheproof's RSA cases: PKCS#1 v1.5 and PSS verification, and
//! OAEP decryption, across key widths and hashes. The invalid cases
//! are the point: signatures altered every way the encoding can
//! bend, and OAEP ciphertexts built to tease apart the error paths,
//! which must all come out as the same rejection.
//!
//! Every group also carries its key in DER and PEM, which is the
//! external check on the key formats: each is imported and compared
//! with the key built from the raw parts, and exported back to the
//! same bytes. The OAEP suites then run under the key read from
//! PKCS#8 rather than from the parts.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::super::acvp::hex;
use super::load;
use crate::Error;
use crate::hash::Hash;
use crate::hash::sha1::Sha1;
use crate::hash::sha2::{Sha256, Sha512};
use crate::pke::rsa::PrivateKey;
use crate::sig::rsa::{DigestInfo, PublicKey};
use serde_json::Value;

/// Runs every vendored file; each is separately optional.
pub fn run() {
    let mut c = Counts::default();
    pkcs1::<Sha256>("wycheproof/rsa_signature_2048_sha256_test.json", &mut c);
    pkcs1::<Sha512>("wycheproof/rsa_signature_2048_sha512_test.json", &mut c);
    pkcs1::<Sha256>("wycheproof/rsa_signature_3072_sha256_test.json", &mut c);
    pkcs1::<Sha512>("wycheproof/rsa_signature_4096_sha512_test.json", &mut c);
    pss::<Sha256>("wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json", &mut c);
    pss::<Sha512>("wycheproof/rsa_pss_4096_sha512_mgf1_32_test.json", &mut c);
    pss::<Sha1>("wycheproof/rsa_pss_2048_sha1_mgf1_20_test.json", &mut c);
    oaep::<Sha1>("wycheproof/rsa_oaep_2048_sha1_mgf1sha1_test.json", &mut c);
    oaep::<Sha256>(
        "wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json",
        &mut c,
    );
    oaep::<Sha512>(
        "wycheproof/rsa_oaep_2048_sha512_mgf1sha512_test.json",
        &mut c,
    );
    if c.files > 0 {
        assert!(c.valid >= 250, "only {} valid cases", c.valid);
        assert!(c.invalid >= 1000, "only {} invalid cases", c.invalid);
    }
}

#[derive(Default)]
struct Counts {
    files: usize,
    valid: usize,
    invalid: usize,
}

fn public_key(group: &Value) -> PublicKey {
    let n = hex(&group["publicKey"]["modulus"]);
    let e = hex(&group["publicKey"]["publicExponent"]);
    let key = PublicKey::try_new(&n, &e).expect("public key");
    check_public_formats(group, &key);
    key
}

/// The modulus of a key, as bytes; either module's public key.
macro_rules! modulus {
    ($key:expr) => {{
        let key = $key;
        let mut n = vec![0u8; key.modulus_len()];
        key.modulus_bytes(&mut n).expect("modulus");
        n
    }};
}
fn modulus(key: &PublicKey) -> Vec<u8> {
    modulus!(key)
}

/// The group's SubjectPublicKeyInfo, bare RSAPublicKey and PEM all
/// name the same key as the raw parts, and come back out unchanged.
fn check_public_formats(group: &Value, key: &PublicKey) {
    let der = hex(&group["publicKeyDer"]);
    let asn = hex(&group["publicKeyAsn"]);
    let pem = group["publicKeyPem"].as_str().expect("publicKeyPem");
    let n = modulus(key);
    let e = key.exponent_bytes();
    let same =
        |other: &PublicKey| modulus(other) == n && other.exponent_bytes() == e;
    assert!(same(&PublicKey::try_from_der(&der).expect("der")));
    assert!(same(&PublicKey::try_from_pkcs1(&asn).expect("asn")));
    assert!(same(&PublicKey::try_from_pem(pem.as_bytes()).expect("pem")));

    let mut out = vec![0u8; 3 * key.modulus_len()];
    let m = key.der_bytes(&mut out).expect("export der");
    assert_eq!(out[..m], der[..], "SubjectPublicKeyInfo");
    let m = key.pkcs1_bytes(&mut out).expect("export pkcs1");
    assert_eq!(out[..m], asn[..], "RSAPublicKey");
    let m = key.pem_bytes(&mut out).expect("export pem");
    assert_eq!(&out[..m], pem.as_bytes(), "PEM");
}

fn pkcs1<H: DigestInfo + Default>(file: &str, counts: &mut Counts) {
    let Some(doc) = load(file, "RSASSA-PKCS1-v1_5") else {
        return;
    };
    counts.files += 1;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let key = public_key(group);
        for t in group["tests"].as_array().expect("tests") {
            // A signature of the wrong length is refused with the
            // rest.
            let accepted = key
                .verify_pkcs1::<H>(&hex(&t["msg"]), &hex(&t["sig"]))
                .is_ok();
            judge(t, accepted, counts);
        }
    }
}

fn pss<H: Hash + Default>(file: &str, counts: &mut Counts) {
    let Some(doc) = load(file, "RSASSA-PSS") else {
        return;
    };
    counts.files += 1;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let key = public_key(group);
        let salt_len = group["sLen"].as_u64().expect("sLen") as usize;
        for t in group["tests"].as_array().expect("tests") {
            let accepted = key
                .verify_pss_with_salt_len::<H>(
                    &hex(&t["msg"]),
                    &hex(&t["sig"]),
                    salt_len,
                )
                .is_ok();
            judge(t, accepted, counts);
        }
    }
}

fn oaep<H: Hash + Default>(file: &str, counts: &mut Counts) {
    let Some(doc) = load(file, "RSAES-OAEP") else {
        return;
    };
    counts.files += 1;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let key = private_key(group);
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
            let label = hex(&t["label"]);
            let mut out = vec![0u8; key.modulus_len()];
            let outcome = key
                .decrypt_oaep::<H>(&label, &hex(&t["ct"]), &mut out)
                .map(|n| out[..n].to_vec());
            let accepted = match outcome {
                Ok(msg) => {
                    assert_eq!(msg, hex(&t["msg"]), "{tag} plaintext");
                    true
                }
                Err(Error::DecryptionFailed) => false,
                Err(e) => panic!("{tag}: {e}"),
            };
            judge(t, accepted, counts);
        }
    }
}

/// The group's key, read from its PKCS#8, after checking that the
/// PEM and the raw parts agree with it, and that both forms come
/// back out unchanged.
fn private_key(group: &Value) -> PrivateKey {
    let sk = &group["privateKey"];
    let der = hex(&group["privateKeyPkcs8"]);
    let pem = group["privateKeyPem"].as_str().expect("privateKeyPem");
    let key = PrivateKey::try_from_der(&der).expect("pkcs8");
    let from_pem = PrivateKey::try_from_pem(pem.as_bytes()).expect("pem");
    let from_parts = PrivateKey::try_new_crt(
        &hex(&sk["modulus"]),
        &hex(&sk["publicExponent"]),
        &hex(&sk["privateExponent"]),
        &hex(&sk["prime1"]),
        &hex(&sk["prime2"]),
        &hex(&sk["exponent1"]),
        &hex(&sk["exponent2"]),
        &hex(&sk["coefficient"]),
    )
    .expect("private key");
    let secret = |key: &PrivateKey| {
        let mut d = vec![0u8; key.modulus_len()];
        key.d_bytes(&mut d).expect("d");
        d
    };
    for other in [&from_pem, &from_parts] {
        assert_eq!(secret(other), secret(&key));
        assert_eq!(modulus!(&other.public_key()), modulus!(&key.public_key()));
    }

    let mut out = vec![0u8; 8 * key.modulus_len()];
    let m = key.der_bytes(&mut out).expect("export der");
    assert_eq!(out[..m], der[..], "PrivateKeyInfo");
    let m = key.pem_bytes(&mut out).expect("export pem");
    assert_eq!(&out[..m], pem.as_bytes(), "PEM");
    key
}

/// Compares an outcome with the file's verdict. An `acceptable`
/// case is legal either way; the counts still see it.
fn judge(t: &Value, accepted: bool, counts: &mut Counts) {
    let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
    match t["result"].as_str() {
        Some("valid") => {
            assert!(accepted, "{tag} rejected");
            counts.valid += 1;
        }
        Some("invalid") => {
            assert!(!accepted, "{tag} accepted");
            counts.invalid += 1;
        }
        Some("acceptable") => {
            if accepted {
                counts.valid += 1;
            } else {
                counts.invalid += 1;
            }
        }
        other => panic!("{tag}: unknown result {other:?}"),
    }
}
