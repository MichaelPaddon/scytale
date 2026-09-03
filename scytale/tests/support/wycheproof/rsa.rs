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

use super::super::acvp::hex;
use super::load;
use scytale::hash::sha2::{Sha256, Sha512};
use scytale::hash::Hash;
use scytale::pke::rsa::PrivateKey;
use scytale::sig::rsa::{DigestInfo, PublicKey};
use scytale::Error;
use serde_json::Value;

/// Runs every vendored file; each is separately optional.
pub fn run() {
    let mut c = Counts::default();
    pkcs1::<Sha256, 32, 256>(
        "wycheproof/rsa_signature_2048_sha256_test.json",
        &mut c,
    );
    pkcs1::<Sha512, 32, 256>(
        "wycheproof/rsa_signature_2048_sha512_test.json",
        &mut c,
    );
    pkcs1::<Sha256, 48, 384>(
        "wycheproof/rsa_signature_3072_sha256_test.json",
        &mut c,
    );
    pkcs1::<Sha512, 64, 512>(
        "wycheproof/rsa_signature_4096_sha512_test.json",
        &mut c,
    );
    pss::<Sha256, 32, 256>(
        "wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json",
        &mut c,
    );
    pss::<Sha512, 64, 512>(
        "wycheproof/rsa_pss_4096_sha512_mgf1_32_test.json",
        &mut c,
    );
    oaep::<Sha256, 32, 256, 16>(
        "wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json",
        &mut c,
    );
    oaep::<Sha512, 32, 256, 16>(
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

/// A big-endian value left-padded to `width`, however the file
/// spells it; hex leading zeros stripped first so 2049-bit spellings
/// of 2048-bit numbers fit.
fn padded(v: &Value, width: usize) -> Vec<u8> {
    let bytes = hex(v);
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let value = &bytes[start..];
    assert!(value.len() <= width, "value wider than the key");
    let mut out = vec![0u8; width - value.len()];
    out.extend_from_slice(value);
    out
}

fn public_key<const L: usize, const B: usize>(
    group: &Value,
) -> PublicKey<L, B> {
    let n = padded(&group["publicKey"]["modulus"], B);
    let e = hex(&group["publicKey"]["publicExponent"]);
    let key = PublicKey::try_new(&n, &e).expect("public key");
    check_public_formats(group, &key);
    key
}

/// The group's SubjectPublicKeyInfo, bare RSAPublicKey and PEM all
/// name the same key as the raw parts, and come back out unchanged.
fn check_public_formats<const L: usize, const B: usize>(
    group: &Value,
    key: &PublicKey<L, B>,
) {
    let der = hex(&group["publicKeyDer"]);
    let asn = hex(&group["publicKeyAsn"]);
    let pem = group["publicKeyPem"].as_str().expect("publicKeyPem");
    let n = key.modulus_bytes();
    let e = key.exponent_bytes();
    let same = |other: &PublicKey<L, B>| {
        other.modulus_bytes() == n && other.exponent_bytes() == e
    };
    assert!(same(&PublicKey::try_from_der(&der).expect("der")));
    assert!(same(&PublicKey::try_from_pkcs1(&asn).expect("asn")));
    assert!(same(&PublicKey::try_from_pem(pem.as_bytes()).expect("pem")));

    let mut out = vec![0u8; 3 * B];
    let m = key.der_bytes(&mut out).expect("export der");
    assert_eq!(out[..m], der[..], "SubjectPublicKeyInfo");
    let m = key.pkcs1_bytes(&mut out).expect("export pkcs1");
    assert_eq!(out[..m], asn[..], "RSAPublicKey");
    let m = key.pem_bytes(&mut out).expect("export pem");
    assert_eq!(&out[..m], pem.as_bytes(), "PEM");
}

fn pkcs1<H: DigestInfo, const L: usize, const B: usize>(
    file: &str,
    counts: &mut Counts,
) {
    let Some(doc) = load(file, "RSASSA-PKCS1-v1_5") else {
        return;
    };
    counts.files += 1;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let key = public_key::<L, B>(group);
        for t in group["tests"].as_array().expect("tests") {
            let accepted = match <[u8; B]>::try_from(hex(&t["sig"])) {
                Ok(sig) => key.verify_pkcs1::<H>(&hex(&t["msg"]), &sig).is_ok(),
                // The wrong length cannot even be presented.
                Err(_) => false,
            };
            judge(t, accepted, counts);
        }
    }
}

fn pss<H: Hash, const L: usize, const B: usize>(
    file: &str,
    counts: &mut Counts,
) {
    let Some(doc) = load(file, "RSASSA-PSS") else {
        return;
    };
    counts.files += 1;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let key = public_key::<L, B>(group);
        let salt_len = group["sLen"].as_u64().expect("sLen") as usize;
        for t in group["tests"].as_array().expect("tests") {
            let accepted = match <[u8; B]>::try_from(hex(&t["sig"])) {
                Ok(sig) => {
                    key.verify_pss::<H>(&hex(&t["msg"]), &sig, salt_len).is_ok()
                }
                Err(_) => false,
            };
            judge(t, accepted, counts);
        }
    }
}

fn oaep<H: Hash, const L: usize, const B: usize, const HF: usize>(
    file: &str,
    counts: &mut Counts,
) {
    let Some(doc) = load(file, "RSAES-OAEP") else {
        return;
    };
    counts.files += 1;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let key = private_key::<L, B, HF>(group);
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
            let label = hex(&t["label"]);
            let mut out = vec![0u8; B];
            let outcome = match <[u8; B]>::try_from(hex(&t["ct"])) {
                Ok(ct) => key
                    .decrypt_oaep::<H>(&label, &ct, &mut out)
                    .map(|n| out[..n].to_vec()),
                Err(_) => Err(Error::DecryptionFailed),
            };
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
fn private_key<const L: usize, const B: usize, const H: usize>(
    group: &Value,
) -> PrivateKey<L, B, H> {
    let sk = &group["privateKey"];
    let der = hex(&group["privateKeyPkcs8"]);
    let pem = group["privateKeyPem"].as_str().expect("privateKeyPem");
    let key = PrivateKey::<L, B, H>::try_from_der(&der).expect("pkcs8");
    let from_pem =
        PrivateKey::<L, B, H>::try_from_pem(pem.as_bytes()).expect("pem");
    let from_parts = PrivateKey::<L, B, H>::try_new_crt(
        &padded(&sk["modulus"], B),
        &hex(&sk["publicExponent"]),
        &padded(&sk["privateExponent"], B),
        &padded(&sk["prime1"], B / 2),
        &padded(&sk["prime2"], B / 2),
        &padded(&sk["exponent1"], B / 2),
        &padded(&sk["exponent2"], B / 2),
        &padded(&sk["coefficient"], B / 2),
    )
    .expect("private key");
    for other in [&from_pem, &from_parts] {
        assert_eq!(other.d_bytes(), key.d_bytes());
        assert_eq!(
            other.public_key().modulus_bytes(),
            key.public_key().modulus_bytes()
        );
    }

    let mut out = vec![0u8; 8 * B];
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
