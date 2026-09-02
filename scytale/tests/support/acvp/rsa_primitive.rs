//! The two RSA component suites, which drive the primitives on
//! their own rather than through a scheme.
//!
//! `RSA-SignaturePrimitive` is the one place where NIST supplies
//! private keys with expected answers, so it is the only external
//! check that a value this crate *produces* under a private exponent
//! is the right one. Everything else about RSA signing is verified
//! rather than generated. It runs at all three widths in both the
//! plain and the Chinese remainder key forms.
//!
//! `RSA-decryptionPrimitive` supplies no private exponent: its
//! entries are public moduli with a ciphertext, so what it checks is
//! the public direction and the refusal of a representative at or
//! above the modulus.

use super::{hex, load};
use scytale::pke::rsa::PublicKey as PkePublicKey;
use scytale::sig::rsa::PrivateKey;
use scytale::Error;
use serde_json::Value;

/// One signature-primitive case at a fixed width. Returns whether
/// the case was one that had to be refused.
fn signature_case<const L: usize, const B: usize, const H: usize>(
    group: &Value,
    t: &Value,
    tag: &str,
) -> bool {
    let n = hex(&t["n"]);
    let e = hex(&t["e"]);
    let key = match group["keyMode"].as_str().expect("keyMode") {
        "standard" => PrivateKey::<L, B, H>::try_new(&n, &e, &hex(&t["d"])),
        "crt" => PrivateKey::<L, B, H>::try_new_crt(
            &n,
            &e,
            &hex(&t["d"]),
            &hex(&t["p"]),
            &hex(&t["q"]),
            &hex(&t["dmp1"]),
            &hex(&t["dmq1"]),
            &hex(&t["iqmp"]),
        ),
        other => panic!("unknown keyMode {other}"),
    }
    .expect("private key");

    let message: [u8; B] = hex(&t["message"]).try_into().expect("message");
    match t["testPassed"].as_bool().expect("testPassed") {
        true => {
            let signature = key.sign_primitive(&message).expect("sign");
            assert_eq!(signature[..], hex(&t["signature"])[..], "{tag}");
            // The public direction must undo it, which also proves
            // the answer is a representative and not a stray value.
            let back = key
                .public_key()
                .verify_primitive(&signature)
                .expect("verify");
            assert_eq!(back, message, "{tag} round trip");
            false
        }
        // The failing cases carry no signature at all. What makes
        // them fail is a representative at or above the modulus,
        // which the primitive is what refuses.
        false => {
            assert!(t["signature"].is_null(), "{tag} has a signature");
            assert_eq!(
                key.sign_primitive(&message),
                Err(Error::MessageTooLong),
                "{tag}"
            );
            true
        }
    }
}

/// Runs the signature primitive suite; a no-op without the vendored
/// vectors.
pub fn run_signature_primitive() {
    let file = "RSA-SignaturePrimitive-2.0/internalProjection.json";
    let Some(doc) = load(file, "RSA", "2.0") else {
        return;
    };
    assert_eq!(doc["mode"], "signaturePrimitive");
    let mut signed = 0;
    let mut refused = 0;
    let mut crt = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        match group["testType"].as_str() {
            Some("AFT") => {}
            other => panic!("unknown testType {other:?}"),
        }
        let is_crt = group["keyMode"] == "crt";
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let out_of_range = match group["modulo"].as_u64().expect("modulo") {
                2048 => signature_case::<32, 256, 16>(group, t, &tag),
                3072 => signature_case::<48, 384, 24>(group, t, &tag),
                4096 => signature_case::<64, 512, 32>(group, t, &tag),
                other => panic!("unknown modulus {other}"),
            };
            if out_of_range {
                refused += 1;
            } else {
                signed += 1;
                if is_crt {
                    crt += 1;
                }
            }
        }
    }
    assert!(signed >= 78, "only {signed} signatures");
    assert!(refused >= 12, "only {refused} refusals");
    // The CRT path is half the point of the suite, so losing it to a
    // change in how the groups are labelled must not pass quietly.
    assert!(crt >= 39, "only {crt} through the primes");
}

/// Runs the decryption primitive suite; a no-op without the vendored
/// vectors.
pub fn run_decryption_primitive() {
    let file = "RSA-decryptionPrimitive-1.0/internalProjection.json";
    let Some(doc) = load(file, "RSA", "1.0") else {
        return;
    };
    assert_eq!(doc["mode"], "decryptionPrimitive");
    let mut verified = 0;
    let mut refused = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        match group["testType"].as_str() {
            Some("AFT") => {}
            other => panic!("unknown testType {other:?}"),
        }
        assert_eq!(group["modulo"], 2048, "only 2048-bit entries expected");
        for t in group["tests"].as_array().expect("tests") {
            // One case holds many independent entries, each with its
            // own key.
            for (i, r) in t["resultsArray"]
                .as_array()
                .expect("resultsArray")
                .iter()
                .enumerate()
            {
                let tag = format!("tcId {} entry {i}", t["tcId"]);
                let built = PkePublicKey::<32, 256>::try_new(
                    &hex(&r["n"]),
                    &hex(&r["e"]),
                );
                let passed = r["testPassed"].as_bool().expect("testPassed");
                // A failing entry can be bad in either of two ways,
                // and the crate refuses them at different points: an
                // even modulus never becomes a key at all, while a
                // ciphertext at or above the modulus is caught by the
                // primitive. Either refusal is the right answer.
                let Ok(key) = built else {
                    assert!(!passed, "{tag} key rejected");
                    refused += 1;
                    continue;
                };
                if passed {
                    // A representative may be written with a
                    // leading zero byte, so it is right-aligned into
                    // the key's width rather than converted.
                    let bytes = hex(&r["plainText"]);
                    let start = bytes.len().saturating_sub(256);
                    let tail = &bytes[start..];
                    assert!(
                        bytes[..start].iter().all(|b| *b == 0),
                        "{tag} wider than the key"
                    );
                    let mut pt = [0u8; 256];
                    pt[256 - tail.len()..].copy_from_slice(tail);
                    let ct = key.encrypt_primitive(&pt).expect("apply");
                    assert_eq!(ct[..], hex(&r["cipherText"])[..], "{tag}");
                    verified += 1;
                } else {
                    // No private exponent is given, so the refusal is
                    // checked against the same modulus comparison the
                    // private primitive makes.
                    let ct: [u8; 256] =
                        hex(&r["cipherText"]).try_into().expect("ciphertext");
                    assert_eq!(
                        key.encrypt_primitive(&ct),
                        Err(Error::MessageTooLong),
                        "{tag}"
                    );
                    refused += 1;
                }
            }
        }
    }
    assert!(verified >= 4, "only {verified} entries verified");
    assert!(refused >= 2, "only {refused} refusals");
}
