//! Wycheproof's RSA cases: PKCS#1 v1.5 and PSS verification, and
//! OAEP decryption, across key widths and hashes. The invalid cases
//! are the point: signatures altered every way the encoding can
//! bend, and OAEP ciphertexts built to tease apart the error paths,
//! which must all come out as the same rejection.

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
    PublicKey::try_new(&n, &e).expect("public key")
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
        let key = private_key::<L, B, HF>(&group["privateKey"]);
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

fn private_key<const L: usize, const B: usize, const H: usize>(
    sk: &Value,
) -> PrivateKey<L, B, H> {
    PrivateKey::try_new_crt(
        &padded(&sk["modulus"], B),
        &hex(&sk["publicExponent"]),
        &padded(&sk["privateExponent"], B),
        &padded(&sk["prime1"], B / 2),
        &padded(&sk["prime2"], B / 2),
        &padded(&sk["exponent1"], B / 2),
        &padded(&sk["exponent2"], B / 2),
        &padded(&sk["coefficient"], B / 2),
    )
    .expect("private key")
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
