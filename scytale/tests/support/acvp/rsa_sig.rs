//! RSA sigVer (FIPS 186-5), plus the sigGen file's sample
//! signatures run through verification: sigGen supplies no private
//! key, so its worked answers serve as extra known-good signatures
//! under NIST-chosen keys and exponents.
//!
//! Groups whose hash or mask function is a SHAKE are skipped: FIPS
//! 186-5 allows XOFs in both roles, and the crate's PSS is defined
//! over fixed-output hashes with MGF1 as the mask.

use super::{hex, load};
use scytale::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use scytale::hash::sha2::{Sha512_224, Sha512_256};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::sig::rsa::PublicKey;
use serde_json::Value;

/// Runs one case through the right hash, or `None` for a hash the
/// crate does not sign with (the SHAKEs).
macro_rules! dispatch_hash {
    ($alg:expr, $run:ident, $($arg:expr),*) => {
        match $alg {
            "SHA2-224" => Some($run::<Sha224>($($arg),*)),
            "SHA2-256" => Some($run::<Sha256>($($arg),*)),
            "SHA2-384" => Some($run::<Sha384>($($arg),*)),
            "SHA2-512" => Some($run::<Sha512>($($arg),*)),
            "SHA2-512/224" => Some($run::<Sha512_224>($($arg),*)),
            "SHA2-512/256" => Some($run::<Sha512_256>($($arg),*)),
            "SHA3-224" => Some($run::<Sha3_224>($($arg),*)),
            "SHA3-256" => Some($run::<Sha3_256>($($arg),*)),
            "SHA3-384" => Some($run::<Sha3_384>($($arg),*)),
            "SHA3-512" => Some($run::<Sha3_512>($($arg),*)),
            "SHAKE-128" | "SHAKE-256" => None,
            other => panic!("unknown hash {other}"),
        }
    };
}

/// One verification, generic over hash and width.
fn verify_one<H, const L: usize, const B: usize>(
    group: &Value,
    t: &Value,
) -> bool
where
    H: scytale::sig::rsa::DigestInfo,
{
    let n = hex(&group["n"]);
    let key =
        PublicKey::<L, B>::try_new(&n, &hex(&group["e"])).expect("public key");
    let message = hex(&t["message"]);
    let Ok(sig) = <[u8; B]>::try_from(hex(&t["signature"])) else {
        return false;
    };
    match group["sigType"].as_str().expect("sigType") {
        "pkcs1v1.5" => key.verify_pkcs1::<H>(&message, &sig).is_ok(),
        "pss" => {
            let salt = group["saltLen"].as_u64().expect("saltLen") as usize;
            key.verify_pss::<H>(&message, &sig, salt).is_ok()
        }
        other => panic!("unknown sigType {other}"),
    }
}

/// Runs the sigVer suite; a no-op without the vendored vectors.
pub fn run_sig_ver() {
    run(
        "RSA-SigVer-FIPS186-5/internalProjection.json",
        "sigVer",
        true,
    );
}

/// Runs the sigGen file's sample answers as verifications.
pub fn run_sig_gen() {
    run(
        "RSA-SigGen-FIPS186-5/internalProjection.json",
        "sigGen",
        false,
    );
}

fn run(file: &str, mode: &str, has_verdicts: bool) {
    let Some(doc) = load(file, "RSA", "FIPS186-5") else {
        return;
    };
    assert_eq!(doc["mode"], mode);
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let alg = group["hashAlg"].as_str().expect("hashAlg");
        if group["sigType"] == "pss" && group["maskFunction"] != "mgf1" {
            continue;
        }
        // SP 800-106 randomized hashing signs a salted transform of
        // the message, which the crate does not offer.
        if group["conformance"] == "SP800-106" {
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let accepted = match group["modulo"].as_u64().expect("modulo") {
                2048 => dispatch_hash!(alg, verify_one_2048, group, t),
                3072 => dispatch_hash!(alg, verify_one_3072, group, t),
                4096 => dispatch_hash!(alg, verify_one_4096, group, t),
                other => panic!("unknown modulus {other}"),
            };
            let Some(accepted) = accepted else {
                continue; // a SHAKE group
            };
            let should_pass = if has_verdicts {
                t["testPassed"].as_bool().expect("testPassed")
            } else {
                true
            };
            assert_eq!(accepted, should_pass, "{tag}");
            cases += 1;
            if !should_pass {
                rejections += 1;
            }
        }
    }
    assert!(cases >= 20, "only {cases} cases in {mode}");
    if has_verdicts {
        assert!(rejections >= 10, "only {rejections} rejections");
    }
}

fn verify_one_2048<H: scytale::sig::rsa::DigestInfo>(
    group: &Value,
    t: &Value,
) -> bool {
    verify_one::<H, 32, 256>(group, t)
}

fn verify_one_3072<H: scytale::sig::rsa::DigestInfo>(
    group: &Value,
    t: &Value,
) -> bool {
    verify_one::<H, 48, 384>(group, t)
}

fn verify_one_4096<H: scytale::sig::rsa::DigestInfo>(
    group: &Value,
    t: &Value,
) -> bool {
    verify_one::<H, 64, 512>(group, t)
}
