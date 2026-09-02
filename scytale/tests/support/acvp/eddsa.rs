//! EDDSA keyGen, keyVer, sigGen and sigVer, for the Ed25519 groups
//! without pre-hashing or context: plain Ed25519 is what the crate
//! implements. Signing is deterministic, so sigGen compares exact
//! bytes; sigVer and keyVer carry the deliberately damaged cases.

use super::{hex, load};
use scytale::sig::ed25519;
use scytale::Error;

/// Runs the generation suite; a no-op without the vendored vectors.
pub fn run_sig_gen() {
    let file = "EDDSA-SigGen-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != "ED-25519" || group["preHash"] != false {
            continue;
        }
        let secret: [u8; 32] = hex(&group["d"]).try_into().expect("d");
        let public: [u8; 32] = hex(&group["q"]).try_into().expect("q");
        assert_eq!(ed25519::public_key(&secret), Ok(public));
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            // Ed25519ctx is not implemented, and plain Ed25519
            // takes no context; the zero-length groups are the
            // plain ones.
            if t["contextLength"].as_u64().unwrap_or(0) != 0 {
                continue;
            }
            let message = hex(&t["message"]);
            let signature = ed25519::sign(&secret, &message).expect("sign");
            assert_eq!(signature[..], hex(&t["signature"])[..], "{tag}");
            ed25519::verify(&public, &message, &signature).expect("verify");
            cases += 1;
        }
    }
    assert!(cases >= 40, "only {cases} sigGen cases");
}

/// Runs the verification suite; a no-op without the vendored
/// vectors.
pub fn run_sig_ver() {
    let file = "EDDSA-SigVer-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != "ED-25519" || group["preHash"] != false {
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let should_pass = t["testPassed"].as_bool().expect("testPassed");
            let public: [u8; 32] = hex(&t["q"]).try_into().expect("q");
            let message = hex(&t["message"]);
            let signature: [u8; 64] =
                hex(&t["signature"]).try_into().expect("signature");
            let accepted =
                ed25519::verify(&public, &message, &signature).is_ok();
            assert_eq!(accepted, should_pass, "{tag}");
            cases += 1;
            if !should_pass {
                rejections += 1;
            }
        }
    }
    assert!(cases >= 5, "only {cases} sigVer cases");
    assert!(rejections >= 1, "no case had to be rejected");
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors. Ed448 is not implemented, so those groups are skipped.
pub fn run_key_gen() {
    let file = "EDDSA-KeyGen-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    assert_eq!(doc["mode"], "keyGen");
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != "ED-25519" {
            eprintln!(
                "tgId {}: {} not implemented; skipping",
                group["tgId"], group["curve"]
            );
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let secret: [u8; 32] = hex(&t["d"]).try_into().expect("d");
            let public: [u8; 32] = hex(&t["q"]).try_into().expect("q");
            assert_eq!(ed25519::public_key(&secret), Ok(public), "{tag}");
            cases += 1;
        }
    }
    assert!(cases >= 3, "only {cases} keyGen cases");
}

/// Runs the key validation suite; a no-op without the vendored
/// vectors.
///
/// The crate has no standalone key check: a public key is validated
/// as part of verifying with it. That is enough here because
/// [`ed25519::verify`] documents the distinction these cases turn on,
/// returning `InvalidPublicKey` when the key is not a point on the
/// curve and `InvalidSignature` for everything else. The signature
/// handed in is therefore a dummy, and the verdict is read from the
/// error alone.
pub fn run_key_ver() {
    let file = "EDDSA-KeyVer-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    assert_eq!(doc["mode"], "keyVer");
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != "ED-25519" {
            eprintln!(
                "tgId {}: {} not implemented; skipping",
                group["tgId"], group["curve"]
            );
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let should_pass = t["testPassed"].as_bool().expect("testPassed");
            let public: [u8; 32] = hex(&t["q"]).try_into().expect("q");
            let usable = !matches!(
                ed25519::verify(&public, b"", &[0u8; 64]),
                Err(Error::InvalidPublicKey)
            );
            assert_eq!(usable, should_pass, "{tag}");
            cases += 1;
            if !should_pass {
                rejections += 1;
            }
        }
    }
    assert!(cases >= 4, "only {cases} keyVer cases");
    assert!(rejections >= 2, "only {rejections} rejections");
}
