//! Wycheproof's Ed25519 verification cases through
//! [`ed25519::verify`]: signature malleability, truncated and
//! padded signatures, wrong-length keys, and edge-case points. The
//! valid cases must verify and every other must fail.

use super::super::acvp::hex;
use super::load;
use scytale::sig::ed25519;

const FILE: &str = "wycheproof/ed25519_test.json";

/// Runs every case; a no-op without the vendored vectors.
pub fn run() {
    let Some(doc) = load(FILE, "EDDSA") else {
        return;
    };
    let mut valid = 0;
    let mut invalid = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let key = &group["publicKey"];
        assert_eq!(key["curve"], "edwards25519");
        let public: [u8; 32] = hex(&key["pk"]).try_into().expect("pk");
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
            let message = hex(&t["msg"]);
            let sig = hex(&t["sig"]);
            let expect_valid = match t["result"].as_str() {
                Some("valid") => true,
                Some("invalid") => false,
                other => panic!("{tag}: unknown result {other:?}"),
            };
            // A signature that is not 64 bytes long is refused by
            // the signature of `verify` itself; the file must agree
            // that every such case is invalid.
            let Ok(sig) = <[u8; 64]>::try_from(sig) else {
                assert!(!expect_valid, "{tag} wrong-length but valid");
                invalid += 1;
                continue;
            };
            let accepted = ed25519::verify(&public, &message, &sig).is_ok();
            assert_eq!(accepted, expect_valid, "{tag}");
            if expect_valid {
                valid += 1;
            } else {
                invalid += 1;
            }
        }
    }
    assert!(valid >= 80, "only {valid} valid cases");
    assert!(invalid >= 60, "only {invalid} invalid cases");
}
