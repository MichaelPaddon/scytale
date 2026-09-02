//! XECDH shared-secret computation and key generation (RFC 7748):
//! the Curve25519 groups, each party's keys given, the shared secret
//! checked from both sides.
//!
//! The keyVer suite is deliberately not run. RFC 7748 masks the top
//! bit and accepts any 32-byte string as a public key, so ACVP's only
//! Curve25519 failures there are keys of 31 and 33 bytes, which
//! `[u8; 32]` refuses at the type level. Its one remaining reason,
//! a set most significant bit, is a passing case whose public key is
//! not derived from the private key it is given, so it cannot serve
//! as extra keyGen coverage either.

use super::{hex, load};
use scytale::kex::x25519;

/// Runs the shared-secret suite; a no-op without the vendored
/// vectors.
pub fn run() {
    let file = "XECDH-SSC-RFC7748/internalProjection.json";
    let Some(doc) = load(file, "XECDH", "RFC7748") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != "Curve25519" {
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let key = |name: &str| -> [u8; 32] {
                hex(&t[name]).try_into().expect("key")
            };
            let z = key("z");
            let iut = x25519::x25519(&key("privateIut"), &key("publicServer"));
            let server =
                x25519::x25519(&key("privateServer"), &key("publicIut"));
            assert_eq!(iut, z, "{tag} IUT side");
            assert_eq!(server, z, "{tag} server side");
            cases += 1;
        }
    }
    assert!(cases >= 20, "only {cases} cases");
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors. Curve448 is not implemented, so those groups are skipped.
pub fn run_key_gen() {
    let file = "XECDH-keyGen-RFC7748/internalProjection.json";
    let Some(doc) = load(file, "XECDH", "RFC7748") else {
        return;
    };
    assert_eq!(doc["mode"], "keyGen");
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != "Curve25519" {
            eprintln!(
                "tgId {}: {} not implemented; skipping",
                group["tgId"], group["curve"]
            );
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let secret: [u8; 32] =
                hex(&t["privateKey"]).try_into().expect("privateKey");
            let public: [u8; 32] =
                hex(&t["publicKey"]).try_into().expect("publicKey");
            assert_eq!(x25519::public_key(&secret), public, "{tag}");
            cases += 1;
        }
    }
    assert!(cases >= 10, "only {cases} keyGen cases");
}
