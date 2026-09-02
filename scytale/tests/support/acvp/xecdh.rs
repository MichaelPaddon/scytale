//! XECDH shared-secret computation (RFC 7748): the Curve25519
//! groups, each party's keys given, the shared secret checked from
//! both sides.

use super::{hex, load};
use scytale::publickey::x25519;

/// Runs the suite; a no-op without the vendored vectors.
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
