//! ACVP-PBKDF 1.0. The vendored file exercises HMAC-SHA-224; the
//! driver is generic over the hash and the caller says which groups
//! are its own.

use super::{hex, load};
use scytale::hash::Hash;
use scytale::kdf::pbkdf2::pbkdf2;

const FILE: &str = "ACVP-PBKDF-1.0/internalProjection.json";

/// Runs the groups whose `hmacAlg` is `hmac_alg` against `H`; a
/// no-op without the vendored vectors.
pub fn run_aft<H: Hash>(hmac_alg: &str) {
    let Some(doc) = load(FILE, "PBKDF", "1.0") else {
        return;
    };
    let mut count = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["hmacAlg"] != hmac_alg {
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let password = t["password"].as_str().expect("password");
            let salt = hex(&t["salt"]);
            let iterations =
                t["iterationCount"].as_u64().expect("iterationCount") as u32;
            let expected = hex(&t["derivedKey"]);
            assert_eq!(
                t["keyLen"].as_u64().expect("keyLen") as usize,
                expected.len() * 8
            );
            let mut key = vec![0u8; expected.len()];
            pbkdf2::<H>(password.as_bytes(), &salt, iterations, &mut key)
                .expect("derive");
            assert_eq!(
                key, expected,
                "tgId {} tcId {}",
                group["tgId"], t["tcId"]
            );
            count += 1;
        }
    }
    assert!(count >= 1, "no {hmac_alg} cases");
}
