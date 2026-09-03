//! Drivers for Project Wycheproof vector files, which test the edge
//! cases the standards' own vectors leave out: wrong tags, truncated
//! inputs, and messages built to trip carries.

pub mod chacha20_poly1305;
pub mod ecdh;
pub mod ecdsa;
pub mod ed25519;
pub mod ml_dsa;
pub mod ml_kem;
pub mod rsa;
pub mod x25519;

use serde_json::Value;

/// Loads and parses a Wycheproof file, checking the algorithm;
/// `None` if the vectors are not vendored in this copy.
pub fn load(file: &str, algorithm: &str) -> Option<Value> {
    let json = super::vectors::load(file)?;
    let doc: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(doc["algorithm"], algorithm);
    Some(doc)
}
