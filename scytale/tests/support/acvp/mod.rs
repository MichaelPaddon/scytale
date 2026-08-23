//! Drivers for NIST ACVP vector files, generic over the primitive's
//! trait so any implementation can run them.

pub mod aes_ecb;

use serde_json::Value;

pub fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Loads and parses a vector file, checking it is the expected suite;
/// `None` if the vectors are not vendored in this copy.
pub fn load(file: &str, algorithm: &str, revision: &str) -> Option<Value> {
    let json = super::vectors::load(file)?;
    let doc: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(doc["algorithm"], algorithm);
    assert_eq!(doc["revision"], revision);
    Some(doc)
}
