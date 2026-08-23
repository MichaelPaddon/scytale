//! Drivers for NIST ACVP vector files, generic over the primitive's
//! trait so any implementation can run them.

pub mod aes_cbc;
pub mod aes_cfb1;
pub mod aes_cfb128;
pub mod aes_cfb8;
pub mod aes_ctr;
pub mod aes_ecb;
pub mod aes_gcm;
pub mod aes_gcm_siv;
pub mod aes_ofb;
pub mod aes_xts;

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
    // Not every suite records a revision.
    if !doc["revision"].is_null() {
        assert_eq!(doc["revision"], revision);
    }
    Some(doc)
}

/// The groups of one test type in a suite, each paired with whether
/// it is the encrypt direction. `None` if the vectors are not
/// vendored in this copy.
pub fn groups(
    file: &str,
    algorithm: &str,
    revision: &str,
    test_type: &str,
) -> Option<Vec<(Value, bool)>> {
    let doc = load(file, algorithm, revision)?;
    let mut selected = Vec::new();
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let encrypt = match group["direction"].as_str() {
            Some("encrypt") => true,
            Some("decrypt") => false,
            other => panic!("unknown direction {other:?}"),
        };
        match group["testType"].as_str() {
            Some(t) if t == test_type => {
                selected.push((group.clone(), encrypt))
            }
            Some("AFT") | Some("MCT") => {}
            other => panic!("unknown testType {other:?}"),
        }
    }
    Some(selected)
}
