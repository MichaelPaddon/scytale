//! Shared plumbing for the vendored NIST ACVP vector files.
//!
//! The vectors live at `vectors/acvp/` in the repository and are deliberately
//! not part of the published crate, so a runner that cannot find them says so
//! and skips rather than failing.

// Each test binary compiles this module separately and uses a different part
// of it, so unused items here are expected rather than dead.
#![allow(dead_code)]

use std::path::PathBuf;

use serde_json::Value;

/// Locate a vendored ACVP file, or `None` when the vectors are absent.
pub fn vector_path(relative: &str) -> Option<PathBuf> {
    // CARGO_MANIFEST_DIR is crates/scytale, so the repository root is two
    // levels up.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/acvp")
        .join(relative);
    if path.exists() { Some(path) } else { None }
}

/// Parse a vendored ACVP file, or `None` when the vectors are absent.
pub fn load(relative: &str) -> Option<Value> {
    let path = vector_path(relative)?;
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let json = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()));
    Some(json)
}

/// Announce a skip in a way that shows up under `cargo test -- --nocapture`.
pub fn skipped(relative: &str) {
    eprintln!(
        "skipping: {relative} not vendored; ACVP vectors are excluded from \
         the published crate"
    );
}

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex in vector file");
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .expect("invalid hex in vector file")
        })
        .collect()
}

pub fn hex_field<'a>(v: &'a Value, name: &str) -> &'a str {
    v.get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("test case has no string field {name}"))
}

/// ACVP ECB payloads are whole numbers of blocks, up to ten of them, so a
/// case is a byte string rather than a single block.
pub fn payload(s: &str) -> Vec<u8> {
    let bytes = unhex(s);
    assert!(
        !bytes.is_empty() && bytes.len().is_multiple_of(16),
        "payload of {} bytes is not a whole number of blocks",
        bytes.len()
    );
    bytes
}

/// Every AES key length ACVP exercises, as a fixed-size array.
pub enum Key {
    K128([u8; 16]),
    K192([u8; 24]),
    K256([u8; 32]),
}

impl Key {
    pub fn from_hex(s: &str, key_len: u64) -> Self {
        let bytes = unhex(s);
        match key_len {
            128 => Key::K128(bytes.try_into().expect("128-bit key")),
            192 => Key::K192(bytes.try_into().expect("192-bit key")),
            256 => Key::K256(bytes.try_into().expect("256-bit key")),
            other => panic!("unexpected keyLen {other}"),
        }
    }

    /// Encrypt a whole payload in ECB, expanding the key once.
    ///
    /// Hands the entire payload to the cipher in one call, which is the
    /// interface an accelerated backend can pipeline.
    pub fn encrypt(&self, data: &mut [u8]) -> usize {
        use scytale::symmetric::aes::{Aes128, Aes192, Aes256};
        match self {
            Key::K128(k) => Aes128::new(k).encrypt(data),
            Key::K192(k) => Aes192::new(k).encrypt(data),
            Key::K256(k) => Aes256::new(k).encrypt(data),
        }
    }

    /// Decrypt a whole payload in ECB, expanding the key once.
    pub fn decrypt(&self, data: &mut [u8]) -> usize {
        use scytale::symmetric::aes::{Aes128, Aes192, Aes256};
        match self {
            Key::K128(k) => Aes128::new(k).decrypt(data),
            Key::K192(k) => Aes192::new(k).decrypt(data),
            Key::K256(k) => Aes256::new(k).decrypt(data),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Key::K128(k) => k,
            Key::K192(k) => k,
            Key::K256(k) => k,
        }
    }
}

/// Iterate the test groups of one testType, e.g. "AFT" or "MCT".
pub fn groups<'a>(
    vectors: &'a Value,
    test_type: &str,
) -> impl Iterator<Item = &'a Value> {
    vectors
        .get("testGroups")
        .and_then(Value::as_array)
        .expect("vector file has no testGroups array")
        .iter()
        .filter(move |g| {
            g.get("testType").and_then(Value::as_str) == Some(test_type)
        })
}

pub fn group_key_len(group: &Value) -> u64 {
    group
        .get("keyLen")
        .and_then(Value::as_u64)
        .expect("test group has no keyLen")
}

pub fn group_is_encrypt(group: &Value) -> bool {
    match group.get("direction").and_then(Value::as_str) {
        Some("encrypt") => true,
        Some("decrypt") => false,
        other => panic!("unexpected direction {other:?}"),
    }
}

pub fn group_tests(group: &Value) -> &[Value] {
    group
        .get("tests")
        .and_then(Value::as_array)
        .expect("test group has no tests array")
}
