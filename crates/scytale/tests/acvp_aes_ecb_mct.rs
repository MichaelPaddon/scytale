//! NIST ACVP AES-ECB Monte Carlo Tests.
//!
//! MCT chains 100 outer iterations of 1000 inner ones per group, so it is
//! marked `#[ignore]` and runs under `cargo test-extended`. It exercises
//! the key schedule far harder than AFT does, because every outer
//! iteration derives a fresh key from ciphertext.
//!
//! Every group runs through every AES implementation this machine can
//! reach, so each key schedule is driven by the chain rather than only
//! the one a dispatching type would pick.


mod acvp;

use acvp::{
    EcbImpl, Key, ecb_implementations, group_is_encrypt, group_key_len,
    group_tests, groups, hex_field, load, payload, skipped,
};
use serde_json::Value;

const VECTORS: &str = "ACVP-AES-ECB-1.0/internalProjection.json";
const OUTER: usize = 100;
const INNER: usize = 1000;

/// Derive the next key, per the AESAVS Monte Carlo construction. The wider
/// the key, the further back through the ciphertext chain it reaches.
fn next_key(key: &[u8], prev: &[u8; 16], last: &[u8; 16]) -> Vec<u8> {
    let mut feed = Vec::with_capacity(key.len());
    match key.len() {
        16 => feed.extend_from_slice(last),
        24 => {
            feed.extend_from_slice(&prev[8..]);
            feed.extend_from_slice(last);
        }
        32 => {
            feed.extend_from_slice(prev);
            feed.extend_from_slice(last);
        }
        other => panic!("unexpected key length {other}"),
    }
    key.iter().zip(feed).map(|(k, f)| k ^ f).collect()
}

/// Run one Monte Carlo group and compare all 100 recorded results.
fn run_group(group: &Value, imp: &EcbImpl) {
    let key_len = group_key_len(group);
    let encrypting = group_is_encrypt(group);

    for test in group_tests(group) {
        let mut key_bytes = acvp::unhex(hex_field(test, "key"));
        // For an encrypt group the chain starts from pt, for decrypt from ct.
        let start = if encrypting { "pt" } else { "ct" };
        let mut text = payload(hex_field(test, start));
        assert_eq!(text.len(), 16, "MCT seeds are a single block");

        let results = test
            .get("resultsArray")
            .and_then(Value::as_array)
            .expect("MCT case has no resultsArray");
        assert_eq!(results.len(), OUTER);

        for (i, expected) in results.iter().enumerate() {
            let key = Key::from_hex(&hex(&key_bytes), key_len);
            assert_eq!(
                hex(&key_bytes),
                hex_field(expected, "key").to_lowercase(),
                "{} key mismatch at outer iteration {i}",
                imp.name
            );
            assert_eq!(
                hex(&text),
                hex_field(expected, start).to_lowercase(),
                "{} input mismatch at outer iteration {i}",
                imp.name
            );

            let mut prev = [0u8; 16];
            let mut last = [0u8; 16];
            for j in 0..INNER {
                prev = last;
                if encrypting {
                    (imp.encrypt)(&key, &mut text);
                } else {
                    (imp.decrypt)(&key, &mut text);
                }
                last.copy_from_slice(&text);
                let _ = j;
            }

            let produced = if encrypting { "ct" } else { "pt" };
            assert_eq!(
                hex(&last),
                hex_field(expected, produced).to_lowercase(),
                "{} output mismatch at outer iteration {i}, keyLen \
                 {key_len}",
                imp.name
            );

            key_bytes = next_key(&key_bytes, &prev, &last);
            text = last.to_vec();
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "Monte Carlo: 600k chained blocks per implementation"]
fn acvp_aes_ecb_mct() {
    let Some(vectors) = load(VECTORS) else {
        skipped(VECTORS);
        return;
    };

    let implementations = ecb_implementations();
    assert!(
        !implementations.is_empty(),
        "no AES implementation to test"
    );

    for imp in &implementations {
        let mut group_count = 0usize;
        for group in groups(&vectors, "MCT") {
            run_group(group, imp);
            group_count += 1;
        }
        assert_eq!(
            group_count, 6,
            "{}: expected six Monte Carlo groups",
            imp.name
        );
    }
}
