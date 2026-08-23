//! ACVP-AES-ECB 1.0, run through the [`BlockCipher`] trait.

use super::{groups as suite_groups, hex};
use scytale::symmetric::BlockCipher;
use serde_json::Value;

const FILE: &str = "ACVP-AES-ECB-1.0/internalProjection.json";

/// Iterations of each Monte Carlo step (ACVP AES MCT).
const MCT_ITERATIONS: usize = 1000;

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
pub fn run_aft<C: BlockCipher>() {
    let Some(groups) = groups("AFT") else { return };
    let count: usize = groups
        .iter()
        .map(|(group, encrypt)| aft::<C>(group, *encrypt))
        .sum();
    // Guard against a truncated or wrong file passing vacuously.
    assert!(count >= 1000, "only {count} AFT cases");
}

/// Runs the Monte Carlo (MCT) groups against `C`; a no-op without the
/// vendored vectors. Slow: 600,000 cipher calls.
pub fn run_mct<C: BlockCipher>() {
    let Some(groups) = groups("MCT") else { return };
    let count: usize = groups
        .iter()
        .map(|(group, encrypt)| mct::<C>(group, *encrypt))
        .sum();
    assert!(count >= 600, "only {count} MCT steps");
}

/// The groups of one test type; `None` without the vectors.
fn groups(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups(FILE, "ACVP-AES-ECB", "1.0", test_type)
}

fn apply<C: BlockCipher>(cipher: &C, encrypt: bool, data: &mut [u8]) {
    if encrypt {
        cipher.encrypt_blocks(data).expect("whole blocks");
    } else {
        cipher.decrypt_blocks(data).expect("whole blocks");
    }
}

/// Algorithm Functional Test: one-shot, possibly several blocks.
fn aft<C: BlockCipher>(group: &Value, encrypt: bool) -> usize {
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let cipher = C::try_new(&hex(&t["key"])).expect("key");
        let (input, expected) = if encrypt {
            (hex(&t["pt"]), hex(&t["ct"]))
        } else {
            (hex(&t["ct"]), hex(&t["pt"]))
        };
        let mut data = input;
        apply(&cipher, encrypt, &mut data);
        assert_eq!(data, expected, "tgId {} tcId {}", group["tgId"], t["tcId"]);
        count += 1;
    }
    count
}

/// Monte Carlo Test, per the ACVP AES MCT for ECB: each of 100 steps
/// runs 1000 chained cipher calls, then derives the next key from the
/// last outputs. The vectors give the key and input of each step, and
/// the output of its final call.
fn mct<C: BlockCipher>(group: &Value, encrypt: bool) -> usize {
    let (input_name, output_name) =
        if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let steps = t["resultsArray"].as_array().expect("resultsArray");
        let mut key = hex(&t["key"]);
        let mut data = hex(&t[input_name]);
        for (i, step) in steps.iter().enumerate() {
            let tag =
                format!("tgId {} tcId {} step {i}", group["tgId"], t["tcId"]);
            assert_eq!(key, hex(&step["key"]), "{tag} key");
            assert_eq!(data, hex(&step[input_name]), "{tag} input");

            let cipher = C::try_new(&key).expect("key");
            let mut previous = data.clone();
            for _ in 0..MCT_ITERATIONS {
                previous.copy_from_slice(&data);
                apply(&cipher, encrypt, &mut data);
            }
            assert_eq!(data, hex(&step[output_name]), "{tag} output");

            // Next key: xor with the last 16, 24 or 32 bytes of the
            // last two outputs, most recent last.
            let mut tail = previous;
            tail.extend_from_slice(&data);
            let tail = &tail[tail.len() - key.len()..];
            for (k, t) in key.iter_mut().zip(tail) {
                *k ^= t;
            }
            count += 1;
        }
    }
    count
}
