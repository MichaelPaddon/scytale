//! ACVP-AES-ECB 1.0, run through the [`BlockCipher`] trait.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{cipher_of, groups as suite_groups, hex, key_of};
use crate::KeyType;
use crate::cipher::BlockCipher;
use serde_json::Value;

const FILE: &str = "ACVP-AES-ECB-1.0/internalProjection.json";

/// Iterations of each Monte Carlo step (ACVP AES MCT).
const MCT_ITERATIONS: usize = 1000;

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups::<C>("AFT") else {
        return;
    };
    let count: usize = groups
        .iter()
        .map(|(group, encrypt)| aft::<C>(group, *encrypt))
        .sum();
    // Guard against a truncated or wrong file passing vacuously.
    assert!(count >= 333, "only {count} AFT cases");
}

/// Runs the Monte Carlo (MCT) groups against `C`; a no-op without the
/// vendored vectors. Slow: 600,000 cipher calls.
pub fn run_mct<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups::<C>("MCT") else {
        return;
    };
    let count: usize = groups
        .iter()
        .map(|(group, encrypt)| mct::<C>(group, *encrypt))
        .sum();
    assert!(count >= 200, "only {count} MCT steps");
}

/// The groups of one test type; `None` without the vectors.
fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-ECB", "1.0", test_type)
}

fn apply<C: BlockCipher<Block = [u8; 16]>>(
    cipher: &C,
    encrypt: bool,
    data: &mut [u8],
) {
    let (blocks, rest) = data.as_chunks_mut::<16>();
    assert!(rest.is_empty(), "whole blocks");
    if encrypt {
        cipher.encrypt(blocks);
    } else {
        cipher.decrypt(blocks);
    }
}

/// Algorithm Functional Test: one-shot, possibly several blocks.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> usize {
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let Some(cipher) = cipher_of::<C>(&hex(&t["key"])) else {
            continue;
        };
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
fn mct<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> usize {
    let (input_name, output_name) =
        if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let steps = t["resultsArray"].as_array().expect("resultsArray");
        let mut key = hex(&t["key"]);
        if key_of::<C>(&key).is_none() {
            continue;
        }
        let mut data = hex(&t[input_name]);
        for (i, step) in steps.iter().enumerate() {
            let tag =
                format!("tgId {} tcId {} step {i}", group["tgId"], t["tcId"]);
            assert_eq!(key, hex(&step["key"]), "{tag} key");
            assert_eq!(data, hex(&step[input_name]), "{tag} input");

            let cipher = cipher_of::<C>(&key).expect("width");
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
