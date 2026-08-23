//! ACVP-AES-OFB 1.0, run through [`Ofb`] over any block cipher.
//!
//! The Monte Carlo test has the same shape as the one for cipher
//! feedback with full-block segments: 1000 blocks through a single
//! continuing state, each input being the IV and then the output one
//! block back.

use super::{groups as suite_groups, hex};
use scytale::symmetric::mode::Ofb;
use scytale::symmetric::BlockCipher;
use serde_json::Value;

const FILE: &str = "ACVP-AES-OFB-1.0/internalProjection.json";

/// Segments in one Monte Carlo step.
const MCT_SEGMENTS: usize = 1000;

/// Blocks of history the IV holds: one.
const HISTORY: usize = 1;

pub fn run_aft<C: BlockCipher>() {
    let Some(groups) = groups("AFT") else { return };
    let count: usize = groups
        .iter()
        .map(|(group, encrypt)| aft::<C>(group, *encrypt))
        .sum();
    assert!(count >= 2000, "only {count} AFT cases");
}

pub fn run_mct<C: BlockCipher>() {
    let Some(groups) = groups("MCT") else { return };
    let count: usize = groups
        .iter()
        .map(|(group, encrypt)| mct::<C>(group, *encrypt))
        .sum();
    assert!(count >= 600, "only {count} MCT steps");
}

fn groups(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups(FILE, "ACVP-AES-OFB", "1.0", test_type)
}

fn ofb<C: BlockCipher>(key: &[u8]) -> Ofb<C> {
    Ofb::new(C::try_new(key).expect("key"))
}

fn aft<C: BlockCipher>(group: &Value, encrypt: bool) -> usize {
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let ofb = ofb::<C>(&hex(&t["key"]));
        let iv = hex(&t["iv"]);
        let (input, expected) = if encrypt {
            (hex(&t["pt"]), hex(&t["ct"]))
        } else {
            (hex(&t["ct"]), hex(&t["pt"]))
        };
        let mut data = input;
        if encrypt {
            ofb.encrypt(&iv, &mut data).expect("whole blocks");
        } else {
            ofb.decrypt(&iv, &mut data).expect("whole blocks");
        }
        assert_eq!(data, expected, "tgId {} tcId {}", group["tgId"], t["tcId"]);
        count += 1;
    }
    count
}

/// Monte Carlo Test. One step is 1000 segments through a single
/// continuing state; each segment's input is a segment of the IV
/// while the register still holds IV material, and an earlier output
/// after that.
fn mct<C: BlockCipher>(group: &Value, encrypt: bool) -> usize {
    let (input_name, output_name) =
        if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let steps = t["resultsArray"].as_array().expect("resultsArray");
        let mut key = hex(&t["key"]);
        let mut iv = hex(&t["iv"]);
        let mut input = hex(&t[input_name]);

        for (i, step) in steps.iter().enumerate() {
            let tag =
                format!("tgId {} tcId {} step {i}", group["tgId"], t["tcId"]);
            assert_eq!(key, hex(&step["key"]), "{tag} key");
            assert_eq!(iv, hex(&step["iv"]), "{tag} iv");
            assert_eq!(input, hex(&step[input_name]), "{tag} input");

            let ofb = ofb::<C>(&key);
            let mut outputs: Vec<Vec<u8>> = Vec::with_capacity(MCT_SEGMENTS);
            // One state serves both directions: the keystream does
            // not depend on the message.
            let mut segment = input.clone();
            let mut state = ofb.stream(&iv).expect("iv");
            for j in 0..MCT_SEGMENTS {
                state.update(&mut segment).expect("one block");
                outputs.push(segment.clone());
                segment = next_input(&iv, &outputs, j);
            }

            let last = &outputs[MCT_SEGMENTS - 1];
            assert_eq!(*last, hex(&step[output_name]), "{tag} output");

            // The tail of the outputs supplies the next key, IV and
            // input. The key takes the last bytes of the stream,
            // which for a 192-bit key is part of one segment and all
            // of the next.
            let size = last.len();
            let segments = key.len().div_ceil(size);
            let recent: Vec<u8> = outputs[MCT_SEGMENTS - segments..].concat();
            let tail = &recent[recent.len() - key.len()..];
            for (k, t) in key.iter_mut().zip(tail) {
                *k ^= t;
            }
            iv = outputs[MCT_SEGMENTS - HISTORY..].concat();
            input = outputs[MCT_SEGMENTS - HISTORY - 1].clone();
            count += 1;
        }
    }
    count
}

/// The input for segment `j + 1`: a segment of the IV until the IV
/// has been consumed, then the output `HISTORY` segments back.
fn next_input(iv: &[u8], outputs: &[Vec<u8>], j: usize) -> Vec<u8> {
    if j < HISTORY {
        iv.to_vec()
    } else {
        outputs[j - HISTORY].clone()
    }
}
