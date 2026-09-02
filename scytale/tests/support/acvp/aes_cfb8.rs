//! ACVP-AES-CFB8 1.0, run through [`Cfb8`] over any block cipher.

use super::{groups as suite_groups, hex};
use scytale::cipher::mode::Cfb8;
use scytale::cipher::{Block, BlockCipher};
use serde_json::Value;

/// The IV as the cipher's block type.
fn block<C: BlockCipher>(bytes: &[u8]) -> C::Block {
    let mut block = C::Block::ZERO;
    block.as_mut().copy_from_slice(bytes);
    block
}

const FILE: &str = "ACVP-AES-CFB8-1.0/internalProjection.json";

/// Segments (bytes) in one Monte Carlo step.
const MCT_SEGMENTS: usize = 1000;

/// Segments the IV holds: sixteen bytes.
const HISTORY: usize = 16;

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
    suite_groups(FILE, "ACVP-AES-CFB8", "1.0", test_type)
}

fn cfb<C: BlockCipher>(key: &[u8]) -> Cfb8<C> {
    Cfb8::new(C::try_new(key).expect("key"))
}

fn aft<C: BlockCipher>(group: &Value, encrypt: bool) -> usize {
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let cfb = cfb::<C>(&hex(&t["key"]));
        let iv = hex(&t["iv"]);
        let (input, expected) = if encrypt {
            (hex(&t["pt"]), hex(&t["ct"]))
        } else {
            (hex(&t["ct"]), hex(&t["pt"]))
        };
        let mut data = input;
        if encrypt {
            cfb.encrypt(&block::<C>(&iv), &mut data)
                .expect("any length");
        } else {
            cfb.decrypt(&block::<C>(&iv), &mut data)
                .expect("any length");
        }
        assert_eq!(data, expected, "tgId {} tcId {}", group["tgId"], t["tcId"]);
        count += 1;
    }
    count
}

/// Monte Carlo Test: 1000 single bytes through one continuing state.
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

            let cfb = cfb::<C>(&key);
            let mut outputs = [0u8; MCT_SEGMENTS];
            let mut segment = [input[0]];
            if encrypt {
                let mut state = cfb.encryptor(&block::<C>(&iv));
                for j in 0..MCT_SEGMENTS {
                    state.update(&mut segment).expect("one byte");
                    outputs[j] = segment[0];
                    segment = [next_input(&iv, &outputs, j)];
                }
            } else {
                let mut state = cfb.decryptor(&block::<C>(&iv));
                for j in 0..MCT_SEGMENTS {
                    state.update(&mut segment).expect("one byte");
                    outputs[j] = segment[0];
                    segment = [next_input(&iv, &outputs, j)];
                }
            }

            let last = outputs[MCT_SEGMENTS - 1];
            assert_eq!(
                [last].as_slice(),
                hex(&step[output_name]),
                "{tag} output"
            );

            let tail = &outputs[MCT_SEGMENTS - key.len()..];
            for (k, t) in key.iter_mut().zip(tail) {
                *k ^= t;
            }
            iv = outputs[MCT_SEGMENTS - HISTORY..].to_vec();
            input = outputs[MCT_SEGMENTS - HISTORY - 1..][..1].to_vec();
            count += 1;
        }
    }
    count
}

/// The input byte for segment `j + 1`: a byte of the IV until the IV
/// has been shifted out, then the output sixteen segments back.
fn next_input(iv: &[u8], outputs: &[u8], j: usize) -> u8 {
    if j < HISTORY {
        iv[j]
    } else {
        outputs[j - HISTORY]
    }
}
