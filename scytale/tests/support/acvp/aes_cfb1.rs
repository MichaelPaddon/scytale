//! ACVP-AES-CFB1 1.0, run through [`Cfb1`] over any block cipher.
//!
//! Segments are single bits. The vectors carry each one in the top
//! bit of a byte, which is how the mode reads them too.

use super::{groups as suite_groups, hex};
use scytale::symmetric::mode::Cfb1;
use scytale::symmetric::BlockCipher;
use serde_json::Value;

const FILE: &str = "ACVP-AES-CFB1-1.0/internalProjection.json";

/// Segments (bits) in one Monte Carlo step.
const MCT_SEGMENTS: usize = 1000;

/// Segments the IV holds: 128 bits.
const HISTORY: usize = 128;

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
    suite_groups(FILE, "ACVP-AES-CFB1", "1.0", test_type)
}

fn cfb<C: BlockCipher>(key: &[u8]) -> Cfb1<C> {
    Cfb1::new(C::try_new(key).expect("key"))
}

fn aft<C: BlockCipher>(group: &Value, encrypt: bool) -> usize {
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let cfb = cfb::<C>(&hex(&t["key"]));
        let iv = hex(&t["iv"]);
        let bits = t["payloadLen"].as_u64().expect("payloadLen") as usize;
        let (input, expected) = if encrypt {
            (hex(&t["pt"]), hex(&t["ct"]))
        } else {
            (hex(&t["ct"]), hex(&t["pt"]))
        };
        let mut data = input;
        if encrypt {
            cfb.encrypt(&iv, &mut data, bits).expect("bits fit");
        } else {
            cfb.decrypt(&iv, &mut data, bits).expect("bits fit");
        }
        assert_eq!(data, expected, "tgId {} tcId {}", group["tgId"], t["tcId"]);
        count += 1;
    }
    count
}

/// Monte Carlo Test: 1000 single bits through one continuing state.
fn mct<C: BlockCipher>(group: &Value, encrypt: bool) -> usize {
    let (input_name, output_name) =
        if encrypt { ("pt", "ct") } else { ("ct", "pt") };
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let steps = t["resultsArray"].as_array().expect("resultsArray");
        let mut key = hex(&t["key"]);
        let mut iv = hex(&t["iv"]);
        let mut input = top_bit(&hex(&t[input_name]));

        for (i, step) in steps.iter().enumerate() {
            let tag =
                format!("tgId {} tcId {} step {i}", group["tgId"], t["tcId"]);
            assert_eq!(key, hex(&step["key"]), "{tag} key");
            assert_eq!(iv, hex(&step["iv"]), "{tag} iv");
            assert_eq!(input, top_bit(&hex(&step[input_name])), "{tag} input");

            let cfb = cfb::<C>(&key);
            let mut outputs = [0u8; MCT_SEGMENTS];
            let mut segment = [input << 7];
            if encrypt {
                let mut state = cfb.encryptor(&iv).expect("iv");
                for j in 0..MCT_SEGMENTS {
                    state.update(&mut segment, 1).expect("one bit");
                    outputs[j] = segment[0] >> 7;
                    segment = [next_input(&iv, &outputs, j) << 7];
                }
            } else {
                let mut state = cfb.decryptor(&iv).expect("iv");
                for j in 0..MCT_SEGMENTS {
                    state.update(&mut segment, 1).expect("one bit");
                    outputs[j] = segment[0] >> 7;
                    segment = [next_input(&iv, &outputs, j) << 7];
                }
            }

            let last = outputs[MCT_SEGMENTS - 1];
            assert_eq!(last, top_bit(&hex(&step[output_name])), "{tag} output");

            let bits = 8 * key.len();
            let tail = pack(&outputs[MCT_SEGMENTS - bits..]);
            for (k, t) in key.iter_mut().zip(&tail) {
                *k ^= t;
            }
            iv = pack(&outputs[MCT_SEGMENTS - HISTORY..]);
            input = outputs[MCT_SEGMENTS - HISTORY - 1];
            count += 1;
        }
    }
    count
}

/// The input bit for segment `j + 1`: a bit of the IV until the IV
/// has been shifted out, then the output 128 segments back.
fn next_input(iv: &[u8], outputs: &[u8], j: usize) -> u8 {
    if j < HISTORY {
        (iv[j / 8] >> (7 - j % 8)) & 1
    } else {
        outputs[j - HISTORY]
    }
}

/// The single bit a vector carries in the top of its first byte.
fn top_bit(bytes: &[u8]) -> u8 {
    bytes[0] >> 7
}

/// Packs bits, most significant first, into bytes.
fn pack(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| {
            c.iter()
                .enumerate()
                .fold(0u8, |acc, (i, b)| acc | ((b & 1) << (7 - i)))
        })
        .collect()
}
