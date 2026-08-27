//! ACVP-AES-FF1 1.0, run through [`Ff1`] over any block cipher.
//!
//! The vectors give messages as text in a stated alphabet. [`Ff1`]
//! works in symbol values, so each character is turned into its
//! position in that alphabet and back again.

use super::{groups as suite_groups, hex};
use scytale::symmetric::mode::Ff1;
use scytale::symmetric::BlockCipher;
use serde_json::Value;

const FILE: &str = "ACVP-AES-FF1-1.0/internalProjection.json";

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups("AFT") else { return };
    let count: usize = groups
        .iter()
        .map(|(group, encrypt)| aft::<C>(group, *encrypt))
        .sum();
    assert!(count >= 700, "only {count} AFT cases");
}

fn groups(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups(FILE, "ACVP-AES-FF1", "1.0", test_type)
}

/// Turns text into symbol values, by position in the alphabet.
fn symbols(text: &str, alphabet: &str) -> Vec<u16> {
    text.chars()
        .map(|c| {
            alphabet
                .chars()
                .position(|a| a == c)
                .unwrap_or_else(|| panic!("{c:?} is not in the alphabet"))
                as u16
        })
        .collect()
}

/// Turns symbol values back into text.
fn text(values: &[u16], alphabet: &str) -> String {
    let letters: Vec<char> = alphabet.chars().collect();
    values.iter().map(|&v| letters[v as usize]).collect()
}

fn aft<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> usize {
    let alphabet = group["alphabet"].as_str().expect("alphabet");
    let radix = group["radix"].as_u64().expect("radix") as u32;
    let mut count = 0;

    for t in group["tests"].as_array().expect("tests") {
        let label = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
        let cipher = C::try_new(&hex(&t["key"])).expect("key");
        let ff1 = Ff1::try_new(cipher, radix).expect("radix");
        let tweak = hex(&t["tweak"]);

        let (input, expected) = if encrypt {
            (t["pt"].as_str().unwrap(), t["ct"].as_str().unwrap())
        } else {
            (t["ct"].as_str().unwrap(), t["pt"].as_str().unwrap())
        };
        let mut data = symbols(input, alphabet);
        if encrypt {
            ff1.encrypt(&tweak, &mut data).expect("encrypt");
        } else {
            ff1.decrypt(&tweak, &mut data).expect("decrypt");
        }
        assert_eq!(text(&data, alphabet), expected, "{label}");
        count += 1;
    }
    count
}
