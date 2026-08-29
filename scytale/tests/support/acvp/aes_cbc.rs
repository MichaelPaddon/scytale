//! ACVP-AES-CBC 1.0, run through [`Cbc`] over any block cipher.

use super::{groups as suite_groups, hex};
use scytale::symmetric::mode::Cbc;
use scytale::symmetric::{Block, BlockCipher};
use serde_json::Value;

/// The IV as the cipher's block type.
fn block<C: BlockCipher>(bytes: &[u8]) -> C::Block {
    let mut block = C::Block::ZERO;
    block.as_mut().copy_from_slice(bytes);
    block
}

const FILE: &str = "ACVP-AES-CBC-1.0/internalProjection.json";

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
    assert!(count >= 2000, "only {count} AFT cases");
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
    suite_groups(FILE, "ACVP-AES-CBC", "1.0", test_type)
}

fn cbc<C: BlockCipher>(key: &[u8]) -> Cbc<C> {
    Cbc::new(C::try_new(key).expect("key"))
}

/// Algorithm Functional Test: one message, one IV.
fn aft<C: BlockCipher>(group: &Value, encrypt: bool) -> usize {
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let cbc = cbc::<C>(&hex(&t["key"]));
        let iv = hex(&t["iv"]);
        let (input, expected) = if encrypt {
            (hex(&t["pt"]), hex(&t["ct"]))
        } else {
            (hex(&t["ct"]), hex(&t["pt"]))
        };
        let mut data = input;
        if encrypt {
            cbc.encrypt(&block::<C>(&iv), &mut data)
                .expect("whole blocks");
        } else {
            cbc.decrypt(&block::<C>(&iv), &mut data)
                .expect("whole blocks");
        }
        assert_eq!(data, expected, "tgId {} tcId {}", group["tgId"], t["tcId"]);
        count += 1;
    }
    count
}

/// Monte Carlo Test. Each of 100 steps runs 1000 single-block
/// operations whose inputs chain into one another, then derives the
/// next key, IV and input from the last two outputs.
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

            let cbc = cbc::<C>(&key);
            let (last, previous) = if encrypt {
                step_encrypt(&cbc, &iv, &input)
            } else {
                step_decrypt(&cbc, &iv, &input)
            };
            assert_eq!(last, hex(&step[output_name]), "{tag} output");

            // Next key: xor with the tail of the last two outputs.
            let mut tail = previous.clone();
            tail.extend_from_slice(&last);
            let tail = &tail[tail.len() - key.len()..];
            for (k, t) in key.iter_mut().zip(tail) {
                *k ^= t;
            }
            iv = last;
            input = previous;
            count += 1;
        }
    }
    count
}

/// One encryption step. Each iteration encrypts one block, and the
/// next input is the chaining value this one used: the IV to begin
/// with, then the ciphertext before last. Returns the last two
/// ciphertext blocks.
fn step_encrypt<C: BlockCipher>(
    cbc: &Cbc<C>,
    iv: &[u8],
    pt: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut chain = iv.to_vec();
    let mut input = pt.to_vec();
    let mut previous = vec![0u8; iv.len()];
    let mut output = vec![0u8; iv.len()];
    for _ in 0..MCT_ITERATIONS {
        previous.copy_from_slice(&output);
        output.copy_from_slice(&input);
        cbc.encrypt(&block::<C>(&chain), &mut output)
            .expect("one block");
        input.copy_from_slice(&chain);
        chain.copy_from_slice(&output);
    }
    (output, previous)
}

/// One decryption step, which is the encryption step with plaintext
/// and ciphertext exchanged: the chaining value is the previous
/// ciphertext, and the next ciphertext is the plaintext before last.
/// Returns the last two plaintext blocks.
fn step_decrypt<C: BlockCipher>(
    cbc: &Cbc<C>,
    iv: &[u8],
    ct: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut chain = iv.to_vec();
    let mut input = ct.to_vec();
    let mut previous = vec![0u8; iv.len()];
    let mut output = vec![0u8; iv.len()];
    for j in 0..MCT_ITERATIONS {
        previous.copy_from_slice(&output);
        output.copy_from_slice(&input);
        cbc.decrypt(&block::<C>(&chain), &mut output)
            .expect("one block");
        let next = if j == 0 {
            iv.to_vec()
        } else {
            previous.clone()
        };
        chain.copy_from_slice(&input);
        input = next;
    }
    (output, previous)
}
