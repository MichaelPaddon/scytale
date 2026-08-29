//! ACVP-AES-CTR 1.0, run through [`Ctr`] over any block cipher.
//!
//! This suite has no Monte Carlo tests, only one-shot ones, but they
//! are more searching than the other suites': the payload length is
//! given in bits and is usually not a whole number of bytes.
//!
//! Counter mode is defined for any number of bits, the final
//! keystream block simply being cut short. [`Ctr`] works in whole
//! bytes, which is what callers want, so a length that is not a
//! multiple of eight is checked over its significant bits only: the
//! bits past the end are ours to leave as we like, and the vectors
//! record them as zero.

use super::{groups as suite_groups, hex};
use scytale::symmetric::mode::Ctr;
use scytale::symmetric::{Block, BlockCipher};
use serde_json::Value;

/// The IV as the cipher's block type.
fn block<C: BlockCipher>(bytes: &[u8]) -> C::Block {
    let mut block = C::Block::ZERO;
    block.as_mut().copy_from_slice(bytes);
    block
}

const FILE: &str = "ACVP-AES-CTR-1.0/internalProjection.json";

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
pub fn run_aft<C: BlockCipher>() {
    let Some(groups) = groups("AFT") else { return };
    let count: usize = groups
        .iter()
        .map(|(group, encrypt)| aft::<C>(group, *encrypt))
        .sum();
    // Guard against a truncated or wrong file passing vacuously.
    assert!(count >= 100, "only {count} AFT cases");
}

fn groups(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups(FILE, "ACVP-AES-CTR", "1.0", test_type)
}

/// Zeroes every bit past `bits`, so that two answers can be compared
/// over the part the vector actually specifies.
fn truncate(data: &mut [u8], bits: usize) {
    for i in bits..8 * data.len() {
        data[i / 8] &= !(1 << (7 - i % 8));
    }
}

fn aft<C: BlockCipher>(group: &Value, encrypt: bool) -> usize {
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let ctr = Ctr::new(C::try_new(&hex(&t["key"])).expect("key"));
        let counter = hex(&t["iv"]);
        let bits = t["payloadLen"].as_u64().expect("payloadLen") as usize;
        let (input, expected) = if encrypt {
            (hex(&t["pt"]), hex(&t["ct"]))
        } else {
            (hex(&t["ct"]), hex(&t["pt"]))
        };

        let mut data = input;
        if encrypt {
            ctr.encrypt(&block::<C>(&counter), &mut data)
                .expect("any length");
        } else {
            ctr.decrypt(&block::<C>(&counter), &mut data)
                .expect("any length");
        }

        let mut expected = expected;
        truncate(&mut data, bits);
        truncate(&mut expected, bits);
        assert_eq!(
            data, expected,
            "tgId {} tcId {} ({bits} bits)",
            group["tgId"], t["tcId"]
        );
        count += 1;
    }
    count
}
