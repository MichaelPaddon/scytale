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

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{groups as suite_groups, hex, key_of};
use crate::KeyType;
use crate::cipher::BlockCipher;
use crate::cipher::mode::Ctr;
use crate::cipher::mode::ctr;
use serde_json::Value;

/// The IV as the cipher's block type.
fn block<C: BlockCipher<Block = [u8; 16]>>(bytes: &[u8]) -> C::Block {
    let mut block = C::zero_block();
    block.as_mut().copy_from_slice(bytes);
    block
}

const FILE: &str = "ACVP-AES-CTR-1.0/internalProjection.json";

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
/// Runs them against every implementation this processor has, not
/// only the one the mode would pick: which that is depends on the
/// machine, so anything else leaves whichever the machine did not
/// choose unvalidated.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups::<C>("AFT") else {
        return;
    };
    let mut count = 0;
    let mut engines = 0;
    for &choice in ctr::CHOICES {
        if Ctr::<C>::with_choice(&C::zero_key(), choice).is_none() {
            continue;
        }
        engines += 1;
        for (group, encrypt) in &groups {
            count += aft::<C>(group, *encrypt, choice);
        }
    }
    assert!(engines >= 1, "no implementation to test");
    // Guard against a truncated or wrong file passing vacuously.
    assert!(count >= 33, "only {count} AFT cases");
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-CTR", "1.0", test_type)
}

/// Zeroes every bit past `bits`, so that two answers can be compared
/// over the part the vector actually specifies.
fn truncate(data: &mut [u8], bits: usize) {
    for i in bits..8 * data.len() {
        data[i / 8] &= !(1 << (7 - i % 8));
    }
}

fn aft<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
    choice: crate::implementation::Implementation,
) -> usize {
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let Some(key) = key_of::<C>(&hex(&t["key"])) else {
            continue;
        };
        let ctr = Ctr::<C>::with_choice(&key, choice).expect("implementation");
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
