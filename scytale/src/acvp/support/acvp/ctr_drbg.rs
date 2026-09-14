//! ctrDRBG 1.0, run through [`CtrDrbg`].
//!
//! The generator is not generic over a block cipher the way the modes
//! are: it is AES-256 and nothing else, so there is one run of this
//! rather than one per implementation. The AES underneath is the
//! dispatching one, so whichever implementation this processor uses is
//! the one being checked.
//!
//! # What is checked
//!
//! The suite covers four shapes of the mechanism for each key size,
//! and all four run for AES-256:
//!
//! - **With the derivation function**, which is
//!   [`CtrDrbg::from_seed`] and every reseeding from it.
//! - **Without it**, which is [`CtrDrbg::from_full_entropy`]: the
//!   seed goes straight in, the personalization and every later input
//!   padded and XORed over it.
//! - **With prediction resistance**, where every request is preceded
//!   by a reseeding from fresh entropy and the additional input:
//!   [`CtrDrbg::reseed_with`] followed by a plain request.
//! - **Without it**, where one reseeding is followed by requests
//!   carrying additional input of their own: [`CtrDrbg::fill_with`].
//!
//! Between them that is the whole of the mechanism's arithmetic: both
//! ways of making a seed, instantiation, reseeding, generation with
//! and without additional input, and the state update after every
//! request. The other key sizes are skipped, and say so, since the
//! library offers only AES-256.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{hex, load};
use crate::Random;
use crate::random::{CtrDrbg, SEED};
use serde_json::Value;

const FILE: &str = "ctrDRBG-1.0/internalProjection.json";

/// Runs the one-shot (AFT) groups; a no-op without the vendored
/// vectors.
pub fn run_aft() {
    let Some(doc) = load(FILE, "ctrDRBG", "1.0") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        match skip_reason(group) {
            None => cases += aft(group),
            Some(why) => eprintln!("tgId {}: {why}; skipping", group["tgId"]),
        }
    }
    // Guard against a truncated or wrong file passing vacuously.
    assert!(cases >= 60, "only {cases} AFT cases");
}

/// Why this group is not one this library can answer, if it is not.
fn skip_reason(group: &Value) -> Option<&'static str> {
    match group["testType"].as_str() {
        Some("AFT") => {}
        other => panic!("unknown testType {other:?}"),
    }
    if group["mode"] != "AES-256" {
        return Some("not AES-256");
    }
    None
}

/// Returns the cases run.
fn aft(group: &Value) -> usize {
    let bits = group["returnedBitsLen"].as_u64().expect("returnedBitsLen");
    let derivation = group["derFunc"] == true;
    let mut cases = 0;

    for t in group["tests"].as_array().expect("tests") {
        let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);

        let mut rng = if derivation {
            // Instantiation takes the entropy, the nonce and the
            // personalization string as one run of material, which is
            // what the derivation function is handed.
            let mut material = hex(&t["entropyInput"]);
            material.extend(hex(&t["nonce"]));
            material.extend(hex(&t["persoString"]));
            CtrDrbg::from_seed(&material).expect("instantiate")
        } else {
            // Without it the entropy is the seed itself, no nonce, and
            // the personalization is applied over it.
            let entropy: [u8; SEED] = hex(&t["entropyInput"])
                .try_into()
                .unwrap_or_else(|_| panic!("{tag}: entropy is not a seed"));
            CtrDrbg::from_full_entropy(&entropy, &hex(&t["persoString"]))
                .expect("instantiate")
        };

        let mut out = vec![0u8; bits as usize / 8];
        for other in t["otherInput"].as_array().expect("otherInput") {
            let entropy = hex(&other["entropyInput"]);
            let additional = hex(&other["additionalInput"]);
            match other["intendedUse"].as_str() {
                Some("reSeed") => {
                    rng.reseed_with(&entropy, &additional).expect("reseed");
                }
                // Prediction resistance is a reseeding from fresh
                // entropy and the additional input, then a request
                // carrying nothing further.
                Some("generate") if !entropy.is_empty() => {
                    rng.reseed_with(&entropy, &additional).expect("reseed");
                    rng.fill(&mut out).expect("generate");
                }
                Some("generate") => {
                    rng.fill_with(&mut out, &additional).expect("generate");
                }
                other => panic!("{tag}: unknown intendedUse {other:?}"),
            }
        }
        // The bits compared are those of the last request.
        assert_eq!(out, hex(&t["returnedBits"]), "{tag}");
        cases += 1;
    }
    cases
}
