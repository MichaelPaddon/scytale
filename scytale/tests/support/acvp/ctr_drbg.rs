//! ctrDRBG 1.0, run through [`Rng`].
//!
//! The generator is not generic over a block cipher the way the modes
//! are: it is AES-256 and nothing else, so there is one run of this
//! rather than one per implementation. The AES underneath is the
//! dispatching one, so whichever implementation this processor uses is
//! the one being checked.
//!
//! # What is checked, and what is not
//!
//! The suite covers four shapes of the mechanism for each key size,
//! and only one of them matches what this library offers:
//!
//! - **Without the derivation function.** Not implemented, on purpose.
//!   Seed material always goes through the derivation function here,
//!   so that entropy of any length and any density can be accepted.
//! - **Generating with additional input.** There is no way to pass
//!   additional input to a request: fresh material goes in through
//!   [`Rng::reseed_from`], which is the stronger of the two.
//! - **With prediction resistance.** This is the one that runs. Every
//!   request is preceded by a reseeding from fresh entropy and the
//!   additional input, which is exactly `reseed_from` followed by
//!   `fill`.
//!
//! What that leaves checked is the whole of the mechanism's
//! arithmetic: the derivation function, instantiation, reseeding,
//! generation and the state update after every request. A skipped
//! group says so out loud rather than passing quietly.

use super::{hex, load};
use scytale::random::{Random, Rng};
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
    assert!(cases >= 15, "only {cases} AFT cases");
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
    if group["derFunc"] != true {
        return Some("no derivation function");
    }
    if group["predResistance"] != true {
        return Some("additional input on generate");
    }
    None
}

/// Returns the cases run.
fn aft(group: &Value) -> usize {
    let bits = group["returnedBitsLen"].as_u64().expect("returnedBitsLen");
    let mut cases = 0;

    for t in group["tests"].as_array().expect("tests") {
        let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);

        // Instantiation takes the entropy, the nonce and the
        // personalization string as one run of material, which is
        // what the derivation function is handed.
        let mut material = hex(&t["entropyInput"]);
        material.extend(hex(&t["nonce"]));
        material.extend(hex(&t["persoString"]));
        let mut rng = Rng::from_seed(&material).expect("instantiate");

        let mut out = vec![0u8; bits as usize / 8];
        for other in t["otherInput"].as_array().expect("otherInput") {
            assert_eq!(other["intendedUse"], "generate", "{tag}");
            // Prediction resistance is a reseeding from fresh entropy
            // and the additional input, and then a request carrying
            // nothing further.
            let mut material = hex(&other["entropyInput"]);
            material.extend(hex(&other["additionalInput"]));
            rng.reseed_from(&material).expect("reseed");
            rng.fill(&mut out).expect("generate");
        }
        // The bits compared are those of the last request.
        assert_eq!(out, hex(&t["returnedBits"]), "{tag}");
        cases += 1;
    }
    cases
}
