//! CMAC-AES 1.0, run through [`Cmac`] over any block cipher and the
//! [`Mac`] trait.
//!
//! Generation and verification at every key width, with messages of
//! no bytes, a partial last block and many blocks, and tags of 64, 88
//! and 128 bits. A verification case marked as not passing carries a
//! tag that must be refused.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{hex, key_of, load};
use crate::cipher::BlockCipher;
use crate::constant_time;
use crate::mac::Mac;
use crate::mac::cmac::Cmac;

const FILE: &str = "CMAC-AES-1.0/internalProjection.json";

/// Runs every case at `C`'s key width; a no-op without the vendored
/// vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    // Not the shared `groups`, which knows only encrypt and decrypt;
    // this suite's directions are gen and ver.
    let Some(doc) = load(FILE, "CMAC-AES", "1.0") else {
        return;
    };
    let bits = 8 * C::zero_key().as_ref().len() as u64;
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["keyLen"].as_u64() != Some(bits) {
            continue;
        }
        assert_eq!(group["testType"], "AFT");
        let generate = match group["direction"].as_str() {
            Some("gen") => true,
            Some("ver") => false,
            other => panic!("unknown direction {other:?}"),
        };
        let mac_len = group["macLen"].as_u64().expect("macLen") as usize / 8;

        for t in group["tests"].as_array().expect("tests") {
            let name = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let key = key_of::<C>(&hex(&t["key"])).expect("key width");
            let mut mac = Cmac::<C>::new(&key);
            let message = hex(&t["message"]);
            let expected = hex(&t["mac"]);
            assert_eq!(expected.len(), mac_len, "{name} macLen");

            mac.update(&message);
            let tag = mac.finalize();
            if generate {
                assert_eq!(tag[..mac_len], expected, "{name} mac");
            } else {
                // A tag cut short is compared as a prefix, in constant
                // time, as a protocol that truncates would check it.
                let should_pass = t["testPassed"].as_bool().expect("pass");
                let passed = constant_time::equal(&tag[..mac_len], &expected);
                assert_eq!(passed, should_pass, "{name} verdict");
                if !passed {
                    rejections += 1;
                }
                // A full tag goes through the trait's check as well;
                // `finalize` left the MAC keyed and ready.
                if mac_len == tag.len() {
                    mac.update(&message);
                    assert_eq!(
                        mac.verify(&expected).is_ok(),
                        should_pass,
                        "{name} verify"
                    );
                }
            }
            cases += 1;
        }
    }
    // Guard against a truncated or wrong file passing vacuously, and
    // against the rejection cases quietly disappearing. The file has
    // 252 cases a width, 42 or more of them rejections.
    assert!(cases >= 252, "only {cases} cases");
    assert!(rejections >= 42, "only {rejections} rejections");
}
