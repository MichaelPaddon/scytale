//! ACVP-AES-GCM 1.0, run through [`Gcm`] over any block cipher.
//!
//! This suite is smaller than the others but reaches further: tags
//! of 32 and 128 bits, empty and non-empty additional data and
//! message, and decryption cases that are *meant* to fail, which
//! check that a bad tag is rejected rather than quietly accepted,
//! and nonces of 96 bits and otherwise.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{groups as suite_groups, hex, key_of};
use crate::Error;
use crate::KeyType;
use crate::aead::gcm;
use crate::aead::{Aead, Gcm};
use crate::cipher::BlockCipher;
use serde_json::Value;

const FILE: &str = "ACVP-AES-GCM-1.0/internalProjection.json";

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
    let mut cases = 0;
    let mut rejections = 0;
    let mut engines = 0;
    for &implementation in gcm::CHOICES {
        if Gcm::<C>::with_implementation(&C::zero_key(), implementation)
            .is_none()
        {
            continue;
        }
        engines += 1;
        for (group, encrypt) in &groups {
            let (n, r) = aft::<C>(group, *encrypt, implementation);
            cases += n;
            rejections += r;
        }
    }
    assert!(engines >= 1, "no implementation to test");
    // Guard against a truncated or wrong file passing vacuously, and
    // against the rejection cases quietly disappearing.
    assert!(cases >= 20, "only {cases} AFT cases");
    assert!(
        rejections >= 1,
        "only {rejections} cases had to be rejected"
    );
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-GCM", "1.0", test_type)
}

/// Returns the cases run and, of those, the ones that had to fail.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
    implementation: crate::implementation::Implementation,
) -> (usize, usize) {
    let tag_len = group["tagLen"].as_u64().expect("tagLen") as usize / 8;
    let mut cases = 0;
    let mut rejections = 0;

    for t in group["tests"].as_array().expect("tests") {
        let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
        let Some(key) = key_of::<C>(&hex(&t["key"])) else {
            continue;
        };
        let gcm = Gcm::<C>::with_implementation(&key, implementation)
            .expect("implementation");
        let nonce = hex(&t["iv"]);
        let aad = hex(&t["aad"]);

        if encrypt {
            let mut data = hex(&t["pt"]);
            let mut got = [0u8; 16];
            // The suite runs several nonce lengths. The one-shot takes
            // the standard twelve bytes; the rest go through the
            // incremental form, which accepts any length.
            match <&[u8; 12]>::try_from(&nonce[..]) {
                Ok(nonce) => gcm
                    .encrypt(nonce, &aad, &mut data, &mut got)
                    .expect("encrypt"),
                Err(_) => {
                    let mut state = gcm.encryptor(&nonce).expect("encryptor");
                    state.aad(&aad).expect("aad");
                    state.update(&mut data).expect("update");
                    got = state.finalize().expect("finalize");
                }
            }
            assert_eq!(data, hex(&t["ct"]), "{tag} ciphertext");
            assert_eq!(got[..tag_len], hex(&t["tag"]), "{tag} tag");
        } else {
            // A case marked as not passing carries a tag that must be
            // rejected. The one-shot takes full tags only, so the
            // shorter ones go through the streaming form, which is
            // where a protocol would check them.
            let should_pass = t["testPassed"].as_bool().unwrap_or(true);
            let mut data = hex(&t["ct"]);
            let expected = hex(&t["tag"]);
            let short_nonce = <&[u8; 12]>::try_from(&nonce[..]).ok();
            let result = if let (16, Some(nonce)) = (tag_len, short_nonce) {
                let full: [u8; 16] = expected.try_into().expect("tag");
                gcm.decrypt(nonce, &aad, &mut data, &full)
            } else {
                let mut state = gcm.decryptor(&nonce).expect("decryptor");
                state.aad(&aad).expect("aad");
                state.update(&mut data).expect("update");
                state.verify_truncated(&expected)
            };
            match result {
                Ok(()) => {
                    assert!(should_pass, "{tag} accepted a bad tag");
                    assert_eq!(data, hex(&t["pt"]), "{tag} plaintext");
                }
                Err(Error::AuthenticationFailed) => {
                    assert!(!should_pass, "{tag} rejected a good tag");
                    rejections += 1;
                }
                Err(e) => panic!("{tag}: {e}"),
            }
        }
        cases += 1;
    }
    (cases, rejections)
}
