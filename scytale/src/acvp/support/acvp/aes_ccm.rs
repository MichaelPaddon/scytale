//! ACVP-AES-CCM 1.0, run through [`Ccm`] over any block cipher.
//!
//! Every nonce length from 7 to 13 bytes and every tag length from 4
//! to 16, payloads up to 32 bytes, additional data up to 8,192, and
//! decryption cases that are *meant* to fail. The ciphertext in the
//! file carries the tag on its end.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{groups as suite_groups, hex, key_of};
use crate::Error;
use crate::KeyType;
use crate::aead::{Ccm, ccm};
use crate::cipher::BlockCipher;
use serde_json::Value;

const FILE: &str = "ACVP-AES-CCM-1.0/internalProjection.json";

/// Runs the one-shot (AFT) groups against `C`, through every
/// implementation this processor has; a no-op without the vendored
/// vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups::<C>("AFT") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    let mut engines = 0;
    for &implementation in ccm::CHOICES {
        if Ccm::<C>::with_implementation(&C::zero_key(), implementation)
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
    // against the rejection cases quietly disappearing. The file has
    // 2,770 cases a width, 457 or more of them rejections.
    assert!(cases >= 2770 * engines, "only {cases} AFT cases");
    assert!(
        rejections >= 450 * engines,
        "only {rejections} cases had to be rejected"
    );
}

fn groups<C: KeyType>(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups::<C>(FILE, "ACVP-AES-CCM", "1.0", test_type)
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
        let name = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
        let Some(key) = key_of::<C>(&hex(&t["key"])) else {
            continue;
        };
        let ccm = Ccm::<C>::with_implementation(&key, implementation)
            .expect("implementation");
        let nonce = hex(&t["iv"]);
        let aad = hex(&t["aad"]);
        let sealed = hex(&t["ct"]);
        let (ct, tag) = sealed.split_at(sealed.len() - tag_len);

        if encrypt {
            let mut data = hex(&t["pt"]);
            let mut got = vec![0u8; tag_len];
            ccm.encrypt(&nonce, &aad, &mut data, &mut got)
                .expect("encrypt");
            assert_eq!(data, ct, "{name} ciphertext");
            assert_eq!(got, tag, "{name} tag");
        } else {
            let should_pass = t["testPassed"].as_bool().unwrap_or(true);
            let mut data = ct.to_vec();
            match ccm.decrypt(&nonce, &aad, &mut data, tag) {
                Ok(()) => {
                    assert!(should_pass, "{name} accepted a bad tag");
                    assert_eq!(data, hex(&t["pt"]), "{name} plaintext");
                }
                Err(Error::AuthenticationFailed) => {
                    assert!(!should_pass, "{name} rejected a good tag");
                    assert!(data.iter().all(|&b| b == 0), "{name} wipe");
                    rejections += 1;
                }
                Err(e) => panic!("{name}: {e}"),
            }
        }
        cases += 1;
    }
    (cases, rejections)
}
