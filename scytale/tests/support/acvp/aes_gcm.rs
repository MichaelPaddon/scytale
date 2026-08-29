//! ACVP-AES-GCM 1.0, run through [`Gcm`] over any block cipher.
//!
//! This suite is smaller than the others but reaches further: tags
//! of 32 and 128 bits, empty and non-empty additional data and
//! message, and decryption cases that are *meant* to fail, which
//! check that a bad tag is rejected rather than quietly accepted,
//! and nonces of 96 bits and otherwise.

use super::{groups as suite_groups, hex};
use scytale::symmetric::mode::Gcm;
use scytale::symmetric::BlockCipher;
use scytale::Error;
use serde_json::Value;

const FILE: &str = "ACVP-AES-GCM-1.0/internalProjection.json";

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups("AFT") else { return };
    let mut cases = 0;
    let mut rejections = 0;
    for (group, encrypt) in &groups {
        let (n, r) = aft::<C>(group, *encrypt);
        cases += n;
        rejections += r;
    }
    // Guard against a truncated or wrong file passing vacuously, and
    // against the rejection cases quietly disappearing.
    assert!(cases >= 60, "only {cases} AFT cases");
    assert!(
        rejections >= 3,
        "only {rejections} cases had to be rejected"
    );
}

fn groups(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups(FILE, "ACVP-AES-GCM", "1.0", test_type)
}

/// Returns the cases run and, of those, the ones that had to fail.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> (usize, usize) {
    let tag_len = group["tagLen"].as_u64().expect("tagLen") as usize / 8;
    let mut cases = 0;
    let mut rejections = 0;

    for t in group["tests"].as_array().expect("tests") {
        let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
        let cipher = C::try_new(&hex(&t["key"])).expect("key");
        let gcm = Gcm::try_new(cipher).expect("gcm");
        let nonce = hex(&t["iv"]);
        let aad = hex(&t["aad"]);

        if encrypt {
            let mut data = hex(&t["pt"]);
            let mut got = [0u8; 16];
            gcm.encrypt(&nonce, &aad, &mut data, &mut got)
                .expect("encrypt");
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
            let result = if tag_len == 16 {
                let full: [u8; 16] = expected.try_into().expect("tag");
                gcm.decrypt(&nonce, &aad, &mut data, &full)
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
