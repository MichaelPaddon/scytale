//! ACVP-AES-GCM-SIV, run through [`GcmSiv`] over any block cipher.
//!
//! This suite records the ciphertext with its tag appended, rather
//! than as separate fields, and includes thirteen decryption cases
//! whose tags must be rejected.

use super::{groups as suite_groups, hex};
use scytale::cipher::mode::GcmSiv;
use scytale::cipher::BlockCipher;
use scytale::Error;
use serde_json::Value;

const FILE: &str = "ACVP-AES-GCM-SIV-1.0/internalProjection.json";

/// The tag length the standard fixes.
const TAG: usize = 16;

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
    assert!(cases >= 100, "only {cases} AFT cases");
    assert!(
        rejections >= 5,
        "only {rejections} cases had to be rejected"
    );
}

fn groups(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups(FILE, "ACVP-AES-GCM-SIV", "1.0", test_type)
}

/// Returns the cases run and, of those, the ones that had to fail.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> (usize, usize) {
    let mut cases = 0;
    let mut rejections = 0;

    for t in group["tests"].as_array().expect("tests") {
        let label = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
        let siv = GcmSiv::<C>::try_new(&hex(&t["key"])).expect("key");
        let nonce: [u8; 12] = hex(&t["iv"]).try_into().expect("nonce");
        let aad = hex(&t["aad"]);
        let sealed = hex(&t["ct"]);

        if encrypt {
            let mut data = hex(&t["pt"]);
            let mut tag = [0u8; TAG];
            siv.encrypt(&nonce, &aad, &mut data, &mut tag)
                .expect("encrypt");
            // The vector holds the ciphertext with its tag appended.
            let (want_ct, want_tag) = sealed.split_at(sealed.len() - TAG);
            assert_eq!(data, want_ct, "{label} ciphertext");
            assert_eq!(tag, want_tag, "{label} tag");
        } else {
            let should_pass = t["testPassed"].as_bool().unwrap_or(true);
            let (cipher, tag) = sealed.split_at(sealed.len() - TAG);
            let tag: &[u8; TAG] = tag.try_into().expect("tag");
            let mut data = cipher.to_vec();
            match siv.decrypt(&nonce, &aad, &mut data, tag) {
                Ok(()) => {
                    assert!(should_pass, "{label} accepted a bad tag");
                    assert_eq!(data, hex(&t["pt"]), "{label} plaintext");
                }
                Err(Error::AuthenticationFailed) => {
                    assert!(!should_pass, "{label} rejected a good tag");
                    rejections += 1;
                }
                Err(e) => panic!("{label}: {e}"),
            }
        }
        cases += 1;
    }
    (cases, rejections)
}
