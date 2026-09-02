//! ACVP-AES-KWP 1.0, run through [`Kwp`] over any block cipher.
//!
//! The suite covers both cipher directions the standard allows, both
//! wrapping and unwrapping, and a large number of unwrapping cases
//! that are meant to fail, which is what checks that an altered
//! wrapping is refused rather than quietly accepted. Padded lengths
//! reach down to a single byte, so the single-block case the
//! standard handles separately is covered too.

use super::{groups as suite_groups, hex};
use scytale::cipher::mode::Kwp;
use scytale::cipher::BlockCipher;
use scytale::Error;
use serde_json::Value;

const FILE: &str = "ACVP-AES-KWP-1.0/internalProjection.json";

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
    assert!(cases >= 5000, "only {cases} AFT cases");
    assert!(rejections >= 100, "only {rejections} had to be rejected");
}

fn groups(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups(FILE, "ACVP-AES-KWP", "1.0", test_type)
}

/// Returns the cases run and, of those, the ones that had to fail.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> (usize, usize) {
    // The standard lets the wrapping be built on either direction of
    // the cipher, and the suite exercises both.
    let forward = match group["kwCipher"].as_str() {
        Some("cipher") => true,
        Some("inverse") => false,
        other => panic!("unknown kwCipher {other:?}"),
    };
    let mut cases = 0;
    let mut rejections = 0;

    for t in group["tests"].as_array().expect("tests") {
        let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
        let cipher = C::try_new(&hex(&t["key"])).expect("key");
        let kwp = if forward {
            Kwp::new(cipher)
        } else {
            Kwp::new_inverse(cipher)
        };

        if encrypt {
            let plain = hex(&t["pt"]);
            let mut got = vec![0u8; plain.len().next_multiple_of(8) + 8];
            let n = kwp.wrap(&plain, &mut got).expect("wrap");
            assert_eq!(got[..n], hex(&t["ct"])[..], "{tag}");
        } else {
            // A case marked as not passing carries a wrapping that
            // must be refused.
            let should_pass = t["testPassed"].as_bool().unwrap_or(true);
            let wrapped = hex(&t["ct"]);
            let mut got = vec![0u8; wrapped.len()];
            match kwp.unwrap(&wrapped, &mut got) {
                Ok(n) => {
                    assert!(should_pass, "{tag} accepted a bad wrapping");
                    assert_eq!(got[..n], hex(&t["pt"])[..], "{tag}");
                }
                Err(Error::AuthenticationFailed) => {
                    assert!(!should_pass, "{tag} refused a good wrapping");
                    rejections += 1;
                }
                Err(e) => panic!("{tag}: {e}"),
            }
        }
        cases += 1;
    }
    (cases, rejections)
}
