//! ACVP-AES-XPN 1.0, run through [`Xpn`] over any block cipher.
//!
//! The vectors give the session salt and the frame identifier
//! separately, which is how the mode takes them. Twelve of the
//! decryption cases carry a tag that must be rejected.

use super::{groups as suite_groups, hex};
use scytale::symmetric::mode::Xpn;
use scytale::symmetric::{BlockCipher, Error};
use serde_json::Value;

const FILE: &str = "ACVP-AES-XPN-1.0/internalProjection.json";

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
pub fn run_aft<C: BlockCipher>() {
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
    suite_groups(FILE, "ACVP-AES-XPN", "1.0", test_type)
}

/// Returns the cases run and, of those, the ones that had to fail.
fn aft<C: BlockCipher>(group: &Value, encrypt: bool) -> (usize, usize) {
    let tag_len = group["tagLen"].as_u64().expect("tagLen") as usize / 8;
    let mut cases = 0;
    let mut rejections = 0;

    for t in group["tests"].as_array().expect("tests") {
        let label = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
        let cipher = C::try_new(&hex(&t["key"])).expect("key");
        let xpn = Xpn::try_new(cipher).expect("xpn");
        let salt = hex(&t["salt"]);
        let frame = hex(&t["iv"]);
        let aad = hex(&t["aad"]);

        if encrypt {
            let mut data = hex(&t["pt"]);
            let mut got = vec![0u8; tag_len];
            xpn.encrypt(&salt, &frame, &aad, &mut data, &mut got)
                .expect("encrypt");
            assert_eq!(data, hex(&t["ct"]), "{label} ciphertext");
            assert_eq!(got, hex(&t["tag"]), "{label} tag");
        } else {
            let should_pass = t["testPassed"].as_bool().unwrap_or(true);
            let mut data = hex(&t["ct"]);
            let expected = hex(&t["tag"]);
            match xpn.decrypt(&salt, &frame, &aad, &mut data, &expected) {
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
