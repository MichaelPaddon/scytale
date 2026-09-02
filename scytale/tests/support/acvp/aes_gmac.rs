//! ACVP-AES-GMAC 1.0: GCM with no plaintext, which is how the crate
//! provides GMAC. The suite's value is its verdicts: tags over
//! additional data only, at 128 and truncated 32 bits, under 96-bit
//! and longer nonces, with cases that must be rejected.

use super::{groups as suite_groups, hex};
use scytale::cipher::mode::Gcm;
use scytale::cipher::BlockCipher;
use scytale::Error;

const FILE: &str = "ACVP-AES-GMAC-1.0/internalProjection.json";

/// Runs the suite against `C`; a no-op without the vendored
/// vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = suite_groups(FILE, "ACVP-AES-GMAC", "1.0", "AFT") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    for (group, encrypt) in &groups {
        let tag_len = group["tagLen"].as_u64().expect("tagLen") as usize / 8;
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let key = C::try_new(&hex(&t["key"])).expect("key");
            let gcm = Gcm::<C>::try_new(key).expect("gcm");
            let nonce = hex(&t["iv"]);
            let aad = hex(&t["aad"]);
            let expected = hex(&t["tag"]);
            assert!(hex(&t["pt"]).is_empty() && hex(&t["ct"]).is_empty());
            if *encrypt {
                let mut got = [0u8; 16];
                gcm.encrypt(&nonce, &aad, &mut [], &mut got)
                    .expect("encrypt");
                assert_eq!(got[..tag_len], expected, "{tag}");
            } else {
                let should_pass =
                    t["testPassed"].as_bool().expect("testPassed");
                let mut state = gcm.decryptor(&nonce).expect("decryptor");
                state.aad(&aad).expect("aad");
                let result = state.verify_truncated(&expected);
                match result {
                    Ok(()) => assert!(should_pass, "{tag} accepted"),
                    Err(Error::AuthenticationFailed) => {
                        assert!(!should_pass, "{tag} rejected");
                        rejections += 1;
                    }
                    Err(e) => panic!("{tag}: {e}"),
                }
            }
            cases += 1;
        }
    }
    assert!(cases >= 25, "only {cases} cases");
    assert!(rejections >= 3, "only {rejections} rejections");
}
