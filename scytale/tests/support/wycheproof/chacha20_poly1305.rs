//! Wycheproof's ChaCha20-Poly1305 cases through [`ChaCha20Poly1305`]:
//! the valid ones must round-trip, and the invalid ones (wrong tags,
//! wrong lengths, and ciphertexts built to exercise Poly1305 carries)
//! must be rejected with the buffer wiped.

use super::super::acvp::hex;
use super::load;
use scytale::symmetric::mode::ChaCha20Poly1305;
use scytale::Error;

const FILE: &str = "wycheproof/chacha20_poly1305_test.json";

/// Runs every case; a no-op without the vendored vectors.
pub fn run() {
    let Some(doc) = load(FILE, "CHACHA20-POLY1305") else {
        return;
    };
    let mut valid = 0;
    let mut invalid = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        assert_eq!(group["keySize"], 256);
        assert_eq!(group["tagSize"], 128);
        // Nonces of other sizes are outside the standard, and the
        // type system refuses them before any code runs. The file
        // expects every such case to be rejected, which it is.
        if group["ivSize"] != 96 {
            for t in group["tests"].as_array().expect("tests") {
                assert_eq!(t["result"], "invalid", "tcId {}", t["tcId"]);
                invalid += 1;
            }
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
            let aead = ChaCha20Poly1305::try_new(&hex(&t["key"])).expect("key");
            let nonce: [u8; 12] = hex(&t["iv"]).try_into().expect("nonce");
            let aad = hex(&t["aad"]);
            let msg = hex(&t["msg"]);
            let ct = hex(&t["ct"]);
            let expected: [u8; 16] = hex(&t["tag"]).try_into().expect("tag");
            match t["result"].as_str() {
                Some("valid") => {
                    let mut data = msg.clone();
                    let mut got = [0u8; 16];
                    aead.encrypt(&nonce, &aad, &mut data, &mut got)
                        .expect("encrypt");
                    assert_eq!(data, ct, "{tag} ciphertext");
                    assert_eq!(got, expected, "{tag} tag");
                    aead.decrypt(&nonce, &aad, &mut data, &expected)
                        .expect("decrypt");
                    assert_eq!(data, msg, "{tag} plaintext");
                    valid += 1;
                }
                Some("invalid") => {
                    let mut data = ct.clone();
                    assert_eq!(
                        aead.decrypt(&nonce, &aad, &mut data, &expected),
                        Err(Error::AuthenticationFailed),
                        "{tag}"
                    );
                    assert!(data.iter().all(|&b| b == 0), "{tag} wiped");
                    invalid += 1;
                }
                other => panic!("{tag}: unknown result {other:?}"),
            }
        }
    }
    assert!(valid >= 200, "only {valid} valid cases");
    assert!(invalid >= 50, "only {invalid} invalid cases");
}
