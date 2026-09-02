//! Wycheproof's ChaCha20-Poly1305 cases through [`ChaCha20Poly1305`]:
//! the valid ones must round-trip, and the invalid ones (wrong tags,
//! wrong lengths, and ciphertexts built to exercise Poly1305 carries)
//! must be rejected with the buffer wiped.
//!
//! [`run`] drives the whole AEAD, which fixes the backend to the one
//! the processor picks. [`run_cipher`] takes the same file the other
//! way round and drives one named backend, so that every keystream
//! this crate can produce meets external vectors rather than only
//! the in-module comparison against the portable code.

use super::super::acvp::hex;
use super::load;
use scytale::cipher::chacha20::{Backend, Cipher};
use scytale::cipher::mode::ChaCha20Poly1305;
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

/// Runs the keystream of every valid case under backend `B`, which
/// `what` names for the skip message; a no-op without the vendored
/// vectors.
///
/// The AEAD takes its Poly1305 key from block zero and encrypts from
/// block one, so a valid case's ciphertext is its message xored with
/// the keystream from block one. That is the whole of what a backend
/// contributes to the AEAD: Poly1305 has no backends, and the
/// framing around it is the same code whichever keystream runs
/// underneath.
///
/// Block zero is not reachable this way, since only the tag depends
/// on it. It is covered for the processor's chosen backend by [`run`]
/// checking the tag, and for the others by the in-module comparison
/// against the portable keystream.
pub fn run_cipher<B: Backend>(what: &str) {
    let Some(doc) = load(FILE, "CHACHA20-POLY1305") else {
        return;
    };
    // Asked once rather than per case, and reported: a silent skip
    // would look like a pass.
    match Cipher::<B>::try_new(&[0u8; 32]) {
        Ok(_) => {}
        Err(Error::NotSupported) => {
            eprintln!("{what} not available; skipping");
            return;
        }
        Err(e) => panic!("{e}"),
    }

    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        // The nonce length is the AEAD's business, not the cipher's.
        if group["ivSize"] != 96 {
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            // Only a valid case has a ciphertext that is its message
            // under the keystream; the rest are forgeries.
            if t["result"] != "valid" {
                continue;
            }
            let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
            let cipher = Cipher::<B>::try_new(&hex(&t["key"])).expect("key");
            let nonce: [u8; 12] = hex(&t["iv"]).try_into().expect("nonce");
            let msg = hex(&t["msg"]);

            let mut data = msg.clone();
            cipher.encrypt(&nonce, 1, &mut data).expect("encrypt");
            assert_eq!(data, hex(&t["ct"]), "{tag} ciphertext");
            cipher.decrypt(&nonce, 1, &mut data).expect("decrypt");
            assert_eq!(data, msg, "{tag} plaintext");
            cases += 1;
        }
    }
    assert!(cases >= 200, "only {cases} cases under {what}");
}
