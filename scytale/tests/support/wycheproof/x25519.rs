//! Wycheproof's X25519 cases through [`x25519`]: twist points,
//! low-order points, non-canonical coordinates and edge-case
//! multiples. The raw function must always match the file, and
//! [`shared_secret`](x25519::shared_secret) must refuse exactly the
//! zero outputs.

use super::super::acvp::hex;
use super::load;
use scytale::publickey::x25519;
use scytale::Error;

const FILE: &str = "wycheproof/x25519_test.json";

/// Runs every case; a no-op without the vendored vectors.
pub fn run() {
    let Some(doc) = load(FILE, "XDH") else {
        return;
    };
    let mut cases = 0;
    let mut zeros = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        assert_eq!(group["curve"], "curve25519");
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
            let private: [u8; 32] =
                hex(&t["private"]).try_into().expect("private");
            let public: [u8; 32] =
                hex(&t["public"]).try_into().expect("public");
            let shared: [u8; 32] =
                hex(&t["shared"]).try_into().expect("shared");
            match t["result"].as_str() {
                Some("valid") | Some("acceptable") => {}
                other => panic!("{tag}: unknown result {other:?}"),
            }

            assert_eq!(x25519::x25519(&private, &public), shared, "{tag}");
            // The checked form refuses a zero secret, which is what
            // every low-order public key produces, and nothing else.
            let checked = x25519::shared_secret(&private, &public);
            if shared == [0u8; 32] {
                assert_eq!(
                    checked,
                    Err(Error::InvalidPublicKey),
                    "{tag} accepted a zero secret",
                );
                zeros += 1;
            } else {
                assert_eq!(checked, Ok(shared), "{tag}");
            }
            cases += 1;
        }
    }
    assert!(cases >= 500, "only {cases} cases");
    assert!(zeros >= 30, "only {zeros} zero-secret cases");
}
