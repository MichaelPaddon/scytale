//! ACVP-HMAC-SHA2 1.0, run through [`Hmac`] over the hash and the
//! [`Mac`] trait. One driver serves every variant; the caller names
//! the file.

use super::{hex, load};
use scytale::BlockType;
use scytale::hash::Hash;
use scytale::mac::Mac;
use scytale::mac::hmac::Hmac;

/// Runs every case against HMAC over `H`; a no-op without the
/// vendored vectors. Tags are compared over `macLen` bits, a prefix
/// of the full tag. The vectors' keys come in every length, so the
/// any-length constructor keys the MAC.
pub fn run_aft<H: Hash + Clone + BlockType>(file: &str, algorithm: &str) {
    let Some(doc) = load(file, algorithm, "1.0") else {
        return;
    };
    let mut count = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        assert_eq!(group["testType"], "AFT");
        let mac_bytes = group["macLen"].as_u64().expect("macLen") as usize / 8;
        for t in group["tests"].as_array().expect("tests") {
            let mut mac = Hmac::<H>::try_new(&hex(&t["key"])).expect("key");
            let msg = hex(&t["msg"]);
            mac.update(&msg);
            let expected = hex(&t["mac"]);
            assert_eq!(expected.len(), mac_bytes);
            let tag = mac.finalize();
            assert_eq!(
                tag.as_ref()[..mac_bytes],
                expected,
                "tgId {} tcId {}",
                group["tgId"],
                t["tcId"]
            );
            // A full-length tag must verify too; `finalize` left the
            // MAC keyed and at the start of a message.
            if mac_bytes == tag.as_ref().len() {
                mac.update(&msg);
                mac.verify(&expected).expect("verify");
            }
            count += 1;
        }
    }
    assert!(count >= 500, "only {count} cases");
}
