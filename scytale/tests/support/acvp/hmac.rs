//! ACVP-HMAC-SHA2 1.0, run through the [`Mac`] trait. One driver
//! serves every variant; the caller names the file.

use super::{hex, load};
use scytale::mac::Mac;

/// Runs every case against `M`; a no-op without the vendored
/// vectors. Tags are compared over `macLen` bits, a prefix of the
/// full tag.
pub fn run_aft<M: Mac>(file: &str, algorithm: &str)
where
    M::Tag: AsRef<[u8]>,
{
    let Some(doc) = load(file, algorithm, "1.0") else {
        return;
    };
    let mut count = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        assert_eq!(group["testType"], "AFT");
        let mac_bytes = group["macLen"].as_u64().expect("macLen") as usize / 8;
        for t in group["tests"].as_array().expect("tests") {
            let mut mac = M::try_new(&hex(&t["key"])).expect("key");
            mac.update(&hex(&t["msg"]));
            let expected = hex(&t["mac"]);
            assert_eq!(expected.len(), mac_bytes);
            let tag = mac.clone().finalize();
            assert_eq!(
                tag.as_ref()[..mac_bytes],
                expected,
                "tgId {} tcId {}",
                group["tgId"],
                t["tcId"]
            );
            // A full-length tag must verify too.
            if mac_bytes == tag.as_ref().len() {
                mac.verify(&expected).expect("verify");
            }
            count += 1;
        }
    }
    assert!(count >= 500, "only {count} cases");
}
