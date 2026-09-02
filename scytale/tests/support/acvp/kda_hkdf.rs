//! KDA HKDF (SP 800-56Cr2): HKDF as the key-derivation step of a
//! key agreement. The input keying material is the hybrid shared
//! secret `Z || T`, and the info string is built from both parties'
//! identifiers and ephemeral data with the derived length appended,
//! which is the one fixed-info pattern the vendored file uses.
//!
//! The multi-expansion groups exercise a different flow the crate
//! does not model, and are skipped by test type.

use super::{hex, load};
use scytale::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use scytale::hash::sha2::{Sha512_224, Sha512_256};
use scytale::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use scytale::hash::Hash;
use scytale::kdf::hkdf;
use serde_json::Value;

/// Runs the suite; a no-op without the vendored vectors.
pub fn run() {
    let file = "KDA-HKDF-Sp800-56Cr2/internalProjection.json";
    let Some(doc) = load(file, "KDA", "Sp800-56Cr2") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let Some(cfg) = group.get("kdfConfiguration") else {
            continue; // a multi-expansion group
        };
        assert_eq!(cfg["fixedInfoPattern"], "uPartyInfo||vPartyInfo||l");
        assert_eq!(cfg["fixedInfoEncoding"], "concatenation");
        let alg = cfg["hmacAlg"].as_str().expect("hmacAlg");
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            // The validation groups carry deliberately wrong key
            // material, marked by the verdict.
            let should_pass = t["testPassed"].as_bool().unwrap_or(true);
            let ok = match alg {
                "SHA2-224" => case::<Sha224>(t),
                "SHA2-256" => case::<Sha256>(t),
                "SHA2-384" => case::<Sha384>(t),
                "SHA2-512" => case::<Sha512>(t),
                "SHA2-512/224" => case::<Sha512_224>(t),
                "SHA2-512/256" => case::<Sha512_256>(t),
                "SHA3-224" => case::<Sha3_224>(t),
                "SHA3-256" => case::<Sha3_256>(t),
                "SHA3-384" => case::<Sha3_384>(t),
                "SHA3-512" => case::<Sha3_512>(t),
                other => panic!("unknown hash {other}"),
            };
            assert_eq!(ok, should_pass, "{tag}");
            cases += 1;
            if !should_pass {
                rejections += 1;
            }
        }
    }
    assert!(cases >= 500, "only {cases} cases");
    assert!(rejections >= 100, "only {rejections} rejections");
}

/// One derivation compared against the file's key material.
fn case<H: Hash>(t: &Value) -> bool {
    let param = &t["kdfParameter"];
    let salt = hex(&param["salt"]);
    // The hybrid shared secret: the classical part then the
    // auxiliary part, in the order the standard fixes.
    let mut ikm = hex(&param["z"]);
    ikm.extend_from_slice(&hex(&param["t"]));

    let l_bits = match &param["l"] {
        Value::String(s) => s.parse::<u32>().expect("l"),
        v => v.as_u64().expect("l") as u32,
    };
    let mut info = Vec::new();
    for party in ["fixedInfoPartyU", "fixedInfoPartyV"] {
        let p = &t[party];
        info.extend_from_slice(&hex(&p["partyId"]));
        if !p["ephemeralData"].is_null() {
            info.extend_from_slice(&hex(&p["ephemeralData"]));
        }
    }
    info.extend_from_slice(&l_bits.to_be_bytes());

    let expected = hex(&t["dkm"]);
    assert_eq!(expected.len(), l_bits as usize / 8);
    let mut dkm = vec![0u8; expected.len()];
    hkdf::derive::<H>(&salt, &ikm, &info, &mut dkm).expect("derive");
    dkm == expected
}
