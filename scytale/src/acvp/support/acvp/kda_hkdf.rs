//! KDA HKDF (SP 800-56Cr2): HKDF as the key-derivation step of a
//! key agreement. The input keying material is the hybrid shared
//! secret `Z || T`, and the info string is built from both parties'
//! identifiers and ephemeral data with the derived length appended,
//! which is the one fixed-info pattern the vendored file uses.
//!
//! The multi-expansion groups extract once and then expand several
//! times, each expansion with its own fixed info and length, which
//! is [`hkdf::extract`] followed by repeated [`hkdf::expand`].

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{hex, load};
use crate::BlockType;
use crate::hash::Hash;
use crate::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use crate::hash::sha2::{Sha512_224, Sha512_256};
use crate::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use crate::kdf::hkdf;
use serde_json::Value;

/// Dispatches on the group's HMAC hash, which names the whole
/// derivation. Both flows need the same ten arms.
macro_rules! with_hash {
    ($alg:expr, $f:ident($($arg:expr),*)) => {
        match $alg {
            "SHA2-224" => $f::<Sha224>($($arg),*),
            "SHA2-256" => $f::<Sha256>($($arg),*),
            "SHA2-384" => $f::<Sha384>($($arg),*),
            "SHA2-512" => $f::<Sha512>($($arg),*),
            "SHA2-512/224" => $f::<Sha512_224>($($arg),*),
            "SHA2-512/256" => $f::<Sha512_256>($($arg),*),
            "SHA3-224" => $f::<Sha3_224>($($arg),*),
            "SHA3-256" => $f::<Sha3_256>($($arg),*),
            "SHA3-384" => $f::<Sha3_384>($($arg),*),
            "SHA3-512" => $f::<Sha3_512>($($arg),*),
            other => panic!("unknown hash {other}"),
        }
    };
}

/// Runs the suite; a no-op without the vendored vectors.
pub fn run() {
    let file = "KDA-HKDF-Sp800-56Cr2/internalProjection.json";
    let Some(doc) = load(file, "KDA", "Sp800-56Cr2") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        // A group is one flow or the other, named by its
        // configuration; the multi-expansion one has no fixed-info
        // pattern because each expansion carries its own.
        let alg = match group.get("kdfConfiguration") {
            Some(cfg) => {
                assert_eq!(
                    cfg["fixedInfoPattern"],
                    "uPartyInfo||vPartyInfo||l"
                );
                assert_eq!(cfg["fixedInfoEncoding"], "concatenation");
                cfg["hmacAlg"].as_str().expect("hmacAlg")
            }
            None => {
                let cfg = &group["kdfMultiExpansionConfiguration"];
                assert_eq!(cfg["kdfType"], "hkdf");
                cfg["hmacAlg"].as_str().expect("hmacAlg")
            }
        };
        let multi = group.get("kdfConfiguration").is_none();
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            // The validation groups carry deliberately wrong key
            // material, marked by the verdict.
            let should_pass = t["testPassed"].as_bool().unwrap_or(true);
            let ok = if multi {
                with_hash!(alg, multi_case(t))
            } else {
                with_hash!(alg, case(t))
            };
            assert_eq!(ok, should_pass, "{tag}");
            cases += 1;
            if !should_pass {
                rejections += 1;
            }
        }
    }
    assert!(cases >= 1500, "only {cases} cases");
    assert!(rejections >= 150, "only {rejections} rejections");
}

/// The derived length in bits, which one flow records as a string
/// and the other as a number.
fn bits(v: &Value) -> u32 {
    match v {
        Value::String(s) => s.parse::<u32>().expect("l"),
        v => v.as_u64().expect("l") as u32,
    }
}

/// One extract and several expansions, each with its own fixed info
/// and length, compared against the file's key material. The PRK is
/// computed once, which is the whole point of the flow.
fn multi_case<H: Hash + Clone + BlockType>(t: &Value) -> bool {
    let param = &t["kdfMultiExpansionParameter"];
    let salt = hex(&param["salt"]);
    let mut ikm = hex(&param["z"]);
    ikm.extend_from_slice(&hex(&param["t"]));
    let prk = hkdf::extract::<H>(&salt, &ikm).expect("extract");

    let iterations = param["iterationParameters"]
        .as_array()
        .expect("iterationParameters");
    let expected = t["dkms"].as_array().expect("dkms");
    assert_eq!(iterations.len(), expected.len(), "one dkm per expansion");

    iterations.iter().zip(expected).all(|(iteration, want)| {
        let want = hex(want);
        let l_bits = bits(&iteration["l"]);
        assert_eq!(want.len(), l_bits as usize / 8);
        let info = hex(&iteration["fixedInfo"]);
        let mut dkm = vec![0u8; want.len()];
        hkdf::expand::<H>(prk.as_ref(), &[&info], &mut dkm).expect("expand");
        dkm == want
    })
}

/// One derivation compared against the file's key material.
fn case<H: Hash + Clone + BlockType>(t: &Value) -> bool {
    let param = &t["kdfParameter"];
    let salt = hex(&param["salt"]);
    // The hybrid shared secret: the classical part then the
    // auxiliary part, in the order the standard fixes.
    let mut ikm = hex(&param["z"]);
    ikm.extend_from_slice(&hex(&param["t"]));

    let l_bits = bits(&param["l"]);
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
    hkdf::derive::<H>(&salt, &ikm, &[&info], &mut dkm).expect("derive");
    dkm == expected
}
