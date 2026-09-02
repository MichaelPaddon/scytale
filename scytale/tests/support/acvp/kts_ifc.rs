//! KTS-IFC (SP 800-56Br2): RSA-OAEP key transport, which is what
//! [`pke::rsa`](scytale::pke::rsa) implements.
//!
//! Every group in the suite is `KTS-OAEP-Party_V-confirmation`, so
//! every one asks for key confirmation over the transported key. The
//! crate does no key confirmation, and the tag here is HMAC-SHA-1 or
//! KMAC-128, neither of which it has: `macKey`, `macData` and `tag`
//! are therefore **not checked**. What runs is the OAEP transport
//! alone, which is the part the crate owns.
//!
//! That still leaves a real test. The mode is `noKdfKc`, so the
//! transported secret is the derived keying material itself with no
//! derivation step in between, and each case hands over the whole
//! private key of whichever party decrypts. The groups using SHA-1
//! for OAEP are skipped, leaving the two under SHA-512.
//!
//! One of those two carries an associated-data pattern, which is the
//! OAEP label: `l` as four big-endian bytes, then the initiator's
//! identifier, then the responder's, then the label from the case.
//! The initiator is the server in a responder group and the IUT in an
//! initiator group.

use super::{hex, load};
use scytale::hash::sha2::Sha512;
use scytale::pke::rsa::Rsa2048PrivateKey;
use serde_json::Value;

const FILE: &str = "KTS-IFC-Sp800-56Br2/internalProjection.json";

/// The associated-data patterns this driver knows how to build.
const EMPTY: &str = "";
const PARTY_INFO: &str = "l||uPartyInfo||vPartyInfo||label";

/// Why a group cannot run, or `None` if it can.
fn skip_reason(group: &Value) -> Option<String> {
    match group["testType"].as_str() {
        Some("AFT") => {}
        other => panic!("unknown testType {other:?}"),
    }
    if group["kasMode"] != "noKdfKc" {
        return Some(format!(
            "{} derives the key rather than transporting it",
            group["kasMode"]
        ));
    }
    let kts = &group["ktsConfiguration"];
    if kts["hashAlg"] != "SHA2-512" {
        return Some(format!("OAEP under {}", kts["hashAlg"]));
    }
    if group["modulo"] != 2048 {
        return Some(format!("a {}-bit modulus", group["modulo"]));
    }
    let pattern = kts["associatedDataPattern"].as_str().expect("pattern");
    if pattern != EMPTY && pattern != PARTY_INFO {
        return Some(format!("the pattern {pattern}"));
    }
    // An empty pattern makes the encoding moot; a built one must say
    // how its pieces join.
    if pattern == PARTY_INFO && kts["encoding"] != "concatenation" {
        return Some(format!("the encoding {}", kts["encoding"]));
    }
    None
}

/// The OAEP label a group asks for, for one case.
fn label(group: &Value, t: &Value) -> Vec<u8> {
    let kts = &group["ktsConfiguration"];
    if kts["associatedDataPattern"] == EMPTY {
        return Vec::new();
    }
    let l = group["l"].as_u64().expect("l") as u32;
    // The initiator contributes uPartyInfo, so which identifier comes
    // first depends on which side the IUT is.
    let (u, v) = if group["kasRole"] == "responder" {
        (&group["serverId"], &group["iutId"])
    } else {
        (&group["iutId"], &group["serverId"])
    };
    let mut out = Vec::new();
    out.extend_from_slice(&l.to_be_bytes());
    out.extend_from_slice(&hex(u));
    out.extend_from_slice(&hex(v));
    out.extend_from_slice(&hex(&t["ktsParameter"]["label"]));
    out
}

/// Runs the suite; a no-op without the vendored vectors.
pub fn run() {
    let Some(doc) = load(FILE, "KTS-IFC", "Sp800-56Br2") else {
        return;
    };
    let mut plain = 0;
    let mut labelled = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if let Some(why) = skip_reason(group) {
            eprintln!("tgId {}: {why}; skipping", group["tgId"]);
            continue;
        }
        let responder = group["kasRole"] == "responder";
        let bits = group["l"].as_u64().expect("l") as usize;
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            // Every case in this file transports successfully; a
            // future one that does not should be noticed, not scored
            // as a pass.
            assert_eq!(t["testCaseDisposition"], "Success", "{tag}");
            assert_eq!(t["testPassed"], true, "{tag}");

            // The party that decrypts is the one whose private key
            // the case gives in full.
            let (n, e, d, c, expected) = if responder {
                ("iutN", "iutE", "iutD", "serverC", "serverK")
            } else {
                ("serverN", "serverE", "serverD", "iutC", "iutK")
            };
            let key = Rsa2048PrivateKey::try_new(
                &hex(&t[n]),
                &hex(&t[e]),
                &hex(&t[d]),
            )
            .expect("private key");
            let ciphertext: [u8; 256] =
                hex(&t[c]).try_into().expect("ciphertext");

            let label = label(group, t);
            let mut out = [0u8; 256];
            let len = key
                .decrypt_oaep::<Sha512>(&label, &ciphertext, &mut out)
                .expect("decrypt");
            assert_eq!(len * 8, bits, "{tag} length");
            assert_eq!(out[..len], hex(&t[expected])[..], "{tag}");
            // With no derivation step the transported key is the
            // keying material.
            assert_eq!(out[..len], hex(&t["dkm"])[..], "{tag} dkm");

            if label.is_empty() {
                plain += 1;
            } else {
                labelled += 1;
            }
        }
    }
    // Counted apart so that losing the labelled groups to a skip
    // cannot hide as a pass.
    assert!(plain >= 10, "only {plain} cases without a label");
    assert!(labelled >= 10, "only {labelled} cases with one");
}
