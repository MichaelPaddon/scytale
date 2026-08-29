//! ACVP-SHAKE 1.0, run through the [`Xof`] trait: the one-shot
//! test, the variable output test, and a Monte Carlo test whose
//! output length wanders.

use super::sha::{Family, Message};
use super::{hex, load};
use scytale::hash::{BitXof, XofReader};
use serde_json::Value;

/// Runs the one-shot and variable-output groups against `X`; a no-op
/// without the vendored vectors.
pub fn run_aft<X: BitXof>(file: &str, algorithm: &str) {
    let Some(doc) = load(file, algorithm, "1.0") else {
        return;
    };
    let mut count = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if !matches!(group["testType"].as_str(), Some("AFT" | "VOT")) {
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let bits = t["outLen"].as_u64().expect("outLen") as usize;
            let mut out = vec![0u8; bits.div_ceil(8)];
            Message::of(t).squeeze::<X>(&mut out);
            // A length that is not whole bytes keeps the last byte's
            // low bits, numbered as FIPS 202 numbers them, and the
            // rest zero.
            if !bits.is_multiple_of(8) {
                let last = out.last_mut().expect("out");
                *last &= (1u8 << (bits % 8)) - 1;
            }
            assert_eq!(
                out,
                hex(&t["md"]),
                "tgId {} tcId {}",
                group["tgId"],
                t["tcId"]
            );
            count += 1;
        }
    }
    assert!(count >= 500, "only {count} cases");
}

/// Runs the Monte Carlo groups against `X`; a no-op without the
/// vendored vectors. Slow: 100,000 SHAKE calls per group.
pub fn run_mct<X: BitXof>(file: &str, algorithm: &str) {
    let Some(doc) = load(file, algorithm, "1.0") else {
        return;
    };
    let mut count = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["testType"] != "MCT" {
            continue;
        }
        count += mct::<X>(group);
    }
    assert!(count >= 100, "only {count} MCT steps");
}

impl Message {
    /// Squeezes `out.len()` bytes from the message.
    fn squeeze<X: BitXof>(&self, out: &mut [u8]) {
        let mut xof = X::try_new().expect("xof");
        let (whole, tail) = self.split(Family::Sha3);
        xof.update(whole);
        let mut reader = match tail {
            None => xof.finalize_xof(),
            Some((last, extra)) => {
                xof.finalize_bits_xof(last, extra).expect("bits")
            }
        };
        reader.squeeze(out);
    }
}

/// The SHAKE Monte Carlo test: each of 100 steps squeezes 1000
/// times, feeding the first 16 bytes of each output (zero-padded)
/// into the next, with the output length chosen each time by the
/// last two bytes of the previous output within the group's range.
fn mct<X: BitXof>(group: &Value) -> usize {
    let min_bits = group["minOutLen"].as_u64().expect("minOutLen") as usize;
    let max_bits = group["maxOutLen"].as_u64().expect("maxOutLen") as usize;
    let range = (max_bits - min_bits) / 8 + 1;
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let seed = Message::of(t);
        assert_eq!(seed.bits % 8, 0, "tcId {}: bit seed", t["tcId"]);
        let mut md = seed.bytes.clone();
        let mut out_len = max_bits / 8;
        let steps = t["resultsArray"].as_array().expect("resultsArray");
        for (i, step) in steps.iter().enumerate() {
            for _ in 0..1000 {
                let mut msg = md.clone();
                msg.resize(16, 0);
                let message = Message {
                    bytes: msg,
                    bits: 128,
                };
                let mut out = vec![0u8; out_len];
                message.squeeze::<X>(&mut out);
                let tail = &out[out.len() - 2..];
                let right = u16::from_be_bytes([tail[0], tail[1]]) as usize;
                out_len = min_bits / 8 + right % range;
                md = out;
            }
            let expected = hex(&step["md"]);
            let expected_len = step["outLen"].as_u64().expect("outLen");
            let tag =
                format!("tgId {} tcId {} step {i}", group["tgId"], t["tcId"]);
            assert_eq!(md.len() as u64 * 8, expected_len, "{tag} length");
            assert_eq!(md, expected, "{tag}");
            count += 1;
        }
    }
    count
}
