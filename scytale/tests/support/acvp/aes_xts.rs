//! ACVP-AES-XTS 1.0, run through [`Xts`] over any block cipher.
//!
//! Some groups give a data unit length that is not a whole number of
//! bytes. IEEE 1619 does define XTS down to the bit, but no storage
//! device has ever needed it, and [`Xts`] works in bytes. Those
//! groups are skipped, and the count of what was skipped is reported
//! rather than passed over quietly.
//!
//! The tweak is taken from `tweakValue`, which the vectors carry even
//! for the groups that also give a sequence number.

use super::{groups as suite_groups, hex};
use scytale::symmetric::mode::Xts;
use scytale::symmetric::BlockCipher;
use serde_json::Value;

const FILE: &str = "ACVP-AES-XTS-1.0/internalProjection.json";

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups("AFT") else { return };
    let mut cases = 0;
    let mut skipped = 0;
    for (group, encrypt) in &groups {
        let bits = group["payloadLen"].as_u64().expect("payloadLen");
        if !bits.is_multiple_of(8) {
            skipped += group["tests"].as_array().expect("tests").len();
            continue;
        }
        cases += aft::<C>(group, *encrypt);
    }
    assert!(cases >= 200, "only {cases} AFT cases");
    if skipped > 0 {
        eprintln!("XTS: skipped {skipped} cases not a whole number of bytes");
    }
}

fn groups(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups(FILE, "ACVP-AES-XTS", "1.0", test_type)
}

fn aft<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
) -> usize {
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let label = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
        let xts = Xts::<C>::try_new(&hex(&t["key"])).expect("key");
        let tweak: [u8; 16] = hex(&t["tweakValue"]).try_into().expect("tweak");
        let (input, expected) = if encrypt {
            (hex(&t["pt"]), hex(&t["ct"]))
        } else {
            (hex(&t["ct"]), hex(&t["pt"]))
        };

        let mut data = input;
        if encrypt {
            xts.encrypt(&tweak, &mut data).expect("encrypt");
        } else {
            xts.decrypt(&tweak, &mut data).expect("decrypt");
        }
        assert_eq!(data, expected, "{label}");
        count += 1;
    }
    count
}
