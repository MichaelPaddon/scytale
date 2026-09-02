//! ACVP-AES-XTS 1.0, run through [`Xts`] over any block cipher.
//!
//! Some groups give a data unit length that is not a whole number of
//! bytes, as IEEE 1619 allows; those go through the bit-length
//! methods, the rest through the byte ones.
//!
//! The tweak is taken from `tweakValue`, which the vectors carry even
//! for the groups that also give a sequence number.

use super::{groups as suite_groups, hex};
use scytale::cipher::mode::Xts;
use scytale::cipher::BlockCipher;
use serde_json::Value;

const FILE: &str = "ACVP-AES-XTS-1.0/internalProjection.json";

/// Runs the one-shot (AFT) groups against `C`; a no-op without the
/// vendored vectors.
pub fn run_aft<C: BlockCipher<Block = [u8; 16]>>() {
    let Some(groups) = groups("AFT") else { return };
    let mut cases = 0;
    for (group, encrypt) in &groups {
        let bits = group["payloadLen"].as_u64().expect("payloadLen");
        cases += aft::<C>(group, *encrypt, bits as usize);
    }
    assert!(cases >= 400, "only {cases} AFT cases");
}

fn groups(test_type: &str) -> Option<Vec<(Value, bool)>> {
    suite_groups(FILE, "ACVP-AES-XTS", "1.0", test_type)
}

/// One group; units of `bits` bits, which may not be whole bytes,
/// in which case ACVP keeps the last byte's spare low bits zero, as
/// the mode does.
fn aft<C: BlockCipher<Block = [u8; 16]>>(
    group: &Value,
    encrypt: bool,
    bits: usize,
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
        match (encrypt, bits % 8) {
            (true, 0) => xts.encrypt(&tweak, &mut data).expect("encrypt"),
            (false, 0) => xts.decrypt(&tweak, &mut data).expect("decrypt"),
            (true, _) => xts
                .encrypt_bits(&tweak, &mut data, bits)
                .expect("encrypt bits"),
            (false, _) => xts
                .decrypt_bits(&tweak, &mut data, bits)
                .expect("decrypt bits"),
        }
        assert_eq!(data, expected, "{label}");
        count += 1;
    }
    count
}
