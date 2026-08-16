//! NIST ACVP AES-ECB Algorithm Functional Tests.
//!
//! AFT is the fast tier: 2138 cases across all three key sizes and both
//! directions, payloads of one to ten blocks, which run in milliseconds. The
//! Monte Carlo groups in the same file are driven by the extended tier.

mod acvp;

use acvp::{
    Key, group_key_len, group_tests, groups, hex_field, load, payload,
    skipped,
};

const VECTORS: &str = "ACVP-AES-ECB-1.0/internalProjection.json";

#[test]
fn acvp_aes_ecb_aft() {
    let Some(vectors) = load(VECTORS) else {
        skipped(VECTORS);
        return;
    };

    let mut cases = 0usize;
    for group in groups(&vectors, "AFT") {
        let key_len = group_key_len(group);

        for test in group_tests(group) {
            let key = Key::from_hex(hex_field(test, "key"), key_len);
            let pt = payload(hex_field(test, "pt"));
            let ct = payload(hex_field(test, "ct"));
            let tc_id = test.get("tcId").cloned().unwrap_or_default();

            // ACVP supplies both sides of every case, so each is checked in
            // both directions whatever the group's declared direction.
            let mut buf = pt.clone();
            key.encrypt(&mut buf);
            assert_eq!(
                buf, ct,
                "encrypt mismatch, tcId {tc_id}, keyLen {key_len}"
            );

            let mut buf = ct.clone();
            key.decrypt(&mut buf);
            assert_eq!(
                buf, pt,
                "decrypt mismatch, tcId {tc_id}, keyLen {key_len}"
            );

            cases += 1;
        }
    }

    // Guard against a silently empty run if the file layout ever changes.
    assert!(cases > 2000, "only {cases} AFT cases found");
}
