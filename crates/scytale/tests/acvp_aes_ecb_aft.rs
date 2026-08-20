//! NIST ACVP AES-ECB Algorithm Functional Tests.
//!
//! AFT is the fast tier: 2138 cases across all three key sizes and both
//! directions, payloads of one to ten blocks, which run in milliseconds. The
//! Monte Carlo groups in the same file are driven by the extended tier.
//!
//! Every case runs through every AES implementation this machine can
//! reach, not only the one a dispatching type would pick, so a backend is
//! certified on the machine it actually runs on rather than by proxy.

mod acvp;

use acvp::{
    Key, ecb_implementations, group_key_len, group_tests, groups,
    hex_field, load, payload, skipped,
};

const VECTORS: &str = "ACVP-AES-ECB-1.0/internalProjection.json";

#[test]
fn acvp_aes_ecb_aft() {
    let Some(vectors) = load(VECTORS) else {
        skipped(VECTORS);
        return;
    };

    let implementations = ecb_implementations();
    assert!(
        !implementations.is_empty(),
        "no AES implementation to test"
    );

    for imp in &implementations {
        let mut cases = 0usize;
        for group in groups(&vectors, "AFT") {
            let key_len = group_key_len(group);

            for test in group_tests(group) {
                let key = Key::from_hex(hex_field(test, "key"), key_len);
                let pt = payload(hex_field(test, "pt"));
                let ct = payload(hex_field(test, "ct"));
                let tc_id = test.get("tcId").cloned().unwrap_or_default();

                // ACVP supplies both sides of every case, so each is
                // checked in both directions whatever the group's
                // declared direction.
                let mut buf = pt.clone();
                (imp.encrypt)(&key, &mut buf);
                assert_eq!(
                    buf, ct,
                    "{} encrypt mismatch, tcId {tc_id}, keyLen {key_len}",
                    imp.name
                );

                let mut buf = ct.clone();
                (imp.decrypt)(&key, &mut buf);
                assert_eq!(
                    buf, pt,
                    "{} decrypt mismatch, tcId {tc_id}, keyLen {key_len}",
                    imp.name
                );

                cases += 1;
            }
        }

        // Guard against a silently empty run if the file layout ever
        // changes, per implementation rather than in total.
        assert!(
            cases > 2000,
            "{}: only {cases} AFT cases found",
            imp.name
        );
        // Visible under `--nocapture`, so what was certified on this
        // machine can be read off rather than inferred.
        eprintln!("{}: {cases} AFT cases", imp.name);
    }
}
