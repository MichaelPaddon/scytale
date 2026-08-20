//! NIST ACVP AES-CTR Algorithm Functional Tests.
//!
//! The whole file is fast-tier: 150 cases across all three key sizes and
//! both directions. Payload lengths are bit-granular, so outputs are
//! masked to the declared bit length before comparing, matching how the
//! vector files zero their pad bits.
//!
//! Every case runs through every CTR implementation this machine can
//! reach: the generic mode over each cipher, each fused counter kernel,
//! and the dispatching types. The fused kernels take whole blocks only,
//! so they answer for the 90 block-aligned cases and the modes built on
//! them answer for all 150.

mod acvp;

use acvp::{
    BLOCK_SIZE, Key, ctr_implementations, group_key_len, group_tests,
    groups, hex_field, load, mask_to_bits, payload_bits, skipped,
    test_payload_len, unhex,
};

const VECTORS: &str = "ACVP-AES-CTR-1.0/internalProjection.json";

#[test]
fn acvp_aes_ctr_aft() {
    let Some(vectors) = load(VECTORS) else {
        skipped(VECTORS);
        return;
    };

    let implementations = ctr_implementations();
    assert!(
        !implementations.is_empty(),
        "no CTR implementation to test"
    );

    for imp in &implementations {
        let mut cases = 0usize;
        for group in groups(&vectors, "AFT") {
            let key_len = group_key_len(group);

            for test in group_tests(group) {
                let bits = test_payload_len(test);
                // A fused kernel has no way to take a partial block, so
                // the cases that end in one are not its to answer.
                if imp.whole_blocks_only
                    && !bits.is_multiple_of(8 * BLOCK_SIZE as u64)
                {
                    continue;
                }

                let key = Key::from_hex(hex_field(test, "key"), key_len);
                let iv = unhex(hex_field(test, "iv"));
                let iv: [u8; BLOCK_SIZE] =
                    iv.try_into().expect("vector IV is one block");
                let pt = payload_bits(hex_field(test, "pt"), bits);
                let ct = payload_bits(hex_field(test, "ct"), bits);
                let tc_id = test.get("tcId").cloned().unwrap_or_default();

                // ACVP supplies both sides of every case, so each is
                // checked in both directions whatever the group's
                // declared direction. For CTR they are one operation.
                let mut buf = pt.clone();
                (imp.apply)(&key, &iv, &mut buf);
                mask_to_bits(&mut buf, bits);
                assert_eq!(
                    buf, ct,
                    "{} encrypt mismatch, tcId {tc_id}, keyLen {key_len}",
                    imp.name
                );

                let mut buf = ct.clone();
                (imp.apply)(&key, &iv, &mut buf);
                mask_to_bits(&mut buf, bits);
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
        let least = if imp.whole_blocks_only { 90 } else { 150 };
        assert!(
            cases >= least,
            "{}: only {cases} CTR AFT cases found, expected {least}",
            imp.name
        );
        // Visible under `--nocapture`, so what was certified on this
        // machine can be read off rather than inferred.
        eprintln!("{}: {cases} AFT cases", imp.name);
    }
}
