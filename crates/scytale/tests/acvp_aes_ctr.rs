//! NIST ACVP AES-CTR Algorithm Functional Tests.
//!
//! Vector set ACVP-AES-CTR-1.0, testType AFT. Primitive: AES-128, -192
//! and -256 in CTR, 150 cases. Payload lengths are bit-granular, so
//! outputs are masked to the declared bit length before comparing,
//! matching how the vector file zeroes its own pad bits.
//!
//! The generic mode is one construct and is certified once, over the
//! widest kernel this machine has; the ciphers under it are already
//! certified by the ECB vectors. The fused counter kernels are separate
//! code that those vectors never reach, so each answers for itself.
//! They take whole blocks only, so they cover the 90 block-aligned
//! cases and the modes built on them cover all 150.

mod acvp;

use acvp::{
    BLOCK_SIZE, CtrImpl, Key, group_key_len, group_tests, groups,
    hex_field, load, mask_to_bits, payload_bits, skipped,
    test_payload_len, unhex,
};

const VECTORS: &str = "ACVP-AES-CTR-1.0/internalProjection.json";

/// Drive the whole vector set through one implementation.
fn run(imp: &CtrImpl) {
    let Some(vectors) = load(VECTORS) else {
        skipped(VECTORS);
        return;
    };

    let mut cases = 0usize;
    for group in groups(&vectors, "AFT") {
        let key_len = group_key_len(group);

        for test in group_tests(group) {
            let bits = test_payload_len(test);
            // A fused kernel has no way to take a partial block, so the
            // cases that end in one are not its to answer.
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

            // ACVP supplies both sides of every case, so each is checked
            // in both directions. For CTR they are one operation.
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

    // Guard against a silently empty run if the file layout ever changes.
    let least = if imp.whole_blocks_only { 90 } else { 150 };
    assert!(
        cases >= least,
        "{}: only {cases} CTR AFT cases found, expected {least}",
        imp.name
    );
    eprintln!("{}: {cases} AFT cases", imp.name);
}

/// A backend this CPU cannot run is not this machine's to certify.
fn run_if_available(imp: Option<CtrImpl>) {
    match imp {
        Some(imp) => run(&imp),
        None => eprintln!("not available on this CPU"),
    }
}

#[test]
fn generic_mode() {
    run(&acvp::ctr_generic());
}

#[test]
fn dispatching_type() {
    run(&acvp::ctr_dispatch());
}

#[test]
fn ttable_counter_kernel() {
    run(&acvp::ctr_fused_ttable());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn aesni_counter_kernel() {
    run_if_available(acvp::ctr_fused_aesni());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn vaes_counter_kernel() {
    run_if_available(acvp::ctr_fused_vaes());
}

#[cfg(target_arch = "aarch64")]
#[test]
fn armv8_counter_kernel() {
    run_if_available(acvp::ctr_fused_armv8());
}
