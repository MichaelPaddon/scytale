//! NIST ACVP AES-ECB Algorithm Functional Tests.
//!
//! Vector set ACVP-AES-ECB-1.0, testType AFT. Primitive: AES-128, -192
//! and -256 in ECB, both directions, payloads of one to ten blocks.
//! 2138 cases, which run in milliseconds. The Monte Carlo groups in the
//! same file are driven by `acvp_aes_ecb_mct`.
//!
//! One test per kernel, so a run says which kernels it certified. See
//! `acvp/mod.rs` for why this is one test per kernel rather than a
//! cross product.

mod acvp;

use acvp::{
    EcbImpl, Key, group_key_len, group_tests, groups, hex_field, load,
    payload, skipped,
};

const VECTORS: &str = "ACVP-AES-ECB-1.0/internalProjection.json";

/// Drive the whole vector set through one implementation.
fn run(imp: &EcbImpl) {
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

            // ACVP supplies both sides of every case, so each is checked
            // in both directions whatever the group's declared direction.
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

    // Guard against a silently empty run if the file layout ever changes.
    assert!(cases > 2000, "{}: only {cases} AFT cases found", imp.name);
    eprintln!("{}: {cases} AFT cases", imp.name);
}

/// A backend this CPU cannot run is not this machine's to certify.
fn run_if_available(imp: Option<EcbImpl>) {
    match imp {
        Some(imp) => run(&imp),
        None => eprintln!("not available on this CPU"),
    }
}

#[test]
fn ttable_kernel() {
    run(&acvp::ecb_ttable());
}

#[test]
fn dispatching_type() {
    run(&acvp::ecb_dispatch());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn aesni_kernel() {
    run_if_available(acvp::ecb_aesni());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn vaes_kernel() {
    run_if_available(acvp::ecb_vaes());
}

#[cfg(target_arch = "aarch64")]
#[test]
fn armv8_kernel() {
    run_if_available(acvp::ecb_armv8());
}
