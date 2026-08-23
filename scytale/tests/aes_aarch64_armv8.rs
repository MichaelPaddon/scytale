//! Vector suites for the ARMv8 implementation. Skipped on processors
//! without the crypto extensions.

#![cfg(target_arch = "aarch64")]

mod support;

use scytale::symmetric::aes::aarch64::armv8::Aes;
use scytale::symmetric::Error;

fn supported() -> bool {
    match Aes::try_new(&[0u8; 16]) {
        Ok(_) => true,
        Err(Error::NotSupported) => {
            eprintln!("ARMv8 AES not available; skipping");
            false
        }
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn acvp_aes_ecb_aft() {
    if supported() {
        support::acvp::aes_ecb::run_aft::<Aes>();
    }
}

/// Slow; run with `cargo test-extended`.
#[test]
#[ignore]
fn acvp_aes_ecb_mct() {
    if supported() {
        support::acvp::aes_ecb::run_mct::<Aes>();
    }
}
