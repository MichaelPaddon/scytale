//! Vector suites for the AES-NI implementation. Skipped on processors
//! without AES-NI.

#![cfg(target_arch = "x86_64")]

mod support;

use scytale::symmetric::aes::x86_64::aesni::Aes;
use scytale::symmetric::Error;

fn supported() -> bool {
    match Aes::try_new(&[0u8; 16]) {
        Ok(_) => true,
        Err(Error::NotSupported) => {
            eprintln!("AES-NI not available; skipping");
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
