//! Vector suites for the RISC-V zvkned implementation. Skipped on processors
//! without the extension.

#![cfg(target_arch = "riscv64")]

mod support;

use scytale::symmetric::aes::riscv64::zvkned::Aes;
use scytale::symmetric::Error;

fn supported() -> bool {
    match Aes::try_new(&[0u8; 16]) {
        Ok(_) => true,
        Err(Error::NotSupported) => {
            eprintln!("RISC-V zvkned AES not available; skipping");
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
