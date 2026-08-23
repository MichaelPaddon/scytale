//! Vector suites for the portable bitsliced AES implementation.

mod support;

use scytale::symmetric::aes::portable::bitsliced::Aes;

#[test]
fn acvp_aes_ecb_aft() {
    support::acvp::aes_ecb::run_aft::<Aes>();
}

/// Slow; run with `cargo test-extended`.
#[test]
#[ignore]
fn acvp_aes_ecb_mct() {
    support::acvp::aes_ecb::run_mct::<Aes>();
}
