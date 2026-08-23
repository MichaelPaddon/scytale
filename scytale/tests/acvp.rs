//! NIST ACVP vector suites.
//!
//! One test binary covers every primitive and every implementation of
//! it, so `cargo test -- --list` shows the whole inventory in one
//! place. Test names read `primitive::implementation::suite`.
//! Implementations that do not exist on this architecture are left
//! out, rather than appearing as empty test binaries.

mod support;

use support::acvp::aes_ecb;

/// Defines the suites for an implementation that is always available.
macro_rules! suites {
    ($name:ident, $ty:ty, $suite:ident) => {
        mod $name {
            use super::*;

            #[test]
            fn acvp_aft() {
                $suite::run_aft::<$ty>();
            }

            /// Slow; run with `cargo test-extended`.
            #[test]
            #[ignore]
            fn acvp_mct() {
                $suite::run_mct::<$ty>();
            }
        }
    };
}

/// Defines the suites for a hardware implementation, which skip when
/// the processor lacks the instructions.
macro_rules! hardware_suites {
    ($name:ident, $ty:ty, $suite:ident, $what:literal) => {
        mod $name {
            use super::*;
            use scytale::symmetric::Error;

            /// Whether to run, reporting a skip when the processor
            /// cannot. A silent skip would look like a pass.
            fn supported() -> bool {
                match <$ty>::try_new(&[0u8; 16]) {
                    Ok(_) => true,
                    Err(Error::NotSupported) => {
                        eprintln!(concat!($what, " not available; skipping"));
                        false
                    }
                    Err(e) => panic!("{e}"),
                }
            }

            #[test]
            fn acvp_aft() {
                if supported() {
                    $suite::run_aft::<$ty>();
                }
            }

            /// Slow; run with `cargo test-extended`.
            #[test]
            #[ignore]
            fn acvp_mct() {
                if supported() {
                    $suite::run_mct::<$ty>();
                }
            }
        }
    };
}

/// AES (FIPS 197), through the ACVP-AES-ECB suites.
mod aes {
    use super::*;
    use scytale::symmetric::aes;

    suites!(automatic, aes::Aes, aes_ecb);
    suites!(portable, aes::portable::Aes, aes_ecb);
    suites!(bitsliced, aes::portable::bitsliced::Aes, aes_ecb);

    #[cfg(target_arch = "x86_64")]
    hardware_suites!(aesni, aes::x86_64::aesni::Aes, aes_ecb, "AES-NI");

    #[cfg(target_arch = "x86_64")]
    hardware_suites!(vaes, aes::x86_64::vaes::Aes, aes_ecb, "VAES");

    #[cfg(target_arch = "aarch64")]
    hardware_suites!(armv8, aes::aarch64::armv8::Aes, aes_ecb, "ARMv8 AES");

    #[cfg(target_arch = "riscv64")]
    hardware_suites!(zkn, aes::riscv64::zkn::Aes, aes_ecb, "RISC-V scalar AES");

    #[cfg(target_arch = "riscv64")]
    hardware_suites!(
        zvkned,
        aes::riscv64::zvkned::Aes,
        aes_ecb,
        "RISC-V vector AES"
    );
}
