//! NIST ACVP vector suites.
//!
//! One test binary covers every primitive and every implementation of
//! it, so `cargo test -- --list` shows the whole inventory in one
//! place. Test names read `primitive::implementation::suite`.
//! Implementations that do not exist on this architecture are left
//! out, rather than appearing as empty test binaries.

mod support;

use support::acvp::{
    aes_cbc as cbc, aes_cfb1 as cfb1, aes_cfb128 as cfb128, aes_cfb8 as cfb8,
    aes_ctr as ctr, aes_ecb as ecb, aes_gcm as gcm, aes_ofb as ofb,
};

/// Defines the suites for an implementation that is always
/// available. `both` covers suites with a Monte Carlo test as well as
/// a one-shot one; `aft_only` those with just the one-shot test.
macro_rules! suites {
    ($name:ident, $ty:ty, $suite:ident, both) => {
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
    ($name:ident, $ty:ty, $suite:ident, aft_only) => {
        mod $name {
            use super::*;

            #[test]
            fn acvp_aft() {
                $suite::run_aft::<$ty>();
            }
        }
    };
}

/// Defines the suites for a hardware implementation, which skip when
/// the processor lacks the instructions.
macro_rules! hardware_suites {
    ($name:ident, $ty:ty, $suite:ident, $what:literal, $kind:ident) => {
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

            hardware_tests!($ty, $suite, $kind);
        }
    };
}

/// The test bodies inside a hardware implementation's module.
macro_rules! hardware_tests {
    ($ty:ty, $suite:ident, both) => {
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
    };
    ($ty:ty, $suite:ident, aft_only) => {
        #[test]
        fn acvp_aft() {
            if supported() {
                $suite::run_aft::<$ty>();
            }
        }
    };
}

/// Runs one suite against every AES implementation this architecture
/// has. Suites with a Monte Carlo test take no second argument.
macro_rules! every_aes {
    ($suite:ident) => {
        every_aes!($suite, both);
    };
    ($suite:ident, $kind:ident) => {
        use super::*;
        use scytale::symmetric::aes;

        suites!(automatic, aes::Aes, $suite, $kind);
        suites!(portable, aes::portable::Aes, $suite, $kind);
        suites!(bitsliced, aes::portable::bitsliced::Aes, $suite, $kind);

        #[cfg(target_arch = "x86_64")]
        hardware_suites!(
            aesni,
            aes::x86_64::aesni::Aes,
            $suite,
            "AES-NI",
            $kind
        );

        #[cfg(target_arch = "x86_64")]
        hardware_suites!(vaes, aes::x86_64::vaes::Aes, $suite, "VAES", $kind);

        #[cfg(target_arch = "aarch64")]
        hardware_suites!(
            armv8,
            aes::aarch64::armv8::Aes,
            $suite,
            "ARMv8 AES",
            $kind
        );

        #[cfg(target_arch = "riscv64")]
        hardware_suites!(
            zkn,
            aes::riscv64::zkn::Aes,
            $suite,
            "RISC-V scalar AES",
            $kind
        );

        #[cfg(target_arch = "riscv64")]
        hardware_suites!(
            zvkned,
            aes::riscv64::zvkned::Aes,
            $suite,
            "RISC-V vector AES",
            $kind
        );
    };
}

/// AES (FIPS 197) with each block encrypted independently.
mod aes_ecb {
    every_aes!(ecb);
}

/// AES in cipher block chaining mode (SP 800-38A).
mod aes_cbc {
    every_aes!(cbc);
}

/// AES in cipher feedback mode with full-block segments.
mod aes_cfb128 {
    every_aes!(cfb128);
}

/// AES in cipher feedback mode with 8-bit segments.
mod aes_cfb8 {
    every_aes!(cfb8);
}

/// AES in cipher feedback mode with 1-bit segments.
mod aes_cfb1 {
    every_aes!(cfb1);
}

/// AES in output feedback mode (SP 800-38A).
mod aes_ofb {
    every_aes!(ofb);
}

/// AES in counter mode (SP 800-38A). This suite has no Monte Carlo
/// test.
mod aes_ctr {
    every_aes!(ctr, aft_only);
}

/// AES in Galois/Counter Mode (SP 800-38D), the first authenticated
/// mode. This suite has no Monte Carlo test.
mod aes_gcm {
    every_aes!(gcm, aft_only);
}
