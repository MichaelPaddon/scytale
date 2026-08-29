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
    aes_ctr as ctr, aes_ecb as ecb, aes_ff1 as ff1, aes_ff3_1 as ff3_1,
    aes_gcm as gcm, aes_gcm_siv as gcm_siv, aes_kw as kw, aes_kwp as kwp,
    aes_ofb as ofb, aes_xpn as xpn, aes_xts as xts, ctr_drbg as drbg,
    hmac as hmac_vectors, pbkdf as pbkdf_vectors, sha2 as sha2_vectors,
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
            use scytale::Error;

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

/// AES-GCM-SIV (RFC 8452), which survives a repeated nonce.
mod aes_gcm_siv {
    every_aes!(gcm_siv, aft_only);
}

/// AES in XTS mode (SP 800-38E), the mode used for storage.
mod aes_xts {
    every_aes!(xts, aft_only);
}

/// AES-FF1, format-preserving encryption (SP 800-38G).
mod aes_ff1 {
    every_aes!(ff1, aft_only);
}

/// AES-FF3-1, format-preserving encryption (SP 800-38G revision 1).
mod aes_ff3_1 {
    every_aes!(ff3_1, aft_only);
}

/// AES-GCM with extended packet numbering, as MACsec uses it.
mod aes_xpn {
    every_aes!(xpn, aft_only);
}

/// AES key wrapping without padding (SP 800-38F). Deterministic and
/// nonce-free, and the only mode here whose output is longer than its
/// input. This suite has no Monte Carlo test.
mod aes_kw {
    every_aes!(kw, aft_only);
}

/// AES key wrapping with padding (SP 800-38F), which takes any length
/// from one byte up. This suite has no Monte Carlo test.
mod aes_kwp {
    every_aes!(kwp, aft_only);
}

/// The CTR_DRBG random number generator (SP 800-90A). Not generic
/// over a block cipher: it is AES-256 by construction, so there is
/// one run rather than one per implementation.
mod ctr_drbg {
    use super::*;

    #[test]
    fn acvp_aft() {
        drbg::run_aft();
    }
}

/// Defines the SHA-2 suites for one implementation of one variant.
/// The hardware ones skip, saying so, when the processor cannot.
macro_rules! sha2_suites {
    ($name:ident, $ty:ty, $file:literal, $algorithm:literal) => {
        sha2_suites!($name, $ty, $file, $algorithm, "portable code");
    };
    ($name:ident, $ty:ty, $file:literal, $algorithm:literal,
     $what:literal) => {
        mod $name {
            use super::*;
            use scytale::hash::Hash;
            use scytale::Error;

            /// Whether to run, reporting a skip when the processor
            /// cannot. A silent skip would look like a pass.
            fn supported() -> bool {
                match <$ty>::try_new() {
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
                    sha2_vectors::run_aft::<$ty>($file, $algorithm);
                }
            }

            /// Slow; run with `cargo test-extended`.
            #[test]
            #[ignore]
            fn acvp_mct() {
                if supported() {
                    sha2_vectors::run_mct::<$ty>($file, $algorithm);
                }
            }

            /// Gigabytes of hashing; run with `cargo test-extended`.
            #[test]
            #[ignore]
            fn acvp_ldt() {
                if supported() {
                    sha2_vectors::run_ldt::<$ty>($file, $algorithm);
                }
            }
        }
    };
}

/// Runs one variant's suites against every implementation this
/// architecture has.
macro_rules! every_sha2 {
    ($variant:ident, $file:literal, $algorithm:literal) => {
        use super::*;
        use scytale::hash::sha2;

        sha2_suites!(automatic, sha2::$variant, $file, $algorithm);
        sha2_suites!(portable, sha2::portable::$variant, $file, $algorithm);

        #[cfg(target_arch = "aarch64")]
        sha2_suites!(
            armv8,
            sha2::aarch64::$variant,
            $file,
            $algorithm,
            "ARMv8 SHA2"
        );

        #[cfg(target_arch = "riscv64")]
        sha2_suites!(
            zknh,
            sha2::riscv64::$variant,
            $file,
            $algorithm,
            "RISC-V Zknh"
        );
    };
}

/// SHA-224 (FIPS 180-4).
mod sha2_224 {
    every_sha2!(
        Sha224,
        "ACVP-SHA2-224-1.0/internalProjection.json",
        "SHA2-224"
    );

    #[cfg(target_arch = "x86_64")]
    sha2_suites!(
        shani,
        sha2::x86_64::Sha224,
        "ACVP-SHA2-224-1.0/internalProjection.json",
        "SHA2-224",
        "SHA-NI"
    );
}

/// SHA-256 (FIPS 180-4).
mod sha2_256 {
    every_sha2!(
        Sha256,
        "ACVP-SHA2-256-1.0/internalProjection.json",
        "SHA2-256"
    );

    #[cfg(target_arch = "x86_64")]
    sha2_suites!(
        shani,
        sha2::x86_64::Sha256,
        "ACVP-SHA2-256-1.0/internalProjection.json",
        "SHA2-256",
        "SHA-NI"
    );
}

/// SHA-384 (FIPS 180-4).
mod sha2_384 {
    every_sha2!(
        Sha384,
        "ACVP-SHA2-384-1.0/internalProjection.json",
        "SHA2-384"
    );
}

/// SHA-512 (FIPS 180-4).
mod sha2_512 {
    every_sha2!(
        Sha512,
        "ACVP-SHA2-512-1.0/internalProjection.json",
        "SHA2-512"
    );
}

/// SHA-512/224 (FIPS 180-4 section 5.3.6).
mod sha2_512_224 {
    every_sha2!(
        Sha512_224,
        "ACVP-SHA2-512-224-1.0/internalProjection.json",
        "SHA2-512/224"
    );
}

/// SHA-512/256 (FIPS 180-4 section 5.3.6).
mod sha2_512_256 {
    every_sha2!(
        Sha512_256,
        "ACVP-SHA2-512-256-1.0/internalProjection.json",
        "SHA2-512/256"
    );
}

/// Defines the HMAC suite for one hash implementation. The hardware
/// ones skip, saying so, when the processor cannot.
macro_rules! hmac_suite {
    ($name:ident, $hash:ty, $file:literal, $algorithm:literal) => {
        hmac_suite!($name, $hash, $file, $algorithm, "portable code");
    };
    ($name:ident, $hash:ty, $file:literal, $algorithm:literal,
     $what:literal) => {
        mod $name {
            use super::*;
            use scytale::mac::hmac::Hmac;
            use scytale::Error;

            #[test]
            fn acvp_aft() {
                match Hmac::<$hash>::try_new(&[0u8; 16]) {
                    Ok(_) => {}
                    Err(Error::NotSupported) => {
                        eprintln!(concat!($what, " not available; skipping"));
                        return;
                    }
                    Err(e) => panic!("{e}"),
                }
                hmac_vectors::run_aft::<Hmac<$hash>>($file, $algorithm);
            }
        }
    };
}

/// Runs one variant's HMAC suite against every implementation this
/// architecture has.
macro_rules! every_hmac {
    ($variant:ident, $file:literal, $algorithm:literal) => {
        use super::*;
        use scytale::hash::sha2;

        hmac_suite!(automatic, sha2::$variant, $file, $algorithm);
        hmac_suite!(portable, sha2::portable::$variant, $file, $algorithm);

        #[cfg(target_arch = "aarch64")]
        hmac_suite!(
            armv8,
            sha2::aarch64::$variant,
            $file,
            $algorithm,
            "ARMv8 SHA2"
        );

        #[cfg(target_arch = "riscv64")]
        hmac_suite!(
            zknh,
            sha2::riscv64::$variant,
            $file,
            $algorithm,
            "RISC-V Zknh"
        );
    };
}

/// HMAC (FIPS 198-1) over each SHA-2 variant.
mod hmac_sha2_224 {
    every_hmac!(
        Sha224,
        "ACVP-HMAC-SHA2-224-1.0/internalProjection.json",
        "HMAC-SHA2-224"
    );

    #[cfg(target_arch = "x86_64")]
    hmac_suite!(
        shani,
        sha2::x86_64::Sha224,
        "ACVP-HMAC-SHA2-224-1.0/internalProjection.json",
        "HMAC-SHA2-224",
        "SHA-NI"
    );
}

mod hmac_sha2_256 {
    every_hmac!(
        Sha256,
        "ACVP-HMAC-SHA2-256-1.0/internalProjection.json",
        "HMAC-SHA2-256"
    );

    #[cfg(target_arch = "x86_64")]
    hmac_suite!(
        shani,
        sha2::x86_64::Sha256,
        "ACVP-HMAC-SHA2-256-1.0/internalProjection.json",
        "HMAC-SHA2-256",
        "SHA-NI"
    );
}

mod hmac_sha2_384 {
    every_hmac!(
        Sha384,
        "ACVP-HMAC-SHA2-384-1.0/internalProjection.json",
        "HMAC-SHA2-384"
    );
}

mod hmac_sha2_512 {
    every_hmac!(
        Sha512,
        "ACVP-HMAC-SHA2-512-1.0/internalProjection.json",
        "HMAC-SHA2-512"
    );
}

mod hmac_sha2_512_224 {
    every_hmac!(
        Sha512_224,
        "ACVP-HMAC-SHA2-512-224-1.0/internalProjection.json",
        "HMAC-SHA2-512/224"
    );
}

mod hmac_sha2_512_256 {
    every_hmac!(
        Sha512_256,
        "ACVP-HMAC-SHA2-512-256-1.0/internalProjection.json",
        "HMAC-SHA2-512/256"
    );
}

/// PBKDF2 (SP 800-132). The vendored file covers HMAC-SHA-224 only,
/// and the function is generic over the hash, so one run suffices.
mod pbkdf2 {
    use super::*;

    #[test]
    fn acvp_aft() {
        pbkdf_vectors::run_aft::<scytale::hash::sha2::Sha224>("SHA2-224");
    }
}
