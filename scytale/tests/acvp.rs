//! NIST ACVP vector suites, and the Wycheproof suites for what ACVP
//! does not cover.
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
    aes_gcm as gcm, aes_gcm_siv as gcm_siv, aes_gmac as gmac, aes_kw as kw,
    aes_kwp as kwp, aes_ofb as ofb, aes_xpn as xpn, aes_xts as xts,
    ctr_drbg as drbg, hmac as hmac_vectors, pbkdf as pbkdf_vectors,
    sha as sha_vectors, shake as shake_vectors,
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
        use scytale::cipher::aes;

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

/// ACVP-AES-GMAC: GCM with no plaintext, which is how the crate
/// offers GMAC. Run across every implementation, as the other modes
/// are, because the tag is the cipher's work.
mod aes_gmac {
    every_aes!(gmac, aft_only);
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
    ($name:ident, $ty:ty, $file:literal, $algorithm:literal,
     $family:expr) => {
        sha2_suites!($name, $ty, $file, $algorithm, $family, "portable code");
    };
    ($name:ident, $ty:ty, $file:literal, $algorithm:literal,
     $family:expr, $what:literal) => {
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
                    sha_vectors::run_aft::<$ty>($file, $algorithm, $family);
                }
            }

            /// Slow; run with `cargo test-extended`.
            #[test]
            #[ignore]
            fn acvp_mct() {
                if supported() {
                    sha_vectors::run_mct::<$ty>($file, $algorithm, $family);
                }
            }
        }
    };
}

/// Runs one SHA-2 variant's suites against every implementation
/// this architecture has.
macro_rules! every_sha2 {
    ($variant:ident, $file:literal, $algorithm:literal) => {
        use super::*;
        use scytale::hash::sha2;
        use support::acvp::sha::Family;

        sha2_suites!(
            automatic,
            sha2::$variant,
            $file,
            $algorithm,
            Family::Sha2
        );
        sha2_suites!(
            portable,
            sha2::portable::$variant,
            $file,
            $algorithm,
            Family::Sha2
        );

        #[cfg(target_arch = "aarch64")]
        sha2_suites!(
            armv8,
            sha2::aarch64::$variant,
            $file,
            $algorithm,
            Family::Sha2,
            "ARMv8 SHA2"
        );

        #[cfg(target_arch = "riscv64")]
        sha2_suites!(
            zknh,
            sha2::riscv64::$variant,
            $file,
            $algorithm,
            Family::Sha2,
            "RISC-V Zknh"
        );
    };
}

/// Runs one SHA-3 digest's suites against every implementation
/// this architecture has.
macro_rules! every_sha3 {
    ($variant:ident, $file:literal, $algorithm:literal) => {
        use super::*;
        use scytale::hash::sha3;
        use support::acvp::sha::Family;

        sha2_suites!(
            automatic,
            sha3::$variant,
            $file,
            $algorithm,
            Family::Sha3
        );
        sha2_suites!(
            portable,
            sha3::portable::$variant,
            $file,
            $algorithm,
            Family::Sha3
        );

        #[cfg(target_arch = "aarch64")]
        sha2_suites!(
            armv8,
            sha3::aarch64::$variant,
            $file,
            $algorithm,
            Family::Sha3,
            "ARMv8 SHA3"
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
        Family::Sha2,
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
        Family::Sha2,
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

/// SHA3-224 (FIPS 202).
mod sha3_224 {
    every_sha3!(
        Sha3_224,
        "ACVP-SHA3-224-2.0/internalProjection.json",
        "SHA3-224"
    );
}

/// SHA3-256 (FIPS 202).
mod sha3_256 {
    every_sha3!(
        Sha3_256,
        "ACVP-SHA3-256-2.0/internalProjection.json",
        "SHA3-256"
    );
}

/// SHA3-384 (FIPS 202).
mod sha3_384 {
    every_sha3!(
        Sha3_384,
        "ACVP-SHA3-384-2.0/internalProjection.json",
        "SHA3-384"
    );
}

/// SHA3-512 (FIPS 202).
mod sha3_512 {
    every_sha3!(
        Sha3_512,
        "ACVP-SHA3-512-2.0/internalProjection.json",
        "SHA3-512"
    );
}

/// Defines the SHAKE suites for one implementation.
macro_rules! shake_suites {
    ($name:ident, $ty:ty, $file:literal, $algorithm:literal) => {
        shake_suites!($name, $ty, $file, $algorithm, "portable code");
    };
    ($name:ident, $ty:ty, $file:literal, $algorithm:literal,
     $what:literal) => {
        mod $name {
            use super::*;
            use scytale::hash::Xof;
            use scytale::Error;

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
                    shake_vectors::run_aft::<$ty>($file, $algorithm);
                }
            }

            /// Slow; run with `cargo test-extended`.
            #[test]
            #[ignore]
            fn acvp_mct() {
                if supported() {
                    shake_vectors::run_mct::<$ty>($file, $algorithm);
                }
            }
        }
    };
}

/// Runs one SHAKE function's suites against every implementation
/// this architecture has.
macro_rules! every_shake {
    ($variant:ident, $file:literal, $algorithm:literal) => {
        use super::*;
        use scytale::hash::sha3;

        shake_suites!(automatic, sha3::$variant, $file, $algorithm);
        shake_suites!(portable, sha3::portable::$variant, $file, $algorithm);

        #[cfg(target_arch = "aarch64")]
        shake_suites!(
            armv8,
            sha3::aarch64::$variant,
            $file,
            $algorithm,
            "ARMv8 SHA3"
        );
    };
}

/// SHAKE128 (FIPS 202).
mod shake_128 {
    every_shake!(
        Shake128,
        "ACVP-SHAKE-128-1.0/internalProjection.json",
        "SHAKE-128"
    );
}

/// SHAKE256 (FIPS 202).
mod shake_256 {
    every_shake!(
        Shake256,
        "ACVP-SHAKE-256-1.0/internalProjection.json",
        "SHAKE-256"
    );
}

/// The large data tests: messages of 1 to 8 GiB, which take the
/// length field past 2^32 bits. That field belongs to the shared
/// engine, one per SHA-2 word size, not to any variant or backend:
/// the variants differ only in starting value and truncation, and
/// the backends only in the compression function, and AFT and MCT
/// cover both of those for each. SHA-3 keeps no length at all, so
/// its one run checks only that nothing else breaks over 8 GiB. One
/// whole group each, on the best implementation the machine has.
mod sha_ldt {
    use super::*;
    use scytale::hash::{sha2, sha3};
    use support::acvp::sha::Family;

    /// Gigabytes of hashing; run with `cargo test-extended`.
    #[test]
    #[ignore]
    fn sha256() {
        sha_vectors::run_ldt::<sha2::Sha256>(
            "ACVP-SHA2-256-1.0/internalProjection.json",
            "SHA2-256",
            Family::Sha2,
        );
    }

    /// Gigabytes of hashing; run with `cargo test-extended`.
    #[test]
    #[ignore]
    fn sha512() {
        sha_vectors::run_ldt::<sha2::Sha512>(
            "ACVP-SHA2-512-1.0/internalProjection.json",
            "SHA2-512",
            Family::Sha2,
        );
    }

    /// Thirty-two gigabytes of hashing; run with `cargo
    /// test-extended`.
    #[test]
    #[ignore]
    fn sha3_256() {
        sha_vectors::run_ldt::<sha3::Sha3_256>(
            "ACVP-SHA3-256-2.0/internalProjection.json",
            "SHA3-256",
            Family::Sha3,
        );
    }
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
/// The same for HMAC over a SHA-3 digest, whose backends differ from
/// the SHA-2 ones: only AArch64 has instructions for Keccak.
macro_rules! every_hmac_sha3 {
    ($variant:ident, $file:literal, $algorithm:literal) => {
        use super::*;
        use scytale::hash::sha3;

        hmac_suite!(automatic, sha3::$variant, $file, $algorithm);
        hmac_suite!(portable, sha3::portable::$variant, $file, $algorithm);

        #[cfg(target_arch = "aarch64")]
        hmac_suite!(
            armv8,
            sha3::aarch64::$variant,
            $file,
            $algorithm,
            "ARMv8 SHA3"
        );
    };
}

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

/// HMAC over each SHA-3 digest, whose rates exceed any SHA-2 block.
mod hmac_sha3_224 {
    every_hmac_sha3!(
        Sha3_224,
        "ACVP-HMAC-SHA3-224-1.0/internalProjection.json",
        "HMAC-SHA3-224"
    );
}

mod hmac_sha3_256 {
    every_hmac_sha3!(
        Sha3_256,
        "ACVP-HMAC-SHA3-256-1.0/internalProjection.json",
        "HMAC-SHA3-256"
    );
}

mod hmac_sha3_384 {
    every_hmac_sha3!(
        Sha3_384,
        "ACVP-HMAC-SHA3-384-1.0/internalProjection.json",
        "HMAC-SHA3-384"
    );
}

mod hmac_sha3_512 {
    every_hmac_sha3!(
        Sha3_512,
        "ACVP-HMAC-SHA3-512-1.0/internalProjection.json",
        "HMAC-SHA3-512"
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

/// ChaCha20-Poly1305 (RFC 8439), through Project Wycheproof's cases:
/// there is no ACVP suite for it. The automatic type is what runs;
/// every ChaCha20 backend is checked against the portable one in
/// the unit tests.
mod chacha20_poly1305 {
    use super::*;

    #[test]
    fn wycheproof() {
        support::wycheproof::chacha20_poly1305::run();
    }
}

/// Key agreement: X25519, through ACVP's shared-secret and key
/// generation suites and Project Wycheproof's edge cases.
///
/// ACVP's XECDH keyVer suite is not here; [`support::acvp::xecdh`]
/// says why.
mod kex {
    use super::*;

    #[test]
    fn wycheproof_x25519() {
        support::wycheproof::x25519::run();
    }

    #[test]
    fn acvp_xecdh() {
        support::acvp::xecdh::run();
    }

    #[test]
    fn acvp_xecdh_key_gen() {
        support::acvp::xecdh::run_key_gen();
    }
}

/// Public-key encryption: RSA-OAEP, through ACVP's key transport
/// suite and Project Wycheproof's decryption cases, with the raw
/// decryption primitive beside them.
mod pke {
    use super::*;

    #[test]
    fn acvp_kts_ifc() {
        support::acvp::kts_ifc::run();
    }

    #[test]
    fn acvp_rsa_decryption_primitive() {
        support::acvp::rsa_primitive::run_decryption_primitive();
    }
}

/// Signatures: Ed25519 and RSA, through ACVP and Project Wycheproof.
///
/// ACVP RSA keyGen is deliberately absent: its vectors replay a
/// seeded candidate stream, and `generate` draws from a live random
/// source.
mod sig {
    use super::*;

    #[test]
    fn wycheproof_ed25519() {
        support::wycheproof::ed25519::run();
    }

    #[test]
    fn wycheproof_rsa() {
        support::wycheproof::rsa::run();
    }

    #[test]
    fn acvp_eddsa_key_gen() {
        support::acvp::eddsa::run_key_gen();
    }

    #[test]
    fn acvp_eddsa_key_ver() {
        support::acvp::eddsa::run_key_ver();
    }

    #[test]
    fn acvp_eddsa_sig_gen() {
        support::acvp::eddsa::run_sig_gen();
    }

    #[test]
    fn acvp_eddsa_sig_ver() {
        support::acvp::eddsa::run_sig_ver();
    }

    #[test]
    fn acvp_rsa_sig_ver() {
        support::acvp::rsa_sig::run_sig_ver();
    }

    #[test]
    fn acvp_rsa_sig_ver_186_4() {
        support::acvp::rsa_sig::run_sig_ver_186_4();
    }

    #[test]
    fn acvp_rsa_sig_gen_answers() {
        support::acvp::rsa_sig::run_sig_gen();
    }

    #[test]
    fn acvp_rsa_signature_primitive() {
        support::acvp::rsa_primitive::run_signature_primitive();
    }
}

/// HKDF, as SP 800-56Cr2's key-derivation step.
mod hkdf {
    use super::*;

    #[test]
    fn acvp_kda_hkdf() {
        support::acvp::kda_hkdf::run();
    }
}
