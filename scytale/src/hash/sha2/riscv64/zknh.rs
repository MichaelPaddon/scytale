//! SHA-2 with the RISC-V scalar cryptography extension Zknh.
//!
//! Zknh adds one instruction for each of the four sigma functions of
//! each family and nothing more: the rounds are still ordinary
//! integer arithmetic. So the portable round loop is reused with
//! those four functions swapped for the instructions, which is how
//! the extension is meant to be used.
//!
//! The vector backend beside this one does the whole round, and the
//! message schedule with it, so it is the better choice where there
//! is a vector unit; this is what a processor without one uses.

#![allow(unsafe_code)]

use super::super::engine::{Compress32, Compress64, Engine32, Engine64};
use super::super::portable::{
    Compress, Functions32, Functions64, compress256, compress512,
};
use super::super::variant;
use crate::arch::riscv64::{EXT_ZKNH, extensions};

/// SHA-224 with Zknh.
pub type Sha224 = Engine32<Zknh, variant::Sha224>;
/// SHA-256 with Zknh.
pub type Sha256 = Engine32<Zknh, variant::Sha256>;
/// SHA-384 with Zknh.
pub type Sha384 = Engine64<Zknh, variant::Sha384>;
/// SHA-512 with Zknh.
pub type Sha512 = Engine64<Zknh, variant::Sha512>;
/// SHA-512/224 with Zknh.
pub type Sha512_224 = Engine64<Zknh, variant::Sha512_224>;
/// SHA-512/256 with Zknh.
pub type Sha512_256 = Engine64<Zknh, variant::Sha512_256>;

/// Whether the Zknh instructions are available.
pub(crate) fn has_zknh() -> bool {
    present(extensions())
}

/// Whether `ext` reports the scalar sigma instructions.
fn present(ext: u64) -> bool {
    ext & EXT_ZKNH != 0
}

/// The sigma functions as Zknh instructions.
pub struct Zknh;

impl super::super::engine::Sealed for Zknh {}

/// Defines a one-instruction function.
macro_rules! sigma {
    ($name:ident, $instruction:literal, $word:ty) => {
        #[inline(always)]
        fn $name(x: $word) -> $word {
            let out: $word;
            // SAFETY: a register-to-register instruction; the caller
            // of the compression function confirmed Zknh.
            unsafe {
                core::arch::asm!(
                    ".option push",
                    concat!(".option arch, +zknh"),
                    concat!($instruction, " {out}, {x}"),
                    ".option pop",
                    x = in(reg) x,
                    out = lateout(reg) out,
                    options(pure, nomem, nostack, preserves_flags),
                );
            }
            out
        }
    };
}

impl Functions32 for Zknh {
    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        <Compress as Functions32>::ch(x, y, z)
    }
    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        <Compress as Functions32>::maj(x, y, z)
    }
    sigma!(big_sigma0, "sha256sum0", u32);
    sigma!(big_sigma1, "sha256sum1", u32);
    sigma!(small_sigma0, "sha256sig0", u32);
    sigma!(small_sigma1, "sha256sig1", u32);
}

impl Functions64 for Zknh {
    #[inline(always)]
    fn ch(x: u64, y: u64, z: u64) -> u64 {
        <Compress as Functions64>::ch(x, y, z)
    }
    #[inline(always)]
    fn maj(x: u64, y: u64, z: u64) -> u64 {
        <Compress as Functions64>::maj(x, y, z)
    }
    sigma!(big_sigma0, "sha512sum0", u64);
    sigma!(big_sigma1, "sha512sum1", u64);
    sigma!(small_sigma0, "sha512sig0", u64);
    sigma!(small_sigma1, "sha512sig1", u64);
}

impl Compress32 for Zknh {
    fn supported() -> bool {
        has_zknh()
    }

    unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        compress256::<Zknh>(state, blocks)
    }
}

impl Compress64 for Zknh {
    fn supported() -> bool {
        has_zknh()
    }

    unsafe fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
        compress512::<Zknh>(state, blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;
    use crate::hash::sha2::portable;
    use crate::hash::sha2::tests::{
        check_known_answers, check_matches_portable,
    };

    #[test]
    fn known_answers() {
        if has_zknh() {
            check_known_answers::<Sha224, Sha256, Sha384, Sha512>();
        }
    }

    #[test]
    fn matches_portable() {
        if has_zknh() {
            check_matches_portable::<Sha224, portable::Sha224>();
            check_matches_portable::<Sha256, portable::Sha256>();
            check_matches_portable::<Sha384, portable::Sha384>();
            check_matches_portable::<Sha512, portable::Sha512>();
        }
    }

    #[test]
    fn probes_agree_with_constructors() {
        assert_eq!(Sha256::try_new().is_ok(), has_zknh());
        assert_eq!(Sha512::try_new().is_ok(), has_zknh());
    }

    /// Zknh covers both families at once, and comes with the scalar
    /// set rather than with any vector one.
    #[test]
    fn the_scalar_sigmas_come_with_the_scalar_set() {
        use crate::arch::riscv64::profile;

        assert!(present(profile::ZKN));
        assert!(!present(profile::ZVKNG));
        assert!(!present(profile::RVA23));
    }
}
