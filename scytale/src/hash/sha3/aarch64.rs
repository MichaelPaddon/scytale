//! Keccak-f\[1600\] with the ARMv8.2 SHA3 instructions.
//!
//! The extension adds four instructions that are the steps of a
//! round: `eor3` for the column parities of theta, `rax1` for the
//! rotate-and-xor that finishes it, `xar` for the rotation of rho
//! combined with the xor of theta, and `bcax` for chi. With the
//! twenty-five lanes held in v0 to v24 a round is straight-line code
//! and the state never touches memory between rounds. The upper half
//! of each register carries junk that costs nothing and is never
//! stored.

#![allow(unsafe_code)]

use super::engine::{Permutation, Sponge, LANES};
use super::portable::ROUND_CONSTANTS;
use super::variant;

/// SHA3-224 with the SHA3 instructions.
pub type Sha3_224 = Sponge<Armv8, variant::Sha3_224>;
/// SHA3-256 with the SHA3 instructions.
pub type Sha3_256 = Sponge<Armv8, variant::Sha3_256>;
/// SHA3-384 with the SHA3 instructions.
pub type Sha3_384 = Sponge<Armv8, variant::Sha3_384>;
/// SHA3-512 with the SHA3 instructions.
pub type Sha3_512 = Sponge<Armv8, variant::Sha3_512>;
/// SHAKE128 with the SHA3 instructions.
pub type Shake128 = Sponge<Armv8, variant::Shake128>;
/// SHAKE256 with the SHA3 instructions.
pub type Shake256 = Sponge<Armv8, variant::Shake256>;

/// Whether the SHA3 instructions are available.
pub(crate) fn has_sha3() -> bool {
    cfg!(target_feature = "sha3") || id_register_reports_sha3()
}

/// The SHA3 field of ID_AA64ISAR0_EL1, bits 35:32, is nonzero when
/// the instructions are implemented. Linux traps and emulates reads
/// of the ID registers from user space (since 4.11).
#[cfg(target_os = "linux")]
fn id_register_reports_sha3() -> bool {
    let isar0: u64;
    // SAFETY: reads a register the kernel exposes to user space; no
    // memory is touched.
    unsafe {
        core::arch::asm!(
            "mrs {}, ID_AA64ISAR0_EL1",
            out(reg) isar0,
            options(nomem, nostack, preserves_flags),
        );
    }
    (isar0 >> 32) & 0xf != 0
}

/// Without an operating system that exposes the ID registers there is
/// no safe way to ask, so only the compile-time feature counts.
#[cfg(not(target_os = "linux"))]
fn id_register_reports_sha3() -> bool {
    false
}

/// The permutation via the SHA3 instructions.
pub struct Armv8;

impl super::engine::Sealed for Armv8 {}

impl Permutation for Armv8 {
    fn supported() -> bool {
        has_sha3()
    }

    unsafe fn permute(state: &mut [u64; LANES]) {
        keccak_f1600(state.as_mut_ptr())
    }
}

/// Applies Keccak-f\[1600\] to the twenty-five lanes at `state`.
///
/// Lane `x + 5y` lives in `v(x + 5y)`. Theta leaves the five column
/// xors D[x] in v30, v31, v26, v27 and v28; rho and pi then follow
/// the single 24-lane cycle of pi backwards, each lane taking its
/// predecessor xored with its D and rotated, with v25 holding the
/// lane the cycle starts from. Chi keeps a row's first two lanes in
/// v25 and v29 while the row is overwritten.
///
/// # Safety
/// Requires the SHA3 instructions; `state` must point at 25 lanes.
#[target_feature(enable = "sha3")]
#[rustfmt::skip]
unsafe fn keccak_f1600(state: *mut u64) {
    core::arch::asm!(
        "ld1 {{v0.1d, v1.1d, v2.1d, v3.1d}}, [{p}], #32",
        "ld1 {{v4.1d, v5.1d, v6.1d, v7.1d}}, [{p}], #32",
        "ld1 {{v8.1d, v9.1d, v10.1d, v11.1d}}, [{p}], #32",
        "ld1 {{v12.1d, v13.1d, v14.1d, v15.1d}}, [{p}], #32",
        "ld1 {{v16.1d, v17.1d, v18.1d, v19.1d}}, [{p}], #32",
        "ld1 {{v20.1d, v21.1d, v22.1d, v23.1d}}, [{p}], #32",
        "ld1 {{v24.1d}}, [{p}]",
        "2:",
        "eor3 v25.16b, v0.16b, v5.16b, v10.16b",
        "eor3 v25.16b, v25.16b, v15.16b, v20.16b",
        "eor3 v26.16b, v1.16b, v6.16b, v11.16b",
        "eor3 v26.16b, v26.16b, v16.16b, v21.16b",
        "eor3 v27.16b, v2.16b, v7.16b, v12.16b",
        "eor3 v27.16b, v27.16b, v17.16b, v22.16b",
        "eor3 v28.16b, v3.16b, v8.16b, v13.16b",
        "eor3 v28.16b, v28.16b, v18.16b, v23.16b",
        "eor3 v29.16b, v4.16b, v9.16b, v14.16b",
        "eor3 v29.16b, v29.16b, v19.16b, v24.16b",
        "rax1 v30.2d, v29.2d, v26.2d",
        "rax1 v31.2d, v25.2d, v27.2d",
        "rax1 v26.2d, v26.2d, v28.2d",
        "rax1 v27.2d, v27.2d, v29.2d",
        "rax1 v28.2d, v28.2d, v25.2d",
        "eor v0.16b, v0.16b, v30.16b",
        "mov v25.16b, v1.16b",
        "xar v1.2d, v6.2d, v31.2d, #20",
        "xar v6.2d, v9.2d, v28.2d, #44",
        "xar v9.2d, v22.2d, v26.2d, #3",
        "xar v22.2d, v14.2d, v28.2d, #25",
        "xar v14.2d, v20.2d, v30.2d, #46",
        "xar v20.2d, v2.2d, v26.2d, #2",
        "xar v2.2d, v12.2d, v26.2d, #21",
        "xar v12.2d, v13.2d, v27.2d, #39",
        "xar v13.2d, v19.2d, v28.2d, #56",
        "xar v19.2d, v23.2d, v27.2d, #8",
        "xar v23.2d, v15.2d, v30.2d, #23",
        "xar v15.2d, v4.2d, v28.2d, #37",
        "xar v4.2d, v24.2d, v28.2d, #50",
        "xar v24.2d, v21.2d, v31.2d, #62",
        "xar v21.2d, v8.2d, v27.2d, #9",
        "xar v8.2d, v16.2d, v31.2d, #19",
        "xar v16.2d, v5.2d, v30.2d, #28",
        "xar v5.2d, v3.2d, v27.2d, #36",
        "xar v3.2d, v18.2d, v27.2d, #43",
        "xar v18.2d, v17.2d, v26.2d, #49",
        "xar v17.2d, v11.2d, v31.2d, #54",
        "xar v11.2d, v7.2d, v26.2d, #58",
        "xar v7.2d, v10.2d, v30.2d, #61",
        "xar v10.2d, v25.2d, v31.2d, #63",
        "mov v25.16b, v0.16b",
        "mov v29.16b, v1.16b",
        "bcax v0.16b, v0.16b, v2.16b, v1.16b",
        "bcax v1.16b, v1.16b, v3.16b, v2.16b",
        "bcax v2.16b, v2.16b, v4.16b, v3.16b",
        "bcax v3.16b, v3.16b, v25.16b, v4.16b",
        "bcax v4.16b, v4.16b, v29.16b, v25.16b",
        "mov v25.16b, v5.16b",
        "mov v29.16b, v6.16b",
        "bcax v5.16b, v5.16b, v7.16b, v6.16b",
        "bcax v6.16b, v6.16b, v8.16b, v7.16b",
        "bcax v7.16b, v7.16b, v9.16b, v8.16b",
        "bcax v8.16b, v8.16b, v25.16b, v9.16b",
        "bcax v9.16b, v9.16b, v29.16b, v25.16b",
        "mov v25.16b, v10.16b",
        "mov v29.16b, v11.16b",
        "bcax v10.16b, v10.16b, v12.16b, v11.16b",
        "bcax v11.16b, v11.16b, v13.16b, v12.16b",
        "bcax v12.16b, v12.16b, v14.16b, v13.16b",
        "bcax v13.16b, v13.16b, v25.16b, v14.16b",
        "bcax v14.16b, v14.16b, v29.16b, v25.16b",
        "mov v25.16b, v15.16b",
        "mov v29.16b, v16.16b",
        "bcax v15.16b, v15.16b, v17.16b, v16.16b",
        "bcax v16.16b, v16.16b, v18.16b, v17.16b",
        "bcax v17.16b, v17.16b, v19.16b, v18.16b",
        "bcax v18.16b, v18.16b, v25.16b, v19.16b",
        "bcax v19.16b, v19.16b, v29.16b, v25.16b",
        "mov v25.16b, v20.16b",
        "mov v29.16b, v21.16b",
        "bcax v20.16b, v20.16b, v22.16b, v21.16b",
        "bcax v21.16b, v21.16b, v23.16b, v22.16b",
        "bcax v22.16b, v22.16b, v24.16b, v23.16b",
        "bcax v23.16b, v23.16b, v25.16b, v24.16b",
        "bcax v24.16b, v24.16b, v29.16b, v25.16b",
        "ld1r {{v29.2d}}, [{rc}], #8",
        "eor v0.16b, v0.16b, v29.16b",
        "subs {n}, {n}, #1",
        "b.ne 2b",
        "st1 {{v0.1d, v1.1d, v2.1d, v3.1d}}, [{q}], #32",
        "st1 {{v4.1d, v5.1d, v6.1d, v7.1d}}, [{q}], #32",
        "st1 {{v8.1d, v9.1d, v10.1d, v11.1d}}, [{q}], #32",
        "st1 {{v12.1d, v13.1d, v14.1d, v15.1d}}, [{q}], #32",
        "st1 {{v16.1d, v17.1d, v18.1d, v19.1d}}, [{q}], #32",
        "st1 {{v20.1d, v21.1d, v22.1d, v23.1d}}, [{q}], #32",
        "st1 {{v24.1d}}, [{q}]",
        p = inout(reg) state => _,
        q = inout(reg) state => _,
        rc = inout(reg) ROUND_CONSTANTS.as_ptr() => _,
        n = inout(reg) ROUND_CONSTANTS.len() => _,
        out("v0") _,
        out("v1") _,
        out("v2") _,
        out("v3") _,
        out("v4") _,
        out("v5") _,
        out("v6") _,
        out("v7") _,
        out("v8") _,
        out("v9") _,
        out("v10") _,
        out("v11") _,
        out("v12") _,
        out("v13") _,
        out("v14") _,
        out("v15") _,
        out("v16") _,
        out("v17") _,
        out("v18") _,
        out("v19") _,
        out("v20") _,
        out("v21") _,
        out("v22") _,
        out("v23") _,
        out("v24") _,
        out("v25") _,
        out("v26") _,
        out("v27") _,
        out("v28") _,
        out("v29") _,
        out("v30") _,
        out("v31") _,
        options(nostack),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha3::portable::{self, keccak_f1600 as reference};
    use crate::hash::sha3::tests::{
        check_known_answers, check_matches_portable,
    };
    use crate::hash::Hash;

    #[test]
    fn known_answers() {
        if has_sha3() {
            check_known_answers::<
                Sha3_224,
                Sha3_256,
                Sha3_384,
                Sha3_512,
                Shake128,
                Shake256,
            >();
        }
    }

    #[test]
    fn matches_portable() {
        if has_sha3() {
            check_matches_portable::<
                Sha3_256,
                portable::Sha3_256,
                Shake128,
                portable::Shake128,
            >();
        }
    }

    /// The permutation alone, on states that are not all zeros.
    #[test]
    fn permutes_as_the_portable_code() {
        if !has_sha3() {
            return;
        }
        let mut seed = 0x9e3779b97f4a7c15u64;
        for _ in 0..8 {
            let mut state = [0u64; LANES];
            for lane in state.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *lane = seed;
            }
            let mut expected = state;
            reference(&mut expected);
            // SAFETY: `has_sha3` was just checked.
            unsafe { Armv8::permute(&mut state) };
            assert_eq!(state, expected);
        }
    }

    #[test]
    fn probes_agree_with_constructors() {
        assert_eq!(Sha3_256::try_new().is_ok(), has_sha3());
    }
}
