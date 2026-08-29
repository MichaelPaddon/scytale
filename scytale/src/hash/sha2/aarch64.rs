//! SHA-2 with the ARMv8 cryptographic extensions.
//!
//! `sha256h` and `sha256h2` do four rounds each on the state held as
//! two vectors, `ABCD` and `EFGH`, and `sha256su0` and `sha256su1`
//! make the next four schedule words. The SHA512 extension (FEAT_SHA512,
//! Armv8.2 onwards) has the same shape two rounds at a time, with the
//! state as four vectors of two words. The two are separate features
//! and are probed separately: a processor may well have SHA-256 and
//! not SHA-512.

#![allow(unsafe_code)]

use super::engine::{Compress32, Compress64, Engine32, Engine64};
use super::portable::{K256, K512};
use super::variant;

/// SHA-224 with the SHA2 instructions.
pub type Sha224 = Engine32<Armv8, variant::Sha224>;
/// SHA-256 with the SHA2 instructions.
pub type Sha256 = Engine32<Armv8, variant::Sha256>;
/// SHA-384 with the SHA512 instructions.
pub type Sha384 = Engine64<Armv8, variant::Sha384>;
/// SHA-512 with the SHA512 instructions.
pub type Sha512 = Engine64<Armv8, variant::Sha512>;
/// SHA-512/224 with the SHA512 instructions.
pub type Sha512_224 = Engine64<Armv8, variant::Sha512_224>;
/// SHA-512/256 with the SHA512 instructions.
pub type Sha512_256 = Engine64<Armv8, variant::Sha512_256>;

/// Whether the SHA-256 instructions are available.
pub(crate) fn has_sha256() -> bool {
    cfg!(target_feature = "sha2") || id_register_sha2() >= 1
}

/// Whether the SHA-512 instructions are available.
pub(crate) fn has_sha512() -> bool {
    cfg!(target_feature = "sha3") || id_register_sha2() >= 2
}

/// The SHA2 field of ID_AA64ISAR0_EL1, bits 15:12: 1 means SHA-256,
/// 2 means SHA-256 and SHA-512. Linux traps and emulates reads of the
/// ID registers from user space (since 4.11).
#[cfg(target_os = "linux")]
fn id_register_sha2() -> u64 {
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
    (isar0 >> 12) & 0xf
}

/// Without an operating system that exposes the ID registers there is
/// no safe way to ask, so only the compile-time feature counts.
#[cfg(not(target_os = "linux"))]
fn id_register_sha2() -> u64 {
    0
}

/// The compression functions via the ARMv8 instructions.
pub struct Armv8;

impl Compress32 for Armv8 {
    fn supported() -> bool {
        has_sha256()
    }

    unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        if !blocks.is_empty() {
            compress256(state, blocks.as_ptr().cast(), blocks.len());
        }
    }
}

impl Compress64 for Armv8 {
    fn supported() -> bool {
        has_sha512()
    }

    unsafe fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
        if !blocks.is_empty() {
            compress512(state, blocks.as_ptr().cast(), blocks.len());
        }
    }
}

/// Four SHA-256 rounds on the schedule words in `$w`, with constants
/// in `$k`; `$w` then becomes the words for sixteen rounds on, made
/// from the three vectors after it.
// Kept as written: one instruction per line.
#[rustfmt::skip]
macro_rules! rounds4 {
    ($w:literal, $k:literal, $w1:literal, $w2:literal, $w3:literal) => {
        concat!(
            rounds4!($w, $k),
            "sha256su0 ", $w, ".4s, ", $w1, ".4s\n",
            "sha256su1 ", $w, ".4s, ", $w2, ".4s, ", $w3, ".4s\n",
        )
    };
    ($w:literal, $k:literal) => {
        concat!(
            "add v8.4s, ", $w, ".4s, ", $k, ".4s\n",
            "mov v9.16b, v0.16b\n",
            "sha256h q0, q1, v8.4s\n",
            "sha256h2 q1, q9, v8.4s\n",
        )
    };
}

/// Folds `count` blocks at `data` into `state`.
///
/// # Safety
/// Requires the SHA-256 instructions; `data` must point at `count`
/// whole blocks.
#[target_feature(enable = "sha2")]
unsafe fn compress256(state: &mut [u32; 8], data: *const u8, count: usize) {
    // The constants stay in v16 to v31 for every block.
    core::arch::asm!(
        "ld1 {{v0.4s, v1.4s}}, [{state}]",
        "ld1 {{v16.4s, v17.4s, v18.4s, v19.4s}}, [{k}], #64",
        "ld1 {{v20.4s, v21.4s, v22.4s, v23.4s}}, [{k}], #64",
        "ld1 {{v24.4s, v25.4s, v26.4s, v27.4s}}, [{k}], #64",
        "ld1 {{v28.4s, v29.4s, v30.4s, v31.4s}}, [{k}]",
        "2:",
        "ld1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{data}], #64",
        "mov v2.16b, v0.16b",
        "mov v3.16b, v1.16b",
        "rev32 v4.16b, v4.16b",
        "rev32 v5.16b, v5.16b",
        "rev32 v6.16b, v6.16b",
        "rev32 v7.16b, v7.16b",
        rounds4!("v4", "v16", "v5", "v6", "v7"),
        rounds4!("v5", "v17", "v6", "v7", "v4"),
        rounds4!("v6", "v18", "v7", "v4", "v5"),
        rounds4!("v7", "v19", "v4", "v5", "v6"),
        rounds4!("v4", "v20", "v5", "v6", "v7"),
        rounds4!("v5", "v21", "v6", "v7", "v4"),
        rounds4!("v6", "v22", "v7", "v4", "v5"),
        rounds4!("v7", "v23", "v4", "v5", "v6"),
        rounds4!("v4", "v24", "v5", "v6", "v7"),
        rounds4!("v5", "v25", "v6", "v7", "v4"),
        rounds4!("v6", "v26", "v7", "v4", "v5"),
        rounds4!("v7", "v27", "v4", "v5", "v6"),
        rounds4!("v4", "v28"),
        rounds4!("v5", "v29"),
        rounds4!("v6", "v30"),
        rounds4!("v7", "v31"),
        "add v0.4s, v0.4s, v2.4s",
        "add v1.4s, v1.4s, v3.4s",
        "subs {count}, {count}, #1",
        "b.ne 2b",
        "st1 {{v0.4s, v1.4s}}, [{state}]",
        state = in(reg) state.as_mut_ptr(),
        k = inout(reg) K256.as_ptr() => _,
        data = inout(reg) data => _,
        count = inout(reg) count => _,
        out("v0") _, out("v1") _, out("v2") _, out("v3") _,
        out("v4") _, out("v5") _, out("v6") _, out("v7") _,
        out("v8") _, out("v9") _,
        out("v16") _, out("v17") _, out("v18") _, out("v19") _,
        out("v20") _, out("v21") _, out("v22") _, out("v23") _,
        out("v24") _, out("v25") _, out("v26") _, out("v27") _,
        out("v28") _, out("v29") _, out("v30") _, out("v31") _,
        options(nostack),
    );
}

/// Two SHA-512 rounds. The state is four vectors of two words each,
/// `(a, b)`, `(c, d)`, `(e, f)`, `(g, h)`, named `$ab` and so on, plus
/// a spare `$s`. After two rounds the new `(a, b)` is in `$s`, the new
/// `(e, f)` where `(g, h)` was, and the old `(a, b)` and `(e, f)` have
/// become `(c, d)` and `(g, h)`; callers rotate the names to match.
/// Registers are given by number, since the same one is named as `v`
/// in some instructions and `q` in others.
/// `$w` is the schedule pair these rounds use, and with `$w1`, `$w4`,
/// `$w5` and `$w7` (the pairs one, four, five and seven on from it)
/// it is then advanced sixteen words.
// Kept as written: one instruction per line.
#[rustfmt::skip]
macro_rules! rounds2 {
    ($ab:literal, $cd:literal, $ef:literal, $gh:literal, $s:literal,
     $w:literal, $w1:literal, $w4:literal, $w5:literal, $w7:literal) => {
        concat!(
            rounds2!($ab, $cd, $ef, $gh, $s, $w),
            "ext v5.16b, v", $w4, ".16b, v", $w5, ".16b, #8\n",
            "sha512su0 v", $w, ".2d, v", $w1, ".2d\n",
            "sha512su1 v", $w, ".2d, v", $w7, ".2d, v5.2d\n",
        )
    };
    ($ab:literal, $cd:literal, $ef:literal, $gh:literal, $s:literal,
     $w:literal) => {
        concat!(
            "ld1 {{v16.2d}}, [{kp}], #16\n",
            // (h + K + W, g + K' + W') go in with the first round's
            // in the high half.
            "add v5.2d, v", $w, ".2d, v16.2d\n",
            "ext v5.16b, v5.16b, v5.16b, #8\n",
            "add v", $s, ".2d, v5.2d, v", $gh, ".2d\n",
            // The rounds want (d, e) and (f, g), which straddle the
            // pairs the state is kept in.
            "ext v6.16b, v", $cd, ".16b, v", $ef, ".16b, #8\n",
            "ext v7.16b, v", $ef, ".16b, v", $gh, ".16b, #8\n",
            "sha512h q", $s, ", q7, v6.2d\n",
            "add v", $gh, ".2d, v", $cd, ".2d, v", $s, ".2d\n",
            "sha512h2 q", $s, ", q", $cd, ", v", $ab, ".2d\n",
        )
    };
}

/// Folds `count` blocks at `data` into `state`.
///
/// # Safety
/// Requires the SHA-512 instructions; `data` must point at `count`
/// whole blocks.
#[target_feature(enable = "sha3")]
unsafe fn compress512(state: &mut [u64; 8], data: *const u8, count: usize) {
    // The running state lives in v17 to v20 and is copied into v0 to
    // v3 for each block; the rounds leave the result scattered over
    // v0 to v4, which is why the copy is added back by name at the
    // end rather than in place.
    core::arch::asm!(
        "ld1 {{v17.2d, v18.2d, v19.2d, v20.2d}}, [{state}]",
        "2:",
        "ld1 {{v8.2d, v9.2d, v10.2d, v11.2d}}, [{data}], #64",
        "ld1 {{v12.2d, v13.2d, v14.2d, v15.2d}}, [{data}], #64",
        "mov {kp}, {k}",
        "mov v0.16b, v17.16b",
        "mov v1.16b, v18.16b",
        "mov v2.16b, v19.16b",
        "mov v3.16b, v20.16b",
        "rev64 v8.16b, v8.16b",
        "rev64 v9.16b, v9.16b",
        "rev64 v10.16b, v10.16b",
        "rev64 v11.16b, v11.16b",
        "rev64 v12.16b, v12.16b",
        "rev64 v13.16b, v13.16b",
        "rev64 v14.16b, v14.16b",
        "rev64 v15.16b, v15.16b",
        rounds2!(0, 1, 2, 3, 4, 8, 9, 12, 13, 15),
        rounds2!(4, 0, 3, 2, 1, 9, 10, 13, 14, 8),
        rounds2!(1, 4, 2, 3, 0, 10, 11, 14, 15, 9),
        rounds2!(0, 1, 3, 2, 4, 11, 12, 15, 8, 10),
        rounds2!(4, 0, 2, 3, 1, 12, 13, 8, 9, 11),
        rounds2!(1, 4, 3, 2, 0, 13, 14, 9, 10, 12),
        rounds2!(0, 1, 2, 3, 4, 14, 15, 10, 11, 13),
        rounds2!(4, 0, 3, 2, 1, 15, 8, 11, 12, 14),
        rounds2!(1, 4, 2, 3, 0, 8, 9, 12, 13, 15),
        rounds2!(0, 1, 3, 2, 4, 9, 10, 13, 14, 8),
        rounds2!(4, 0, 2, 3, 1, 10, 11, 14, 15, 9),
        rounds2!(1, 4, 3, 2, 0, 11, 12, 15, 8, 10),
        rounds2!(0, 1, 2, 3, 4, 12, 13, 8, 9, 11),
        rounds2!(4, 0, 3, 2, 1, 13, 14, 9, 10, 12),
        rounds2!(1, 4, 2, 3, 0, 14, 15, 10, 11, 13),
        rounds2!(0, 1, 3, 2, 4, 15, 8, 11, 12, 14),
        rounds2!(4, 0, 2, 3, 1, 8, 9, 12, 13, 15),
        rounds2!(1, 4, 3, 2, 0, 9, 10, 13, 14, 8),
        rounds2!(0, 1, 2, 3, 4, 10, 11, 14, 15, 9),
        rounds2!(4, 0, 3, 2, 1, 11, 12, 15, 8, 10),
        rounds2!(1, 4, 2, 3, 0, 12, 13, 8, 9, 11),
        rounds2!(0, 1, 3, 2, 4, 13, 14, 9, 10, 12),
        rounds2!(4, 0, 2, 3, 1, 14, 15, 10, 11, 13),
        rounds2!(1, 4, 3, 2, 0, 15, 8, 11, 12, 14),
        rounds2!(0, 1, 2, 3, 4, 8, 9, 12, 13, 15),
        rounds2!(4, 0, 3, 2, 1, 9, 10, 13, 14, 8),
        rounds2!(1, 4, 2, 3, 0, 10, 11, 14, 15, 9),
        rounds2!(0, 1, 3, 2, 4, 11, 12, 15, 8, 10),
        rounds2!(4, 0, 2, 3, 1, 12, 13, 8, 9, 11),
        rounds2!(1, 4, 3, 2, 0, 13, 14, 9, 10, 12),
        rounds2!(0, 1, 2, 3, 4, 14, 15, 10, 11, 13),
        rounds2!(4, 0, 3, 2, 1, 15, 8, 11, 12, 14),
        rounds2!(1, 4, 2, 3, 0, 8),
        rounds2!(0, 1, 3, 2, 4, 9),
        rounds2!(4, 0, 2, 3, 1, 10),
        rounds2!(1, 4, 3, 2, 0, 11),
        rounds2!(0, 1, 2, 3, 4, 12),
        rounds2!(4, 0, 3, 2, 1, 13),
        rounds2!(1, 4, 2, 3, 0, 14),
        rounds2!(0, 1, 3, 2, 4, 15),
        // After forty steps (a, b) is in v4, (c, d) in v0, (e, f) in
        // v2 and (g, h) in v3.
        "add v17.2d, v17.2d, v4.2d",
        "add v18.2d, v18.2d, v0.2d",
        "add v19.2d, v19.2d, v2.2d",
        "add v20.2d, v20.2d, v3.2d",
        "subs {count}, {count}, #1",
        "b.ne 2b",
        "st1 {{v17.2d, v18.2d, v19.2d, v20.2d}}, [{state}]",
        state = in(reg) state.as_mut_ptr(),
        k = in(reg) K512.as_ptr(),
        kp = out(reg) _,
        data = inout(reg) data => _,
        count = inout(reg) count => _,
        out("v0") _, out("v1") _, out("v2") _, out("v3") _,
        out("v4") _, out("v5") _, out("v6") _, out("v7") _,
        out("v8") _, out("v9") _, out("v10") _, out("v11") _,
        out("v12") _, out("v13") _, out("v14") _, out("v15") _,
        out("v16") _, out("v17") _, out("v18") _, out("v19") _,
        out("v20") _,
        options(nostack),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::portable;
    use crate::hash::sha2::tests::{
        check_known_answers, check_matches_portable,
    };
    use crate::hash::Hash;

    #[test]
    fn known_answers() {
        if has_sha256() {
            check_known_answers::<
                Sha224,
                Sha256,
                portable::Sha384,
                portable::Sha512,
            >();
        }
        if has_sha512() {
            check_known_answers::<
                portable::Sha224,
                portable::Sha256,
                Sha384,
                Sha512,
            >();
        }
    }

    #[test]
    fn matches_portable() {
        if has_sha256() {
            check_matches_portable::<Sha224, portable::Sha224>();
            check_matches_portable::<Sha256, portable::Sha256>();
        }
        if has_sha512() {
            check_matches_portable::<Sha384, portable::Sha384>();
            check_matches_portable::<Sha512, portable::Sha512>();
        }
    }

    #[test]
    fn probes_agree_with_constructors() {
        assert_eq!(Sha256::try_new().is_ok(), has_sha256());
        assert_eq!(Sha512::try_new().is_ok(), has_sha512());
    }
}
