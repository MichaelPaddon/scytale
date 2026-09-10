//! SHA-2 with the RISC-V vector cryptography extension (Zvknh).
//!
//! Unlike the scalar extension beside this one, which supplies the
//! sigma functions and leaves the rest of the round to be written
//! out, this one has the round itself: `vsha2cl` and `vsha2ch` each
//! perform two rounds of compression, and `vsha2ms` produces four
//! words of the message schedule. Sixty-four rounds of SHA-256 are
//! thirty-two of those instructions, and the schedule is another
//! twelve, where the scalar version needs some fifteen instructions a
//! round.
//!
//! Zvknha has the SHA-256 instructions and Zvknhb both families, so
//! SHA-256 accepts either and SHA-512 only the second.
//!
//! # The layout
//!
//! Each instruction works on a group of four elements, and the
//! grouping is not the obvious one. The eight words of state are
//! split between two registers as `{a, b, e, f}` and `{c, d, g, h}`,
//! most significant element first, so the words go into memory in the
//! order `f, e, b, a` and `h, g, d, c`; [`pack`] and [`unpack`] do
//! that and nothing else. The compression instruction takes the
//! first group as `vs2` and the second as `vd`, and leaves the next
//! `{a, b, e, f}` in `vd` -- which means the two registers simply
//! change places between one instruction and the next, so a pair of
//! them returns the state to the registers it started in.
//!
//! The message schedule is held as four registers of four words, and
//! `vsha2ms` wants eleven of the last sixteen words in an arrangement
//! that is three quarters of one register and the first word of
//! another. A mask holding only its lowest bit, and `vmerge`, put
//! that together in one instruction.
//!
//! The first sixteen words come from the message in big-endian byte
//! order and the instructions read little-endian words, so `vrev8.v`
//! turns each one into its integer. That belongs to Zvkb, which Zvkn
//! includes along with these instructions. Nothing else needs
//! reversing: the state stays as integers from beginning to end.
//!
//! # Width
//!
//! SHA-256 holds a group of four 32-bit words in 128 bits, which one
//! register covers, and SHA-512 needs 256, which is a pair of them.
//! So the SHA-512 code is the same instructions at `LMUL=2`, and the
//! register numbers are even throughout to suit both.

#![allow(unsafe_code)]

use super::super::engine::{Compress32, Compress64, Engine32, Engine64};
use super::super::portable::{K256, K512};
use super::super::variant;
use crate::arch::riscv64::{
    EXT_ZVBB, EXT_ZVKB, EXT_ZVKNHA, EXT_ZVKNHB, IMA_V, extensions, vector_bytes,
};

/// SHA-224 with Zvknh.
pub type Sha224 = Engine32<Zvknh, variant::Sha224>;
/// SHA-256 with Zvknh.
pub type Sha256 = Engine32<Zvknh, variant::Sha256>;
/// SHA-384 with Zvknh.
pub type Sha384 = Engine64<Zvknh, variant::Sha384>;
/// SHA-512 with Zvknh.
pub type Sha512 = Engine64<Zvknh, variant::Sha512>;
/// SHA-512/224 with Zvknh.
pub type Sha512_224 = Engine64<Zvknh, variant::Sha512_224>;
/// SHA-512/256 with Zvknh.
pub type Sha512_256 = Engine64<Zvknh, variant::Sha512_256>;

/// The vector SHA-2 instructions.
pub struct Zvknh;

impl super::super::engine::Sealed for Zvknh {}

/// Whether `ext` reports a vector unit, a byte reverse and any of
/// `wanted`, on a processor whose vector registers are `bytes` wide.
fn present(ext: u64, bytes: usize, wanted: u64) -> bool {
    ext & IMA_V != 0
        && ext & wanted != 0
        && ext & (EXT_ZVBB | EXT_ZVKB) != 0
        && bytes >= 16
}

/// Whether the SHA-256 instructions are available. Zvknha has them
/// and Zvknhb has them as well as SHA-512's.
pub(crate) fn has_sha256() -> bool {
    let ext = extensions();
    present(ext, vector_bytes(ext), EXT_ZVKNHA | EXT_ZVKNHB)
}

/// Whether the SHA-512 instructions are available; only Zvknhb has
/// them.
pub(crate) fn has_sha512() -> bool {
    let ext = extensions();
    present(ext, vector_bytes(ext), EXT_ZVKNHB)
}

/// Splits the state into the two element groups the instructions
/// want: `{a, b, e, f}` and `{c, d, g, h}`, least significant element
/// first.
fn pack<T: Copy>(state: &[T; 8]) -> ([T; 4], [T; 4]) {
    (
        [state[5], state[4], state[1], state[0]],
        [state[7], state[6], state[3], state[2]],
    )
}

/// Puts the two element groups back, undoing [`pack`].
fn unpack<T: Copy>(state: &mut [T; 8], abef: &[T; 4], cdgh: &[T; 4]) {
    state[0] = abef[3];
    state[1] = abef[2];
    state[4] = abef[1];
    state[5] = abef[0];
    state[2] = cdgh[3];
    state[3] = cdgh[2];
    state[6] = cdgh[1];
    state[7] = cdgh[0];
}

/// Loads four message words into register `$r` and turns each into an
/// integer.
#[rustfmt::skip]
macro_rules! message {
    ($le:literal, $step:literal, $r:literal) => {
        concat!(
            $le, " v", $r, ", ({data})\n",
            "addi {data}, {data}, ", $step, "\n",
            "vrev8.v v", $r, ", v", $r, "\n",
        )
    };
}

/// Four rounds: the schedule words in register `$cur` added to their
/// round constants, then two instructions of two rounds each.
#[rustfmt::skip]
macro_rules! rounds {
    ($le:literal, $step:literal, $cur:literal) => {
        concat!(
            $le, " v18, ({k})\n",
            "addi {k}, {k}, ", $step, "\n",
            "vadd.vv v18, v18, v", $cur, "\n",
            "vsha2cl.vv v12, v10, v18\n",
            "vsha2ch.vv v10, v12, v18\n",
        )
    };
}

/// The same four rounds, and then the next four schedule words in
/// place of the four just used. `vsha2ms` wants the eleven words it
/// needs as three quarters of `$next2` and the first word of `$next`.
#[rustfmt::skip]
macro_rules! rounds_and_schedule {
    ($le:literal, $step:literal, $cur:literal, $next:literal,
     $next2:literal, $next3:literal) => {
        concat!(
            $le, " v18, ({k})\n",
            "addi {k}, {k}, ", $step, "\n",
            "vadd.vv v18, v18, v", $cur, "\n",
            "vsha2cl.vv v12, v10, v18\n",
            "vsha2ch.vv v10, v12, v18\n",
            "vmerge.vvm v20, v", $next2, ", v", $next, ", v0\n",
            "vsha2ms.vv v", $cur, ", v20, v", $next3, "\n",
        )
    };
}

/// Folds `blocks` whole blocks of SHA-256 into the state, which
/// arrives and leaves split as [`pack`] leaves it.
///
/// # Safety
/// Requires the vector extension, Zvknha or Zvknhb, and a byte
/// reverse, with `VLEN >= 128`; `data` must point at `blocks` whole
/// blocks and `blocks >= 1`.
unsafe fn rounds256(
    abef: &mut [u32; 4],
    cdgh: &mut [u32; 4],
    data: *const u8,
    blocks: usize,
) {
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v, +zvknhb, +zvkb",
            "vsetivli zero, 4, e32, m1, ta, ma",
            // The mask for vmerge: its lowest bit and nothing else,
            // which is the first element of four.
            "vmv.v.i v0, 1",
            "vle32.v v10, ({abef})",
            "vle32.v v12, ({cdgh})",
            "1:",
            message!("vle32.v", "16", "2"),
            message!("vle32.v", "16", "4"),
            message!("vle32.v", "16", "6"),
            message!("vle32.v", "16", "8"),
            // Davies-Meyer: the block's own output is added to the
            // state it started from.
            "vmv.v.v v14, v10",
            "vmv.v.v v16, v12",
            "mv {k}, {kt}",
            rounds_and_schedule!("vle32.v", "16", "2", "4", "6", "8"),
            rounds_and_schedule!("vle32.v", "16", "4", "6", "8", "2"),
            rounds_and_schedule!("vle32.v", "16", "6", "8", "2", "4"),
            rounds_and_schedule!("vle32.v", "16", "8", "2", "4", "6"),
            rounds_and_schedule!("vle32.v", "16", "2", "4", "6", "8"),
            rounds_and_schedule!("vle32.v", "16", "4", "6", "8", "2"),
            rounds_and_schedule!("vle32.v", "16", "6", "8", "2", "4"),
            rounds_and_schedule!("vle32.v", "16", "8", "2", "4", "6"),
            rounds_and_schedule!("vle32.v", "16", "2", "4", "6", "8"),
            rounds_and_schedule!("vle32.v", "16", "4", "6", "8", "2"),
            rounds_and_schedule!("vle32.v", "16", "6", "8", "2", "4"),
            rounds_and_schedule!("vle32.v", "16", "8", "2", "4", "6"),
            // The last four groups of rounds need no more schedule.
            rounds!("vle32.v", "16", "2"),
            rounds!("vle32.v", "16", "4"),
            rounds!("vle32.v", "16", "6"),
            rounds!("vle32.v", "16", "8"),
            "vadd.vv v10, v10, v14",
            "vadd.vv v12, v12, v16",
            "addi {n}, {n}, -1",
            "bnez {n}, 1b",
            "vse32.v v10, ({abef})",
            "vse32.v v12, ({cdgh})",
            ".option pop",
            abef = in(reg) abef.as_mut_ptr(),
            cdgh = in(reg) cdgh.as_mut_ptr(),
            kt = in(reg) K256.as_ptr(),
            data = inout(reg) data => _,
            n = inout(reg) blocks => _,
            k = out(reg) _,
            out("v0") _, out("v2") _, out("v4") _, out("v6") _,
            out("v8") _, out("v10") _, out("v12") _, out("v14") _,
            out("v16") _, out("v18") _, out("v20") _,
            options(nostack),
        );
    }
}

/// Folds `blocks` whole blocks of SHA-512 into the state.
///
/// The same instructions as [`rounds256`] on twice the width, so each
/// group of four words is a pair of registers and there are twenty
/// groups of rounds rather than sixteen.
///
/// # Safety
/// Requires the vector extension, Zvknhb and a byte reverse, with
/// `VLEN >= 128`; `data` must point at `blocks` whole blocks and
/// `blocks >= 1`.
unsafe fn rounds512(
    abef: &mut [u64; 4],
    cdgh: &mut [u64; 4],
    data: *const u8,
    blocks: usize,
) {
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v, +zvknhb, +zvkb",
            "vsetivli zero, 4, e64, m2, ta, ma",
            "vmv.v.i v0, 1",
            "vle64.v v10, ({abef})",
            "vle64.v v12, ({cdgh})",
            "1:",
            message!("vle64.v", "32", "2"),
            message!("vle64.v", "32", "4"),
            message!("vle64.v", "32", "6"),
            message!("vle64.v", "32", "8"),
            "vmv.v.v v14, v10",
            "vmv.v.v v16, v12",
            "mv {k}, {kt}",
            rounds_and_schedule!("vle64.v", "32", "2", "4", "6", "8"),
            rounds_and_schedule!("vle64.v", "32", "4", "6", "8", "2"),
            rounds_and_schedule!("vle64.v", "32", "6", "8", "2", "4"),
            rounds_and_schedule!("vle64.v", "32", "8", "2", "4", "6"),
            rounds_and_schedule!("vle64.v", "32", "2", "4", "6", "8"),
            rounds_and_schedule!("vle64.v", "32", "4", "6", "8", "2"),
            rounds_and_schedule!("vle64.v", "32", "6", "8", "2", "4"),
            rounds_and_schedule!("vle64.v", "32", "8", "2", "4", "6"),
            rounds_and_schedule!("vle64.v", "32", "2", "4", "6", "8"),
            rounds_and_schedule!("vle64.v", "32", "4", "6", "8", "2"),
            rounds_and_schedule!("vle64.v", "32", "6", "8", "2", "4"),
            rounds_and_schedule!("vle64.v", "32", "8", "2", "4", "6"),
            rounds_and_schedule!("vle64.v", "32", "2", "4", "6", "8"),
            rounds_and_schedule!("vle64.v", "32", "4", "6", "8", "2"),
            rounds_and_schedule!("vle64.v", "32", "6", "8", "2", "4"),
            rounds_and_schedule!("vle64.v", "32", "8", "2", "4", "6"),
            rounds!("vle64.v", "32", "2"),
            rounds!("vle64.v", "32", "4"),
            rounds!("vle64.v", "32", "6"),
            rounds!("vle64.v", "32", "8"),
            "vadd.vv v10, v10, v14",
            "vadd.vv v12, v12, v16",
            "addi {n}, {n}, -1",
            "bnez {n}, 1b",
            "vse64.v v10, ({abef})",
            "vse64.v v12, ({cdgh})",
            ".option pop",
            abef = in(reg) abef.as_mut_ptr(),
            cdgh = in(reg) cdgh.as_mut_ptr(),
            kt = in(reg) K512.as_ptr(),
            data = inout(reg) data => _,
            n = inout(reg) blocks => _,
            k = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _,
            options(nostack),
        );
    }
}

impl Compress32 for Zvknh {
    fn supported() -> bool {
        has_sha256()
    }

    unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        unsafe {
            if blocks.is_empty() {
                return;
            }
            let (mut abef, mut cdgh) = pack(state);
            rounds256(
                &mut abef,
                &mut cdgh,
                blocks.as_flattened().as_ptr(),
                blocks.len(),
            );
            unpack(state, &abef, &cdgh);
        }
    }
}

impl Compress64 for Zvknh {
    fn supported() -> bool {
        has_sha512()
    }

    unsafe fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
        unsafe {
            if blocks.is_empty() {
                return;
            }
            let (mut abef, mut cdgh) = pack(state);
            rounds512(
                &mut abef,
                &mut cdgh,
                blocks.as_flattened().as_ptr(),
                blocks.len(),
            );
            unpack(state, &abef, &cdgh);
        }
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
        if has_sha256() && has_sha512() {
            check_known_answers::<Sha224, Sha256, Sha384, Sha512>();
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
            check_matches_portable::<Sha512_224, portable::Sha512_224>();
            check_matches_portable::<Sha512_256, portable::Sha512_256>();
        }
    }

    #[test]
    fn probes_agree_with_constructors() {
        assert_eq!(Sha256::try_new().is_ok(), has_sha256());
        assert_eq!(Sha512::try_new().is_ok(), has_sha512());
    }

    /// Zvknha is SHA-256 alone and Zvknhb is both families, so a
    /// processor with the first must be offered one and not the
    /// other. Zvkn includes Zvknhb, so real vector hardware has both.
    #[test]
    fn the_narrow_extension_offers_only_sha256() {
        use crate::arch::riscv64::profile;

        let narrow = IMA_V | EXT_ZVKB | EXT_ZVKNHA;
        assert!(present(narrow, 16, EXT_ZVKNHA | EXT_ZVKNHB));
        assert!(!present(narrow, 16, EXT_ZVKNHB));

        for wanted in [EXT_ZVKNHA | EXT_ZVKNHB, EXT_ZVKNHB] {
            assert!(present(profile::ZVKN, 16, wanted));
            // No byte reverse to put the message words the right way
            // round, no vector unit, or registers too narrow.
            assert!(!present(IMA_V | EXT_ZVKNHB, 16, wanted));
            assert!(!present(profile::ZVKN & !IMA_V, 16, wanted));
            assert!(!present(profile::ZVKN, 8, wanted));
            assert!(!present(profile::ZKN, 0, wanted));
        }
    }

    /// The two element groups have to survive the round trip, or the
    /// state would be scrambled between blocks.
    #[test]
    fn packing_is_reversible() {
        let state: [u32; 8] = core::array::from_fn(|i| i as u32 + 1);
        let (abef, cdgh) = pack(&state);
        assert_eq!(abef, [6, 5, 2, 1]);
        assert_eq!(cdgh, [8, 7, 4, 3]);
        let mut back = [0u32; 8];
        unpack(&mut back, &abef, &cdgh);
        assert_eq!(back, state);
    }
}
