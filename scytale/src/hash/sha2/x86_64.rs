//! SHA-256 with the SHA-NI instructions on x86-64.
//!
//! `sha256rnds2` does two rounds on a pair of registers holding the
//! state as `ABEF` and `CDGH`, and `sha256msg1` and `sha256msg2`
//! between them do the message schedule four words at a time. The
//! whole compression is written out here, sixty-four rounds unrolled,
//! because the register rotation between four-round groups is fixed
//! and a loop would spend its time moving registers around.
//!
//! There is no SHA-512 counterpart in common use, so SHA-384 and
//! SHA-512 stay portable on this architecture.

#![allow(unsafe_code)]

use core::arch::x86_64::__cpuid_count;

use super::engine::{Compress32, Engine32};
use super::portable::K256;
use super::variant;

/// SHA-224 with SHA-NI.
pub type Sha224 = Engine32<ShaNi, variant::Sha224>;
/// SHA-256 with SHA-NI.
pub type Sha256 = Engine32<ShaNi, variant::Sha256>;

/// Whether the processor reports SHA-NI (CPUID leaf 7, EBX bit 29).
/// Every such processor also has the SSSE3 and SSE4.1 shuffles the
/// code uses.
pub(crate) fn has_sha() -> bool {
    __cpuid_count(7, 0).ebx & (1 << 29) != 0
}

/// The compression function via SHA-NI.
pub struct ShaNi;

impl super::engine::Sealed for ShaNi {}

impl Compress32 for ShaNi {
    fn supported() -> bool {
        has_sha()
    }

    unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        if !blocks.is_empty() {
            compress(state, blocks.as_ptr().cast(), blocks.len());
        }
    }
}

/// Loads message words big-endian: reverses the bytes of each dword.
#[repr(align(16))]
struct Aligned([u8; 16]);
static BYTE_SWAP: Aligned =
    Aligned([3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]);

/// Four rounds from constant byte offset `$i`: adds the constants to
/// the four message words in `$m0`, runs two `sha256rnds2` on them,
/// and advances the schedule. `$m0` through `$m3` are the last
/// sixteen words, oldest first.
// Kept as written: one instruction per line.
#[rustfmt::skip]
macro_rules! rounds4 {
    ($i:literal, $m0:literal, $m1:literal, $m2:literal, $m3:literal) => {
        concat!(
            "movdqu xmm0, [{k} + ", $i, "]\n",
            "paddd xmm0, ", $m0, "\n",
            "sha256rnds2 xmm2, xmm1\n",
            "pshufd xmm0, xmm0, 0x0e\n",
            "sha256rnds2 xmm1, xmm2\n",
            rounds4!(@schedule $i, $m0, $m1, $m2, $m3),
        )
    };
    // Words 16 to 63 are made from the previous sixteen; each group
    // finishes the words the group after next will need.
    (@schedule $i:literal, $m0:literal, $m1:literal, $m2:literal,
     $m3:literal) => {
        concat!(
            rounds4!(@msg2 $i, $m0, $m1, $m3),
            rounds4!(@msg1 $i, $m0, $m3),
        )
    };
    (@msg2 $i:literal, $m0:literal, $m1:literal, $m3:literal) => {
        concat!(
            "movdqa xmm7, ", $m0, "\n",
            "palignr xmm7, ", $m3, ", 4\n",
            "paddd ", $m1, ", xmm7\n",
            "sha256msg2 ", $m1, ", ", $m0, "\n",
        )
    };
    (@msg1 $i:literal, $m0:literal, $m3:literal) => {
        concat!("sha256msg1 ", $m3, ", ", $m0, "\n")
    };
}

/// Loads four message words from byte offset `$i`, big-endian.
// Kept as written: one instruction per line.
#[rustfmt::skip]
macro_rules! load4 {
    ($i:literal, $m:literal) => {
        concat!(
            "movdqu ", $m, ", [{data} + ", $i, "]\n",
            "pshufb ", $m, ", xmm8\n",
        )
    };
}

/// Folds `count` blocks at `data` into `state`.
///
/// # Safety
/// Requires SHA-NI, SSSE3 and SSE4.1; `data` must point at `count`
/// whole blocks.
unsafe fn compress(state: &mut [u32; 8], data: *const u8, count: usize) {
    // State words a..h in memory become ABEF in xmm1 and CDGH in
    // xmm2, the layout the instructions want, and are put back at
    // the end.
    core::arch::asm!(
        "movdqu xmm1, [{state}]",
        "movdqu xmm2, [{state} + 16]",
        "movdqa xmm8, [{swap}]",
        "pshufd xmm1, xmm1, 0xb1",
        "pshufd xmm2, xmm2, 0x1b",
        "movdqa xmm7, xmm1",
        "palignr xmm1, xmm2, 8",
        "pblendw xmm2, xmm7, 0xf0",

        "2:",
        "movdqa xmm9, xmm1",
        "movdqa xmm10, xmm2",

        // Rounds 0 to 15: load, then round, then start the schedule.
        load4!(0, "xmm3"),
        "movdqu xmm0, [{k}]",
        "paddd xmm0, xmm3",
        "sha256rnds2 xmm2, xmm1",
        "pshufd xmm0, xmm0, 0x0e",
        "sha256rnds2 xmm1, xmm2",

        load4!(16, "xmm4"),
        "movdqu xmm0, [{k} + 16]",
        "paddd xmm0, xmm4",
        "sha256rnds2 xmm2, xmm1",
        "pshufd xmm0, xmm0, 0x0e",
        "sha256rnds2 xmm1, xmm2",
        "sha256msg1 xmm3, xmm4",

        load4!(32, "xmm5"),
        "movdqu xmm0, [{k} + 32]",
        "paddd xmm0, xmm5",
        "sha256rnds2 xmm2, xmm1",
        "pshufd xmm0, xmm0, 0x0e",
        "sha256rnds2 xmm1, xmm2",
        "sha256msg1 xmm4, xmm5",

        load4!(48, "xmm6"),
        rounds4!(48, "xmm6", "xmm3", "xmm4", "xmm5"),
        // Rounds 16 to 51: full schedule.
        rounds4!(64, "xmm3", "xmm4", "xmm5", "xmm6"),
        rounds4!(80, "xmm4", "xmm5", "xmm6", "xmm3"),
        rounds4!(96, "xmm5", "xmm6", "xmm3", "xmm4"),
        rounds4!(112, "xmm6", "xmm3", "xmm4", "xmm5"),
        rounds4!(128, "xmm3", "xmm4", "xmm5", "xmm6"),
        rounds4!(144, "xmm4", "xmm5", "xmm6", "xmm3"),
        rounds4!(160, "xmm5", "xmm6", "xmm3", "xmm4"),
        rounds4!(176, "xmm6", "xmm3", "xmm4", "xmm5"),
        rounds4!(192, "xmm3", "xmm4", "xmm5", "xmm6"),
        // Rounds 52 to 59: msg2 only, the last words to finish.
        "movdqu xmm0, [{k} + 208]",
        "paddd xmm0, xmm4",
        "sha256rnds2 xmm2, xmm1",
        "pshufd xmm0, xmm0, 0x0e",
        "sha256rnds2 xmm1, xmm2",
        "movdqa xmm7, xmm4",
        "palignr xmm7, xmm3, 4",
        "paddd xmm5, xmm7",
        "sha256msg2 xmm5, xmm4",

        "movdqu xmm0, [{k} + 224]",
        "paddd xmm0, xmm5",
        "sha256rnds2 xmm2, xmm1",
        "pshufd xmm0, xmm0, 0x0e",
        "sha256rnds2 xmm1, xmm2",
        "movdqa xmm7, xmm5",
        "palignr xmm7, xmm4, 4",
        "paddd xmm6, xmm7",
        "sha256msg2 xmm6, xmm5",

        // Rounds 60 to 63.
        "movdqu xmm0, [{k} + 240]",
        "paddd xmm0, xmm6",
        "sha256rnds2 xmm2, xmm1",
        "pshufd xmm0, xmm0, 0x0e",
        "sha256rnds2 xmm1, xmm2",

        "paddd xmm1, xmm9",
        "paddd xmm2, xmm10",
        "add {data}, 64",
        "dec {count}",
        "jnz 2b",

        "pshufd xmm1, xmm1, 0x1b",
        "pshufd xmm2, xmm2, 0xb1",
        "movdqa xmm7, xmm1",
        "pblendw xmm1, xmm2, 0xf0",
        "palignr xmm2, xmm7, 8",
        "movdqu [{state}], xmm1",
        "movdqu [{state} + 16], xmm2",
        state = in(reg) state.as_mut_ptr(),
        k = in(reg) K256.as_ptr(),
        swap = in(reg) BYTE_SWAP.0.as_ptr(),
        data = inout(reg) data => _,
        count = inout(reg) count => _,
        out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
        out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
        out("xmm8") _, out("xmm9") _, out("xmm10") _,
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
    use crate::Error;

    #[test]
    fn known_answers() {
        if !has_sha() {
            return;
        }
        type Sha384 = portable::Sha384;
        type Sha512 = portable::Sha512;
        check_known_answers::<Sha224, Sha256, Sha384, Sha512>();
    }

    #[test]
    fn matches_portable() {
        if !has_sha() {
            return;
        }
        check_matches_portable::<Sha224, portable::Sha224>();
        check_matches_portable::<Sha256, portable::Sha256>();
    }

    #[test]
    fn probe_agrees_with_constructor() {
        assert_eq!(Sha256::try_new().is_ok(), has_sha());
        if !has_sha() {
            assert_eq!(Sha256::try_new().err(), Some(Error::NotSupported));
        }
    }
}
