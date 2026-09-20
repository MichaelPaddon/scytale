//! SHA-1 with the ARMv8 cryptographic extensions.
//!
//! `sha1c`, `sha1p` and `sha1m` each do four rounds on the state held
//! as `ABCD` in one vector, taking `E` in a scalar register with the
//! four schedule words already summed with the round constant;
//! `sha1h` is the rotation of `A` that becomes the next group's `E`,
//! and `sha1su0` and `sha1su1` make the next four schedule words. The
//! whole compression is written out, twenty groups of four rounds, as
//! SHA-256's is in [`sha2::aarch64`](crate::hash::sha2::aarch64).
//!
//! # How the groups thread
//!
//! Each group needs `E` rotated from the `A` of the group before it,
//! and the instruction that makes it reads the state the round
//! instruction is about to overwrite, so `sha1h` comes first and
//! writes a register the round does not touch. Two such registers
//! alternate, one holding the `E` this group uses while the other
//! takes the one the next group will. The sums of schedule and
//! constant alternate the same way and are computed a group ahead, so
//! nothing in a round waits on an addition.

#![allow(unsafe_code)]

use crate::hash::sha2::aarch64::has_sha1;

/// The four round constants, one for each twenty rounds. Read one at
/// a time into all four lanes.
static RCON: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

/// Folds `blocks` into `state` on the SHA-1 instructions, returning
/// whether it did: not where the processor lacks them.
pub(crate) fn compress(state: &mut [u32; 5], blocks: &[[u8; 64]]) -> bool {
    if !has_sha1() {
        return false;
    }
    if !blocks.is_empty() {
        // SAFETY: the instructions were just confirmed, and `blocks`
        // is that many whole blocks, at least one.
        unsafe { compress_blocks(state, blocks.as_ptr().cast(), blocks.len()) }
    }
    true
}

/// One group of four rounds: the rotation that makes the next `E`,
/// the rounds themselves, and the sum the next group will use.
///
/// `$op` is which of the three round instructions this group's twenty
/// rounds call for, `$e` the register holding this group's `E` and
/// `$en` the one to leave the next in, `$t` the sum to round with and
/// `$tn` the one to prepare, and `$w` the schedule word to prepare it
/// from, with `$k` its constant.
#[rustfmt::skip]
macro_rules! group {
    ($op:literal, $e:literal, $en:literal, $t:literal, $tn:literal,
     $w:literal, $k:literal) => {
        concat!(
            "add ", $tn, ".4s, ", $w, ".4s, ", $k, ".4s\n",
            "sha1h ", $en, ", s16\n",
            "sha1", $op, " q16, ", $e, ", ", $t, ".4s\n",
        )
    };
}

/// The same, for the last four groups, which have no schedule left to
/// prepare.
#[rustfmt::skip]
macro_rules! last {
    ($op:literal, $e:literal, $en:literal, $t:literal) => {
        concat!(
            "sha1h ", $en, ", s16\n",
            "sha1", $op, " q16, ", $e, ", ", $t, ".4s\n",
        )
    };
}

/// A group with the schedule update around it: `$w0` becomes the four
/// words sixteen rounds ahead, from the three that follow it.
#[rustfmt::skip]
macro_rules! group_update {
    ($op:literal, $e:literal, $en:literal, $t:literal, $tn:literal,
     $w0:literal, $w1:literal, $w2:literal, $w3:literal,
     $k:literal) => {
        concat!(
            "sha1su0 ", $w0, ".4s, ", $w1, ".4s, ", $w2, ".4s\n",
            group!($op, $e, $en, $t, $tn, $w1, $k),
            "sha1su1 ", $w0, ".4s, ", $w3, ".4s\n",
        )
    };
}

/// Folds `count` blocks at `data` into `state`.
///
/// # Safety
/// Requires the SHA-1 instructions; `data` must point at `count`
/// whole blocks, with `count >= 1`.
///
/// The SHA-1 and SHA-256 instructions are one feature to the
/// assembler, which is why this names `sha2`.
#[target_feature(enable = "sha2")]
#[rustfmt::skip]
unsafe fn compress_blocks(state: &mut [u32; 5], data: *const u8, count: usize) {
    unsafe {
        core::arch::asm!(
            // The round constants, then the state: ABCD in v12 and E
            // in the low word of v13.
            "ld1r {{v0.4s}}, [{rcon}], #4",
            "ld1r {{v1.4s}}, [{rcon}], #4",
            "ld1r {{v2.4s}}, [{rcon}], #4",
            "ld1r {{v3.4s}}, [{rcon}]",
            "ld1 {{v12.4s}}, [{state}]",
            "ldr s13, [{state}, #16]",
            "2:",
            // The block, as sixteen big-endian words made numbers.
            "ld1 {{v8.4s, v9.4s, v10.4s, v11.4s}}, [{data}], #64",
            "rev32 v8.16b, v8.16b",
            "rev32 v9.16b, v9.16b",
            "rev32 v10.16b, v10.16b",
            "rev32 v11.16b, v11.16b",
            "add v14.4s, v8.4s, v0.4s",
            "mov v16.16b, v12.16b",
            // Rounds 0 to 19, where E comes in from the block above.
            group_update!("c", "s13", "s18", "v14", "v15",
                          "v8", "v9", "v10", "v11", "v0"),
            group_update!("c", "s18", "s17", "v15", "v14",
                          "v9", "v10", "v11", "v8", "v0"),
            group_update!("c", "s17", "s18", "v14", "v15",
                          "v10", "v11", "v8", "v9", "v0"),
            group_update!("c", "s18", "s17", "v15", "v14",
                          "v11", "v8", "v9", "v10", "v0"),
            group_update!("c", "s17", "s18", "v14", "v15",
                          "v8", "v9", "v10", "v11", "v1"),
            // Rounds 20 to 39.
            group_update!("p", "s18", "s17", "v15", "v14",
                          "v9", "v10", "v11", "v8", "v1"),
            group_update!("p", "s17", "s18", "v14", "v15",
                          "v10", "v11", "v8", "v9", "v1"),
            group_update!("p", "s18", "s17", "v15", "v14",
                          "v11", "v8", "v9", "v10", "v1"),
            group_update!("p", "s17", "s18", "v14", "v15",
                          "v8", "v9", "v10", "v11", "v1"),
            group_update!("p", "s18", "s17", "v15", "v14",
                          "v9", "v10", "v11", "v8", "v2"),
            // Rounds 40 to 59.
            group_update!("m", "s17", "s18", "v14", "v15",
                          "v10", "v11", "v8", "v9", "v2"),
            group_update!("m", "s18", "s17", "v15", "v14",
                          "v11", "v8", "v9", "v10", "v2"),
            group_update!("m", "s17", "s18", "v14", "v15",
                          "v8", "v9", "v10", "v11", "v2"),
            group_update!("m", "s18", "s17", "v15", "v14",
                          "v9", "v10", "v11", "v8", "v2"),
            group_update!("m", "s17", "s18", "v14", "v15",
                          "v10", "v11", "v8", "v9", "v3"),
            // Rounds 60 to 79. The schedule runs out four groups from
            // the end, and the last of it is prepared here.
            group_update!("p", "s18", "s17", "v15", "v14",
                          "v11", "v8", "v9", "v10", "v3"),
            group!("p", "s17", "s18", "v14", "v15", "v9", "v3"),
            group!("p", "s18", "s17", "v15", "v14", "v10", "v3"),
            group!("p", "s17", "s18", "v14", "v15", "v11", "v3"),
            last!("p", "s18", "s17", "v15"),
            // The block's state onto the chaining value.
            "add v13.2s, v13.2s, v17.2s",
            "add v12.4s, v12.4s, v16.4s",
            "subs {count}, {count}, #1",
            "b.ne 2b",
            "st1 {{v12.4s}}, [{state}]",
            "str s13, [{state}, #16]",
            state = in(reg) state.as_mut_ptr(),
            rcon = inout(reg) RCON.as_ptr() => _,
            data = inout(reg) data => _,
            count = inout(reg) count => _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _,
            options(nostack),
        );
    }
}
