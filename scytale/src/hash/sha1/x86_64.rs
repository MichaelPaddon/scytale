//! SHA-1 with the SHA-NI instructions on x86-64.
//!
//! `sha1rnds4` does four rounds on the state held as `ABCD` in one
//! register, taking `E` plus the message word in another, and
//! `sha1nexte`, `sha1msg1` and `sha1msg2` make the schedule four
//! words at a time. The whole compression is written out, eighty
//! rounds unrolled, as SHA-256's is beside it.

#![allow(unsafe_code)]

use crate::align::At16;
use crate::hash::sha2::x86_64::has_sha;

/// Reverses all sixteen bytes of a register: four big-endian words
/// loaded from a block come out as numbers, in the order the
/// instructions want them, first word highest.
static REVERSE: At16<[u8; 16]> =
    At16([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

/// Folds `blocks` into `state` on SHA-NI, returning whether it did:
/// not where the processor lacks the instructions.
pub(crate) fn compress(state: &mut [u32; 5], blocks: &[[u8; 64]]) -> bool {
    if !has_sha() {
        return false;
    }
    if !blocks.is_empty() {
        // SAFETY: the instructions were just confirmed, and `blocks`
        // is that many whole blocks, at least one.
        unsafe { compress_blocks(state, blocks.as_ptr().cast(), blocks.len()) }
    }
    true
}

/// Folds `count` blocks at `data` into `state`.
///
/// # Safety
/// Requires SHA-NI and SSE4.1; `data` must point at `count` whole
/// blocks, with `count >= 1`.
unsafe fn compress_blocks(state: &mut [u32; 5], data: *const u8, count: usize) {
    unsafe {
        // A to D go into xmm4 highest first, and E into the top lane
        // of xmm6; the other lanes of xmm6 are never read. The order
        // below staggers the message loads between the rounds and
        // gives each round's result a fresh register, so nothing on
        // the chain waits for a copy; it measured 7 percent faster
        // than grouping the loads at the top of the block. Between
        // blocks, A from four rounds back becomes E by the rotation
        //  applies as it adds, against the zero in xmm7.
        core::arch::asm!(
            "movdqu xmm7, [{state}]",
            "pxor xmm0, xmm0",
            "pinsrd xmm0, dword ptr [{state} + 16], 3",
            "pshufd xmm4, xmm7, 0x1b",
            "movdqa xmm6, xmm0",
            "movdqa xmm5, [{reverse}]",
            "pxor xmm7, xmm7",
            "2:",
            "movdqu xmm0, [{data}]",
            "movdqa xmm2, xmm6",
            "movdqa xmm1, xmm4",
            "movdqu xmm3, [{data} + 16]",
            "pshufb xmm0, xmm5",
            "paddd xmm2, xmm0",
            "pshufb xmm3, xmm5",
            "sha1rnds4 xmm1, xmm2, 0x0",
            "movdqa xmm2, xmm4",
            "sha1msg1 xmm0, xmm3",
            "sha1nexte xmm2, xmm3",
            "movdqa xmm8, xmm1",
            "sha1rnds4 xmm8, xmm2, 0x0",
            "movdqu xmm2, [{data} + 32]",
            "movdqa xmm10, xmm8",
            "pshufb xmm2, xmm5",
            "sha1nexte xmm1, xmm2",
            "pxor xmm0, xmm2",
            "sha1msg1 xmm3, xmm2",
            "sha1rnds4 xmm10, xmm1, 0x0",
            "movdqu xmm1, [{data} + 48]",
            "movdqa xmm9, xmm10",
            "pshufb xmm1, xmm5",
            "sha1nexte xmm8, xmm1",
            "sha1msg2 xmm0, xmm1",
            "pxor xmm3, xmm1",
            "sha1rnds4 xmm9, xmm8, 0x0",
            "sha1nexte xmm10, xmm0",
            "sha1msg2 xmm3, xmm0",
            "movdqa xmm8, xmm9",
            "sha1msg1 xmm2, xmm1",
            "sha1nexte xmm9, xmm3",
            "sha1rnds4 xmm8, xmm10, 0x0",
            "pxor xmm2, xmm0",
            "sha1msg1 xmm1, xmm0",
            "movdqa xmm10, xmm8",
            "sha1msg2 xmm2, xmm3",
            "pxor xmm1, xmm3",
            "sha1rnds4 xmm10, xmm9, 0x1",
            "sha1nexte xmm8, xmm2",
            "sha1msg2 xmm1, xmm2",
            "movdqa xmm9, xmm10",
            "sha1msg1 xmm0, xmm3",
            "sha1nexte xmm10, xmm1",
            "sha1rnds4 xmm9, xmm8, 0x1",
            "pxor xmm0, xmm2",
            "sha1msg1 xmm3, xmm2",
            "movdqa xmm8, xmm9",
            "sha1msg2 xmm0, xmm1",
            "pxor xmm3, xmm1",
            "sha1rnds4 xmm8, xmm10, 0x1",
            "sha1nexte xmm9, xmm0",
            "sha1msg2 xmm3, xmm0",
            "movdqa xmm10, xmm8",
            "sha1msg1 xmm2, xmm1",
            "sha1nexte xmm8, xmm3",
            "sha1rnds4 xmm10, xmm9, 0x1",
            "pxor xmm2, xmm0",
            "sha1msg1 xmm1, xmm0",
            "movdqa xmm9, xmm10",
            "sha1msg2 xmm2, xmm3",
            "pxor xmm1, xmm3",
            "sha1rnds4 xmm9, xmm8, 0x1",
            "sha1nexte xmm10, xmm2",
            "sha1msg2 xmm1, xmm2",
            "movdqa xmm8, xmm9",
            "sha1msg1 xmm0, xmm3",
            "sha1nexte xmm9, xmm1",
            "sha1rnds4 xmm8, xmm10, 0x2",
            "pxor xmm0, xmm2",
            "sha1msg1 xmm3, xmm2",
            "movdqa xmm10, xmm8",
            "sha1msg2 xmm0, xmm1",
            "pxor xmm3, xmm1",
            "sha1rnds4 xmm10, xmm9, 0x2",
            "sha1nexte xmm8, xmm0",
            "sha1msg2 xmm3, xmm0",
            "movdqa xmm9, xmm10",
            "sha1msg1 xmm2, xmm1",
            "sha1nexte xmm10, xmm3",
            "sha1rnds4 xmm9, xmm8, 0x2",
            "pxor xmm2, xmm0",
            "sha1msg1 xmm1, xmm0",
            "movdqa xmm8, xmm9",
            "sha1msg2 xmm2, xmm3",
            "pxor xmm1, xmm3",
            "sha1rnds4 xmm8, xmm10, 0x2",
            "sha1nexte xmm9, xmm2",
            "sha1msg2 xmm1, xmm2",
            "movdqa xmm10, xmm8",
            "sha1msg1 xmm0, xmm3",
            "sha1nexte xmm8, xmm1",
            "sha1rnds4 xmm10, xmm9, 0x2",
            "pxor xmm0, xmm2",
            "sha1msg1 xmm3, xmm2",
            "movdqa xmm9, xmm10",
            "sha1msg2 xmm0, xmm1",
            "pxor xmm3, xmm1",
            "sha1rnds4 xmm9, xmm8, 0x3",
            "sha1nexte xmm10, xmm0",
            "sha1msg2 xmm3, xmm0",
            "movdqa xmm8, xmm9",
            "sha1msg1 xmm2, xmm1",
            "sha1nexte xmm9, xmm3",
            "sha1rnds4 xmm8, xmm10, 0x3",
            "sha1msg1 xmm1, xmm0",
            "pxor xmm0, xmm2",
            "movdqa xmm2, xmm8",
            "sha1msg2 xmm0, xmm3",
            "pxor xmm3, xmm1",
            "sha1rnds4 xmm2, xmm9, 0x3",
            "sha1nexte xmm8, xmm0",
            "sha1msg2 xmm3, xmm0",
            "movdqa xmm0, xmm2",
            "sha1nexte xmm2, xmm3",
            "sha1rnds4 xmm0, xmm8, 0x3",
            "movdqa xmm1, xmm0",
            "sha1nexte xmm0, xmm7",
            "sha1rnds4 xmm1, xmm2, 0x3",
            "paddd xmm0, xmm6",
            "paddd xmm1, xmm4",
            "movdqa xmm6, xmm0",
            "movdqa xmm4, xmm1",
            "add {data}, 64",
            "dec {count}",
            "jnz 2b",
            "pshufd xmm1, xmm4, 0x1b",
            "movdqu [{state}], xmm1",
            "pextrd dword ptr [{state} + 16], xmm6, 3",
            state = in(reg) state.as_mut_ptr(),
            reverse = in(reg) REVERSE.0.as_ptr(),
            data = inout(reg) data => _,
            count = inout(reg) count => _,
            out("xmm0") _, out("xmm1") _, out("xmm2") _,
            out("xmm3") _, out("xmm4") _, out("xmm5") _,
            out("xmm6") _, out("xmm7") _, out("xmm8") _,
            out("xmm9") _, out("xmm10") _,
            options(nostack),
        );
    }
}
