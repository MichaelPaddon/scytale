//! GHASH multiplication using the RISC-V scalar carry-less multiply
//! (Zbc, or Zbkc, which has the same two instructions).
//!
//! `clmul` and `clmulh` give the low and high halves of the
//! carry-less product of two 64-bit values, which is the primitive
//! x86's `pclmulqdq` and ARM's `pmull` provide and the portable code
//! spends 128 iterations emulating. Everything around it -- the three
//! products of Karatsuba and the two that fold the excess down -- is
//! exclusive ors on general registers, written in Rust: the extension
//! supplies the multiply and nothing else, and there is nothing in
//! the bookkeeping for hand-written assembly to schedule better.
//!
//! This is what a processor with no vector unit uses. Every processor
//! with the scalar AES instructions has it, because Zkn includes
//! Zbkc, so it is available wherever this crate already accelerates
//! AES on the general registers.
//!
//! # The bit order
//!
//! GHASH numbers its bits backwards, so a block held as two
//! big-endian words is the reversal of the natural integer, and a
//! product of reversals is the reversal of the product shifted up one
//! place. Dividing the subkey by `x` once, in [`prepare`], pays that
//! shift in advance; see the note in the x86 backend for the whole
//! argument.

use super::super::{BLOCK, MAX_GROUP, divide_by_x, halve};
use super::finish;
use crate::arch::riscv64::{EXT_ZBC, EXT_ZBKC};

/// How many blocks the group multiply takes at once. Eight products
/// share one reduction, which is four of the ten multiplications a
/// block would otherwise cost, and none of the eight depends on
/// another, so a processor that pipelines `clmul` can overlap them.
pub(super) const GROUP: usize = MAX_GROUP;

/// Whether `ext` reports the scalar carry-less multiply. Zbc and Zbkc
/// both provide it, and either will do; neither needs a vector unit,
/// so the register width does not come into it.
pub(super) fn present(ext: u64, _bytes: usize) -> bool {
    ext & (EXT_ZBC | EXT_ZBKC) != 0
}

/// Prepares the subkey for [`multiply`].
pub(super) fn prepare(h: &[u64; 2]) -> [u64; 2] {
    divide_by_x(h)
}

/// The carry-less product of `a` and `b`, least significant word
/// first.
///
/// # Safety
/// Requires Zbc or Zbkc.
#[inline]
#[allow(unsafe_code)]
unsafe fn wide(a: u64, b: u64) -> [u64; 2] {
    let (lo, hi): (u64, u64);
    // SAFETY: the caller has confirmed the instructions; the block
    // reads no memory and has no effect but its two results.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +zbc",
            "clmul  {lo}, {a}, {b}",
            "clmulh {hi}, {a}, {b}",
            ".option pop",
            lo = out(reg) lo,
            hi = out(reg) hi,
            a = in(reg) a,
            b = in(reg) b,
            options(pure, nomem, nostack),
        );
    }
    [lo, hi]
}

/// Multiplies `value` by the prepared subkey `h`, in place.
///
/// # Safety
/// Requires Zbc or Zbkc.
#[allow(unsafe_code)]
pub(super) unsafe fn multiply(value: &mut [u64; 2], h: &[u64; 2]) {
    unsafe {
        // The words are held most significant first; the arithmetic
        // below wants them the other way round, which is the order
        // the subkey already comes in from prepare.
        let (xl, xh) = (value[1], value[0]);
        let (hl, hh) = (h[0], h[1]);
        let out = finish(
            wide(xl, hl),
            wide(xl ^ xh, hl ^ hh),
            wide(xh, hh),
            |a, b| wide(a, b),
        );
        value[0] = out[1];
        value[1] = out[0];
    }
}

/// Multiplies in the whole of `blocks`, which is [`GROUP`] blocks,
/// leaving the running hash in `value`.
///
/// The products are accumulated unreduced, in three running sums
/// holding the low, middle and high thirds of the 256-bit total, and
/// reduced once at the end.
///
/// # Safety
/// Requires Zbc or Zbkc, and `blocks` must be exactly [`GROUP`]
/// blocks long. `powers` holds the prepared powers of the subkey, `H`
/// first, so the first block meets `H^8` and the last meets `H`.
#[allow(unsafe_code)]
pub(super) unsafe fn multiply_group(
    value: &mut [u64; 2],
    powers: &[[u64; 2]; MAX_GROUP],
    blocks: &[u8],
) {
    unsafe {
        debug_assert_eq!(blocks.len(), GROUP * BLOCK);
        let mut lo = [0u64; 2];
        let mut m = [0u64; 2];
        let mut hi = [0u64; 2];
        // The running hash joins the first block and nothing after
        // it, so it is cleared once used.
        let mut y = [value[1], value[0]];

        for (i, block) in blocks.chunks_exact(BLOCK).enumerate() {
            let xl = halve(&block[8..]) ^ y[0];
            let xh = halve(&block[..8]) ^ y[1];
            y = [0, 0];
            let h = &powers[GROUP - 1 - i];
            let (hl, hh) = (h[0], h[1]);

            for (sum, piece) in [
                (&mut lo, wide(xl, hl)),
                (&mut m, wide(xl ^ xh, hl ^ hh)),
                (&mut hi, wide(xh, hh)),
            ] {
                sum[0] ^= piece[0];
                sum[1] ^= piece[1];
            }
        }

        let out = finish(lo, m, hi, |a, b| wide(a, b));
        value[0] = out[1];
        value[1] = out[0];
    }
}
