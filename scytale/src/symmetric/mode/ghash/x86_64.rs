//! GHASH multiplication using the x86-64 carry-less multiply.
//!
//! `pclmulqdq` multiplies two 64-bit values as polynomials over
//! GF(2), which is exactly what this field needs and what the
//! portable code spends 128 iterations emulating.
//!
//! # How the bit order works out
//!
//! GHASH numbers its bits backwards: the most significant bit of the
//! first byte is the coefficient of `x^0`. A block held as two
//! big-endian words is therefore already the reversal of the natural
//! integer, and reversing turns a product into the reversal of the
//! product shifted up one place, because a product of two degree-127
//! polynomials has degree 254 rather than 255.
//!
//! That leftover place would cost a 256-bit shift on every block.
//! Instead the subkey is divided by `x` once, when the hash starts,
//! and every product then comes out already in place.
//!
//! # The reduction
//!
//! Reducing the 256-bit product modulo the field polynomial takes
//! two more carry-less multiplications by the constant below, which
//! is the polynomial's low half in this reversed order. Each one
//! folds half of the excess down, and the halves of the register are
//! swapped between them so that the same instruction does both.

#![allow(unsafe_code)]

use core::arch::x86_64::__cpuid;

/// The field polynomial `x^128 + x^7 + x^2 + x + 1` without its
/// leading term, written in the reversed bit order.
const POLYNOMIAL: u64 = 0xc200_0000_0000_0000;

/// How many blocks the group multiply takes at once. Eight is enough
/// independent work to fill the multiplier's pipeline, and eight
/// powers of the subkey still fit comfortably in registers.
pub(super) const GROUP: usize = 8;

/// Reverses all sixteen bytes of a register, which turns a block as
/// it arrives into the order the arithmetic below wants.
const REVERSE: [u8; 16] =
    [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

/// Whether the processor has the instructions used here: `pclmulqdq`
/// (CPUID leaf 1, ECX bit 1) and `pshufb`, which comes with SSSE3
/// (bit 9). Every processor with the first has the second, but the
/// group multiply below uses both, so both are checked.
pub(super) fn has_carryless_multiply() -> bool {
    let features = __cpuid(1).ecx;
    features & (1 << 1) != 0 && features & (1 << 9) != 0
}

/// Prepares the subkey for [`multiply`].
pub(super) fn prepare(h: &[u64; 2]) -> [u64; 2] {
    super::divide_by_x(h)
}

/// Multiplies `value` by the prepared subkey `h`, in place.
///
/// # Safety
/// Requires `pclmulqdq`.
pub(super) unsafe fn multiply(value: &mut [u64; 2], h: &[u64; 2]) {
    core::arch::asm!(
        // The words are held most significant first; a register
        // wants them the other way round. The subkey is already in
        // register order from prepare.
        "movdqu    xmm0, [{value}]",
        "pshufd    xmm0, xmm0, 0x4e",
        "movdqu    xmm1, [{h}]",

        // The four cross products of the two halves. The two middle
        // ones belong half in each end of the 256-bit result.
        "movdqa    xmm2, xmm0",
        "pclmulqdq xmm2, xmm1, 0x00",
        "movdqa    xmm3, xmm0",
        "pclmulqdq xmm3, xmm1, 0x11",
        "movdqa    xmm4, xmm0",
        "pclmulqdq xmm4, xmm1, 0x10",
        "movdqa    xmm5, xmm0",
        "pclmulqdq xmm5, xmm1, 0x01",
        "pxor      xmm4, xmm5",
        "movdqa    xmm5, xmm4",
        "pslldq    xmm4, 8",
        "psrldq    xmm5, 8",
        "pxor      xmm2, xmm4",
        "pxor      xmm3, xmm5",

        // Fold the excess down in two halves.
        "movq      xmm6, {polynomial}",
        "movdqa    xmm4, xmm6",
        "pclmulqdq xmm4, xmm2, 0x00",
        "pshufd    xmm5, xmm2, 0x4e",
        "pxor      xmm5, xmm4",
        "movdqa    xmm4, xmm6",
        "pclmulqdq xmm4, xmm5, 0x00",
        "pshufd    xmm2, xmm5, 0x4e",
        "pxor      xmm2, xmm4",
        "pxor      xmm3, xmm2",

        "pshufd    xmm3, xmm3, 0x4e",
        "movdqu    [{value}], xmm3",
        value = in(reg) value.as_mut_ptr(),
        h = in(reg) h.as_ptr(),
        polynomial = in(reg) POLYNOMIAL,
        out("xmm0") _, out("xmm1") _, out("xmm2") _,
        out("xmm3") _, out("xmm4") _, out("xmm5") _, out("xmm6") _,
        options(nostack),
    );
}

/// Multiplies in the whole of `blocks`, which is [`GROUP`] blocks,
/// leaving the running hash in `value`.
///
/// The eight products are accumulated unreduced, in three registers
/// holding the low, middle and high thirds of the 256-bit sum, and
/// reduced once at the end. Nothing in the loop depends on the
/// iteration before it, so the multiplier stays busy.
///
/// # Safety
/// Requires `pclmulqdq` and SSSE3, and `blocks` must be exactly
/// [`GROUP`] blocks long. `powers` holds the prepared powers of the
/// subkey, `H` first, so the last block meets `H` and the first meets
/// `H^8`.
pub(super) unsafe fn multiply_group(
    value: &mut [u64; 2],
    powers: &[[u64; 2]; super::MAX_GROUP],
    blocks: &[u8],
) {
    debug_assert_eq!(blocks.len(), GROUP * super::BLOCK);
    let count = GROUP as u32;
    core::arch::asm!(
        "movdqu    xmm7, [{reverse}]",
        "pxor      xmm0, xmm0",
        "pxor      xmm1, xmm1",
        "pxor      xmm2, xmm2",
        // The running hash joins the first block and nothing after
        // it, so the register holding it is cleared once used.
        "movdqu    xmm3, [{value}]",
        "pshufd    xmm3, xmm3, 0x4e",

        "2:",
        "movdqu    xmm4, [{blocks}]",
        "pshufb    xmm4, xmm7",
        "pxor      xmm4, xmm3",
        "pxor      xmm3, xmm3",
        "movdqu    xmm5, [{powers}]",
        "movdqa    xmm6, xmm4",
        "pclmulqdq xmm6, xmm5, 0x00",
        "pxor      xmm0, xmm6",
        "movdqa    xmm6, xmm4",
        "pclmulqdq xmm6, xmm5, 0x11",
        "pxor      xmm2, xmm6",
        "movdqa    xmm6, xmm4",
        "pclmulqdq xmm6, xmm5, 0x10",
        "pxor      xmm1, xmm6",
        "pclmulqdq xmm4, xmm5, 0x01",
        "pxor      xmm1, xmm4",
        "add       {blocks}, 16",
        "sub       {powers}, 16",
        "dec       {count:e}",
        "jnz       2b",

        // The middle third belongs half in each of the other two.
        "movdqa    xmm4, xmm1",
        "pslldq    xmm1, 8",
        "psrldq    xmm4, 8",
        "pxor      xmm0, xmm1",
        "pxor      xmm2, xmm4",

        // Fold the excess down in two halves, as for one block.
        "movq      xmm6, {polynomial}",
        "movdqa    xmm4, xmm6",
        "pclmulqdq xmm4, xmm0, 0x00",
        "pshufd    xmm5, xmm0, 0x4e",
        "pxor      xmm5, xmm4",
        "movdqa    xmm4, xmm6",
        "pclmulqdq xmm4, xmm5, 0x00",
        "pshufd    xmm0, xmm5, 0x4e",
        "pxor      xmm0, xmm4",
        "pxor      xmm2, xmm0",

        "pshufd    xmm2, xmm2, 0x4e",
        "movdqu    [{value}], xmm2",
        value = in(reg) value.as_mut_ptr(),
        // The first block meets the highest power, so this walks
        // backwards through the table.
        powers = inout(reg) powers.as_ptr().add(GROUP - 1) => _,
        blocks = inout(reg) blocks.as_ptr() => _,
        count = inout(reg) count => _,
        reverse = in(reg) REVERSE.as_ptr(),
        polynomial = in(reg) POLYNOMIAL,
        out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
        out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
        options(nostack),
    );
}
