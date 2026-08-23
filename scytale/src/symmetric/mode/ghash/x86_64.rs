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

/// Whether the processor has `pclmulqdq` (CPUID leaf 1, ECX bit 1).
pub(super) fn has_carryless_multiply() -> bool {
    __cpuid(1).ecx & (1 << 1) != 0
}

/// Prepares the subkey for [`multiply`], dividing it by `x` so that
/// products need no shifting, and putting its halves in the order a
/// register wants them.
///
/// Division by `x` is the reverse of multiplication by it: the top
/// bit says whether the polynomial was folded in on the way, so it
/// both selects the term to undo and supplies the bit that comes
/// back at the bottom.
pub(super) fn prepare(h: &[u64; 2]) -> [u64; 2] {
    let bit = h[0] >> 63;
    // A mask rather than a branch: the subkey is secret.
    let mask = 0u64.wrapping_sub(bit);
    let high = h[0] ^ (mask & (0xe1 << 56));
    let low = h[1];
    [(low << 1) | bit, (high << 1) | (low >> 63)]
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
