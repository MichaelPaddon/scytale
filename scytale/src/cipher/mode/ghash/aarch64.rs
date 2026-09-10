//! GHASH multiplication using the ARMv8 polynomial multiply.
//!
//! `pmull` multiplies two 64-bit values as polynomials over GF(2),
//! which is exactly what this field needs and what the portable code
//! spends 128 iterations emulating. It comes with the AES
//! instructions as part of the cryptography extension.
//!
//! The bit order, the divided subkey and the two-step reduction all
//! work as described for [x86-64](super::x86_64); only the
//! instructions differ. `ext` takes the place of the shifts and
//! shuffles: every rearrangement needed here is a rotation of the
//! register by eight bytes, or a shift of eight bytes with zeros
//! coming in.

#![allow(unsafe_code)]

/// The field polynomial `x^128 + x^7 + x^2 + x + 1` without its
/// leading term, written in the reversed bit order.
const POLYNOMIAL: u64 = 0xc200_0000_0000_0000;

/// How many blocks the group multiply takes at once.
///
/// Eight is enough independent work to cover the multiply's latency,
/// and it is what fixes the size of the table of powers.
pub(super) const GROUP: usize = super::MAX_GROUP;

/// Multiplies in the whole of `blocks`, which is [`GROUP`] blocks,
/// leaving the running hash in `value`.
///
/// The eight products are accumulated unreduced, in three registers
/// holding the low, middle and high thirds of the 256-bit sum, and
/// reduced once at the end. Nothing in the loop depends on the
/// iteration before it, so the multiplier stays busy, and the
/// reduction, which is a chain that nothing can be spread across,
/// falls due once for eight blocks rather than once for each.
///
/// # Three multiplications a block rather than four
///
/// The two middle products are only ever wanted added together, and
/// Karatsuba's identity gets that sum from one more multiplication
/// instead of two:
///
/// ```text
/// X.hi H.lo + X.lo H.hi = (X.lo + X.hi)(H.lo + H.hi) + X.lo H.lo
///                         + X.hi H.hi
/// ```
///
/// Both corrections are products already being accumulated, so they
/// are applied once at the reduction. Adding a value's halves
/// together is an `ext` and an `eor`, which are cheaper than the
/// multiply they replace.
///
/// # Safety
/// Requires the polynomial multiply, and `blocks` must be exactly
/// [`GROUP`] blocks long. `powers` holds the prepared powers of the
/// subkey, `H` first, so the last block meets `H` and the first meets
/// `H^8`.
#[target_feature(enable = "aes")]
pub(crate) unsafe fn multiply_group(
    value: &mut [u64; 2],
    powers: &[[u64; 2]; super::MAX_GROUP],
    blocks: &[u8],
) {
    unsafe {
        debug_assert_eq!(blocks.len(), GROUP * super::BLOCK);
        let count = GROUP as u64;
        core::arch::asm!(
            "movi   v0.16b, #0",
            "movi   v1.16b, #0",
            "movi   v2.16b, #0",
            // The running hash joins the first block and nothing
            // after it, so the register holding it is cleared once
            // used.
            "ld1    {{v3.2d}}, [{value}]",
            "ext    v3.16b, v3.16b, v3.16b, #8",

            "2:",
            // The block, with its bytes turned round: GHASH numbers
            // them backwards, so reversed is the order the arithmetic
            // wants. A rotation by eight bytes finishes what the
            // pairwise reverse starts.
            "ld1    {{v4.16b}}, [{blocks}], #16",
            "rev64  v4.16b, v4.16b",
            "ext    v4.16b, v4.16b, v4.16b, #8",
            "eor    v4.16b, v4.16b, v3.16b",
            "movi   v3.16b, #0",
            "ld1    {{v5.2d}}, [{powers}]",
            "sub    {powers}, {powers}, #16",

            // Each operand's halves added together, for the middle
            // product.
            "ext    v6.16b, v4.16b, v4.16b, #8",
            "eor    v6.16b, v6.16b, v4.16b",
            "ext    v7.16b, v5.16b, v5.16b, #8",
            "eor    v7.16b, v7.16b, v5.16b",

            "pmull  v17.1q, v4.1d, v5.1d",
            "eor    v0.16b, v0.16b, v17.16b",
            "pmull2 v17.1q, v4.2d, v5.2d",
            "eor    v2.16b, v2.16b, v17.16b",
            "pmull  v17.1q, v6.1d, v7.1d",
            "eor    v1.16b, v1.16b, v17.16b",

            "subs   {count}, {count}, #1",
            "b.ne   2b",

            // The middle sum wants the other two products added in.
            "eor    v1.16b, v1.16b, v0.16b",
            "eor    v1.16b, v1.16b, v2.16b",

            // The middle third belongs half in each of the other two.
            "movi   v7.16b, #0",
            "ext    v6.16b, v7.16b, v1.16b, #8",
            "ext    v4.16b, v1.16b, v7.16b, #8",
            "eor    v0.16b, v0.16b, v6.16b",
            "eor    v2.16b, v2.16b, v4.16b",

            // Fold the excess down in two halves, as for one block.
            "fmov   d16, {polynomial}",
            "pmull  v4.1q, v16.1d, v0.1d",
            "ext    v5.16b, v0.16b, v0.16b, #8",
            "eor    v5.16b, v5.16b, v4.16b",
            "pmull  v4.1q, v16.1d, v5.1d",
            "ext    v0.16b, v5.16b, v5.16b, #8",
            "eor    v0.16b, v0.16b, v4.16b",
            "eor    v2.16b, v2.16b, v0.16b",

            "ext    v2.16b, v2.16b, v2.16b, #8",
            "st1    {{v2.2d}}, [{value}]",
            value = in(reg) value.as_mut_ptr(),
            // The first block meets the highest power, so this walks
            // backwards through the table.
            powers = inout(reg) powers.as_ptr().add(GROUP - 1) => _,
            blocks = inout(reg) blocks.as_ptr() => _,
            count = inout(reg) count => _,
            polynomial = in(reg) POLYNOMIAL,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v16") _, out("v17") _,
            options(nostack),
        );
    }
}

/// How many blocks the group multiply takes at once, asked as a
/// call because one architecture decides it at run time.
pub(super) fn group() -> usize {
    GROUP
}

/// Whether the polynomial multiply is available.
pub(crate) fn has_carryless_multiply() -> bool {
    cfg!(target_feature = "aes") || id_register_reports_pmull()
}

/// Linux traps and emulates reads of the ID registers from user space
/// (since 4.11). Bits 7:4 of ID_AA64ISAR0_EL1 hold 2 or more when the
/// 64-bit polynomial multiply is implemented, and 1 when only the AES
/// instructions are.
#[cfg(target_os = "linux")]
fn id_register_reports_pmull() -> bool {
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
    (isar0 >> 4) & 0xf >= 2
}

/// Without an operating system that exposes the ID registers there is
/// no safe way to ask, so only the compile-time feature counts.
#[cfg(not(target_os = "linux"))]
fn id_register_reports_pmull() -> bool {
    false
}

/// Prepares the subkey for [`multiply`].
pub(crate) fn prepare(h: &[u64; 2]) -> [u64; 2] {
    super::divide_by_x(h)
}

/// Multiplies `value` by the prepared subkey `h`, in place.
///
/// # Safety
/// Requires the polynomial multiply.
#[target_feature(enable = "aes")]
pub(crate) unsafe fn multiply(value: &mut [u64; 2], h: &[u64; 2]) {
    unsafe {
        core::arch::asm!(
            // The words are held most significant first; a register
            // wants them the other way round. The subkey is already in
            // register order from prepare.
            "ld1    {{v0.2d}}, [{value}]",
            "ext    v0.16b, v0.16b, v0.16b, #8",
            "ld1    {{v1.2d}}, [{h}]",
            "movi   v7.16b, #0",
            "fmov   d16, {polynomial}",

            // The four cross products of the two halves. Swapping the
            // subkey's halves brings the two middle ones into reach of
            // the same pair of instructions.
            "pmull  v2.1q, v0.1d, v1.1d",
            "pmull2 v3.1q, v0.2d, v1.2d",
            "ext    v4.16b, v1.16b, v1.16b, #8",
            "pmull  v5.1q, v0.1d, v4.1d",
            "pmull2 v6.1q, v0.2d, v4.2d",
            "eor    v5.16b, v5.16b, v6.16b",

            // The middle products belong half in each end of the result.
            "ext    v6.16b, v7.16b, v5.16b, #8",
            "ext    v4.16b, v5.16b, v7.16b, #8",
            "eor    v2.16b, v2.16b, v6.16b",
            "eor    v3.16b, v3.16b, v4.16b",

            // Fold the excess down in two halves.
            "pmull  v4.1q, v16.1d, v2.1d",
            "ext    v5.16b, v2.16b, v2.16b, #8",
            "eor    v5.16b, v5.16b, v4.16b",
            "pmull  v4.1q, v16.1d, v5.1d",
            "ext    v2.16b, v5.16b, v5.16b, #8",
            "eor    v2.16b, v2.16b, v4.16b",
            "eor    v3.16b, v3.16b, v2.16b",

            "ext    v3.16b, v3.16b, v3.16b, #8",
            "st1    {{v3.2d}}, [{value}]",
            value = in(reg) value.as_mut_ptr(),
            h = in(reg) h.as_ptr(),
            polynomial = in(reg) POLYNOMIAL,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v16") _,
            options(nostack),
        );
    }
}
