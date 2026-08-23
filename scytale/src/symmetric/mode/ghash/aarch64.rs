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

/// How many blocks the group multiply takes at once. One means there
/// is no group multiply yet.
pub(super) const GROUP: usize = 1;

/// Never called: [`GROUP`] is one.
///
/// # Safety
/// Unreachable.
pub(super) unsafe fn multiply_group(
    _value: &mut [u64; 2],
    _powers: &[[u64; 2]; super::MAX_GROUP],
    _blocks: &[u8],
) {
    unreachable!("no group multiply on this architecture")
}

/// Whether the polynomial multiply is available.
pub(super) fn has_carryless_multiply() -> bool {
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
pub(super) fn prepare(h: &[u64; 2]) -> [u64; 2] {
    super::divide_by_x(h)
}

/// Multiplies `value` by the prepared subkey `h`, in place.
///
/// # Safety
/// Requires the polynomial multiply.
#[target_feature(enable = "aes")]
pub(super) unsafe fn multiply(value: &mut [u64; 2], h: &[u64; 2]) {
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
