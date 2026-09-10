//! GHASH multiplication using the RISC-V vector cryptography
//! extension (Zvkg).
//!
//! Where the other architectures build the field multiplication out
//! of carry-less multiplies and a reduction, RISC-V has the whole
//! operation as one instruction: `vgmul.vv` multiplies two 128-bit
//! element groups in exactly the field and bit order GHASH uses.
//! This is the best of the three multiplies here, and the one
//! [`super::best`] reaches for first.
//!
//! # The byte order
//!
//! `vgmul` reverses the bits of each byte on the way in and out,
//! which is what turns GHASH's backwards numbering into ordinary
//! polynomial arithmetic. What it wants in the register is therefore
//! the block's sixteen bytes as they stand. The running hash is held
//! as two words most significant byte first, so both it and the
//! subkey are turned back into that byte order around the
//! instruction.

#![allow(unsafe_code)]

use crate::arch::riscv64::{EXT_ZVKG, IMA_V};

/// How many blocks the group multiply takes at once. `vgmul` does a
/// whole field multiplication in one instruction, so there is no
/// reduction for a group to amortise and no group multiply here.
pub(super) const GROUP: usize = 1;

/// Never called: [`GROUP`] is one.
///
/// # Safety
/// Unreachable.
pub(super) unsafe fn multiply_group(
    _value: &mut [u64; 2],
    _powers: &[[u64; 2]; super::super::MAX_GROUP],
    _blocks: &[u8],
) {
    unreachable!("no group multiply on this architecture")
}

/// Whether `ext` reports the vector GHASH instruction, on a processor
/// whose vector registers are `bytes` wide: the vector extension,
/// Zvkg, and at least 128 bits, which the element groups need.
pub(super) fn present(ext: u64, bytes: usize) -> bool {
    let want = IMA_V | EXT_ZVKG;
    ext & want == want && bytes >= 16
}

/// Puts the subkey in the byte order [`multiply`] wants.
pub(crate) fn prepare(h: &[u64; 2]) -> [u64; 2] {
    [h[0].swap_bytes(), h[1].swap_bytes()]
}

/// Multiplies `value` by the prepared subkey `h`, in place.
///
/// # Safety
/// Requires the vector extension and Zvkg.
pub(crate) unsafe fn multiply(value: &mut [u64; 2], h: &[u64; 2]) {
    unsafe {
        let mut group = prepare(value);
        core::arch::asm!(
            ".option push",
            ".option arch, +v, +zvkg",
            // Four 32-bit elements make up one 128-bit element group.
            "vsetivli zero, 4, e32, m1, ta, ma",
            "vle32.v v0, ({group})",
            "vle32.v v1, ({h})",
            "vgmul.vv v0, v1",
            "vse32.v v0, ({group})",
            ".option pop",
            group = in(reg) group.as_mut_ptr(),
            h = in(reg) h.as_ptr(),
            out("v0") _, out("v1") _,
            options(nostack),
        );
        *value = prepare(&group);
    }
}
