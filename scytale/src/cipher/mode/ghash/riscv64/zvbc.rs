//! GHASH multiplication using the RISC-V vector carry-less multiply
//! (Zvbc).
//!
//! `vclmul.vv` and `vclmulh.vv` are the carry-less product of 64-bit
//! elements, lane by lane, which is the primitive `pclmulqdq` and
//! `pmull` provide with one pair of operands at a time. Here there are
//! as many pairs as the vector registers hold, so a whole group of
//! blocks is multiplied by its powers of the subkey at once and the
//! lanes are added together afterwards: every block's product is a
//! term of the same sum, so adding the lanes costs one reduction
//! instruction for each third of the result and no shuffling.
//!
//! This is the backend for a processor with `Zvknc`, which is the
//! vector cryptography set with the carry-less multiply rather than
//! the GHASH instruction. A processor with `Zvkng` has [`zvkg`] and
//! never reaches this file.
//!
//! [`zvkg`]: super::zvkg
//!
//! # The layout
//!
//! `LMUL=4` with eight 64-bit elements holds one word of each of the
//! eight blocks, whatever the vector length is, as long as it is at
//! least 128 bits: on a wider machine the same code uses a smaller
//! part of each register group. The words are gathered with strided
//! loads, because a block's two halves are sixteen bytes apart, and
//! the powers of the subkey are gathered with a negative stride,
//! because the first block meets the highest power.
//!
//! A block arrives most significant byte first and `vrev8.v` turns
//! each half into an integer. That instruction belongs to Zvkb, which
//! `Zvkn` includes, so every processor with `Zvknc` has it.
//!
//! # The bit order
//!
//! As in the scalar backend: the subkey is divided by `x` once so
//! that no product needs shifting afterwards. See [`zbc`] and the
//! longer note in the x86 one.
//!
//! [`zbc`]: super::zbc

use super::super::{BLOCK, MAX_GROUP, divide_by_x};
use super::finish;
use crate::arch::riscv64::{EXT_ZVBB, EXT_ZVBC, EXT_ZVKB, IMA_V};

/// How many blocks the group multiply takes at once. Eight fills the
/// registers at the narrowest vector length this backend accepts, and
/// shares one reduction between all eight.
pub(super) const GROUP: usize = MAX_GROUP;

/// Whether `ext` reports the vector carry-less multiply, on a
/// processor whose vector registers are `bytes` wide: the vector
/// extension, Zvbc, a byte reverse from Zvbb or Zvkb, and at least
/// 128 bits, which eight elements at `LMUL=4` need.
pub(super) fn present(ext: u64, bytes: usize) -> bool {
    let want = IMA_V | EXT_ZVBC;
    ext & want == want && ext & (EXT_ZVBB | EXT_ZVKB) != 0 && bytes >= 16
}

/// Prepares the subkey for [`multiply`].
pub(super) fn prepare(h: &[u64; 2]) -> [u64; 2] {
    divide_by_x(h)
}

/// The carry-less products of four pairs, the low halves in the first
/// array and the high halves in the second.
///
/// # Safety
/// Requires the vector extension and Zvbc with `VLEN >= 128`.
#[allow(unsafe_code)]
unsafe fn wides(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    let mut lo = [0u64; 4];
    let mut hi = [0u64; 4];
    // SAFETY: the caller has confirmed the instructions; the asm
    // reads eight words through the two pointers and writes eight
    // through the other two, all of which are whole arrays here.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v, +zvbc",
            "vsetivli zero, 4, e64, m4, ta, ma",
            "vle64.v v4, ({a})",
            "vle64.v v8, ({b})",
            "vclmul.vv v12, v4, v8",
            "vclmulh.vv v16, v4, v8",
            "vse64.v v12, ({lo})",
            "vse64.v v16, ({hi})",
            ".option pop",
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            lo = in(reg) lo.as_mut_ptr(),
            hi = in(reg) hi.as_mut_ptr(),
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            options(nostack),
        );
    }
    (lo, hi)
}

/// The carry-less product of one pair, least significant word first.
///
/// Only one lane of [`wides`] is wanted, which is what the reduction
/// needs: its two steps depend on each other and cannot be batched.
///
/// # Safety
/// As [`wides`].
#[inline]
#[allow(unsafe_code)]
unsafe fn wide(a: u64, b: u64) -> [u64; 2] {
    // SAFETY: the caller has confirmed the instructions.
    let (lo, hi) = unsafe { wides(&[a, 0, 0, 0], &[b, 0, 0, 0]) };
    [lo[0], hi[0]]
}

/// Multiplies `value` by the prepared subkey `h`, in place.
///
/// # Safety
/// As [`wides`].
#[allow(unsafe_code)]
pub(super) unsafe fn multiply(value: &mut [u64; 2], h: &[u64; 2]) {
    unsafe {
        // The words are held most significant first; the arithmetic
        // wants them the other way round, which is the order the
        // subkey already comes in from prepare.
        let (xl, xh) = (value[1], value[0]);
        let (hl, hh) = (h[0], h[1]);
        // All three of Karatsuba's products in one pass.
        let (lo, hi) = wides(&[xl, xl ^ xh, xh, 0], &[hl, hl ^ hh, hh, 0]);
        let out =
            finish([lo[0], hi[0]], [lo[1], hi[1]], [lo[2], hi[2]], |a, b| {
                wide(a, b)
            });
        value[0] = out[1];
        value[1] = out[0];
    }
}

/// Multiplies in the whole of `blocks`, which is [`GROUP`] blocks,
/// leaving the running hash in `value`.
///
/// # Safety
/// As [`wides`], and `blocks` must be exactly [`GROUP`] blocks long.
/// `powers` holds the prepared powers of the subkey, `H` first, so the
/// first block meets `H^8` and the last meets `H`.
#[allow(unsafe_code)]
pub(super) unsafe fn multiply_group(
    value: &mut [u64; 2],
    powers: &[[u64; 2]; MAX_GROUP],
    blocks: &[u8],
) {
    unsafe {
        debug_assert_eq!(blocks.len(), GROUP * BLOCK);
        let (lo0, lo1, m0, m1, hi0, hi1): (u64, u64, u64, u64, u64, u64);
        // The first block meets the highest power, so the powers are
        // walked backwards.
        let last = powers.as_ptr().add(GROUP - 1) as *const u64;
        // SAFETY: eight blocks are read through two pointers sixteen
        // bytes apart with a stride of sixteen, which is the whole of
        // `blocks`, and the powers likewise backwards from the last.
        core::arch::asm!(
            ".option push",
            ".option arch, +v, +zvbc, +zvkb",
            "vsetivli zero, 8, e64, m4, ta, ma",
            // One word of every block, gathered a block apart. The
            // halves arrive most significant byte first.
            "vlse64.v v8, ({bhi}), {stride}",
            "vrev8.v v8, v8",
            "vlse64.v v4, ({blo}), {stride}",
            "vrev8.v v4, v4",
            // The powers are plain words already in register order.
            "vlse64.v v16, ({phi}), {back}",
            "vlse64.v v12, ({plo}), {back}",

            // The running hash joins the first block and nothing
            // after it, so only lane zero is touched.
            "vsetivli zero, 1, e64, m4, tu, ma",
            "vmv.s.x v20, {ylo}",
            "vxor.vv v4, v4, v20",
            "vmv.s.x v20, {yhi}",
            "vxor.vv v8, v8, v20",
            "vsetivli zero, 8, e64, m4, ta, ma",

            // The products of the halves, and then of each operand's
            // halves added together, which is Karatsuba's middle.
            "vclmul.vv v20, v4, v12",
            "vclmulh.vv v24, v4, v12",
            "vclmul.vv v28, v8, v16",
            "vclmulh.vv v0, v8, v16",
            "vxor.vv v4, v4, v8",
            "vxor.vv v12, v12, v16",
            "vclmul.vv v8, v4, v12",
            "vclmulh.vv v16, v4, v12",

            // Add the lanes together: the blocks' products are terms
            // of one sum. v12 supplies the zero each starts from.
            "vmv.v.i v12, 0",
            "vredxor.vs v4, v20, v12",
            "vmv.x.s {lo0}, v4",
            "vredxor.vs v4, v24, v12",
            "vmv.x.s {lo1}, v4",
            "vredxor.vs v4, v8, v12",
            "vmv.x.s {m0}, v4",
            "vredxor.vs v4, v16, v12",
            "vmv.x.s {m1}, v4",
            "vredxor.vs v4, v28, v12",
            "vmv.x.s {hi0}, v4",
            "vredxor.vs v4, v0, v12",
            "vmv.x.s {hi1}, v4",
            ".option pop",
            bhi = in(reg) blocks.as_ptr(),
            blo = in(reg) blocks.as_ptr().add(8),
            plo = in(reg) last,
            phi = in(reg) last.add(1),
            stride = in(reg) BLOCK,
            back = in(reg) -(BLOCK as isize),
            ylo = in(reg) value[1],
            yhi = in(reg) value[0],
            lo0 = out(reg) lo0,
            lo1 = out(reg) lo1,
            m0 = out(reg) m0,
            m1 = out(reg) m1,
            hi0 = out(reg) hi0,
            hi1 = out(reg) hi1,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            out("v24") _, out("v25") _, out("v26") _, out("v27") _,
            out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            options(nostack),
        );

        let out = finish([lo0, lo1], [m0, m1], [hi0, hi1], |a, b| wide(a, b));
        value[0] = out[1];
        value[1] = out[0];
    }
}
