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
//! # The reduction is in the block
//!
//! The scalar backend reduces in Rust, with one `clmul` pair per
//! fold taken from a general-register instruction. There is no such
//! instruction here: a single-lane product means a vector multiply,
//! and getting its operands in and its result out through memory,
//! which an earlier version of this file did, cost more than the
//! reduction it was for. So the six thirds of the product stay in
//! vector registers and the two folds are done there, at a vector
//! length of one, and only the two words of the answer come out.
//!
//! [`zbc`]: super::zbc

use super::super::{BLOCK, MAX_GROUP, divide_by_x};
use super::POLYNOMIAL;
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

/// The reduction, at a vector length of one: [`super::finish`]
/// written in `vxor`, `vclmul` and `vclmulh`, on the six thirds of
/// the product held in v5/v6 (low), v7/v13 (middle) and v14/v15
/// (high), with the field polynomial in v4 and v8/v9 as scratch.
/// Leaves the two words of the answer in v14 and v15. The caller has
/// set `vl = 1` with 64-bit elements.
macro_rules! reduce {
    () => {
        concat!(
            // Karatsuba's middle term is the sum of the cross
            // products, recovered from the product of the sums, and
            // belongs half in each end of the 256-bit result.
            "vxor.vv v7, v7, v5\n",
            "vxor.vv v7, v7, v14\n",
            "vxor.vv v13, v13, v6\n",
            "vxor.vv v13, v13, v15\n",
            "vxor.vv v6, v6, v7\n",
            "vxor.vv v14, v14, v13\n",
            // Fold the low half down in two steps, exchanging the
            // halves in between so that the same step does both.
            "vclmul.vv v8, v4, v5\n",
            "vclmulh.vv v9, v4, v5\n",
            "vxor.vv v6, v6, v8\n",
            "vxor.vv v5, v5, v9\n",
            "vclmul.vv v8, v4, v6\n",
            "vclmulh.vv v9, v4, v6\n",
            "vxor.vv v14, v14, v5\n",
            "vxor.vv v14, v14, v8\n",
            "vxor.vv v15, v15, v6\n",
            "vxor.vv v15, v15, v9\n",
        )
    };
}

/// Multiplies `value` by the prepared subkey `h`, in place.
///
/// One block, nothing through memory: the four words go in with
/// `vmv.s.x`, the three products and the reduction happen at a
/// vector length of one, and two words come out. This is the tail of
/// a message; the lanes are for [`multiply_group`].
///
/// # Safety
/// Requires the vector extension and Zvbc.
#[allow(unsafe_code)]
pub(super) unsafe fn multiply(value: &mut [u64; 2], h: &[u64; 2]) {
    // The words are held most significant first; the arithmetic
    // wants them the other way round, which is the order the subkey
    // already comes in from prepare.
    let (xl, xh) = (value[1], value[0]);
    let (hl, hh) = (h[0], h[1]);
    let (out0, out1): (u64, u64);
    // SAFETY: the caller has confirmed the instructions; the block
    // touches no memory.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v, +zvbc",
            "vsetivli zero, 1, e64, m1, ta, ma",
            "vmv.s.x v1, {xl}",
            "vmv.s.x v2, {xh}",
            "vmv.s.x v3, {hl}",
            "vmv.s.x v10, {hh}",
            "vmv.v.x v4, {poly}",
            // The low, high and middle products, the middle from
            // each operand's halves added together.
            "vclmul.vv v5, v1, v3",
            "vclmulh.vv v6, v1, v3",
            "vclmul.vv v14, v2, v10",
            "vclmulh.vv v15, v2, v10",
            "vxor.vv v1, v1, v2",
            "vxor.vv v3, v3, v10",
            "vclmul.vv v7, v1, v3",
            "vclmulh.vv v13, v1, v3",
            reduce!(),
            "vmv.x.s {out0}, v14",
            "vmv.x.s {out1}, v15",
            ".option pop",
            xl = in(reg) xl,
            xh = in(reg) xh,
            hl = in(reg) hl,
            hh = in(reg) hh,
            poly = in(reg) POLYNOMIAL,
            out0 = out(reg) out0,
            out1 = out(reg) out1,
            out("v1") _, out("v2") _, out("v3") _, out("v4") _,
            out("v5") _, out("v6") _, out("v7") _, out("v8") _,
            out("v9") _, out("v10") _, out("v13") _, out("v14") _,
            out("v15") _,
            options(nomem, nostack),
        );
    }
    value[0] = out1;
    value[1] = out0;
}

/// Multiplies in the whole of `blocks`, which is [`GROUP`] blocks,
/// leaving the running hash in `value`.
///
/// # Safety
/// Requires the vector extension, Zvbc and a byte reverse, and
/// `blocks` must be exactly [`GROUP`] blocks long.
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
        let (out0, out1): (u64, u64);
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
            // Each sum lands in lane zero of v4 and is moved to a
            // register of its own for the reduction; those live in
            // v4's and v12's groups, so the tail is kept undisturbed
            // rather than left to the reduction to overwrite.
            "vmv.v.i v12, 0",
            "vsetivli zero, 8, e64, m4, tu, ma",
            "vredxor.vs v4, v20, v12",
            "vmv1r.v v5, v4",
            "vredxor.vs v4, v24, v12",
            "vmv1r.v v6, v4",
            "vredxor.vs v4, v8, v12",
            "vmv1r.v v7, v4",
            "vredxor.vs v4, v16, v12",
            "vmv1r.v v13, v4",
            "vredxor.vs v4, v28, v12",
            "vmv1r.v v14, v4",
            "vredxor.vs v4, v0, v12",
            "vmv1r.v v15, v4",

            // Then the reduction on those six, one lane wide.
            "vsetivli zero, 1, e64, m1, ta, ma",
            "vmv.v.x v4, {poly}",
            reduce!(),
            "vmv.x.s {out0}, v14",
            "vmv.x.s {out1}, v15",
            ".option pop",
            bhi = in(reg) blocks.as_ptr(),
            blo = in(reg) blocks.as_ptr().add(8),
            plo = in(reg) last,
            phi = in(reg) last.add(1),
            stride = in(reg) BLOCK,
            back = in(reg) -(BLOCK as isize),
            ylo = in(reg) value[1],
            yhi = in(reg) value[0],
            poly = in(reg) POLYNOMIAL,
            out0 = out(reg) out0,
            out1 = out(reg) out1,
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

        value[0] = out1;
        value[1] = out0;
    }
}
