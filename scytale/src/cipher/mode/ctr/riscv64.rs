//! Counter mode as one loop, for processors with the RISC-V vector
//! cryptography extension.
//!
//! Everything the loop needs it owns: the counters, the step from one
//! pass to the next, and the rounds. It takes nothing from anywhere
//! else but a pointer to the expanded round keys.
//!
//! The counters are made in registers and encrypted where they lie,
//! then XORed over the data on the way to a single store, so a block
//! is read once and written once, which is what plain ECB costs.
//!
//! # No group, and no tail
//!
//! `vsetvli` sets the vector length from what is left to do, so one
//! call covers a run of any length and there is nothing to round up to
//! and no tail body to write: a register group at `LMUL=8` holds eight
//! blocks on a 128-bit machine and proportionally more on a wider one,
//! and the last pass simply runs short.
//!
//! # The counter field
//!
//! Counter mode counts in the last four bytes of the block, most
//! significant first. The vector holds the block as four plain
//! numbers, so the counter is the last element and a 32-bit add
//! reaches it; one `vrev8.v` puts a whole pass into block order on the
//! way out. The add carries properly within the field, so there is no
//! run length at which this has to stop and carry by hand.
//!
//! # Availability
//!
//! [`Engine::of`] hands back nothing where the processor lacks
//! the instructions or the cipher is not one of ours, and counter mode
//! then uses the construction over the cipher's own `encrypt`. The
//! byte reverse is wanted as well as the cipher: without it the
//! counter field cannot be put back the right way round.

#![allow(unsafe_code)]

use super::super::{ByteOrder, add_counter};
use crate::cipher::BlockCipher;
use crate::cipher::aes::riscv64::{Keys, has_vrev8, has_zvkned, keys};
use crate::implementation::Implementation;

/// The block these loops work in.
const BLOCK: usize = 16;

/// Counter mode's loop, and how to reach the key it runs under.
pub(crate) struct Engine<C> {
    keys: Keys<C>,
}

/// By hand rather than derived: nothing here is a cipher, only a
/// pointer to the way to reach one's round keys, so this clones
/// whatever `C` is.
impl<C> Clone for Engine<C> {
    fn clone(&self) -> Self {
        Engine { keys: self.keys }
    }
}

impl<C: BlockCipher> Engine<C> {
    /// The engine for this cipher, or `None` where this processor
    /// lacks the instructions or `C` is not a cipher this is written
    /// for.
    ///
    /// The loop takes whatever vector length it finds, so there is
    /// one implementation here, and anything but
    /// [`Implementation::Zvkned`] is answered with nothing.
    pub(crate) fn of(implementation: Implementation) -> Option<Self> {
        let wanted = implementation == Implementation::Zvkned;
        if !wanted || !has_zvkned() || !has_vrev8() {
            return None;
        }
        Some(Engine { keys: keys::<C>()? })
    }

    /// Encrypts the counter blocks made from `counter` and XORs them
    /// over `data`, leaving `counter` on the block after the last.
    ///
    /// `data` is a whole number of blocks. The counter wraps inside
    /// its four bytes rather than carrying into the nonce, which is
    /// what counter mode asks for.
    pub(crate) fn xor_counter_blocks(
        &self,
        cipher: &C,
        counter: &mut [u8; BLOCK],
        data: &mut [u8],
    ) {
        debug_assert_eq!(data.len() % BLOCK, 0);
        if data.is_empty() {
            return;
        }
        let Some(schedule) = (self.keys)(cipher) else {
            debug_assert!(false, "the cipher changed under the mode");
            return;
        };
        let blocks = data.len() / BLOCK;

        // The block as four big-endian words: the first three are
        // fixed and the last is the counter, which the loop adds to.
        let word = |i: usize| {
            u32::from_be_bytes([
                counter[i],
                counter[i + 1],
                counter[i + 2],
                counter[i + 3],
            ])
        };
        let run = match schedule.rounds() {
            10 => counter10,
            12 => counter12,
            _ => counter14,
        };
        // SAFETY: the instructions were confirmed when the mode was
        // built, the schedule points at the whole round key array, and
        // `data` holds `blocks` whole blocks with at least one.
        unsafe {
            run(
                schedule.keys(),
                word(12),
                word(0),
                word(4),
                word(8),
                data.as_mut_ptr(),
                blocks,
            );
        }
        add_counter(counter, ByteOrder::Big, blocks as u32);
    }
}

/// Defines `fn $name(rk, n, c0, c1, c2, data, blocks)`: counter mode
/// over `blocks` blocks, with the rounds given as key registers.
///
/// The counters and the per-pass step are built once; the loop then
/// adds the step to the last word of each block, runs the rounds, and
/// XORs the result over the data.
macro_rules! counter_body {
    ($name:ident, $first:literal, [$($mid:literal),*], $last:literal) => {
        /// # Safety
        /// Requires the vector extension, Zvkned and a byte reverse
        /// with VLEN >= 128; `rk` must point at 15 round keys and
        /// `data` at `blocks` writable blocks, `blocks >= 1`.
        unsafe fn $name(
            rk: *const u32,
            n: u32,
            c0: u32,
            c1: u32,
            c2: u32,
            data: *mut u8,
            blocks: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    ".option push",
                    ".option arch, +v, +zvkned, +zvkb",
                    "vsetivli zero, 4, e32, m1, ta, ma",
                    "vle32.v v16, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v17, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v18, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v19, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v20, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v21, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v22, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v23, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v24, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v25, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v26, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v27, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v28, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v29, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v30, ({rk})",
                    // The counters, and the step from one pass to the
                    // next, built once. Element `i` is word `i & 3` of
                    // block `i >> 2`, and word 3 is the counter.
                    "vsetvli {vl}, {avl}, e32, m4, ta, ma",
                    "vid.v v8",
                    "vand.vi v12, v8, 3",
                    "vsrl.vi v8, v8, 2",
                    "vadd.vx v8, v8, {n}",
                    "vmseq.vi v0, v12, 0",
                    "vmerge.vxm v8, v8, {c0}, v0",
                    "vmseq.vi v0, v12, 1",
                    "vmerge.vxm v8, v8, {c1}, v0",
                    "vmseq.vi v0, v12, 2",
                    "vmerge.vxm v8, v8, {c2}, v0",
                    "srli {t}, {vl}, 2",
                    "vmv.v.i v4, 0",
                    "vmseq.vi v0, v12, 3",
                    "vmerge.vxm v4, v4, {t}, v0",
                    "2:",
                    "vsetvli {vl}, {avl}, e32, m4, ta, ma",
                    "vmv.v.v v12, v8",
                    "vrev8.v v12, v12",
                    concat!("vaesz.vs v12, ", $first),
                    $(concat!("vaesem.vs v12, ", $mid),)*
                    concat!("vaesef.vs v12, ", $last),
                    // The keystream never reaches memory: it is XORed
                    // over the data on the way to the one store.
                    "vle32.v v0, ({data})",
                    "vxor.vv v12, v12, v0",
                    "vse32.v v12, ({data})",
                    "slli {t}, {vl}, 2",
                    "add {data}, {data}, {t}",
                    "vadd.vv v8, v8, v4",
                    "sub {avl}, {avl}, {vl}",
                    "bnez {avl}, 2b",
                    ".option pop",
                    rk = inout(reg) rk => _,
                    c0 = in(reg) c0,
                    c1 = in(reg) c1,
                    c2 = in(reg) c2,
                    n = in(reg) n,
                    data = inout(reg) data => _,
                    avl = inout(reg) 4 * blocks => _,
                    vl = out(reg) _,
                    t = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                    out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                    out("v28") _, out("v29") _, out("v30") _,
                    options(nostack),
                );
            }
        }
    };
}

counter_body!(
    counter10,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25"
    ],
    "v26"
);
counter_body!(
    counter12,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27"
    ],
    "v28"
);
counter_body!(
    counter14,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27", "v28", "v29"
    ],
    "v30"
);
