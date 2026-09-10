//! Counter mode as one loop, for processors with the ARMv8
//! cryptography extension.
//!
//! Everything the loop needs it owns: the byte reversal that puts the
//! counter field where an addition can reach it, the offsets that make
//! eight counter blocks from one base, and the bodies for a tail of
//! fewer than a group. It takes nothing from anywhere else but a
//! pointer to the expanded round keys.
//!
//! The counters are made in registers and encrypted where they lie,
//! then XORed over the data on the way to a single store, so a block
//! is read once and written once, which is what plain ECB costs.
//!
//! # One width
//!
//! `aese` works on a register holding one block, so unlike x86-64
//! there is no wider form to reach for: a group is eight blocks, one
//! to a register, and thirty-two registers leave room for the offsets
//! and the data alongside. A message goes through the group loop for
//! as far as whole groups reach, then a tail body of exactly the
//! blocks left.
//!
//! # The counter field
//!
//! Counter mode counts in the last four bytes of the block, most
//! significant first. Reversed, those are the low word of the
//! register, where a 32-bit vector add reaches them -- and a 32-bit
//! add carries properly within the field, so unlike the byte-wise add
//! x86-64 uses, there is no run length at which this has to stop and
//! carry by hand.
//!
//! # Availability
//!
//! [`Engine::at_width`] hands back nothing where the processor lacks
//! the instructions or the cipher is not one of ours, and counter mode
//! then uses the construction over the cipher's own `encrypt`.

#![allow(unsafe_code)]

use super::super::{ByteOrder, add_counter};
use crate::align::At16;
use crate::cipher::BlockCipher;
use crate::cipher::aes::aarch64::{Keys, armv8::has_aes, keys};

/// The block these loops work in.
const BLOCK: usize = 16;

/// Blocks a group keeps in flight, and bytes in one. Enough
/// independent blocks to cover the latency of the round instruction.
const GROUP: usize = 8;
const SPAN: usize = GROUP * BLOCK;

/// Reverses the bytes of a register, as `tbl` indices, which puts the
/// counter field in the low word and afterwards puts it back.
static BSWAP: At16<[u8; BLOCK]> =
    At16([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

/// What each register adds to the base counter to make its block,
/// then one group's worth to move the base on.
static OFFSETS: At16<[u32; 4 * GROUP + 4]> = {
    let mut w = [0u32; 4 * GROUP + 4];
    let mut i = 0;
    while i < GROUP {
        w[4 * i] = i as u32;
        i += 1;
    }
    w[4 * GROUP] = GROUP as u32;
    At16(w)
};

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
    /// The extension works on a register of one block, so there is no
    /// wider form: `wide` is answered with nothing.
    pub(crate) fn at_width(wide: bool) -> Option<Self> {
        if wide || !has_aes() {
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
        let Some(schedule) = (self.keys)(cipher) else {
            debug_assert!(false, "the cipher changed under the mode");
            return;
        };
        let (rk, rounds) = (schedule.keys(), schedule.rounds());

        let mut data = data;
        let groups = data.len() / SPAN;
        if groups > 0 {
            let (whole, rest) = data.split_at_mut(groups * SPAN);
            // SAFETY: the instructions were confirmed when the mode
            // was built, the schedule holds `rounds + 1` round keys,
            // and `whole` is `groups` whole groups with at least one.
            // The loop leaves `counter` on the block after the last.
            unsafe {
                counter_groups(
                    rk,
                    rounds,
                    counter.as_mut_ptr(),
                    whole.as_mut_ptr(),
                    groups,
                );
            }
            data = rest;
        }

        // At most seven blocks are left, with a body for exactly that
        // many, so a short message costs one pass and not a group.
        if !data.is_empty() {
            let blocks = data.len() / BLOCK;
            // SAFETY: as above, and `blocks` is 1 to 7, which indexes
            // the table, with `data` exactly that many blocks.
            unsafe {
                TAILS[blocks - 1](
                    rk,
                    rounds,
                    counter.as_ptr(),
                    data.as_mut_ptr(),
                );
            }
            add_counter(counter, ByteOrder::Big, blocks as u32);
        }
    }
}

/// Runs whole groups of counter blocks through the cipher and XORs
/// them over `data`, leaving `counter` on the block after the last.
///
/// # Safety
/// Requires the AES instructions; `rk` must point at `rounds + 1`
/// round keys, `counter` at a block, and `data` at `groups * 128`
/// writable bytes, with `groups >= 1`.
#[target_feature(enable = "aes")]
unsafe fn counter_groups(
    rk: *const u32,
    rounds: usize,
    counter: *mut u8,
    data: *mut u8,
    groups: usize,
) {
    unsafe {
        core::arch::asm!(
            // The lane offsets and the group advance stay in
            // registers: there are enough to hold them all.
            "ld1 {{v16.16b, v17.16b, v18.16b, v19.16b}}, [{offs}], #64",
            "ld1 {{v20.16b, v21.16b, v22.16b, v23.16b}}, [{offs}], #64",
            "ld1 {{v12.16b}}, [{offs}]",
            "ld1 {{v10.16b}}, [{shuffle}]",
            // The base counter, byte-reversed so the field adds.
            "ld1 {{v11.16b}}, [{counter}]",
            "tbl v11.16b, {{v11.16b}}, v10.16b",
            "3:",
            "add v0.4s, v11.4s, v16.4s",
            "add v1.4s, v11.4s, v17.4s",
            "add v2.4s, v11.4s, v18.4s",
            "add v3.4s, v11.4s, v19.4s",
            "add v4.4s, v11.4s, v20.4s",
            "add v5.4s, v11.4s, v21.4s",
            "add v6.4s, v11.4s, v22.4s",
            "add v7.4s, v11.4s, v23.4s",
            "add v11.4s, v11.4s, v12.4s",
            "tbl v0.16b, {{v0.16b}}, v10.16b",
            "tbl v1.16b, {{v1.16b}}, v10.16b",
            "tbl v2.16b, {{v2.16b}}, v10.16b",
            "tbl v3.16b, {{v3.16b}}, v10.16b",
            "tbl v4.16b, {{v4.16b}}, v10.16b",
            "tbl v5.16b, {{v5.16b}}, v10.16b",
            "tbl v6.16b, {{v6.16b}}, v10.16b",
            "tbl v7.16b, {{v7.16b}}, v10.16b",
            "mov {k}, {rk}",
            "mov {n}, {nr}",
            "2:",
            "ld1 {{v8.16b}}, [{k}], #16",
            "aese v0.16b, v8.16b",
            "aesmc v0.16b, v0.16b",
            "aese v1.16b, v8.16b",
            "aesmc v1.16b, v1.16b",
            "aese v2.16b, v8.16b",
            "aesmc v2.16b, v2.16b",
            "aese v3.16b, v8.16b",
            "aesmc v3.16b, v3.16b",
            "aese v4.16b, v8.16b",
            "aesmc v4.16b, v4.16b",
            "aese v5.16b, v8.16b",
            "aesmc v5.16b, v5.16b",
            "aese v6.16b, v8.16b",
            "aesmc v6.16b, v6.16b",
            "aese v7.16b, v8.16b",
            "aesmc v7.16b, v7.16b",
            "subs {n}, {n}, #1",
            "b.ne 2b",
            "ld1 {{v8.16b, v9.16b}}, [{k}]",
            "aese v0.16b, v8.16b",
            "eor v0.16b, v0.16b, v9.16b",
            "aese v1.16b, v8.16b",
            "eor v1.16b, v1.16b, v9.16b",
            "aese v2.16b, v8.16b",
            "eor v2.16b, v2.16b, v9.16b",
            "aese v3.16b, v8.16b",
            "eor v3.16b, v3.16b, v9.16b",
            "aese v4.16b, v8.16b",
            "eor v4.16b, v4.16b, v9.16b",
            "aese v5.16b, v8.16b",
            "eor v5.16b, v5.16b, v9.16b",
            "aese v6.16b, v8.16b",
            "eor v6.16b, v6.16b, v9.16b",
            "aese v7.16b, v8.16b",
            "eor v7.16b, v7.16b, v9.16b",
            // The keystream never reaches memory: it is XORed over
            // the data on the way to the one store.
            "add {p}, {data}, #64",
            "ld1 {{v24.16b, v25.16b, v26.16b, v27.16b}}, [{data}]",
            "ld1 {{v28.16b, v29.16b, v30.16b, v31.16b}}, [{p}]",
            "eor v0.16b, v0.16b, v24.16b",
            "eor v1.16b, v1.16b, v25.16b",
            "eor v2.16b, v2.16b, v26.16b",
            "eor v3.16b, v3.16b, v27.16b",
            "eor v4.16b, v4.16b, v28.16b",
            "eor v5.16b, v5.16b, v29.16b",
            "eor v6.16b, v6.16b, v30.16b",
            "eor v7.16b, v7.16b, v31.16b",
            "st1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{data}], #64",
            "st1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{data}], #64",
            "subs {groups}, {groups}, #1",
            "b.ne 3b",
            // Hand the counter back in block order.
            "tbl v11.16b, {{v11.16b}}, v10.16b",
            "st1 {{v11.16b}}, [{counter}]",
            rk = in(reg) rk,
            nr = in(reg) rounds - 1,
            counter = in(reg) counter,
            data = inout(reg) data => _,
            groups = inout(reg) groups => _,
            offs = inout(reg) OFFSETS.0.as_ptr() => _,
            shuffle = in(reg) BSWAP.0.as_ptr(),
            p = out(reg) _,
            k = out(reg) _,
            n = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v16") _, out("v17") _, out("v18") _,
            out("v19") _, out("v20") _, out("v21") _, out("v22") _,
            out("v23") _, out("v24") _, out("v25") _, out("v26") _,
            out("v27") _, out("v28") _, out("v29") _, out("v30") _,
            out("v31") _,
            options(nostack),
        );
    }
}

/// Defines a counter body for a fixed number of blocks: it makes its
/// counters from `counter`, encrypts them and XORs them over `data`.
/// Advancing `counter` is left to the caller.
macro_rules! counter_body {
    ($name:ident, [$($r:literal),+]) => {
        /// # Safety
        /// Requires the AES instructions; `rk` must point at
        /// `rounds + 1` round keys, `counter` at a block, and `data`
        /// at the blocks this body handles.
        #[target_feature(enable = "aes")]
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            counter: *const u8,
            data: *mut u8,
        ) {
            unsafe {
                core::arch::asm!(
                    "ld1 {{v10.16b}}, [{shuffle}]",
                    "ld1 {{v11.16b}}, [{counter}]",
                    "tbl v11.16b, {{v11.16b}}, v10.16b",
                    "mov {p}, {offs}",
                    $(concat!(
                        "ld1 {{v12.16b}}, [{p}], #16\n",
                        "add ", $r, ".4s, v11.4s, v12.4s\n",
                        "tbl ", $r, ".16b, {{", $r, ".16b}}, v10.16b"),)+
                    "mov {k}, {rk}",
                    "mov {n}, {nr}",
                    "2:",
                    "ld1 {{v8.16b}}, [{k}], #16",
                    $(concat!(
                        "aese ", $r, ".16b, v8.16b\n",
                        "aesmc ", $r, ".16b, ", $r, ".16b"),)+
                    "subs {n}, {n}, #1",
                    "b.ne 2b",
                    "ld1 {{v8.16b, v9.16b}}, [{k}]",
                    $(concat!(
                        "aese ", $r, ".16b, v8.16b\n",
                        "eor ", $r, ".16b, ", $r, ".16b, v9.16b"),)+
                    "mov {p}, {data}",
                    $(concat!(
                        "ld1 {{v13.16b}}, [{p}]\n",
                        "eor ", $r, ".16b, ", $r, ".16b, v13.16b\n",
                        "st1 {{", $r, ".16b}}, [{p}], #16"),)+
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    counter = in(reg) counter,
                    data = in(reg) data,
                    offs = in(reg) OFFSETS.0.as_ptr(),
                    shuffle = in(reg) BSWAP.0.as_ptr(),
                    p = out(reg) _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v8") _,
                    out("v9") _, out("v10") _, out("v11") _, out("v12") _,
                    out("v13") _,
                    options(nostack),
                );
            }
        }
    };
}

counter_body!(counter1, ["v0"]);
counter_body!(counter2, ["v0", "v1"]);
counter_body!(counter3, ["v0", "v1", "v2"]);
counter_body!(counter4, ["v0", "v1", "v2", "v3"]);
counter_body!(counter5, ["v0", "v1", "v2", "v3", "v4"]);
counter_body!(counter6, ["v0", "v1", "v2", "v3", "v4", "v5"]);
counter_body!(counter7, ["v0", "v1", "v2", "v3", "v4", "v5", "v6"]);

/// A counter body: the round keys, the round count, the counter block
/// and the data.
type CounterBody = unsafe fn(*const u32, usize, *const u8, *mut u8);

/// The bodies by block count, so that a tail of `n` blocks is one
/// call.
static TAILS: [CounterBody; 7] = [
    counter1, counter2, counter3, counter4, counter5, counter6, counter7,
];
