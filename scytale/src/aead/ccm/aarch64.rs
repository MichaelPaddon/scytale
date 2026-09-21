//! CCM as one loop, for the ARMv8 cryptography extension.
//!
//! The two halves of CCM run the cipher at different rates: the
//! counter mode keystream takes eight blocks at a time, while the
//! CBC-MAC chains, each block waiting on the one before it. Called in
//! turn, the MAC sets the pace and the keystream is a second pass on
//! top, with its own loads and stores. Written as one loop, a group
//! of eight keystream blocks is issued among the rounds of the eight
//! MAC blocks it belongs to, where the MAC chain's latency has room
//! for it, and the second pass over the data is gone.
//!
//! The group is eight because that is what
//! [`ctr::aarch64`](crate::cipher::mode::ctr::aarch64) uses, and the
//! point here is to keep its width rather than trade it away: a group
//! of eight keystream blocks is the same eighty round instructions as
//! the eight MAC blocks beside it, so neither side is starved.
//!
//! # The plaintext in the round key
//!
//! `aese` adds its round key before it substitutes, so the block a
//! CBC-MAC chains into the cipher need never be exclusive-ored onto
//! the chain at all: the plaintext goes into the first round key
//! instead, off the chain's path, and the chain then waits for the
//! rounds and nothing else.
//!
//! # Sealing only
//!
//! When sealing, the plaintext is the input, so the MAC can take the
//! whole group before the keystream touches it. When opening it is
//! the output, and no block of it exists until its own keystream
//! block has run every round, so there is nothing for the MAC to do
//! while the keystream runs. Opening therefore keeps the two passes,
//! where the keystream is already eight wide and the MAC is already
//! the chaining loop CBC has written out; measurement said a fused
//! loop one block wide lost more to the narrower keystream than it
//! won back, which is the trade this width exists to avoid.
//!
//! # Availability
//!
//! [`Engine::of`] asks for the extension and nothing more; the loop
//! is the baseline instructions.

#![allow(unsafe_code)]

use crate::cipher::BlockCipher;
use crate::cipher::aes::aarch64::{Keys, armv8::has_aes, keys};
use crate::cipher::mode::ctr::aarch64::{BSWAP, GROUP, OFFSETS};
use crate::implementation::Implementation;

/// The block the loop works in.
const BLOCK: usize = 16;

/// Bytes in a group of blocks.
const SPAN: usize = GROUP * BLOCK;

/// The interleaved loop, and how to reach the key it runs under.
pub(crate) struct Engine<C> {
    keys: Keys<C>,
}

/// By hand rather than derived: nothing here is a cipher, only the
/// way to reach one's round keys, so this clones whatever `C` is.
impl<C> Clone for Engine<C> {
    fn clone(&self) -> Self {
        Engine { keys: self.keys }
    }
}

impl<C: BlockCipher> Engine<C> {
    /// The engine `implementation` names, or `None` where the
    /// processor lacks the instructions or `C` is not a cipher this
    /// is written for.
    ///
    /// The extension has one implementation here, so anything but
    /// [`Implementation::Armv8`] is answered with nothing.
    pub(crate) fn of(implementation: Implementation) -> Option<Self> {
        if implementation != Implementation::Armv8 || !has_aes() {
            return None;
        }
        Some(Engine { keys: keys::<C>()? })
    }

    /// Runs CCM over `data`, a whole number of blocks: the keystream
    /// from `counter`, and the MAC from `chain` over the plaintext.
    /// Leaves `counter` at the block after the last and `chain` at
    /// the MAC so far.
    ///
    /// Returns whether it ran, which it does when sealing, wherever
    /// the engine was built for this cipher and the counter's low 32
    /// bits do not wrap inside the run, which would take 64
    /// gigabytes. Opening keeps the two passes, for the reason this
    /// module gives.
    pub(crate) fn run(
        &self,
        cipher: &C,
        chain: &mut [u8; BLOCK],
        counter: &mut [u8; BLOCK],
        data: &mut [u8],
        encrypt: bool,
    ) -> bool {
        debug_assert_eq!(data.len() % BLOCK, 0);
        let blocks = data.len() / BLOCK;
        let Some(schedule) = (self.keys)(cipher) else {
            return false;
        };
        let low = u32::from_be_bytes([
            counter[12],
            counter[13],
            counter[14],
            counter[15],
        ]);
        // Counted in `u64`: the room is a counter-space quantity
        // bounded by 2^32 by the standard, not a length of memory,
        // and 2^32 does not fit a 32-bit `usize`. These files are
        // built only for 64-bit architectures, so the cast was safe
        // where it stood, but the shape is the one that bites.
        let room = u64::from(u32::MAX - low) + 1;
        if !encrypt || blocks == 0 || room < blocks as u64 {
            return false;
        }
        // The counter block the two loops share and move along; the
        // caller's own is advanced once at the end.
        let mut block = *counter;
        let groups = blocks / GROUP;
        if groups > 0 {
            // SAFETY: the instructions were confirmed when the engine
            // was built, the schedule holds `rounds + 1` round keys,
            // and `data` holds at least `groups` whole groups.
            unsafe {
                seal_groups(
                    schedule.keys(),
                    schedule.rounds(),
                    chain.as_mut_ptr(),
                    block.as_mut_ptr(),
                    data.as_mut_ptr(),
                    groups,
                );
            }
        }
        let rest = blocks - groups * GROUP;
        if rest > 0 {
            let low = u32::from_be_bytes([
                block[12], block[13], block[14], block[15],
            ]);
            // SAFETY: as above, with `rest` whole blocks left after
            // the groups and the counter standing at the first.
            unsafe {
                seal_blocks(
                    schedule.keys(),
                    schedule.rounds(),
                    chain.as_mut_ptr(),
                    block.as_ptr(),
                    data[groups * SPAN..].as_mut_ptr(),
                    rest,
                    low,
                );
            }
        }
        *counter = u128::from_be_bytes(*counter)
            .wrapping_add(blocks as u128)
            .to_be_bytes();
        true
    }
}

/// The counter block for this iteration, in `v1`: the caller's block
/// with its last four bytes replaced by the counter, big-endian.
#[rustfmt::skip]
macro_rules! counter_block {
    () => {
        concat!(
            "mov v1.16b, v17.16b\n",
            "rev {t:w}, {low:w}\n",
            "mov v1.s[3], {t:w}\n",
            "add {low:w}, {low:w}, #1\n",
        )
    };
}

/// One block through the cipher, its first round key `$key` rather
/// than `k0`, which is what the fold uses.
#[rustfmt::skip]
macro_rules! rounds {
    ($v:literal, $key:literal, $label:literal) => {
        concat!(
            "aese ", $v, ".16b, ", $key, ".16b\n",
            "aesmc ", $v, ".16b, ", $v, ".16b\n",
            "add {k}, {rk}, #16\n",
            "mov {n}, {nr}\n",
            $label, ":\n",
            "ld1 {{v2.16b}}, [{k}], #16\n",
            "aese ", $v, ".16b, v2.16b\n",
            "aesmc ", $v, ".16b, ", $v, ".16b\n",
            "subs {n}, {n}, #1\n",
            "b.ne ", $label, "b\n",
            "ld1 {{v2.16b, v3.16b}}, [{k}]\n",
            "aese ", $v, ".16b, v2.16b\n",
            "eor ", $v, ".16b, ", $v, ".16b, v3.16b\n",
        )
    };
}

/// Two blocks through the cipher at once, the keystream in `v1` from
/// `k0` and the MAC chain in `v0` from the folded key. They share
/// every round key after the first, so one load serves both.
#[rustfmt::skip]
macro_rules! rounds_both {
    ($label:literal) => {
        concat!(
            "aese v0.16b, v7.16b\n",
            "aesmc v0.16b, v0.16b\n",
            "aese v1.16b, v6.16b\n",
            "aesmc v1.16b, v1.16b\n",
            "add {k}, {rk}, #16\n",
            "mov {n}, {nr}\n",
            $label, ":\n",
            "ld1 {{v2.16b}}, [{k}], #16\n",
            "aese v0.16b, v2.16b\n",
            "aesmc v0.16b, v0.16b\n",
            "aese v1.16b, v2.16b\n",
            "aesmc v1.16b, v1.16b\n",
            "subs {n}, {n}, #1\n",
            "b.ne ", $label, "b\n",
            "ld1 {{v2.16b, v3.16b}}, [{k}]\n",
            "aese v1.16b, v2.16b\n",
            "aese v0.16b, v2.16b\n",
            "eor v1.16b, v1.16b, v3.16b\n",
            "eor v0.16b, v0.16b, v3.16b\n",
        )
    };
}

/// The keystream applied to one block, and the plaintext folded into
/// a round key for the MAC to take on the next pass.
#[rustfmt::skip]
macro_rules! apply {
    () => {
        concat!(
            "ld1 {{v4.16b}}, [{data}]\n",
            "eor v5.16b, v4.16b, v1.16b\n",
            "st1 {{v5.16b}}, [{data}], #16\n",
            "eor v7.16b, v6.16b, v4.16b\n",
        )
    };
}

/// The blocks left over after the whole groups, one at a time: the
/// keystream of this block beside the MAC of the one before it, since
/// a tail is too short to fill a group and too short for the lag to
/// cost anything.
///
/// # Safety
/// Requires the AES instructions; `rk` must point at `rounds + 1`
/// round keys, `chain` and `counter` at a block each, and `data` at
/// `blocks` blocks, with `blocks >= 1` and `low`, the counter's last
/// four bytes read big-endian, not wrapping within them.
#[target_feature(enable = "aes")]
#[rustfmt::skip]
unsafe fn seal_blocks(
    rk: *const u32,
    rounds: usize,
    chain: *mut u8,
    counter: *const u8,
    data: *mut u8,
    blocks: usize,
    low: u32,
) {
    unsafe {
        core::arch::asm!(
            "ld1 {{v0.16b}}, [{chain}]",
            "ld1 {{v6.16b}}, [{rk}]",
            "ld1 {{v17.16b}}, [{counter}]",
            // The first block's keystream has no MAC to run beside
            // it: the chain is still the caller's.
            counter_block!(),
            rounds!("v1", "v6", "4"),
            apply!(),
            "subs {blocks}, {blocks}, #1",
            "b.eq 5f",
            // Each pass: this block's keystream beside the MAC of the
            // block before it.
            "3:",
            counter_block!(),
            rounds_both!("2"),
            apply!(),
            "subs {blocks}, {blocks}, #1",
            "b.ne 3b",
            // The last block's MAC, with no keystream left.
            "5:",
            rounds!("v0", "v7", "6"),
            "st1 {{v0.16b}}, [{chain}]",
            rk = in(reg) rk,
            nr = in(reg) rounds - 2,
            chain = in(reg) chain,
            counter = in(reg) counter,
            data = inout(reg) data => _,
            blocks = inout(reg) blocks => _,
            low = inout(reg) low => _,
            t = out(reg) _,
            k = out(reg) _,
            n = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v17") _,
            options(nostack),
        );
    }
}

/// One block of a group: the MAC block it belongs to, with the
/// plaintext already in `$pt`, and the keystream block `$ks` beside
/// it, sharing every round key after the first.
///
/// The two are the same ten rounds, so the keystream block finishes
/// where the MAC block does and neither waits for the other; eight of
/// these are a group.
#[rustfmt::skip]
macro_rules! group_block {
    ($ks:literal, $pt:literal) => {
        concat!(
            "eor v14.16b, v15.16b, ", $pt, ".16b\n",
            // Each round instruction stays next to the one that
            // mixes its columns: the processor fuses that pair, and
            // anything between them is a round of latency added to
            // the chain that sets the pace.
            "aese v13.16b, v14.16b\n",
            "aesmc v13.16b, v13.16b\n",
            "aese ", $ks, ".16b, v15.16b\n",
            "aesmc ", $ks, ".16b, ", $ks, ".16b\n",
            "add {k}, {rk}, #16\n",
            "mov {n}, {nr}\n",
            "2:\n",
            "ld1 {{v8.16b}}, [{k}], #16\n",
            "aese v13.16b, v8.16b\n",
            "aesmc v13.16b, v13.16b\n",
            "aese ", $ks, ".16b, v8.16b\n",
            "aesmc ", $ks, ".16b, ", $ks, ".16b\n",
            "subs {n}, {n}, #1\n",
            "b.ne 2b\n",
            "ld1 {{v8.16b, v9.16b}}, [{k}]\n",
            "aese v13.16b, v8.16b\n",
            "aese ", $ks, ".16b, v8.16b\n",
            "eor v13.16b, v13.16b, v9.16b\n",
            "eor ", $ks, ".16b, ", $ks, ".16b, v9.16b\n",
        )
    };
}

/// Whole groups of eight blocks: the keystream of a group issued
/// among the rounds of the MAC blocks it belongs to.
///
/// # Safety
/// Requires the AES instructions; `rk` must point at `rounds + 1`
/// round keys, `chain` and `counter` at a block each, and `data` at
/// `groups * 128` writable bytes, with `groups >= 1` and the
/// counter's low word not wrapping within them.
#[target_feature(enable = "aes")]
#[rustfmt::skip]
unsafe fn seal_groups(
    rk: *const u32,
    rounds: usize,
    chain: *mut u8,
    counter: *mut u8,
    data: *mut u8,
    groups: usize,
) {
    unsafe {
        core::arch::asm!(
            // The lane offsets and the group advance stay in
            // registers, as counter mode's loop keeps them.
            "ld1 {{v16.16b, v17.16b, v18.16b, v19.16b}}, [{offs}], #64",
            "ld1 {{v20.16b, v21.16b, v22.16b, v23.16b}}, [{offs}], #64",
            "ld1 {{v12.16b}}, [{offs}]",
            "ld1 {{v10.16b}}, [{shuffle}]",
            // The base counter, byte-reversed so the field adds.
            "ld1 {{v11.16b}}, [{counter}]",
            "tbl v11.16b, {{v11.16b}}, v10.16b",
            "ld1 {{v15.16b}}, [{rk}]",
            "ld1 {{v13.16b}}, [{chain}]",
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
            // The plaintext, read before anything is stored over it.
            "add {p}, {data}, #64",
            "ld1 {{v24.16b, v25.16b, v26.16b, v27.16b}}, [{data}]",
            "ld1 {{v28.16b, v29.16b, v30.16b, v31.16b}}, [{p}]",
            group_block!("v0", "v24"),
            group_block!("v1", "v25"),
            group_block!("v2", "v26"),
            group_block!("v3", "v27"),
            group_block!("v4", "v28"),
            group_block!("v5", "v29"),
            group_block!("v6", "v30"),
            group_block!("v7", "v31"),
            // The keystream never reaches memory: it is XORed over
            // the data on the way to the two stores.
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
            // Both back in block order.
            "tbl v11.16b, {{v11.16b}}, v10.16b",
            "st1 {{v11.16b}}, [{counter}]",
            "st1 {{v13.16b}}, [{chain}]",
            rk = in(reg) rk,
            nr = in(reg) rounds - 2,
            chain = in(reg) chain,
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
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            out("v24") _, out("v25") _, out("v26") _, out("v27") _,
            out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            options(nostack),
        );
    }
}
