//! CCM as one loop, for the ARMv8 cryptography extension.
//!
//! The two halves of CCM run the cipher at different rates: the
//! counter mode keystream could take every block at once, while the
//! CBC-MAC chains, each block waiting on the one before it. Called in
//! turn, the MAC sets the pace of the whole and the keystream is then
//! a second pass on top. Written as one loop, each round instruction
//! of the MAC is issued beside one of the keystream, so the keystream
//! costs little more than the ports it occupies.
//!
//! # The plaintext in the round key
//!
//! `aese` adds its round key before it substitutes, so the block a
//! CBC-MAC chains into the cipher need never be exclusive-ored onto
//! the chain at all: the plaintext goes into the first round key
//! instead, off the chain's path, and the chain then waits for the
//! rounds and nothing else. The key that fold produces is `k0` with
//! the block on it, and `aese` of the chain under it is exactly the
//! first round of the block the chain should take.
//!
//! # Why the MAC lags a block
//!
//! When decrypting, the plaintext the MAC takes is the ciphertext
//! with this iteration's keystream on it, which is not known until
//! the keystream block has run all its rounds. Interleaving the two
//! within an iteration would therefore be impossible in that
//! direction. So the MAC runs a block behind: an iteration issues the
//! keystream of its own block beside the MAC of the one before, and
//! neither waits on the other in either direction. The first block's
//! keystream and the last block's MAC fall outside the loop.
//!
//! # Availability
//!
//! [`Engine::of`] asks for the extension and nothing more; the loop
//! is the baseline instructions.

#![allow(unsafe_code)]

use crate::cipher::BlockCipher;
use crate::cipher::aes::aarch64::{Keys, armv8::has_aes, keys};
use crate::implementation::Implementation;

/// The block the loop works in.
const BLOCK: usize = 16;

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
    /// `encrypt` says which side of the keystream the plaintext is
    /// on. Leaves `counter` at the block after the last and `chain`
    /// at the MAC so far.
    ///
    /// Returns whether it ran, which it does wherever the engine was
    /// built for this cipher and the counter's low 32 bits do not
    /// wrap inside the run, which would take 64 gigabytes.
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
        if blocks == 0 || (u32::MAX - low) as usize + 1 < blocks {
            return false;
        }
        let run = if encrypt { seal } else { open };
        // SAFETY: the instructions were confirmed when the engine was
        // built, the schedule holds `rounds + 1` round keys, `data`
        // is `blocks` whole blocks with at least one, and the
        // counter's low word does not wrap within them.
        unsafe {
            run(
                schedule.keys(),
                schedule.rounds(),
                chain.as_mut_ptr(),
                counter.as_ptr(),
                data.as_mut_ptr(),
                blocks,
                low,
            );
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
            "aese v1.16b, v6.16b\n",
            "aese v0.16b, v7.16b\n",
            "aesmc v1.16b, v1.16b\n",
            "aesmc v0.16b, v0.16b\n",
            "add {k}, {rk}, #16\n",
            "mov {n}, {nr}\n",
            $label, ":\n",
            "ld1 {{v2.16b}}, [{k}], #16\n",
            "aese v1.16b, v2.16b\n",
            "aese v0.16b, v2.16b\n",
            "aesmc v1.16b, v1.16b\n",
            "aesmc v0.16b, v0.16b\n",
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
/// a round key for the MAC to take on the next pass. `$plain` names
/// the register the plaintext is in: the input when sealing, the
/// output when opening.
#[rustfmt::skip]
macro_rules! apply {
    ($plain:literal) => {
        concat!(
            "ld1 {{v4.16b}}, [{data}]\n",
            "eor v5.16b, v4.16b, v1.16b\n",
            "st1 {{v5.16b}}, [{data}], #16\n",
            "eor v7.16b, v6.16b, ", $plain, ".16b\n",
        )
    };
}

/// The loop, written once for both directions.
macro_rules! ccm_loop {
    ($name:ident, $plain:literal, $doc:literal) => {
#[doc = $doc]
        ///
        /// # Safety
        /// Requires the AES instructions; `rk` must point at
        /// `rounds + 1` round keys, `chain` and `counter` at a block
        /// each, and `data` at `blocks` blocks, with `blocks >= 1`
        /// and `low`, the counter's last four bytes read big-endian,
        /// not wrapping within them.
        #[target_feature(enable = "aes")]
        #[rustfmt::skip]
        unsafe fn $name(
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
                    // The first block's keystream has no MAC to run
                    // beside it: the chain is still the caller's.
                    counter_block!(),
                    rounds!("v1", "v6", "4"),
                    apply!($plain),
                    "subs {blocks}, {blocks}, #1",
                    "b.eq 5f",
                    // Each pass: this block's keystream beside the
                    // MAC of the block before it.
                    "3:",
                    counter_block!(),
                    rounds_both!("2"),
                    apply!($plain),
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
    };
}

ccm_loop!(
    seal,
    "v4",
    "Encrypts a run of blocks and takes the MAC over what they were."
);
ccm_loop!(
    open,
    "v5",
    "Decrypts a run of blocks and takes the MAC over what they are."
);
