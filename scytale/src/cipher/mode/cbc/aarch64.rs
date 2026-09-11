//! Cipher block chaining written out for the ARMv8 cryptography
//! extension.
//!
//! Everything the loops need they own: the round keys come in as a
//! pointer and nothing else is taken from elsewhere.
//!
//! # Why the two directions look nothing alike
//!
//! Encryption chains: a block cannot start until the one before it
//! has finished, so there is nothing to interleave and the loop is
//! one block at a time. All it saves over the portable construction
//! is the call around each block.
//!
//! Decryption does not chain through the cipher. Every block can be
//! decrypted at once and only the exclusive or afterwards looks back,
//! so the loop runs eight together. The block each one is combined
//! with is the ciphertext before it, which is the same bytes sixteen
//! earlier in the buffer, so the whole group is read into registers
//! before anything is stored over it and nothing has to be kept
//! aside.
//!
//! # Availability
//!
//! [`Engine::new`] hands back nothing where the processor lacks the
//! instructions or the cipher is not one of ours, and the mode then
//! uses the construction over the cipher's own bulk calls.

#![allow(unsafe_code)]

use crate::cipher::BlockCipher;
use crate::cipher::aes::aarch64::{
    KeysEitherWay as Keys, armv8::has_aes, keys_either_way,
};
use crate::implementation::Implementation;

/// The block these loops work in.
const BLOCK: usize = 16;

/// Blocks a group keeps in flight, and bytes in one.
const GROUP: usize = 8;
const SPAN: usize = GROUP * BLOCK;

/// Chaining written out, and how to reach the key it runs under.
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
    /// The extension works on a register of one block, so unlike
    /// x86-64 there is no wider form: `wide` is answered with
    /// nothing.
    pub(crate) fn of(implementation: Implementation) -> Option<Self> {
        if implementation != Implementation::Armv8 || !has_aes() {
            return None;
        }
        Some(Engine {
            keys: keys_either_way::<C>()?,
        })
    }

    /// Encrypts `data`, a whole number of blocks, chaining from
    /// `chain` and leaving the last block of ciphertext there.
    pub(crate) fn encrypt(
        &self,
        cipher: &C,
        chain: &mut [u8; BLOCK],
        data: &mut [u8],
    ) {
        debug_assert_eq!(data.len() % BLOCK, 0);
        let Some(schedule) = (self.keys)(cipher, false) else {
            debug_assert!(false, "the cipher changed under the mode");
            return;
        };
        if data.is_empty() {
            return;
        }
        // SAFETY: the instructions were confirmed when the mode was
        // built, the schedule holds `rounds + 1` round keys, and
        // `data` is a whole number of blocks, at least one.
        unsafe {
            encrypt_chain(
                schedule.keys(),
                schedule.rounds(),
                chain.as_mut_ptr(),
                data.as_mut_ptr(),
                data.len() / BLOCK,
            );
        }
    }

    /// Decrypts `data`, a whole number of blocks, chaining from
    /// `chain` and leaving the last block of ciphertext there.
    pub(crate) fn decrypt(
        &self,
        cipher: &C,
        chain: &mut [u8; BLOCK],
        data: &mut [u8],
    ) {
        debug_assert_eq!(data.len() % BLOCK, 0);
        let Some(schedule) = (self.keys)(cipher, true) else {
            debug_assert!(false, "the cipher changed under the mode");
            return;
        };
        let (rk, rounds) = (schedule.keys(), schedule.rounds());

        let groups = data.len() / SPAN;
        let (whole, rest) = data.split_at_mut(groups * SPAN);
        if groups > 0 {
            // SAFETY: as in `encrypt`, with `groups` whole groups and
            // at least one.
            unsafe {
                decrypt_groups(
                    rk,
                    rounds,
                    chain.as_mut_ptr(),
                    whole.as_mut_ptr(),
                    groups,
                );
            }
        }
        if !rest.is_empty() {
            // SAFETY: as above, and `blocks` is 1 to 7, which indexes
            // the table, with `rest` exactly that many blocks.
            unsafe {
                TAILS[rest.len() / BLOCK - 1](
                    rk,
                    rounds,
                    chain.as_mut_ptr(),
                    rest.as_mut_ptr(),
                    1,
                );
            }
        }
    }
}

/// Encrypts a whole message, one block at a time, since each waits on
/// the one before it.
///
/// # Safety
/// Requires the AES instructions; `rk` must point at `rounds + 1`
/// round keys, `chain` at a block, and `data` at `blocks` blocks,
/// with `blocks >= 1`.
#[target_feature(enable = "aes")]
unsafe fn encrypt_chain(
    rk: *const u32,
    rounds: usize,
    chain: *mut u8,
    data: *mut u8,
    blocks: usize,
) {
    unsafe {
        core::arch::asm!(
            "ld1 {{v0.16b}}, [{chain}]",
            "3:",
            "ld1 {{v1.16b}}, [{data}]",
            "eor v0.16b, v0.16b, v1.16b",
            "mov {k}, {rk}",
            "mov {n}, {nr}",
            "2:",
            "ld1 {{v2.16b}}, [{k}], #16",
            "aese v0.16b, v2.16b",
            "aesmc v0.16b, v0.16b",
            "subs {n}, {n}, #1",
            "b.ne 2b",
            "ld1 {{v2.16b, v3.16b}}, [{k}]",
            "aese v0.16b, v2.16b",
            "eor v0.16b, v0.16b, v3.16b",
            "st1 {{v0.16b}}, [{data}], #16",
            "subs {blocks}, {blocks}, #1",
            "b.ne 3b",
            "st1 {{v0.16b}}, [{chain}]",
            rk = in(reg) rk,
            nr = in(reg) rounds - 1,
            chain = in(reg) chain,
            data = inout(reg) data => _,
            blocks = inout(reg) blocks => _,
            k = out(reg) _,
            n = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            options(nostack),
        );
    }
}

/// The rounds backwards over `v0` and the listed registers.
macro_rules! rounds {
    ([$($r:literal),*]) => {
        concat!(
            "mov {k}, {rk}\n",
            "mov {n}, {nr}\n",
            "2:\n",
            "ld1 {{v8.16b}}, [{k}], #16\n",
            "aesd v0.16b, v8.16b\n",
            "aesimc v0.16b, v0.16b\n",
            $(concat!(
                "aesd v", $r, ".16b, v8.16b\n",
                "aesimc v", $r, ".16b, v", $r, ".16b\n"),)*
            "subs {n}, {n}, #1\n",
            "b.ne 2b\n",
            "ld1 {{v8.16b, v9.16b}}, [{k}]\n",
            "aesd v0.16b, v8.16b\n",
            "eor v0.16b, v0.16b, v9.16b\n",
            $(concat!(
                "aesd v", $r, ".16b, v8.16b\n",
                "eor v", $r, ".16b, v", $r, ".16b, v9.16b\n"),)*
        )
    };
}

/// Defines a decrypting body over `v0` and the listed registers,
/// each loaded from its own offset.
///
/// The chaining block for the first is in a register; for every other
/// it is the ciphertext sixteen bytes earlier, read from the buffer
/// before anything is stored over it. The last block of the group's
/// ciphertext is taken first, since it is what the next group chains
/// from.
macro_rules! body {
    ($name:ident, $last:literal, $advance:literal,
     [$(($r:literal, $off:literal)),*]) => {
        /// # Safety
        /// Requires the AES instructions; `rk` must point at
        /// `rounds + 1` inverse round keys, `chain` at a block, and
        /// `data` at `groups` runs of the blocks this body handles,
        /// with `groups >= 1`.
        #[target_feature(enable = "aes")]
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            chain: *mut u8,
            data: *mut u8,
            groups: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    "ldr q10, [{chain}]",
                    "3:",
                    concat!("ldr q11, [{data}, #", $last, "]"),
                    "ldr q0, [{data}]",
                    $(concat!("ldr q", $r, ", [{data}, #", $off, "]"),)*
                    rounds!([$($r),*]),
                    // The first takes the chaining block; the rest
                    // take the ciphertext before them, which is still
                    // in the buffer because nothing is stored yet.
                    "eor v0.16b, v0.16b, v10.16b",
                    $(concat!(
                        "ldr q8, [{data}, #", $off, " - 16]\n",
                        "eor v", $r, ".16b, v", $r, ".16b, v8.16b"),)*
                    "str q0, [{data}]",
                    $(concat!("str q", $r, ", [{data}, #", $off, "]"),)*
                    "mov v10.16b, v11.16b",
                    concat!("add {data}, {data}, #", $advance),
                    "subs {groups}, {groups}, #1",
                    "b.ne 3b",
                    "str q10, [{chain}]",
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    chain = in(reg) chain,
                    data = inout(reg) data => _,
                    groups = inout(reg) groups => _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    options(nostack),
                );
            }
        }
    };
}

body!(
    decrypt_groups,
    "112",
    "128",
    [
        ("1", "16"),
        ("2", "32"),
        ("3", "48"),
        ("4", "64"),
        ("5", "80"),
        ("6", "96"),
        ("7", "112")
    ]
);

body!(tail1, "0", "16", []);
body!(tail2, "16", "32", [("1", "16")]);
body!(tail3, "32", "48", [("1", "16"), ("2", "32")]);
body!(tail4, "48", "64", [("1", "16"), ("2", "32"), ("3", "48")]);
body!(
    tail5,
    "64",
    "80",
    [("1", "16"), ("2", "32"), ("3", "48"), ("4", "64")]
);
body!(
    tail6,
    "80",
    "96",
    [
        ("1", "16"),
        ("2", "32"),
        ("3", "48"),
        ("4", "64"),
        ("5", "80")
    ]
);
body!(
    tail7,
    "96",
    "112",
    [
        ("1", "16"),
        ("2", "32"),
        ("3", "48"),
        ("4", "64"),
        ("5", "80"),
        ("6", "96")
    ]
);

/// A body: the round keys, the round count, the chaining block, the
/// data, and how many runs of its own width to do.
type Body = unsafe fn(*const u32, usize, *mut u8, *mut u8, usize);

/// The bodies by block count, so a tail of `n` blocks is one pass.
static TAILS: [Body; 7] = [tail1, tail2, tail3, tail4, tail5, tail6, tail7];
