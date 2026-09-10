//! XTS written out for the ARMv8 cryptography extension.
//!
//! Everything the loops need they own: the round keys come in as a
//! pointer and the tweaks in a buffer the caller filled, and nothing
//! else is taken from elsewhere.
//!
//! # What the one loop saves
//!
//! Every block is combined with its tweak, put through the cipher,
//! and combined with the same tweak again. Built over the cipher's
//! bulk call that is three passes over the data: one to apply the
//! tweaks, one for the cipher, one to apply them again, each reading
//! and writing every block. Here it is one pass, so a block is read
//! once and written once, which is what plain ECB costs.
//!
//! There are thirty-two vector registers, so a group's tweaks are
//! read once into registers of their own and used at both ends
//! without going back to memory.
//!
//! # Where the tweaks come from
//!
//! Not from here. Each is the one before it multiplied by the field
//! element the standard calls alpha, which is a shift and a
//! conditional exclusive or: a handful of instructions on the general
//! registers, which the cipher is not using. The caller works them
//! out there and leaves them in a buffer.
//!
//! # Availability
//!
//! [`Engine::at_width`] hands back nothing where the processor lacks
//! the instructions or the cipher is not one of ours, and the mode
//! then uses the construction over the cipher's own bulk calls.

#![allow(unsafe_code)]

use crate::cipher::BlockCipher;
use crate::cipher::aes::aarch64::{
    KeysEitherWay as Keys, armv8::has_aes, keys_either_way,
};

/// The block these loops work in.
const BLOCK: usize = 16;

/// Blocks a group keeps in flight.
pub(super) const GROUP: usize = 8;

/// The tweaks for one group, one to a block, in the order the blocks
/// come.
struct Tweaks([[u8; BLOCK]; GROUP]);

impl Tweaks {
    fn zeroed() -> Self {
        Tweaks([[0u8; BLOCK]; GROUP])
    }
}

/// Writes the next `take` tweaks, leaving `value` on the one after.
fn fill(tweaks: &mut Tweaks, take: usize, value: &mut u128) {
    for tweak in tweaks.0[..take].iter_mut() {
        *tweak = value.to_le_bytes();
        *value = super::alpha(*value);
    }
}

/// XTS written out, and how to reach the key it runs under.
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

impl<C: BlockCipher<Block = [u8; BLOCK]>> Engine<C> {
    /// The engine for this cipher, or `None` where this processor
    /// lacks the instructions or `C` is not a cipher this is written
    /// for.
    ///
    /// The extension works on a register of one block, so unlike
    /// x86-64 there is no wider form: `wide` is answered with
    /// nothing.
    pub(crate) fn at_width(wide: bool) -> Option<Self> {
        if wide || !has_aes() {
            return None;
        }
        Some(Engine {
            keys: keys_either_way::<C>()?,
        })
    }

    /// Runs `data`, a whole number of blocks, from tweak `t`, leaving
    /// `t` on the tweak after the last block.
    pub(crate) fn bulk(
        &self,
        cipher: &C,
        t: &mut [u8; BLOCK],
        data: &mut [u8],
        encrypt: bool,
    ) {
        debug_assert_eq!(data.len() % BLOCK, 0);
        let Some(schedule) = (self.keys)(cipher, !encrypt) else {
            debug_assert!(false, "the cipher changed under the mode");
            return;
        };
        let (rk, rounds) = (schedule.keys(), schedule.rounds());
        let bodies = if encrypt { &ENCRYPT } else { &DECRYPT };

        // Each tweak is the one before it multiplied by alpha, so a
        // group's worth is a chain of dependent shifts that the cipher
        // would otherwise wait out. Two buffers, and the next group's
        // tweaks worked out before the current group is run: the chain
        // is on the general registers and the cipher on the vector
        // ones, so one covers the other.
        let mut buf = [Tweaks::zeroed(), Tweaks::zeroed()];
        let mut slot = 0usize;
        let mut value = u128::from_le_bytes(*t);

        let blocks = data.len() / BLOCK;
        let base = data.as_mut_ptr();
        let mut done = 0;
        let mut take = blocks.min(GROUP);
        fill(&mut buf[slot], take, &mut value);
        while done < blocks {
            let next = (blocks - done - take).min(GROUP);
            if next > 0 {
                fill(&mut buf[1 - slot], next, &mut value);
            }
            // SAFETY: the instructions were confirmed when the mode
            // was built, the schedule holds `rounds + 1` round keys,
            // the blocks from `done` are exactly the ones this body
            // handles and lie within `data`, and the buffer holds one
            // tweak for each of them.
            unsafe {
                bodies[take - 1](
                    rk,
                    rounds,
                    buf[slot].0.as_ptr().cast::<u8>(),
                    base.add(done * BLOCK),
                );
            }
            done += take;
            slot = 1 - slot;
            take = next;
        }
        *t = value.to_le_bytes();
    }
}

/// A body: the round keys, the round count, the tweaks, the data.
type Body = unsafe fn(*const u32, usize, *const u8, *mut u8);

/// Defines one body: the listed registers, loaded from the listed
/// offsets, each combined with its tweak, put through the rounds, and
/// combined with its tweak again on the way to a single store.
///
/// The tweaks live in registers sixteen places up from the blocks, so
/// each is read once and used at both ends. `aese` and `aesd` take the
/// round key themselves, so there is no separate first exclusive or:
/// the tweak goes in before the first round and nothing else does.
macro_rules! body {
    ($name:ident, $round:literal, $mix:literal,
     [$(($r:literal, $off:literal)),+]) => {
        /// # Safety
        /// Requires the AES instructions; `rk` must point at
        /// `rounds + 1` round keys of the right direction, `tw` at one
        /// tweak for each block this body handles, and `data` at
        /// exactly those blocks.
        #[target_feature(enable = "aes")]
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            tw: *const u8,
            data: *mut u8,
        ) {
            unsafe {
                core::arch::asm!(
                    $(concat!(
                        "ldr q1", $r, ", [{tw}, #", $off, "]\n",
                        "ldr q", $r, ", [{data}, #", $off, "]\n",
                        "eor v", $r, ".16b, v", $r, ".16b, v1", $r,
                        ".16b"),)+
                    "mov {k}, {rk}",
                    "mov {n}, {nr}",
                    "2:",
                    "ld1 {{v8.16b}}, [{k}], #16",
                    $(concat!(
                        $round, " v", $r, ".16b, v8.16b\n",
                        $mix, " v", $r, ".16b, v", $r, ".16b"),)+
                    "subs {n}, {n}, #1",
                    "b.ne 2b",
                    "ld1 {{v8.16b, v9.16b}}, [{k}]",
                    $(concat!(
                        $round, " v", $r, ".16b, v8.16b\n",
                        "eor v", $r, ".16b, v", $r, ".16b, v9.16b\n",
                        "eor v", $r, ".16b, v", $r, ".16b, v1", $r,
                        ".16b\n",
                        "str q", $r, ", [{data}, #", $off, "]"),)+
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    tw = in(reg) tw,
                    data = in(reg) data,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _,
                    out("v10") _, out("v11") _, out("v12") _, out("v13") _,
                    out("v14") _, out("v15") _, out("v16") _, out("v17") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Defines the eight bodies for one direction, one for each count of
/// blocks up to a group.
macro_rules! direction {
    ($table:ident, $round:literal, $mix:literal,
     $w1:ident, $w2:ident, $w3:ident, $w4:ident,
     $w5:ident, $w6:ident, $w7:ident, $w8:ident) => {
        body!($w1, $round, $mix, [("0", "0")]);
        body!($w2, $round, $mix, [("0", "0"), ("1", "16")]);
        body!($w3, $round, $mix, [("0", "0"), ("1", "16"), ("2", "32")]);
        body!(
            $w4,
            $round,
            $mix,
            [("0", "0"), ("1", "16"), ("2", "32"), ("3", "48")]
        );
        body!(
            $w5,
            $round,
            $mix,
            [
                ("0", "0"),
                ("1", "16"),
                ("2", "32"),
                ("3", "48"),
                ("4", "64")
            ]
        );
        body!(
            $w6,
            $round,
            $mix,
            [
                ("0", "0"),
                ("1", "16"),
                ("2", "32"),
                ("3", "48"),
                ("4", "64"),
                ("5", "80")
            ]
        );
        body!(
            $w7,
            $round,
            $mix,
            [
                ("0", "0"),
                ("1", "16"),
                ("2", "32"),
                ("3", "48"),
                ("4", "64"),
                ("5", "80"),
                ("6", "96")
            ]
        );
        body!(
            $w8,
            $round,
            $mix,
            [
                ("0", "0"),
                ("1", "16"),
                ("2", "32"),
                ("3", "48"),
                ("4", "64"),
                ("5", "80"),
                ("6", "96"),
                ("7", "112")
            ]
        );

        static $table: [Body; GROUP] = [$w1, $w2, $w3, $w4, $w5, $w6, $w7, $w8];
    };
}

direction!(
    ENCRYPT, "aese", "aesmc", encrypt1, encrypt2, encrypt3, encrypt4, encrypt5,
    encrypt6, encrypt7, encrypt8
);

direction!(
    DECRYPT, "aesd", "aesimc", decrypt1, decrypt2, decrypt3, decrypt4,
    decrypt5, decrypt6, decrypt7, decrypt8
);
