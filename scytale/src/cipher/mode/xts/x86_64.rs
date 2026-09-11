//! XTS written out for processors with the AES instructions.
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
//! once and written once, which is what plain ECB costs, and the two
//! combinings are a memory operand each.
//!
//! # Where the tweaks come from
//!
//! Not from here. Each is the one before it multiplied by the field
//! element the standard calls alpha, which is a shift and a
//! conditional exclusive or: six instructions on the integer ports,
//! which the cipher is not using. The caller works them out there and
//! leaves them in a buffer, so the loops below read them and spend no
//! vector work making them.
//!
//! # Availability
//!
//! [`Engine::of`] hands back nothing where the processor lacks
//! the instructions or the cipher is not one of ours, and the mode
//! then uses the construction over the cipher's own bulk calls.

#![allow(unsafe_code)]

use crate::cipher::BlockCipher;
use crate::cipher::aes::x86_64::{
    KeysEitherWay as Keys, has_aesni, keys_either_way,
};
use crate::implementation::Implementation;
use crate::probe::Probe;

/// The block these loops work in.
const BLOCK: usize = 16;

/// Registers a group keeps in flight.
const REGISTERS: usize = 8;

/// Blocks in a group at the narrower width.
const GROUP: usize = REGISTERS;

/// The same at the wider width, where a register holds two blocks.
const WIDE_GROUP: usize = 2 * REGISTERS;

/// The tweaks for one group, as the loops want to read them: one to a
/// block, in the order the blocks come.
struct Tweaks([[u8; BLOCK]; WIDE_GROUP]);

impl Tweaks {
    fn zeroed() -> Self {
        Tweaks([[0u8; BLOCK]; WIDE_GROUP])
    }
}

/// Writes the next `take` tweaks, leaving `value` on the one after.
///
/// Each is the one before it multiplied by alpha, so this is a chain
/// of dependent shifts. Four shorter chains run together were tried
/// and came out slower: the bounds checks that picking among them
/// needs cost more than the waiting they save.
fn fill(tweaks: &mut Tweaks, take: usize, value: &mut u128) {
    for tweak in tweaks.0[..take].iter_mut() {
        *tweak = value.to_le_bytes();
        *value = super::alpha(*value);
    }
}

/// XTS written out, and how to reach the key it runs under.
pub(crate) struct Engine<C> {
    keys: Keys<C>,
    /// Whether the wider loop can run here as well.
    wide: bool,
}

/// By hand rather than derived: nothing here is a cipher, only a
/// pointer to the way to reach one's round keys, so this clones
/// whatever `C` is.
impl<C> Clone for Engine<C> {
    fn clone(&self) -> Self {
        Engine {
            keys: self.keys,
            wide: self.wide,
        }
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Engine<C> {
    /// The engine for this cipher at the width asked for, or `None`
    /// where this processor lacks the instructions for it or `C` is
    /// not a cipher this is written for.
    pub(crate) fn of(implementation: Implementation) -> Option<Self> {
        let wide = match implementation {
            Implementation::Vaes if has_vaes() => true,
            Implementation::Aesni if has_aesni() => false,
            _ => return None,
        };
        Some(Engine {
            keys: keys_either_way::<C>()?,
            wide,
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
        // group's worth is a chain of dependent shifts that the
        // cipher would otherwise wait out. Two buffers, and the next
        // group's tweaks worked out before the current group is run:
        // the chain is on the integer ports and the cipher on the
        // vector ones, so one covers the other.
        let mut buf = [Tweaks::zeroed(), Tweaks::zeroed()];
        let mut slot = 0usize;
        let mut value = u128::from_le_bytes(*t);

        // The widest body this processor has for as far as whole
        // groups of that width reach, then the narrower one, then a
        // body of exactly the blocks left.
        let span = |left: usize| {
            if self.wide && left >= WIDE_GROUP {
                WIDE_GROUP
            } else {
                left.min(GROUP)
            }
        };

        let blocks = data.len() / BLOCK;
        let base = data.as_mut_ptr();
        let mut done = 0;
        let mut take = span(blocks);
        fill(&mut buf[slot], take, &mut value);
        while done < blocks {
            let next = span(blocks - done - take);
            if next > 0 {
                fill(&mut buf[1 - slot], next, &mut value);
            }
            let body = if take == WIDE_GROUP {
                bodies.wide
            } else {
                bodies.narrow[take - 1]
            };
            // SAFETY: the instructions were confirmed when the mode
            // was built, the schedule holds `rounds + 1` round keys,
            // the blocks from `done` are exactly the ones this body
            // handles and lie within `data`, and the buffer holds one
            // tweak for each of them.
            unsafe {
                body(
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

/// The bodies for one direction: the widest, and one for each count
/// of blocks below a group of the narrower width.
struct Bodies {
    wide: Body,
    narrow: [Body; GROUP],
}

/// Whether the processor and operating system support VAES on 256-bit
/// registers.
fn has_vaes() -> bool {
    PROBED.yes(ask_vaes)
}

/// Asked once; see [`crate::probe`].
static PROBED: Probe = Probe::new();

fn ask_vaes() -> bool {
    use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};
    let leaf1 = __cpuid(1);
    let wanted = (1 << 27) | (1 << 28);
    if leaf1.ecx & wanted != wanted {
        return false;
    }
    let leaf7 = __cpuid_count(7, 0);
    if leaf7.ecx & (1 << 9) == 0 || leaf7.ebx & (1 << 5) == 0 {
        return false;
    }
    // SAFETY: OSXSAVE was just confirmed, so XGETBV is available.
    let xcr0 = unsafe { _xgetbv(0) };
    xcr0 & 0b110 == 0b110
}

/// Defines one body: the listed registers, loaded from the listed
/// offsets, each combined with its tweak, put through the rounds, and
/// combined with its tweak again on the way to a single store.
///
/// Written once and used at both widths and in both directions. The
/// register prefix `$p` is "xmm" or "ymm", so the same text names one
/// block or two; `$bc` is how a round key is brought in, which at the
/// wider width means broadcasting it into both halves. Everything is
/// in the VEX encoding, so no instruction destroys an input that is
/// still wanted and the tweaks can be memory operands.
macro_rules! body {
    ($name:ident, $p:literal, $mid:literal, $last:literal, $bc:literal,
     $zero:literal, [$(($r:literal, $off:literal)),+]) => {
        /// # Safety
        /// Requires AES-NI and AVX, and at the wider width VAES. `rk`
        /// must point at `rounds + 1` round keys of the right
        /// direction, `tw` at one tweak for each block this body
        /// handles, and `data` at exactly those blocks.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            tw: *const u8,
            data: *mut u8,
        ) {
            unsafe {
                core::arch::asm!(
                    concat!($bc, " ", $p, "8, [{rk}]"),
                    $(concat!("vmovdqu ", $r, ", [{data} + ", $off, "]"),)+
                    $(concat!(
                        "vpxor ", $r, ", ", $r, ", [{tw} + ", $off, "]"),)+
                    $(concat!("vpxor ", $r, ", ", $r, ", ", $p, "8"),)+
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    concat!($bc, " ", $p, "8, [{k}]"),
                    $(concat!($mid, " ", $r, ", ", $r, ", ", $p, "8"),)+
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    concat!($bc, " ", $p, "8, [{k}]"),
                    $(concat!($last, " ", $r, ", ", $r, ", ", $p, "8"),)+
                    $(concat!(
                        "vpxor ", $r, ", ", $r, ", [{tw} + ", $off, "]"),)+
                    $(concat!("vmovdqu [{data} + ", $off, "], ", $r),)+
                    $zero,
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    tw = in(reg) tw,
                    data = in(reg) data,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("ymm0") _, out("ymm1") _, out("ymm2") _,
                    out("ymm3") _, out("ymm4") _, out("ymm5") _,
                    out("ymm6") _, out("ymm7") _, out("ymm8") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Defines the eight narrower bodies and the wider one, for one
/// direction.
macro_rules! direction {
    ($table:ident, $mid:literal, $last:literal,
     $w1:ident, $w2:ident, $w3:ident, $w4:ident,
     $w5:ident, $w6:ident, $w7:ident, $w8:ident, $wide:ident) => {
        body!($w1, "xmm", $mid, $last, "vmovdqu", "", [("xmm0", "0")]);
        body!(
            $w2,
            "xmm",
            $mid,
            $last,
            "vmovdqu",
            "",
            [("xmm0", "0"), ("xmm1", "16")]
        );
        body!(
            $w3,
            "xmm",
            $mid,
            $last,
            "vmovdqu",
            "",
            [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]
        );
        body!(
            $w4,
            "xmm",
            $mid,
            $last,
            "vmovdqu",
            "",
            [
                ("xmm0", "0"),
                ("xmm1", "16"),
                ("xmm2", "32"),
                ("xmm3", "48")
            ]
        );
        body!(
            $w5,
            "xmm",
            $mid,
            $last,
            "vmovdqu",
            "",
            [
                ("xmm0", "0"),
                ("xmm1", "16"),
                ("xmm2", "32"),
                ("xmm3", "48"),
                ("xmm4", "64")
            ]
        );
        body!(
            $w6,
            "xmm",
            $mid,
            $last,
            "vmovdqu",
            "",
            [
                ("xmm0", "0"),
                ("xmm1", "16"),
                ("xmm2", "32"),
                ("xmm3", "48"),
                ("xmm4", "64"),
                ("xmm5", "80")
            ]
        );
        body!(
            $w7,
            "xmm",
            $mid,
            $last,
            "vmovdqu",
            "",
            [
                ("xmm0", "0"),
                ("xmm1", "16"),
                ("xmm2", "32"),
                ("xmm3", "48"),
                ("xmm4", "64"),
                ("xmm5", "80"),
                ("xmm6", "96")
            ]
        );
        body!(
            $w8,
            "xmm",
            $mid,
            $last,
            "vmovdqu",
            "",
            [
                ("xmm0", "0"),
                ("xmm1", "16"),
                ("xmm2", "32"),
                ("xmm3", "48"),
                ("xmm4", "64"),
                ("xmm5", "80"),
                ("xmm6", "96"),
                ("xmm7", "112")
            ]
        );
        // Leaving the upper halves dirty would slow down whatever
        // plain SSE code runs next, so they are cleared on the way
        // out.
        body!(
            $wide,
            "ymm",
            $mid,
            $last,
            "vbroadcasti128",
            "vzeroupper",
            [
                ("ymm0", "0"),
                ("ymm1", "32"),
                ("ymm2", "64"),
                ("ymm3", "96"),
                ("ymm4", "128"),
                ("ymm5", "160"),
                ("ymm6", "192"),
                ("ymm7", "224")
            ]
        );

        static $table: Bodies = Bodies {
            wide: $wide,
            narrow: [$w1, $w2, $w3, $w4, $w5, $w6, $w7, $w8],
        };
    };
}

direction!(
    ENCRYPT,
    "vaesenc",
    "vaesenclast",
    encrypt1,
    encrypt2,
    encrypt3,
    encrypt4,
    encrypt5,
    encrypt6,
    encrypt7,
    encrypt8,
    wide_encrypt
);

direction!(
    DECRYPT,
    "vaesdec",
    "vaesdeclast",
    decrypt1,
    decrypt2,
    decrypt3,
    decrypt4,
    decrypt5,
    decrypt6,
    decrypt7,
    decrypt8,
    wide_decrypt
);
