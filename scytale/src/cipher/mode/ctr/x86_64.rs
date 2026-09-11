//! Counter mode as one loop, for processors with the AES
//! instructions.
//!
//! Everything the loop needs it owns: the byte reversal that puts the
//! counter field where an addition can reach it, the offsets that
//! make eight or sixteen counter blocks from one base, and the bodies
//! for a tail of fewer than a group. It takes nothing from anywhere
//! else but a pointer to the expanded round keys.
//!
//! The counters are made in registers and encrypted where they lie,
//! then XORed over the data on the way to a single store, so a block
//! is read once and written once, which is what plain ECB costs.
//!
//! # Two widths
//!
//! Eight registers hold a group either way. On a processor with VAES
//! each holds two blocks, so a group is sixteen; on one with only
//! AES-NI it holds one and a group is eight. The sequences below are
//! written once and used at both widths, and a message goes through
//! the widest loop this processor has for as far as whole groups of
//! that width reach, then the narrower one, then a tail body of
//! exactly the blocks left.
//!
//! # Availability
//!
//! [`Engine::new`] hands back nothing where the processor lacks the
//! instructions or the cipher is not one of ours, and counter mode
//! then uses the generic construction over the cipher's own
//! `encrypt`.

#![allow(unsafe_code)]

use super::super::{ByteOrder, add_counter};
use crate::align::At16;
use crate::cipher::BlockCipher;
use crate::cipher::aes::x86_64::{Keys, has_aesni, keys};
use crate::implementation::Implementation;
use crate::probe::Probe;

/// The block these loops work in.
const BLOCK: usize = 16;

/// Registers a group keeps in flight. Enough independent blocks to
/// cover the latency of the round instruction, and few enough to
/// leave registers for the counters and the constants.
const REGISTERS: usize = 8;

/// Blocks in a group at the narrower width, and bytes in one.
const GROUP: usize = REGISTERS;
const SPAN: usize = GROUP * BLOCK;

/// The same at the wider width, where a register holds two blocks.
const WIDE_GROUP: usize = 2 * REGISTERS;
const WIDE_SPAN: usize = WIDE_GROUP * BLOCK;

/// What each register adds to the base counter to make its blocks,
/// and after those, in the last place, what the base itself moves on
/// by once a group is made: one group's worth.
///
/// # Why these are added a byte at a time
///
/// The counter is the last four bytes of the block, most significant
/// first, so the byte these change is the last byte of all, and a
/// byte-wise add reaches it where it lies. That is one instruction
/// per register and no more: the block is already in the order the
/// cipher wants it, so nothing has to be turned round on the way in
/// or on the way out.
///
/// The catch is that a byte-wise add does not carry into the byte
/// above, so it is right only while that last byte does not overflow.
/// [`Engine::xor_counter_blocks`] keeps every run short enough that
/// it cannot, and does the carrying itself between runs, which falls
/// due once in every 256 blocks.
static OFFSETS: At16<[u8; BLOCK * (REGISTERS + 1)]> = {
    let mut b = [0u8; BLOCK * (REGISTERS + 1)];
    let mut i = 0;
    while i < REGISTERS {
        b[BLOCK * i + BLOCK - 1] = i as u8;
        i += 1;
    }
    b[BLOCK * REGISTERS + BLOCK - 1] = GROUP as u8;
    At16(b)
};

/// The same at the wider width, where each register makes two
/// consecutive blocks and the base moves on by sixteen.
static WIDE_OFFSETS: At16<[u8; 2 * BLOCK * (REGISTERS + 1)]> = {
    let mut b = [0u8; 2 * BLOCK * (REGISTERS + 1)];
    let mut i = 0;
    while i < REGISTERS {
        b[2 * BLOCK * i + BLOCK - 1] = 2 * i as u8;
        b[2 * BLOCK * i + 2 * BLOCK - 1] = 2 * i as u8 + 1;
        i += 1;
    }
    b[2 * BLOCK * REGISTERS + BLOCK - 1] = WIDE_GROUP as u8;
    b[2 * BLOCK * REGISTERS + 2 * BLOCK - 1] = WIDE_GROUP as u8;
    At16(b)
};

/// Counter mode's loop, and how to reach the key it runs under.
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

impl<C: BlockCipher> Engine<C> {
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
            keys: keys::<C>()?,
            wide,
        })
    }

    /// Encrypts the counter blocks made from `counter` and XORs them
    /// over `data`, leaving `counter` on the block after the last.
    ///
    /// `data` is a whole number of blocks. Only the last four bytes
    /// of the counter are added to, so a run that would carry out of
    /// them is the caller's to split.
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
        while !data.is_empty() {
            // The loops add to the last byte of the block and do not
            // carry out of it, so a run stops where that byte would
            // overflow and the carrying is done here, in full. It
            // falls due once in every 256 blocks.
            let room = (256 - counter[BLOCK - 1] as usize) * BLOCK;
            let take = data.len().min(room);
            let (mut rest, after) = data.split_at_mut(take);
            data = after;

            // The widest loop this processor has, then the narrower
            // one for what a group of that width could not cover,
            // then the odd blocks.
            if self.wide {
                let groups = rest.len() / WIDE_SPAN;
                if groups > 0 {
                    let (whole, tail) = rest.split_at_mut(groups * WIDE_SPAN);
                    // SAFETY: the instructions were confirmed when
                    // the mode was built, the schedule holds
                    // `rounds + 1` round keys, `whole` is `groups`
                    // whole groups with at least one, and the run was
                    // cut so that no counter in it carries.
                    unsafe {
                        wide_groups(
                            rk,
                            rounds,
                            counter.as_ptr(),
                            whole.as_mut_ptr(),
                            groups,
                        );
                    }
                    add_counter(
                        counter,
                        ByteOrder::Big,
                        (groups * WIDE_GROUP) as u32,
                    );
                    rest = tail;
                }
            }

            let groups = rest.len() / SPAN;
            if groups > 0 {
                let (whole, tail) = rest.split_at_mut(groups * SPAN);
                // SAFETY: as above, at the narrower width.
                unsafe {
                    narrow_groups(
                        rk,
                        rounds,
                        counter.as_ptr(),
                        whole.as_mut_ptr(),
                        groups,
                    );
                }
                add_counter(counter, ByteOrder::Big, (groups * GROUP) as u32);
                rest = tail;
            }

            // At most seven blocks are left, each width with a body
            // of its own, so a short message costs one pass and not a
            // group.
            if !rest.is_empty() {
                let blocks = rest.len() / BLOCK;
                // SAFETY: as above, and `blocks` is 1 to 7, which
                // indexes the table, with `rest` exactly that many
                // blocks.
                unsafe {
                    TAILS[blocks - 1](
                        rk,
                        rounds,
                        counter.as_ptr(),
                        rest.as_mut_ptr(),
                    );
                }
                add_counter(counter, ByteOrder::Big, blocks as u32);
            }
        }
    }
}

/// Whether the processor and operating system support VAES on 256-bit
/// registers: VAES (leaf 7, ECX bit 9), AVX2 (leaf 7, EBX bit 5), and
/// the operating system saving the upper halves.
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

// Every sequence below is written once and used at both widths. The
// register prefix `$p` is "xmm" or "ymm" and `$w` is how many bytes
// one of them holds, so the same text names one block or two; `$bc`
// is how a 128-bit constant is brought in, which at the wider width
// means broadcasting it into both halves.
//
// Blocks live in registers 0 to 7 and round keys stream through 8; 9
// holds the base counter and 10 the byte reversal. Everything is in
// the VEX encoding, which takes three operands, so no instruction has
// to destroy an input that is still wanted and no copies are needed.

/// The eight counter registers from the base, and the round key they
/// start with. Leaves the base on the block after the last.
macro_rules! counters {
    ($p:literal, $w:literal, $bc:literal) => {
        concat!(
            "vpaddb ",
            $p,
            "0, ",
            $p,
            "9, [rip + {offs} + 0*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "1, ",
            $p,
            "9, [rip + {offs} + 1*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "2, ",
            $p,
            "9, [rip + {offs} + 2*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "3, ",
            $p,
            "9, [rip + {offs} + 3*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "4, ",
            $p,
            "9, [rip + {offs} + 4*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "5, ",
            $p,
            "9, [rip + {offs} + 5*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "6, ",
            $p,
            "9, [rip + {offs} + 6*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "7, ",
            $p,
            "9, [rip + {offs} + 7*",
            $w,
            "]\n",
            "vpaddb ",
            $p,
            "9, ",
            $p,
            "9, [rip + {offs} + 8*",
            $w,
            "]\n",
            $bc,
            " ",
            $p,
            "8, [{rk}]\n",
            "vpxor ",
            $p,
            "0, ",
            $p,
            "0, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "1, ",
            $p,
            "1, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "2, ",
            $p,
            "2, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "3, ",
            $p,
            "3, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "4, ",
            $p,
            "4, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "5, ",
            $p,
            "5, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "6, ",
            $p,
            "6, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "7, ",
            $p,
            "7, ",
            $p,
            "8\n",
            "lea {k}, [{rk} + 16]\n",
        )
    };
}

/// The middle rounds, all of them, at local label `$at`.
macro_rules! rounds {
    ($at:literal, $p:literal, $bc:literal) => {
        concat!(
            "mov {n}, {nr}\n",
            $at,
            ":\n",
            $bc,
            " ",
            $p,
            "8, [{k}]\n",
            "vaesenc ",
            $p,
            "0, ",
            $p,
            "0, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "1, ",
            $p,
            "1, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "2, ",
            $p,
            "2, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "3, ",
            $p,
            "3, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "4, ",
            $p,
            "4, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "5, ",
            $p,
            "5, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "6, ",
            $p,
            "6, ",
            $p,
            "8\n",
            "vaesenc ",
            $p,
            "7, ",
            $p,
            "7, ",
            $p,
            "8\n",
            "add {k}, 16\n",
            "dec {n}\n",
            "jnz ",
            $at,
            "b\n",
        )
    };
}

/// The last round, and the keystream XORed over the data on the way
/// to a single store, so it never reaches memory.
macro_rules! finish_group {
    ($p:literal, $w:literal, $span:literal, $bc:literal) => {
        concat!(
            $bc,
            " ",
            $p,
            "8, [{k}]\n",
            "vaesenclast ",
            $p,
            "0, ",
            $p,
            "0, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "1, ",
            $p,
            "1, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "2, ",
            $p,
            "2, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "3, ",
            $p,
            "3, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "4, ",
            $p,
            "4, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "5, ",
            $p,
            "5, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "6, ",
            $p,
            "6, ",
            $p,
            "8\n",
            "vaesenclast ",
            $p,
            "7, ",
            $p,
            "7, ",
            $p,
            "8\n",
            "vpxor ",
            $p,
            "0, ",
            $p,
            "0, [{data} + 0*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "1, ",
            $p,
            "1, [{data} + 1*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "2, ",
            $p,
            "2, [{data} + 2*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "3, ",
            $p,
            "3, [{data} + 3*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "4, ",
            $p,
            "4, [{data} + 4*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "5, ",
            $p,
            "5, [{data} + 5*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "6, ",
            $p,
            "6, [{data} + 6*",
            $w,
            "]\n",
            "vpxor ",
            $p,
            "7, ",
            $p,
            "7, [{data} + 7*",
            $w,
            "]\n",
            "vmovdqu [{data} + 0*",
            $w,
            "], ",
            $p,
            "0\n",
            "vmovdqu [{data} + 1*",
            $w,
            "], ",
            $p,
            "1\n",
            "vmovdqu [{data} + 2*",
            $w,
            "], ",
            $p,
            "2\n",
            "vmovdqu [{data} + 3*",
            $w,
            "], ",
            $p,
            "3\n",
            "vmovdqu [{data} + 4*",
            $w,
            "], ",
            $p,
            "4\n",
            "vmovdqu [{data} + 5*",
            $w,
            "], ",
            $p,
            "5\n",
            "vmovdqu [{data} + 6*",
            $w,
            "], ",
            $p,
            "6\n",
            "vmovdqu [{data} + 7*",
            $w,
            "], ",
            $p,
            "7\n",
            "add {data}, ",
            $span,
            "\n",
        )
    };
}

/// Defines the group loop at one width.
macro_rules! groups {
    ($name:ident, $offs:ident, $p:literal, $w:literal, $span:literal,
     $bc:literal, $zero:literal) => {
        /// Encrypts `groups` groups of counter blocks over `data`.
        ///
        /// # Safety
        /// Requires the instructions [`Engine::new`] asked for. `rk`
        /// must point at `rounds + 1` round keys and `counter` at a
        /// block; `data` must be `groups` groups of writable bytes
        /// with `groups >= 1`.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            counter: *const u8,
            data: *mut u8,
            groups: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    // The base counter as it lies. At the wider width
                    // every lane holds the same one and the offsets
                    // make the pair.
                    concat!($bc, " ", $p, "9, [{counter}]"),
                    "3:",
                    counters!($p, $w, $bc),
                    rounds!("2", $p, $bc),
                    finish_group!($p, $w, $span, $bc),
                    "dec {groups}",
                    "jnz 3b",
                    $zero,
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    counter = in(reg) counter,
                    data = inout(reg) data => _,
                    groups = inout(reg) groups => _,
                    k = out(reg) _,
                    n = out(reg) _,
                    offs = sym $offs,
                    out("ymm0") _, out("ymm1") _, out("ymm2") _,
                    out("ymm3") _, out("ymm4") _, out("ymm5") _,
                    out("ymm6") _, out("ymm7") _, out("ymm8") _,
                    out("ymm9") _,
                    options(nostack),
                );
            }
        }
    };
}

groups!(narrow_groups, OFFSETS, "xmm", "16", "128", "vmovdqu", "");
groups!(
    wide_groups,
    WIDE_OFFSETS,
    "ymm",
    "32",
    "256",
    "vbroadcasti128",
    // Leaving the upper halves dirty would slow down whatever plain
    // SSE code runs next, so they are cleared on the way out.
    "vzeroupper"
);

/// Defines the body for a tail of exactly the listed registers, one
/// block in each.
///
/// Advancing the counter is left to the caller, which knows the
/// width.
macro_rules! tail {
    ($name:ident, [$(($r:literal, $off:literal)),+]) => {
        /// # Safety
        /// Requires AES-NI, SSSE3 and AVX; `rk` must point at
        /// `rounds + 1` round keys, `counter` at a block, and `data`
        /// at the blocks this body handles.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            counter: *const u8,
            data: *mut u8,
        ) {
            unsafe {
                core::arch::asm!(
                    "vmovdqu xmm9, [{counter}]",
                    $(concat!(
                        "vpaddb ", $r, ", xmm9, [rip + {offs} + ",
                        $off, "]"),)+
                    "vmovdqu xmm8, [{rk}]",
                    $(concat!("vpxor ", $r, ", ", $r, ", xmm8"),)+
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "vmovdqu xmm8, [{k}]",
                    $(concat!("vaesenc ", $r, ", ", $r, ", xmm8"),)+
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "vmovdqu xmm8, [{k}]",
                    $(concat!("vaesenclast ", $r, ", ", $r, ", xmm8"),)+
                    $(concat!(
                        "vpxor ", $r, ", ", $r, ", [{data} + ", $off, "]\n",
                        "vmovdqu [{data} + ", $off, "], ", $r),)+
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    counter = in(reg) counter,
                    data = in(reg) data,
                    k = out(reg) _,
                    n = out(reg) _,
                    offs = sym OFFSETS,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm8") _, out("xmm9") _,
                    options(nostack),
                );
            }
        }
    };
}

tail!(tail1, [("xmm0", "0")]);
tail!(tail2, [("xmm0", "0"), ("xmm1", "16")]);
tail!(tail3, [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]);
tail!(
    tail4,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48")
    ]
);
tail!(
    tail5,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
tail!(
    tail6,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80")
    ]
);
tail!(
    tail7,
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

/// The bodies by block count, so a tail of `n` blocks is one pass.
static TAILS: [unsafe fn(*const u32, usize, *const u8, *mut u8); 7] =
    [tail1, tail2, tail3, tail4, tail5, tail6, tail7];
