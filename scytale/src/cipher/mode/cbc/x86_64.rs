//! Cipher block chaining written out for processors with the AES
//! instructions.
//!
//! Everything the loops need they own: the round keys come in as a
//! pointer and nothing else is taken from elsewhere.
//!
//! # Why the two directions look nothing alike
//!
//! Encryption chains: a block cannot start until the one before it
//! has finished, so there is nothing to interleave and the loop is
//! one block at a time. All it saves over the portable construction
//! is the call around each block, which at ten rounds of latency is
//! about a fifth of the cost.
//!
//! Decryption does not chain through the cipher. Every block can be
//! decrypted at once and only the exclusive or afterwards looks back,
//! so the loop runs eight registers together like any bulk path. The
//! block each one is combined with is the ciphertext before it, which
//! is the same bytes sixteen earlier in the buffer, so it is read
//! straight from there rather than kept aside: the whole group is in
//! registers before anything is stored over it.
//!
//! # Availability
//!
//! [`Engine::at_width`] hands back nothing where the processor lacks
//! the instructions or the cipher is not one of ours, and the mode
//! then uses the construction over the cipher's own bulk calls.

#![allow(unsafe_code)]

use crate::cipher::BlockCipher;
use crate::cipher::aes::x86_64::{
    KeysEitherWay as Keys, has_aesni, keys_either_way,
};
use crate::probe::Probe;

/// The block these loops work in.
const BLOCK: usize = 16;

/// Registers a group keeps in flight.
const REGISTERS: usize = 8;

/// Blocks in a group at the narrower width, and bytes in one.
const GROUP: usize = REGISTERS;
const SPAN: usize = GROUP * BLOCK;

/// The same at the wider width, where a register holds two blocks.
const WIDE_GROUP: usize = 2 * REGISTERS;
const WIDE_SPAN: usize = WIDE_GROUP * BLOCK;

/// Chaining written out, and how to reach the key it runs under.
pub(crate) struct Engine<C> {
    keys: Keys<C>,
    /// Whether the wider loop can run here as well. Decryption only:
    /// encryption has nothing to widen.
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
    pub(crate) fn at_width(wide: bool) -> Option<Self> {
        if !has_aesni() || (wide && !has_vaes()) {
            return None;
        }
        Some(Engine {
            keys: keys_either_way::<C>()?,
            wide,
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

        // The widest loop this processor has, then the narrower one
        // for what a group of that width could not cover, then the
        // odd blocks. Each leaves the chain on its own last block of
        // ciphertext, so they follow one another with nothing to
        // arrange in between.
        let mut rest = data;
        if self.wide {
            let groups = rest.len() / WIDE_SPAN;
            if groups > 0 {
                let (whole, after) = rest.split_at_mut(groups * WIDE_SPAN);
                // SAFETY: as in `encrypt`, with `groups` whole groups
                // and at least one.
                unsafe {
                    wide_decrypt_groups(
                        rk,
                        rounds,
                        chain.as_mut_ptr(),
                        whole.as_mut_ptr(),
                        groups,
                    );
                }
                rest = after;
            }
        }

        let groups = rest.len() / SPAN;
        if groups > 0 {
            let (whole, after) = rest.split_at_mut(groups * SPAN);
            // SAFETY: as above, at the narrower width.
            unsafe {
                decrypt_groups(
                    rk,
                    rounds,
                    chain.as_mut_ptr(),
                    whole.as_mut_ptr(),
                    groups,
                );
            }
            rest = after;
        }

        if !rest.is_empty() {
            let blocks = rest.len() / BLOCK;
            // SAFETY: as above, and `blocks` is 1 to 7, which indexes
            // the table, with `rest` exactly that many blocks.
            unsafe {
                TAILS[blocks - 1](
                    rk,
                    rounds,
                    chain.as_mut_ptr(),
                    rest.as_mut_ptr(),
                );
            }
        }
    }
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

/// Encrypts a whole message, one block at a time, since each waits on
/// the one before it.
///
/// # Safety
/// Requires AES-NI and AVX; `rk` must point at `rounds + 1` round
/// keys, `chain` at a block, and `data` at `blocks` blocks, with
/// `blocks >= 1`.
unsafe fn encrypt_chain(
    rk: *const u32,
    rounds: usize,
    chain: *mut u8,
    data: *mut u8,
    blocks: usize,
) {
    unsafe {
        core::arch::asm!(
            "vmovdqu xmm0, [{chain}]",
            "3:",
            "vpxor xmm0, xmm0, [{data}]",
            "vpxor xmm0, xmm0, [{rk}]",
            "lea {k}, [{rk} + 16]",
            "mov {n}, {nr}",
            "2:",
            "vaesenc xmm0, xmm0, [{k}]",
            "add {k}, 16",
            "dec {n}",
            "jnz 2b",
            "vaesenclast xmm0, xmm0, [{k}]",
            "vmovdqu [{data}], xmm0",
            "add {data}, 16",
            "dec {blocks}",
            "jnz 3b",
            "vmovdqu [{chain}], xmm0",
            rk = in(reg) rk,
            nr = in(reg) rounds - 1,
            chain = in(reg) chain,
            data = inout(reg) data => _,
            blocks = inout(reg) blocks => _,
            k = out(reg) _,
            n = out(reg) _,
            out("xmm0") _,
            options(nostack),
        );
    }
}

// The sequences below are written once and used at both widths. The
// register prefix `$p` is "xmm" or "ymm" and `$w` is how many bytes
// one of them holds, so the same text names one block or two; `$bc`
// is how a 128-bit constant is brought in, which at the wider width
// means broadcasting it into both halves.
//
// Blocks live in registers 0 to 7 and round keys stream through 8; 9
// holds the chaining block and 10 the one this group will leave
// there.

/// Loads a group of ciphertext and starts it through the rounds.
macro_rules! load {
    ($p:literal, $w:literal, $span:literal, $bc:literal) => {
        concat!(
            // The last block of this group's ciphertext, which is
            // what the next group chains from. Taken before anything
            // is stored over it.
            "vmovdqu xmm10, [{data} + ",
            $span,
            " - 16]\n",
            "vmovdqu ",
            $p,
            "0, [{data} + 0*",
            $w,
            "]\n",
            "vmovdqu ",
            $p,
            "1, [{data} + 1*",
            $w,
            "]\n",
            "vmovdqu ",
            $p,
            "2, [{data} + 2*",
            $w,
            "]\n",
            "vmovdqu ",
            $p,
            "3, [{data} + 3*",
            $w,
            "]\n",
            "vmovdqu ",
            $p,
            "4, [{data} + 4*",
            $w,
            "]\n",
            "vmovdqu ",
            $p,
            "5, [{data} + 5*",
            $w,
            "]\n",
            "vmovdqu ",
            $p,
            "6, [{data} + 6*",
            $w,
            "]\n",
            "vmovdqu ",
            $p,
            "7, [{data} + 7*",
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
            "vaesdec ",
            $p,
            "0, ",
            $p,
            "0, ",
            $p,
            "8\n",
            "vaesdec ",
            $p,
            "1, ",
            $p,
            "1, ",
            $p,
            "8\n",
            "vaesdec ",
            $p,
            "2, ",
            $p,
            "2, ",
            $p,
            "8\n",
            "vaesdec ",
            $p,
            "3, ",
            $p,
            "3, ",
            $p,
            "8\n",
            "vaesdec ",
            $p,
            "4, ",
            $p,
            "4, ",
            $p,
            "8\n",
            "vaesdec ",
            $p,
            "5, ",
            $p,
            "5, ",
            $p,
            "8\n",
            "vaesdec ",
            $p,
            "6, ",
            $p,
            "6, ",
            $p,
            "8\n",
            "vaesdec ",
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

/// The last round, then each block combined with the ciphertext
/// before it and stored.
///
/// That block is the same bytes sixteen earlier in the buffer, and
/// nothing has been stored yet, so it is read from there. The first
/// register of the group is the exception: what comes before it is
/// the chaining block, which `$first` brings in.
macro_rules! finish {
    ($p:literal, $w:literal, $span:literal, $bc:literal,
     $first:expr) => {
        concat!(
            $bc,
            " ",
            $p,
            "8, [{k}]\n",
            "vaesdeclast ",
            $p,
            "0, ",
            $p,
            "0, ",
            $p,
            "8\n",
            "vaesdeclast ",
            $p,
            "1, ",
            $p,
            "1, ",
            $p,
            "8\n",
            "vaesdeclast ",
            $p,
            "2, ",
            $p,
            "2, ",
            $p,
            "8\n",
            "vaesdeclast ",
            $p,
            "3, ",
            $p,
            "3, ",
            $p,
            "8\n",
            "vaesdeclast ",
            $p,
            "4, ",
            $p,
            "4, ",
            $p,
            "8\n",
            "vaesdeclast ",
            $p,
            "5, ",
            $p,
            "5, ",
            $p,
            "8\n",
            "vaesdeclast ",
            $p,
            "6, ",
            $p,
            "6, ",
            $p,
            "8\n",
            "vaesdeclast ",
            $p,
            "7, ",
            $p,
            "7, ",
            $p,
            "8\n",
            $first,
            "vpxor ",
            $p,
            "1, ",
            $p,
            "1, [{data} + 1*",
            $w,
            " - 16]\n",
            "vpxor ",
            $p,
            "2, ",
            $p,
            "2, [{data} + 2*",
            $w,
            " - 16]\n",
            "vpxor ",
            $p,
            "3, ",
            $p,
            "3, [{data} + 3*",
            $w,
            " - 16]\n",
            "vpxor ",
            $p,
            "4, ",
            $p,
            "4, [{data} + 4*",
            $w,
            " - 16]\n",
            "vpxor ",
            $p,
            "5, ",
            $p,
            "5, [{data} + 5*",
            $w,
            " - 16]\n",
            "vpxor ",
            $p,
            "6, ",
            $p,
            "6, [{data} + 6*",
            $w,
            " - 16]\n",
            "vpxor ",
            $p,
            "7, ",
            $p,
            "7, [{data} + 7*",
            $w,
            " - 16]\n",
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
            "vmovdqa xmm9, xmm10\n",
            "add {data}, ",
            $span,
            "\n",
        )
    };
}

/// Defines the decrypting loop at one width.
macro_rules! groups {
    ($name:ident, $p:literal, $w:literal, $span:literal, $bc:literal,
     $first:expr, $zero:literal) => {
        /// # Safety
        /// Requires AES-NI and AVX, and at the wider width VAES. `rk`
        /// must point at `rounds + 1` inverse round keys, `chain` at
        /// a block, and `data` at `groups` groups of writable bytes,
        /// with `groups >= 1`.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            chain: *mut u8,
            data: *mut u8,
            groups: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    "vmovdqu xmm9, [{chain}]",
                    "3:",
                    load!($p, $w, $span, $bc),
                    rounds!("2", $p, $bc),
                    finish!($p, $w, $span, $bc, $first),
                    "dec {groups}",
                    "jnz 3b",
                    "vmovdqu [{chain}], xmm9",
                    $zero,
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    chain = in(reg) chain,
                    data = inout(reg) data => _,
                    groups = inout(reg) groups => _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("ymm0") _, out("ymm1") _, out("ymm2") _,
                    out("ymm3") _, out("ymm4") _, out("ymm5") _,
                    out("ymm6") _, out("ymm7") _, out("ymm8") _,
                    out("ymm9") _, out("ymm10") _, out("ymm11") _,
                    options(nostack),
                );
            }
        }
    };
}

groups!(
    decrypt_groups,
    "xmm",
    "16",
    "128",
    "vmovdqu",
    "vpxor xmm0, xmm0, xmm9\n",
    ""
);

groups!(
    wide_decrypt_groups,
    "ymm",
    "32",
    "256",
    "vbroadcasti128",
    // The first register covers two blocks, so what comes before it
    // is the chaining block followed by the group's own first block:
    // one lane from each.
    concat!(
        "vperm2i128 ymm11, ymm9, [{data}], 0x20\n",
        "vpxor ymm0, ymm0, ymm11\n",
    ),
    // Leaving the upper halves dirty would slow down whatever plain
    // SSE code runs next, so they are cleared on the way out.
    "vzeroupper"
);

/// Defines the body for a tail of fewer blocks than a group, one to a
/// register.
///
/// The first register is combined with the chaining block, which is
/// in a register of its own; every later one with the ciphertext
/// sixteen bytes earlier, read from the buffer before anything is
/// stored over it.
macro_rules! tail {
    ($name:ident, $last:literal, [$(($r:literal, $off:literal)),*]) => {
        /// # Safety
        /// Requires AES-NI and AVX; `rk` must point at `rounds + 1`
        /// inverse round keys, `chain` at a block, and `data` at the
        /// blocks this body handles.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            chain: *mut u8,
            data: *mut u8,
        ) {
            unsafe {
                core::arch::asm!(
                    "vmovdqu xmm9, [{chain}]",
                    concat!("vmovdqu xmm10, [{data} + ", $last, "]"),
                    "vmovdqu xmm0, [{data}]",
                    $(concat!(
                        "vmovdqu ", $r, ", [{data} + ", $off, "]"),)*
                    "vmovdqu xmm8, [{rk}]",
                    "vpxor xmm0, xmm0, xmm8",
                    $(concat!("vpxor ", $r, ", ", $r, ", xmm8"),)*
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "vmovdqu xmm8, [{k}]",
                    "vaesdec xmm0, xmm0, xmm8",
                    $(concat!("vaesdec ", $r, ", ", $r, ", xmm8"),)*
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "vmovdqu xmm8, [{k}]",
                    "vaesdeclast xmm0, xmm0, xmm8",
                    $(concat!("vaesdeclast ", $r, ", ", $r, ", xmm8"),)*
                    "vpxor xmm0, xmm0, xmm9",
                    $(concat!(
                        "vpxor ", $r, ", ", $r, ", [{data} + ", $off,
                        " - 16]"),)*
                    "vmovdqu [{data}], xmm0",
                    $(concat!(
                        "vmovdqu [{data} + ", $off, "], ", $r),)*
                    "vmovdqu [{chain}], xmm10",
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    chain = in(reg) chain,
                    data = in(reg) data,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm8") _, out("xmm9") _,
                    out("xmm10") _,
                    options(nostack),
                );
            }
        }
    };
}

tail!(tail1, "0", []);
tail!(tail2, "16", [("xmm1", "16")]);
tail!(tail3, "32", [("xmm1", "16"), ("xmm2", "32")]);
tail!(
    tail4,
    "48",
    [("xmm1", "16"), ("xmm2", "32"), ("xmm3", "48")]
);
tail!(
    tail5,
    "64",
    [
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
tail!(
    tail6,
    "80",
    [
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80")
    ]
);
tail!(
    tail7,
    "96",
    [
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80"),
        ("xmm6", "96")
    ]
);

/// The bodies by block count, so a tail of `n` blocks is one pass.
static TAILS: [unsafe fn(*const u32, usize, *mut u8, *mut u8); 7] =
    [tail1, tail2, tail3, tail4, tail5, tail6, tail7];
