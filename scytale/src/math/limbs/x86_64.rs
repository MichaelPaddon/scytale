//! The Montgomery product on the ADX and BMI2 instructions.
//!
//! `mulx` multiplies without touching the flags, and `adcx` and
//! `adox` add with a carry each in a flag of its own, so a column of
//! the product can carry two chains at once: one folding the low
//! halves of the products in, the other the high halves into the
//! limb above. That is the multiply the `u128` code spells out one
//! carry at a time, with half the dependent steps.
//!
//! The work goes four rows at a time. A [`block`] takes four limbs of
//! the multiplier and the four reduction words they call for, and
//! walks the columns of the running value once, eight products a
//! column, so each word of it is read and written once per four rows
//! rather than twice per row; the loads and stores are what a row at
//! a time spends its issue width on. The limbs left over after the
//! blocks, and everything below five limbs, go a [`row`] at a time.
//!
//! The length is a run-time value, so nothing is unrolled over it.
//! Every step happens whatever the operands are, which is what keeps
//! a secret out of the timing.

#![allow(unsafe_code)]

use core::arch::x86_64::__cpuid_count;

use crate::probe::Probe;

/// The multiply, where the processor has it. A value exists only by
/// way of [`probe`], so holding one is holding the proof that the
/// instructions are there, and the call on it is safe.
#[derive(Clone, Copy)]
pub(super) struct Adx(());

/// The multiply, where the processor reports ADX (CPUID leaf 7, EBX
/// bit 19) and BMI2 for `mulx` (bit 8). Asked once.
pub(super) fn probe() -> Option<Adx> {
    ADX.yes(ask).then_some(Adx(()))
}

/// Kept: a modulus view is made for every operation.
static ADX: Probe = Probe::new();

fn ask() -> bool {
    let ebx = __cpuid_count(7, 0).ebx;
    ebx & (1 << 19) != 0 && ebx & (1 << 8) != 0
}

impl Adx {
    /// `t = a * b / R mod n` before its final subtraction: the rows
    /// of coarsely integrated operand scanning, leaving the result,
    /// which is below `2n`, in `t` and returning the word above it.
    /// All four slices are one length, at least one limb, and `t`
    /// may not alias the others.
    pub(super) fn rows(
        self,
        a: &[u64],
        b: &[u64],
        n: &[u64],
        inv: u64,
        t: &mut [u64],
    ) -> u64 {
        let limbs = n.len();
        debug_assert!(limbs >= 1);
        debug_assert!(a.len() == limbs && b.len() == limbs && t.len() == limbs);
        t.fill(0);
        let mut hi = 0u64;
        // A block walks columns four to the end, so it wants a fifth
        // limb to have a column to walk.
        let (blocks, rows) = if limbs >= 5 {
            let blocks = limbs & !3;
            (&a[..blocks], &a[blocks..])
        } else {
            (&a[..0], a)
        };
        for four in blocks.chunks_exact(4) {
            // SAFETY: `self` was minted by `probe`, which confirmed
            // the instructions; `four` is four words, the slices are
            // `limbs` words each, and `limbs` is at least five.
            unsafe {
                hi = block(four, b, n, inv, t, hi);
            }
        }
        for &ai in rows {
            // SAFETY: as above; every pointer walks exactly `limbs`
            // words of a slice that long.
            unsafe {
                hi = row(ai, b, n, inv, t, hi);
            }
        }
        hi
    }
}

/// One product of the multiplier in `rdx` into the window: the low
/// half on the CF chain into `$lo`, the high half on the OF chain
/// into `$hi`, the limb above it.
macro_rules! product {
    ($src:literal, $lo:literal, $hi:literal) => {
        concat!(
            "mulx r11, rax, qword ptr ",
            $src,
            "\n",
            "adcx ",
            $lo,
            ", rax\n",
            "adox ",
            $hi,
            ", r11\n",
        )
    };
}

/// Four products of the multiplier in `rdx` by the four words at the
/// sources, into five limbs of the window, then both chains' carries
/// folded into the fifth and sixth limbs so that the chains are
/// clear for the next four. The sixth limb holds at most a small
/// count, so nothing carries out of it.
macro_rules! four {
    (
        $s0:literal, $s1:literal, $s2:literal, $s3:literal,
        $w0:literal, $w1:literal, $w2:literal, $w3:literal,
        $w4:literal, $w5:literal
    ) => {
        concat!(
            product!($s0, $w0, $w1),
            product!($s1, $w1, $w2),
            product!($s2, $w2, $w3),
            product!($s3, $w3, $w4),
            "mov eax, 0\n",
            "adcx ",
            $w4,
            ", rax\n",
            "adox ",
            $w5,
            ", rax\n",
            "adcx ",
            $w5,
            ", rax\n",
        )
    };
}

/// The reduction word for the limb in `$w`, kept at `$at` on the
/// stack for the columns to come. `imul` writes the flags, so they
/// are cleared again before the next chain starts.
macro_rules! reduction_word {
    ($w:literal, $at:literal) => {
        concat!(
            "mov rdx, ",
            $w,
            "\n",
            "imul rdx, qword ptr [rsp + 64]\n",
            "mov qword ptr [rsp + ",
            $at,
            "], rdx\n",
            "xor eax, eax\n",
        )
    };
}

/// One column of the block: the limb of t that lands here, the four
/// products of a with this limb of b, the four of m with this limb
/// of n, and the finished limb out, four places down. The column is
/// `$off` bytes past the count, and the six window registers are
/// given in order from the bottom, the top being the fresh one: its
/// xor gives it a clear value and clears both chains.
macro_rules! column {
    (
        $off:literal, $w0:literal, $w1:literal, $w2:literal,
        $w3:literal, $w4:literal, $w5:literal
    ) => {
        concat!(
            "xor ",
            $w5,
            "d, ",
            $w5,
            "d\n",
            "mov rdx, qword ptr [rsi + r10 * 8 + ",
            $off,
            "]\n",
            "adox ",
            $w0,
            ", qword ptr [rcx + r10 * 8 + ",
            $off,
            "]\n",
            four!(
                "[rsp]",
                "[rsp + 8]",
                "[rsp + 16]",
                "[rsp + 24]",
                $w0,
                $w1,
                $w2,
                $w3,
                $w4,
                $w5
            ),
            "mov rdx, qword ptr [rdi + r10 * 8 + ",
            $off,
            "]\n",
            four!(
                "[rsp + 32]",
                "[rsp + 40]",
                "[rsp + 48]",
                "[rsp + 56]",
                $w0,
                $w1,
                $w2,
                $w3,
                $w4,
                $w5
            ),
            "mov qword ptr [rcx + r10 * 8 + ",
            $off,
            " - 32], ",
            $w0,
            "\n",
        )
    };
}

/// Four rows at once: `t = (t + a * b + m * n) / 2^256` for the four
/// limbs of `a` and the `m` of four words that clears the low four
/// limbs, with `hi` the word above `t` in and out.
///
/// The running value is walked by column, with the five limbs in
/// flight and a carry word held in registers as a window that
/// slides up one limb a column. The first four columns are done a
/// row at a time, since each reduction word is the value of its
/// column once the rows before it are in; those columns come out
/// zero and are dropped. From the fifth column on, one pass adds the
/// eight products that land there, stores the finished limb four
/// places down, and moves on. The four limbs of `a` and the four
/// reduction words are the multiplicands, read from the stack, since
/// the window, the pointers and the count take every register there
/// is.
///
/// Both chains are live across a column, so nothing in one may touch
/// the flags; the count moves at the column's end, where the chains
/// have been folded in.
///
/// # Safety
/// Requires ADX and BMI2. `a` must be four words; `b`, `n` and `t`
/// must be `limbs` words each, with `limbs` at least five.
unsafe fn block(
    a: &[u64],
    b: &[u64],
    n: &[u64],
    inv: u64,
    t: &mut [u64],
    hi: u64,
) -> u64 {
    debug_assert!(a.len() == 4 && n.len() >= 5);
    let hi_out: u64;
    unsafe {
        core::arch::asm!(
            // The stack holds a, the reduction words as they are
            // found, `inv` and the word above.
            "sub rsp, 80",
            "mov qword ptr [rsp + 64], r8",
            "mov qword ptr [rsp + 72], r9",
            "mov rax, qword ptr [r12]",
            "mov qword ptr [rsp], rax",
            "mov rax, qword ptr [r12 + 8]",
            "mov qword ptr [rsp + 8], rax",
            "mov rax, qword ptr [r12 + 16]",
            "mov qword ptr [rsp + 16], rax",
            "mov rax, qword ptr [r12 + 24]",
            "mov qword ptr [rsp + 24], rax",
            // The window starts as the low four limbs of t and two
            // clear limbs; the xor clears the chains as well.
            "mov r12, qword ptr [rcx]",
            "mov r13, qword ptr [rcx + 8]",
            "mov r14, qword ptr [rcx + 16]",
            "mov r15, qword ptr [rcx + 24]",
            "xor r8d, r8d",
            "xor r9d, r9d",
            // Row by row over the low four columns. Each row starts
            // one limb up, and the limb it leaves behind, which is
            // zero, is the fresh top of the window for the row two
            // on: the six registers rotate.
            "mov rdx, qword ptr [rsp]",
            four!(
                "[rsi]", "[rsi + 8]", "[rsi + 16]", "[rsi + 24]",
                "r12", "r13", "r14", "r15", "r8", "r9"
            ),
            reduction_word!("r12", "32"),
            four!(
                "[rdi]", "[rdi + 8]", "[rdi + 16]", "[rdi + 24]",
                "r12", "r13", "r14", "r15", "r8", "r9"
            ),
            "mov rdx, qword ptr [rsp + 8]",
            four!(
                "[rsi]", "[rsi + 8]", "[rsi + 16]", "[rsi + 24]",
                "r13", "r14", "r15", "r8", "r9", "r12"
            ),
            reduction_word!("r13", "40"),
            four!(
                "[rdi]", "[rdi + 8]", "[rdi + 16]", "[rdi + 24]",
                "r13", "r14", "r15", "r8", "r9", "r12"
            ),
            "mov rdx, qword ptr [rsp + 16]",
            four!(
                "[rsi]", "[rsi + 8]", "[rsi + 16]", "[rsi + 24]",
                "r14", "r15", "r8", "r9", "r12", "r13"
            ),
            reduction_word!("r14", "48"),
            four!(
                "[rdi]", "[rdi + 8]", "[rdi + 16]", "[rdi + 24]",
                "r14", "r15", "r8", "r9", "r12", "r13"
            ),
            "mov rdx, qword ptr [rsp + 24]",
            four!(
                "[rsi]", "[rsi + 8]", "[rsi + 16]", "[rsi + 24]",
                "r15", "r8", "r9", "r12", "r13", "r14"
            ),
            reduction_word!("r15", "56"),
            four!(
                "[rdi]", "[rdi + 8]", "[rdi + 16]", "[rdi + 24]",
                "r15", "r8", "r9", "r12", "r13", "r14"
            ),
            // The pointers move to the end and the count is the
            // columns left, counted up to zero, so that one register
            // indexes all three and the loop closes on it without
            // a compare.
            "lea r11, [r10 * 8]",
            "add rsi, r11",
            "add rdi, r11",
            "add rcx, r11",
            "neg r10",
            "add r10, 4",
            // Six columns a pass, so that the window slides by
            // renaming, then the columns left one at a time with the
            // window slid by moves.
            "2:",
            "cmp r10, -6",
            "jg 3f",
            column!("0", "r8", "r9", "r12", "r13", "r14", "r15"),
            column!("8", "r9", "r12", "r13", "r14", "r15", "r8"),
            column!("16", "r12", "r13", "r14", "r15", "r8", "r9"),
            column!("24", "r13", "r14", "r15", "r8", "r9", "r12"),
            column!("32", "r14", "r15", "r8", "r9", "r12", "r13"),
            column!("40", "r15", "r8", "r9", "r12", "r13", "r14"),
            "add r10, 6",
            "jmp 2b",
            "3:",
            "test r10, r10",
            "jz 5f",
            "4:",
            column!("0", "r8", "r9", "r12", "r13", "r14", "r15"),
            "mov r8, r9",
            "mov r9, r12",
            "mov r12, r13",
            "mov r13, r14",
            "mov r14, r15",
            "inc r10",
            "jnz 4b",
            "5:",
            // The word that was above t belongs to the column past
            // the end, the first of the four still in the window
            // after its last slide.
            "add r8, qword ptr [rsp + 72]",
            "adc r9, 0",
            "adc r12, 0",
            "adc r13, 0",
            "adc r14, 0",
            "mov qword ptr [rcx - 32], r8",
            "mov qword ptr [rcx - 24], r9",
            "mov qword ptr [rcx - 16], r12",
            "mov qword ptr [rcx - 8], r13",
            "mov rax, r14",
            "add rsp, 80",
            inout("rsi") b.as_ptr() => _,
            inout("rdi") n.as_ptr() => _,
            inout("rcx") t.as_mut_ptr() => _,
            inout("r12") a.as_ptr() => _,
            inout("r10") n.len() => _,
            inout("r8") inv => _,
            inout("r9") hi => _,
            out("rax") hi_out,
            out("rdx") _, out("r11") _, out("r13") _, out("r14") _,
            out("r15") _,
        );
    }
    hi_out
}

/// One limb of the first loop: `t[j] += ai * b[j]`, with the
/// product's high half carried into the next limb on CF and the
/// running sum on OF.
macro_rules! accumulate {
    ($off:literal) => {
        concat!(
            "mulx r9, r8, qword ptr [{b} + r11 + ",
            $off,
            "]\n",
            "adcx r8, r10\n",
            "adox r8, qword ptr [{t} + r11 + ",
            $off,
            "]\n",
            "mov qword ptr [{t} + r11 + ",
            $off,
            "], r8\n",
            "mov r10, r9\n",
        )
    };
}

/// One limb of the second loop: `t[j] += m * n[j]`, landing one
/// place down.
macro_rules! reduce {
    ($off:literal) => {
        concat!(
            "mulx r9, r8, qword ptr [{n} + rax + ",
            $off,
            "]\n",
            "adcx r8, r11\n",
            "adox r8, qword ptr [{t} + rax + ",
            $off,
            "]\n",
            "mov qword ptr [{t} + rax + ",
            $off,
            " - 8], r8\n",
            "mov r11, r9\n",
        )
    };
}

/// One row: `t += ai * b`, then `t = (t + m * n) / 2^64` for the `m`
/// that clears the low limb, with `hi` the word above `t` in and out.
///
/// Each of the two multiply-accumulate loops keeps its two chains
/// in CF and OF, so nothing inside the loop may touch the flags: the
/// pointers and the counter move by `lea`, and the loop closes on
/// `jrcxz`, which reads the counter and not the flags. That is two
/// taken branches a pass, which is why a pass is four limbs, with a
/// second loop for the limbs left over.
///
/// # Safety
/// Requires ADX and BMI2. `b`, `n` and `t` must be `limbs` words
/// each, with `limbs` at least one.
unsafe fn row(
    ai: u64,
    b: &[u64],
    n: &[u64],
    inv: u64,
    t: &mut [u64],
    hi: u64,
) -> u64 {
    let mut limbs = n.len();
    let mut hi = hi;
    unsafe {
        core::arch::asm!(
            // t += ai * b, four limbs a pass and then the rest. The
            // counts are worked out while the flags are still free.
            "mov rax, {limbs}",
            "and rax, 7",
            "mov rcx, {limbs}",
            "shr rcx, 3",
            "xor r10d, r10d",
            "xor r11d, r11d",
            // `jrcxz` reaches only 127 bytes, which a pass exceeds,
            // so it jumps to a trampoline placed within reach.
            "jmp 2f",
            "20:",
            "jmp 3f",
            "2:",
            "jrcxz 20b",
            accumulate!("0"),
            accumulate!("8"),
            accumulate!("16"),
            accumulate!("24"),
            accumulate!("32"),
            accumulate!("40"),
            accumulate!("48"),
            accumulate!("56"),
            "lea r11, [r11 + 64]",
            "lea rcx, [rcx - 1]",
            "jmp 2b",
            "3:",
            "mov rcx, rax",
            "jrcxz 5f",
            "4:",
            accumulate!("0"),
            "lea r11, [r11 + 8]",
            "lea rcx, [rcx - 1]",
            "jrcxz 5f",
            "jmp 4b",
            "5:",
            // The word above: the last high half, both chains' final
            // carries, and the word that was above before. What
            // overflows that is at most one, kept in {hi} for now.
            "mov eax, 0",
            "adcx r10, {hi}",
            "adox r10, rax",
            "setc al",
            "seto cl",
            "add al, cl",
            "movzx {hi}, al",
            // m = t[0] * inv, then t = (t + m * n) >> 64: the low limb
            // comes out zero and is dropped, each later limb lands one
            // place down, and the top limb is the word from above.
            // The counts are over `limbs - 1`, and are worked out
            // before the chains start; {limbs} keeps the remainder.
            "mov rdx, qword ptr [{t}]",
            "imul rdx, {inv}",
            "mov rcx, {limbs}",
            "lea rcx, [rcx - 1]",
            "mov {limbs}, rcx",
            "and {limbs}, 7",
            "shr rcx, 3",
            "xor eax, eax",
            "mulx r9, r8, qword ptr [{n}]",
            "adcx r8, qword ptr [{t}]",
            "mov r11, r9",
            "jmp 6f",
            "21:",
            "jmp 7f",
            "6:",
            "jrcxz 21b",
            "lea rax, [rax + 64]",
            reduce!("-56"),
            reduce!("-48"),
            reduce!("-40"),
            reduce!("-32"),
            reduce!("-24"),
            reduce!("-16"),
            reduce!("-8"),
            reduce!("0"),
            "lea rcx, [rcx - 1]",
            "jmp 6b",
            "7:",
            "mov rcx, {limbs}",
            "jrcxz 9f",
            "8:",
            "lea rax, [rax + 8]",
            reduce!("0"),
            "lea rcx, [rcx - 1]",
            "jrcxz 9f",
            "jmp 8b",
            "9:",
            "adcx r11, r10",
            "mov r8d, 0",
            "adox r11, r8",
            "mov qword ptr [{t} + rax], r11",
            "setc r8b",
            "seto r9b",
            "add r8b, r9b",
            "movzx r8, r8b",
            "add {hi}, r8",
            b = in(reg) b.as_ptr(),
            n = in(reg) n.as_ptr(),
            t = in(reg) t.as_mut_ptr(),
            limbs = inout(reg) limbs,
            inv = in(reg) inv,
            hi = inout(reg) hi,
            in("rdx") ai,
            out("rax") _, out("rcx") _, out("r8") _, out("r9") _,
            out("r10") _, out("r11") _,
            options(nostack),
        );
    }
    let _ = limbs;
    hi
}
