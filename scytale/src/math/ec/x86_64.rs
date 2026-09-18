//! The P-256 point operations on the ADX and BMI2 instructions.
//!
//! The field product is already written out for this processor, but
//! a doubling is eight of those and sixteen modular additions, and
//! the additions are where the time went: each product is an
//! assembly block that clobbers every register, so the compiler
//! spills the point around every one of them, and the sums were
//! costing as much as the products. Measured on an i7-1355U: a
//! doubling of 1867 instructions where its eight products are 960.
//!
//! So a doubling is one block, start to finish. Its values live in a
//! frame the caller lends it, every operation reads and writes that
//! frame, and no register has to survive anything. The frame is
//! `SLOTS` values of four limbs; the caller puts the point in the
//! first three and reads the result from the last three.
//!
//! The arithmetic is the module's own, in the same order: nothing
//! here is a different formula, only the same one without the
//! spilling. No branch and no address depends on a value.

#![allow(unsafe_code)]

use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

use crate::math::montgomery::x86_64::Adx;
use crate::math::uint::Uint;
use crate::probe::Probe;

use super::{Affine, Jacobian};

/// Four-limb values in the frame a point operation works in.
pub(crate) const SLOTS: usize = 21;

/// The table read, where the processor has the instructions. A value
/// exists only by way of [`probe`], so holding one is the proof.
#[derive(Clone, Copy)]
pub(crate) struct Avx2(());

/// AVX2 (CPUID leaf 7, EBX bit 5) with the operating system saving
/// the upper halves of the registers (XCR0 bits 1 and 2). Asked once.
pub(crate) fn probe() -> Option<Avx2> {
    AVX2.yes(ask).then_some(Avx2(()))
}

/// Kept: every curve operation asks.
static AVX2: Probe = Probe::new();

fn ask() -> bool {
    let leaf1 = __cpuid(1);
    let wanted = (1 << 27) | (1 << 28);
    if leaf1.ecx & wanted != wanted {
        return false;
    }
    if __cpuid_count(7, 0).ebx & (1 << 5) == 0 {
        return false;
    }
    // SAFETY: OSXSAVE was just confirmed, so XGETBV is available.
    let xcr0 = unsafe { _xgetbv(0) };
    xcr0 & 0b110 == 0b110
}

impl Avx2 {
    /// The entry of `table` whose position, counted from one, is
    /// `digit`, or zero where the digit names none. Four-limb
    /// entries only.
    ///
    /// The compiler makes the same scan into 128-bit selects; this
    /// one is 256 bits wide, which halves the work on the 64-entry
    /// tables the fixed-base multiplication reads. It is worth it
    /// only there: on the 16-entry table the variable-base one
    /// builds, entering and leaving the block costs more than the
    /// scan saves, which is why nothing else calls this.
    #[inline(always)]
    pub(super) fn select<const L: usize>(
        self,
        table: &[[[u64; L]; 2]],
        digit: u64,
    ) -> (Uint<L>, Uint<L>) {
        debug_assert_eq!(L, 4);
        let mut out = [Uint::<L>::ZERO; 2];
        // SAFETY: `self` came from `probe`, so the instructions are
        // there; the entries are four limbs, which is what the caller
        // holding one stands for, and the count is the table's own.
        unsafe {
            select(
                table.as_ptr().cast::<u64>(),
                table.len(),
                digit,
                out.as_mut_ptr().cast::<u64>(),
            );
        }
        (out[0], out[1])
    }
}

/// Scans `count` entries of eight words each, keeping the one whose
/// position counted from one is `digit`. Every entry is read whatever
/// the digit is, and the comparison is on the counter, so no address
/// and no branch depends on it.
///
/// # Safety
/// Requires AVX2. `table` must point at `count * 8` words with
/// `count >= 1`, and `out` at eight.
unsafe fn select(table: *const u64, count: usize, digit: u64, out: *mut u64) {
    unsafe {
        core::arch::asm!(
            // The two halves of the entry kept so far, and the digit
            // in every lane to compare the counter against.
            "vpxor ymm0, ymm0, ymm0",
            "vpxor ymm1, ymm1, ymm1",
            "vmovq xmm2, {digit}",
            "vpbroadcastq ymm2, xmm2",
            "vpcmpeqq ymm5, ymm5, ymm5",
            // The counter, one in every lane, and the step.
            "vpsrlq ymm4, ymm5, 63",
            "vmovdqa ymm3, ymm4",
            "2:",
            // All ones where this is the entry wanted, which the
            // blend then takes byte by byte.
            "vpcmpeqq ymm6, ymm3, ymm2",
            "vmovdqu ymm7, [{table}]",
            "vmovdqu ymm8, [{table} + 32]",
            "vpblendvb ymm0, ymm0, ymm7, ymm6",
            "vpblendvb ymm1, ymm1, ymm8, ymm6",
            "vpaddq ymm3, ymm3, ymm4",
            "add {table}, 64",
            "dec {count}",
            "jnz 2b",
            "vmovdqu [{out}], ymm0",
            "vmovdqu [{out} + 32], ymm1",
            "vzeroupper",
            table = inout(reg) table => _,
            count = inout(reg) count => _,
            digit = in(reg) digit,
            out = in(reg) out,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _,
            options(nostack),
        );
    }
}

/// One value moved between two bases, four words at a time.
#[rustfmt::skip]
macro_rules! copy {
    ($from:literal, $i:literal, $to:literal, $j:literal) => {
        concat!(
            "mov rax, qword ptr [", $from, " + ", $i, " * 32]\n",
            "mov rdx, qword ptr [", $from, " + ", $i, " * 32 + 8]\n",
            "mov r8, qword ptr [", $from, " + ", $i, " * 32 + 16]\n",
            "mov r9, qword ptr [", $from, " + ", $i, " * 32 + 24]\n",
            "mov qword ptr [", $to, " + ", $j, " * 32], rax\n",
            "mov qword ptr [", $to, " + ", $j, " * 32 + 8], rdx\n",
            "mov qword ptr [", $to, " + ", $j, " * 32 + 16], r8\n",
            "mov qword ptr [", $to, " + ", $j, " * 32 + 24], r9\n",
        )
    };
}

/// `dst = a + b mod p`, every operand a slot of the frame.
///
/// The sum is below twice the prime, so one subtraction settles it:
/// taken unless it borrowed while the sum itself did not carry out.
/// The moves and the constants between the borrows leave the flags
/// alone, so the chain walks through them.
#[rustfmt::skip]
macro_rules! fadd {
    ($dst:literal, $a:literal, $b:literal) => {
        concat!(
            "mov r8, qword ptr [rsp + ", $a, " * 32]\n",
            "mov r9, qword ptr [rsp + ", $a, " * 32 + 8]\n",
            "mov r10, qword ptr [rsp + ", $a, " * 32 + 16]\n",
            "mov r11, qword ptr [rsp + ", $a, " * 32 + 24]\n",
            "add r8, qword ptr [rsp + ", $b, " * 32]\n",
            "adc r9, qword ptr [rsp + ", $b, " * 32 + 8]\n",
            "adc r10, qword ptr [rsp + ", $b, " * 32 + 16]\n",
            "adc r11, qword ptr [rsp + ", $b, " * 32 + 24]\n",
            "sbb rcx, rcx\n",
            "mov rax, r8\n",
            "sub rax, -1\n",
            "mov edi, -1\n",
            "mov rdx, r9\n",
            "sbb rdx, rdi\n",
            "mov rdi, r10\n",
            "sbb rdi, 0\n",
            "mov rsi, r11\n",
            "sbb rsi, r15\n",
            "sbb rcx, 0\n",
            "cmovnc r8, rax\n",
            "cmovnc r9, rdx\n",
            "cmovnc r10, rdi\n",
            "cmovnc r11, rsi\n",
            "mov qword ptr [rsp + ", $dst, " * 32], r8\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 8], r9\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 16], r10\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 24], r11\n",
        )
    };
}

/// `dst = a - b mod p`. Where it borrowed, the prime goes back on,
/// its words masked before the chain begins since the masking would
/// clear the borrow.
#[rustfmt::skip]
macro_rules! fsub {
    ($dst:literal, $a:literal, $b:literal) => {
        concat!(
            "mov r8, qword ptr [rsp + ", $a, " * 32]\n",
            "mov r9, qword ptr [rsp + ", $a, " * 32 + 8]\n",
            "mov r10, qword ptr [rsp + ", $a, " * 32 + 16]\n",
            "mov r11, qword ptr [rsp + ", $a, " * 32 + 24]\n",
            "sub r8, qword ptr [rsp + ", $b, " * 32]\n",
            "sbb r9, qword ptr [rsp + ", $b, " * 32 + 8]\n",
            "sbb r10, qword ptr [rsp + ", $b, " * 32 + 16]\n",
            "sbb r11, qword ptr [rsp + ", $b, " * 32 + 24]\n",
            "sbb rax, rax\n",
            "mov rcx, rax\n",
            "mov edx, -1\n",
            "and rdx, rax\n",
            "mov rsi, r15\n",
            "and rsi, rax\n",
            "add r8, rcx\n",
            "adc r9, rdx\n",
            "adc r10, 0\n",
            "adc r11, rsi\n",
            "mov qword ptr [rsp + ", $dst, " * 32], r8\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 8], r9\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 16], r10\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 24], r11\n",
        )
    };
}

/// A value held in `r8..r11` between operations, rather than put
/// back in the frame for the next one to fetch: a store and a load
/// with a forwarding stall between them, on the critical path, for
/// every step of a formula that feeds the next.
///
/// These four take the held value as their left operand and leave
/// the result in it.
#[rustfmt::skip]
macro_rules! addr {
    ($b:literal) => {
        concat!(
            "add r8, qword ptr [rsp + ", $b, " * 32]\n",
            "adc r9, qword ptr [rsp + ", $b, " * 32 + 8]\n",
            "adc r10, qword ptr [rsp + ", $b, " * 32 + 16]\n",
            "adc r11, qword ptr [rsp + ", $b, " * 32 + 24]\n",
            trim!(),
        )
    };
}

/// The held value doubled.
#[rustfmt::skip]
macro_rules! dblr {
    () => {
        concat!(
            "add r8, r8\n",
            "adc r9, r9\n",
            "adc r10, r10\n",
            "adc r11, r11\n",
            trim!(),
        )
    };
}

/// The prime taken off a sum that is below twice it, kept unless
/// that borrowed while the sum itself did not carry out.
#[rustfmt::skip]
macro_rules! trim {
    () => {
        concat!(
            "sbb rcx, rcx\n",
            "mov rax, r8\n",
            "sub rax, -1\n",
            "mov edi, -1\n",
            "mov rdx, r9\n",
            "sbb rdx, rdi\n",
            "mov rdi, r10\n",
            "sbb rdi, 0\n",
            "mov rsi, r11\n",
            "sbb rsi, r15\n",
            "sbb rcx, 0\n",
            "cmovnc r8, rax\n",
            "cmovnc r9, rdx\n",
            "cmovnc r10, rdi\n",
            "cmovnc r11, rsi\n",
        )
    };
}

/// The held value less a slot of the frame.
#[rustfmt::skip]
macro_rules! subr {
    ($b:literal) => {
        concat!(
            "sub r8, qword ptr [rsp + ", $b, " * 32]\n",
            "sbb r9, qword ptr [rsp + ", $b, " * 32 + 8]\n",
            "sbb r10, qword ptr [rsp + ", $b, " * 32 + 16]\n",
            "sbb r11, qword ptr [rsp + ", $b, " * 32 + 24]\n",
            // Where it borrowed, the prime goes back on, its words
            // masked before the chain begins.
            "sbb rax, rax\n",
            "mov rcx, rax\n",
            "mov edx, -1\n",
            "and rdx, rax\n",
            "mov rsi, r15\n",
            "and rsi, rax\n",
            "add r8, rcx\n",
            "adc r9, rdx\n",
            "adc r10, 0\n",
            "adc r11, rsi\n",
        )
    };
}

/// A slot of the frame into the held value, and back.
#[rustfmt::skip]
macro_rules! loadr {
    ($a:literal) => {
        concat!(
            "mov r8, qword ptr [rsp + ", $a, " * 32]\n",
            "mov r9, qword ptr [rsp + ", $a, " * 32 + 8]\n",
            "mov r10, qword ptr [rsp + ", $a, " * 32 + 16]\n",
            "mov r11, qword ptr [rsp + ", $a, " * 32 + 24]\n",
        )
    };
}

#[rustfmt::skip]
macro_rules! storer {
    ($dst:literal) => {
        concat!(
            "mov qword ptr [rsp + ", $dst, " * 32], r8\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 8], r9\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 16], r10\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 24], r11\n",
        )
    };
}

/// One row of the product: limb `$i` of `b` against every limb of
/// `a`, folded into the running value on the two carry chains, then
/// the reduction by the new low word. The shifts are `shlx` and
/// `shrx`, which leave the flags alone, so they sit inside the
/// chain; `r14` holds 32 and `r15` the prime's top limb.
#[rustfmt::skip]
macro_rules! row {
    ($a:literal, $b:literal, $i:literal, $w0:literal, $w1:literal,
     $w2:literal, $w3:literal, $w4:literal, $z:literal) => {
        concat!(
            // Clears both flags as well as the word.
            "xor ", $z, "d, ", $z, "d\n",
            "mov rdx, qword ptr [rsp + ", $b, " * 32 + ", $i, " * 8]\n",
            "mulx rdi, rax, qword ptr [rsp + ", $a, " * 32]\n",
            "adcx ", $w0, ", rax\n",
            "adox ", $w1, ", rdi\n",
            "mulx rdi, rax, qword ptr [rsp + ", $a, " * 32 + 8]\n",
            "adcx ", $w1, ", rax\n",
            "adox ", $w2, ", rdi\n",
            "mulx rdi, rax, qword ptr [rsp + ", $a, " * 32 + 16]\n",
            "adcx ", $w2, ", rax\n",
            "adox ", $w3, ", rdi\n",
            "mulx rdi, rax, qword ptr [rsp + ", $a, " * 32 + 24]\n",
            "mov rdx, ", $w0, "\n",
            "adcx ", $w3, ", rax\n",
            "shlx rax, ", $w0, ", r14\n",
            "adox ", $w4, ", rdi\n",
            "shrx rdi, ", $w0, ", r14\n",
            // Both chains' last carries into the sixth word.
            "adcx ", $w4, ", ", $z, "\n",
            "adox ", $z, ", ", $z, "\n",
            "adc ", $z, ", 0\n",
            // The reduction, whose shifts are done already.
            "add ", $w1, ", rax\n",
            "adc ", $w2, ", rdi\n",
            "mulx rdi, rax, r15\n",
            "adc ", $w3, ", rax\n",
            "adc ", $w4, ", rdi\n",
            "adc ", $z, ", 0\n",
        )
    };
}

/// The reduction alone, for the first row, which has nothing to add
/// its products into.
#[rustfmt::skip]
macro_rules! reduce {
    ($w0:literal, $w1:literal, $w2:literal, $w3:literal, $w4:literal,
     $z:literal) => {
        concat!(
            "mov rdx, ", $w0, "\n",
            "shlx rax, ", $w0, ", r14\n",
            "shrx rdi, ", $w0, ", r14\n",
            "add ", $w1, ", rax\n",
            "adc ", $w2, ", rdi\n",
            "mulx rdi, rax, r15\n",
            "adc ", $w3, ", rax\n",
            "adc ", $w4, ", rdi\n",
            "adc ", $z, ", 0\n",
        )
    };
}

/// The conditional subtraction that ends a product or a square: the
/// value is in `$w0..$w3` with a top word in `$z`, and below twice
/// the prime. The four temporaries and the one constant register
/// are named because the words they must not tread on differ.
#[rustfmt::skip]
macro_rules! settle {
    ($dst:literal, $w0:literal, $w1:literal, $w2:literal, $w3:literal,
     $z:literal, $t0:literal, $t1:literal, $t2:literal, $t3:literal,
     $c:literal, $cd:literal) => {
        concat!(
            "mov ", $t0, ", ", $w0, "\n",
            "sub ", $t0, ", -1\n",
            "mov ", $cd, ", -1\n",
            "mov ", $t1, ", ", $w1, "\n",
            "sbb ", $t1, ", ", $c, "\n",
            "mov ", $t2, ", ", $w2, "\n",
            "sbb ", $t2, ", 0\n",
            "mov ", $t3, ", ", $w3, "\n",
            "sbb ", $t3, ", r15\n",
            "sbb ", $z, ", 0\n",
            "cmovnc ", $w0, ", ", $t0, "\n",
            "cmovnc ", $w1, ", ", $t1, "\n",
            "cmovnc ", $w2, ", ", $t2, "\n",
            "cmovnc ", $w3, ", ", $t3, "\n",
            "mov qword ptr [rsp + ", $dst, " * 32], ", $w0, "\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 8], ", $w1, "\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 16], ", $w2, "\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 24], ", $w3, "\n",
        )
    };
}

/// The same conditional subtraction, leaving the value held in
/// `r8..r11` instead of putting it back in the frame. The moves run
/// from the top down, so a word is read before whatever overwrites
/// it.
#[rustfmt::skip]
macro_rules! settle_held {
    ($w0:literal, $w1:literal, $w2:literal, $w3:literal,
     $z:literal, $t0:literal, $t1:literal, $t2:literal, $t3:literal,
     $c:literal, $cd:literal) => {
        concat!(
            "mov ", $t0, ", ", $w0, "\n",
            "sub ", $t0, ", -1\n",
            "mov ", $cd, ", -1\n",
            "mov ", $t1, ", ", $w1, "\n",
            "sbb ", $t1, ", ", $c, "\n",
            "mov ", $t2, ", ", $w2, "\n",
            "sbb ", $t2, ", 0\n",
            "mov ", $t3, ", ", $w3, "\n",
            "sbb ", $t3, ", r15\n",
            "sbb ", $z, ", 0\n",
            "cmovnc ", $w0, ", ", $t0, "\n",
            "cmovnc ", $w1, ", ", $t1, "\n",
            "cmovnc ", $w2, ", ", $t2, "\n",
            "cmovnc ", $w3, ", ", $t3, "\n",
            "mov r11, ", $w3, "\n",
            "mov r10, ", $w2, "\n",
            "mov r9, ", $w1, "\n",
            "mov r8, ", $w0, "\n",
        )
    };
}

/// `dst = a b / 2^256 mod p`, every operand a slot of the frame.
/// Four rows of product and reduction, as
/// [`super::super::montgomery`] describes, with the running value in
/// `r8..r13`. The body is separate from its ending so that the
/// result can either go back to the frame or stay held.
#[rustfmt::skip]
macro_rules! fmul_body {
    ($a:literal, $b:literal) => {
        concat!(
            "mov rdx, qword ptr [rsp + ", $b, " * 32]\n",
            "mulx r9, r8, qword ptr [rsp + ", $a, " * 32]\n",
            "mulx r10, rax, qword ptr [rsp + ", $a, " * 32 + 8]\n",
            "mulx r11, rdi, qword ptr [rsp + ", $a, " * 32 + 16]\n",
            "add r9, rax\n",
            "mulx r12, rax, qword ptr [rsp + ", $a, " * 32 + 24]\n",
            "adc r10, rdi\n",
            "adc r11, rax\n",
            "adc r12, 0\n",
            "mov r13d, 0\n",
            reduce!("r8", "r9", "r10", "r11", "r12", "r13"),
            row!($a, $b, 1, "r9", "r10", "r11", "r12", "r13", "r8"),
            row!($a, $b, 2, "r10", "r11", "r12", "r13", "r8", "r9"),
            row!($a, $b, 3, "r11", "r12", "r13", "r8", "r9", "r10"),
        )
    };
}

/// The product, into a slot of the frame.
#[rustfmt::skip]
macro_rules! fmul {
    ($dst:literal, $a:literal, $b:literal) => {
        concat!(
            fmul_body!($a, $b),
            settle!($dst, "r12", "r13", "r8", "r9", "r10",
                    "rax", "rcx", "rdx", "rsi", "rdi", "edi"),
        )
    };
}

/// The product, held in `r8..r11`.
#[rustfmt::skip]
macro_rules! fmul_held {
    ($a:literal, $b:literal) => {
        concat!(
            fmul_body!($a, $b),
            settle_held!("r12", "r13", "r8", "r9", "r10",
                         "rax", "rcx", "rdx", "rsi", "rdi", "edi"),
        )
    };
}

/// `a a / 2^256 mod p`. The cross products once, then doubled,
/// then the limbs' own squares: ten products where the general
/// product spends sixteen. The whole eight-word product is formed
/// first, and the reduction then walks the low half, keeping each
/// step's carry word aside and adding the four of them to the high
/// half at the end.
#[rustfmt::skip]
macro_rules! fsqr_body {
    ($a:literal) => {
        concat!(
            // The cross products: a0 against the three above it,
            // then a1 against two, then a2 against one.
            "mov rdx, qword ptr [rsp + ", $a, " * 32]\n",
            "mulx r10, r9, qword ptr [rsp + ", $a, " * 32 + 8]\n",
            "mulx r11, rax, qword ptr [rsp + ", $a, " * 32 + 16]\n",
            "add r10, rax\n",
            "mulx r12, rax, qword ptr [rsp + ", $a, " * 32 + 24]\n",
            "adc r11, rax\n",
            "adc r12, 0\n",
            "xor r13d, r13d\n",
            "mov rdx, qword ptr [rsp + ", $a, " * 32 + 8]\n",
            "mulx rcx, rax, qword ptr [rsp + ", $a, " * 32 + 16]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx rcx, rax, qword ptr [rsp + ", $a, " * 32 + 24]\n",
            "adcx r12, rax\n",
            "adox r13, rcx\n",
            "mov esi, 0\n",
            "mov rdx, qword ptr [rsp + ", $a, " * 32 + 16]\n",
            "mulx rcx, rax, qword ptr [rsp + ", $a, " * 32 + 24]\n",
            "adcx r13, rax\n",
            "adox rsi, rcx\n",
            "mov eax, 0\n",
            "adcx rsi, rax\n",
            "adox rsi, rax\n",
            // Doubled, which is those products' other halves.
            "xor edi, edi\n",
            "add r9, r9\n",
            "adc r10, r10\n",
            "adc r11, r11\n",
            "adc r12, r12\n",
            "adc r13, r13\n",
            "adc rsi, rsi\n",
            "adc rdi, 0\n",
            // Then each limb's own square on the diagonal.
            "mov rdx, qword ptr [rsp + ", $a, " * 32]\n",
            "mulx rcx, r8, rdx\n",
            "add r9, rcx\n",
            "mov rdx, qword ptr [rsp + ", $a, " * 32 + 8]\n",
            "mulx rcx, rax, rdx\n",
            "adc r10, rax\n",
            "adc r11, rcx\n",
            "mov rdx, qword ptr [rsp + ", $a, " * 32 + 16]\n",
            "mulx rcx, rax, rdx\n",
            "adc r12, rax\n",
            "adc r13, rcx\n",
            "mov rdx, qword ptr [rsp + ", $a, " * 32 + 24]\n",
            "mulx rcx, rax, rdx\n",
            "adc rsi, rax\n",
            "adc rdi, rcx\n",
            // The reduction, four steps over the low half. The
            // multiplier is the prime's top limb throughout, so it
            // stays in rdx and each step's word is the other operand.
            "mov rdx, r15\n",
            "shlx rcx, r8, r14\n",
            "shrx rax, r8, r14\n",
            "add r9, rcx\n",
            "adc r10, rax\n",
            "mulx r8, rcx, r8\n",
            "adc r11, rcx\n",
            "adc r8, 0\n",
            "shlx rcx, r9, r14\n",
            "shrx rax, r9, r14\n",
            "add r10, rcx\n",
            "adc r11, rax\n",
            "mulx r9, rcx, r9\n",
            "adc r8, rcx\n",
            "adc r9, 0\n",
            "shlx rcx, r10, r14\n",
            "shrx rax, r10, r14\n",
            "add r11, rcx\n",
            "adc r8, rax\n",
            "mulx r10, rcx, r10\n",
            "adc r9, rcx\n",
            "adc r10, 0\n",
            "shlx rcx, r11, r14\n",
            "shrx rax, r11, r14\n",
            "add r8, rcx\n",
            "adc r9, rax\n",
            "mulx r11, rcx, r11\n",
            "adc r10, rcx\n",
            "adc r11, 0\n",
            // The four carry words onto the high half.
            "xor edx, edx\n",
            "add r12, r8\n",
            "adc r13, r9\n",
            "adc rsi, r10\n",
            "adc rdi, r11\n",
            "adc rdx, 0\n",
        )
    };
}

/// The square, into a slot of the frame.
#[rustfmt::skip]
macro_rules! fsqr {
    ($dst:literal, $a:literal) => {
        concat!(
            fsqr_body!($a),
            settle!($dst, "r12", "r13", "rsi", "rdi", "rdx",
                    "rax", "rcx", "r8", "r9", "r10", "r10d"),
        )
    };
}

/// The square, held in `r8..r11`.
#[rustfmt::skip]
macro_rules! fsqr_held {
    ($a:literal) => {
        concat!(
            fsqr_body!($a),
            settle_held!("r12", "r13", "rsi", "rdi", "rdx",
                         "rax", "rcx", "r8", "r9", "r10", "r10d"),
        )
    };
}

/// `dst` squared `$n` times in place, as a counted loop. The count
/// lives in the frame's last slot, every register being spoken for;
/// nothing that uses this macro uses that slot.
#[rustfmt::skip]
macro_rules! sqrn {
    ($dst:literal, $n:literal) => {
        concat!(
            "mov dword ptr [rsp + ", 20, " * 32], ", $n, "\n",
            "2:\n",
            fsqr!($dst, $dst),
            "dec dword ptr [rsp + ", 20, " * 32]\n",
            "jnz 2b\n",
        )
    };
}

/// One value copied to another slot of the frame.
#[rustfmt::skip]
macro_rules! keep {
    ($dst:literal, $src:literal) => {
        concat!(
            "mov rax, qword ptr [rsp + ", $src, " * 32]\n",
            "mov rdx, qword ptr [rsp + ", $src, " * 32 + 8]\n",
            "mov r8, qword ptr [rsp + ", $src, " * 32 + 16]\n",
            "mov r9, qword ptr [rsp + ", $src, " * 32 + 24]\n",
            "mov qword ptr [rsp + ", $dst, " * 32], rax\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 8], rdx\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 16], r8\n",
            "mov qword ptr [rsp + ", $dst, " * 32 + 24], r9\n",
        )
    };
}

/// The inverse of the value at `io`, into the value above it: `a`
/// to the power `p - 2`, which is `a^-1` for everything but zero,
/// and zero for that.
///
/// The exponent is `[32 ones][31 zeros][1][96 zeros][94 ones][0][1]`,
/// so the chain builds `a^(2^k - 1)` for `k` of 2, 4, 8, 16 and 32,
/// and then walks the exponent in those runs: 255 squarings and 13
/// multiplications, against the 295 operations a window slid over
/// the same exponent costs, and all of it in one block rather than
/// one call for each.
///
/// # Safety
/// Requires ADX and BMI2; `io` must point at two values of four
/// limbs, the first below the prime.
#[rustfmt::skip]
unsafe fn invert(io: *mut u64) {
    unsafe {
        core::arch::asm!(
            "movq xmm0, rcx",
            "sub rsp, {frame}",
            "mov r14d, 32",
            "mov r15, 0xffffffff00000001",
            copy!("rcx", 0, "rsp", 0),
            // The ladder: slot 2 is a^(2^2 - 1), slot 3 a^(2^4 - 1),
            // and so on to slot 6.
            keep!(7, 0),
            sqrn!(7, 1),
            fmul!(2, 7, 0),
            keep!(7, 2),
            sqrn!(7, 2),
            fmul!(3, 7, 2),
            keep!(7, 3),
            sqrn!(7, 4),
            fmul!(4, 7, 3),
            keep!(7, 4),
            sqrn!(7, 8),
            fmul!(5, 7, 4),
            keep!(7, 5),
            sqrn!(7, 16),
            fmul!(6, 7, 5),
            // The exponent, run by run.
            keep!(1, 6),
            sqrn!(1, 32),
            fmul!(1, 1, 0),
            sqrn!(1, 96),
            sqrn!(1, 32),
            fmul!(1, 1, 6),
            sqrn!(1, 32),
            fmul!(1, 1, 6),
            sqrn!(1, 16),
            fmul!(1, 1, 5),
            sqrn!(1, 8),
            fmul!(1, 1, 4),
            sqrn!(1, 4),
            fmul!(1, 1, 3),
            sqrn!(1, 2),
            fmul!(1, 1, 2),
            sqrn!(1, 2),
            fmul!(1, 1, 0),
            "movq rcx, xmm0",
            copy!("rsp", 1, "rcx", 1),
            "add rsp, {frame}",
            frame = const SLOTS * 32,
            inout("rcx") io => _,
            out("rax") _, out("rdx") _, out("rsi") _, out("rdi") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _, out("r15") _,
            out("xmm0") _,
        );
    }
}

/// Twice the point in the first three values at `io`, into the three
/// above them. The formula is [`super::Engine::jacobian_double`]'s,
/// with each step's result kept in registers where the next step
/// takes it.
///
/// # Safety
/// Requires ADX and BMI2; `io` must point at six values of four
/// limbs, the first three the point's coordinates, each below the
/// prime.
#[rustfmt::skip]
unsafe fn double(io: *mut u64) {
    unsafe {
        core::arch::asm!(
            // The frame is on the stack and addressed off the stack
            // pointer, so no register holds its base and all thirteen
            // are free for the arithmetic. The caller's buffer waits
            // in a vector register meanwhile.
            "movq xmm0, rcx",
            "sub rsp, {frame}",
            "mov r14d, 32",
            "mov r15, 0xffffffff00000001",
            copy!("rcx", 0, "rsp", 0),
            copy!("rcx", 1, "rsp", 1),
            copy!("rcx", 2, "rsp", 2),
            fsqr!(4, 1),                        // gamma = y^2
            fsqr!(3, 2),                        // delta = z^2
            fmul!(5, 0, 4),                     // beta = x gamma
            fadd!(7, 0, 3),                     // x + delta
            fsub!(6, 0, 3),                     // x - delta
            fsqr!(9, 4),                        // gamma^2, wanted below
            fmul_held!(7, 6), storer!(7),       // their product
            loadr!(5), dblr!(), dblr!(), storer!(8),
            dblr!(), storer!(5),                // four beta, eight beta
            loadr!(7), dblr!(), addr!(7), storer!(6),
                                                // alpha, three times it
            loadr!(9), dblr!(), dblr!(), dblr!(), storer!(9),
                                                // eight gamma^2
            fadd!(12, 1, 2),                    // y + z
            fsqr_held!(6), subr!(5), storer!(10),
                                                // x' = alpha^2 - 8 beta
            fsqr_held!(12), subr!(4), subr!(3), storer!(12),
                                                // z' = (y+z)^2 - g - d
            loadr!(8), subr!(10), storer!(11),  // 4 beta - x'
            fmul_held!(6, 11), subr!(9), storer!(11),
                                                // y'
            "movq rcx, xmm0",
            copy!("rsp", 10, "rcx", 3),
            copy!("rsp", 11, "rcx", 4),
            copy!("rsp", 12, "rcx", 5),
            "add rsp, {frame}",
            frame = const SLOTS * 32,
            inout("rcx") io => _,
            out("rax") _, out("rdx") _, out("rsi") _, out("rdi") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _, out("r15") _,
            out("xmm0") _,
        );
    }
}

/// The sum of the point in the first three values at `io` and the
/// affine point in the two above them, into the three above those.
/// The formula is [`super::Engine::jacobian_add_affine`]'s, and the
/// cases it misses are the caller's, as they are there.
///
/// # Safety
/// Requires ADX and BMI2; `io` must point at eight values of four
/// limbs, the first five the two points' coordinates, each below the
/// prime.
#[rustfmt::skip]
unsafe fn add_affine(io: *mut u64) {
    unsafe {
        core::arch::asm!(
            "movq xmm0, rcx",
            "sub rsp, {frame}",
            "mov r14d, 32",
            "mov r15, 0xffffffff00000001",
            copy!("rcx", 0, "rsp", 0),
            copy!("rcx", 1, "rsp", 1),
            copy!("rcx", 2, "rsp", 2),
            copy!("rcx", 3, "rsp", 3),
            copy!("rcx", 4, "rsp", 4),
            fsqr!(5, 2),                        // zz = z^2
            fmul!(7, 4, 2),                     // qy z
            fmul!(6, 3, 5),                     // u2 = qx zz
            fmul_held!(7, 5), subr!(1), dblr!(), storer!(9),
                                                // r = 2 (s2 - y)
            loadr!(6), subr!(0), storer!(8),    // h = u2 - x
            dblr!(), storer!(11),               // 2 h
            fadd!(17, 2, 8),                    // z + h
            fsqr!(10, 8),                       // hh = h^2
            fsqr!(11, 11),                      // i = (2 h)^2
            fsqr_held!(17), subr!(5), subr!(10), storer!(17),
                                                // z' = (z+h)^2 - zz - hh
            fmul!(12, 8, 11),                   // j = h i
            fmul!(13, 0, 11),                   // v = x i
            fmul_held!(1, 12), dblr!(), storer!(14),
                                                // 2 y j
            loadr!(13), dblr!(), storer!(16),   // 2 v
            fsqr_held!(9), subr!(12), subr!(16), storer!(15),
                                                // x' = r^2 - j - 2 v
            loadr!(13), subr!(15), storer!(16), // v - x'
            fmul_held!(9, 16), subr!(14), storer!(16),
                                                // y' = r (v - x') - 2 y j
            "movq rcx, xmm0",
            copy!("rsp", 15, "rcx", 5),
            copy!("rsp", 16, "rcx", 6),
            copy!("rsp", 17, "rcx", 7),
            "add rsp, {frame}",
            frame = const SLOTS * 32,
            inout("rcx") io => _,
            out("rax") _, out("rdx") _, out("rsi") _, out("rdi") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _, out("r15") _,
            out("xmm0") _,
        );
    }
}

/// The sum of the two points at `io`, into the three values above
/// them. The formula is [`super::Engine::jacobian_add`]'s, and the
/// cases it misses are the caller's, as they are there.
///
/// # Safety
/// Requires ADX and BMI2; `io` must point at nine values of four
/// limbs, the first six the two points' coordinates, each below the
/// prime.
#[rustfmt::skip]
unsafe fn add(io: *mut u64) {
    unsafe {
        core::arch::asm!(
            "movq xmm0, rcx",
            "sub rsp, {frame}",
            "mov r14d, 32",
            "mov r15, 0xffffffff00000001",
            copy!("rcx", 0, "rsp", 0),
            copy!("rcx", 1, "rsp", 1),
            copy!("rcx", 2, "rsp", 2),
            copy!("rcx", 3, "rsp", 3),
            copy!("rcx", 4, "rsp", 4),
            copy!("rcx", 5, "rsp", 5),
            fsqr!(6, 2),                        // zz1 = pz^2
            fsqr!(7, 5),                        // zz2 = qz^2
            fadd!(17, 2, 5),                    // pz + qz
            fmul!(8, 0, 7),                     // u1 = px zz2
            fmul!(9, 3, 6),                     // u2 = qx zz1
            fmul!(10, 1, 5),                    // py qz
            fmul!(11, 4, 2),                    // qy pz
            fsqr!(17, 17),                      // (pz + qz)^2
            fmul!(10, 10, 7),                   // s1
            fmul_held!(11, 6), subr!(10), dblr!(), storer!(13),
                                                // r = 2 (s2 - s1)
            loadr!(9), subr!(8), storer!(12),   // h = u2 - u1
            dblr!(), storer!(14),               // 2 h
            loadr!(17), subr!(6), subr!(7), storer!(17),
                                                // (pz+qz)^2 - zz1 - zz2
            fsqr!(14, 14),                      // i = (2 h)^2
            fmul!(20, 17, 12),                  // z', that times h
            fmul!(15, 12, 14),                  // j = h i
            fmul!(16, 8, 14),                   // v = u1 i
            loadr!(16), dblr!(), storer!(17),   // 2 v
            fmul_held!(10, 15), dblr!(), storer!(19),
                                                // 2 s1 j
            fsqr_held!(13), subr!(15), subr!(17), storer!(18),
                                                // x' = r^2 - j - 2 v
            loadr!(16), subr!(18), storer!(17), // v - x'
            fmul_held!(13, 17), subr!(19), storer!(19),
                                                // y' = r (v - x') - 2 s1 j
            "movq rcx, xmm0",
            copy!("rsp", 18, "rcx", 6),
            copy!("rsp", 19, "rcx", 7),
            copy!("rsp", 20, "rcx", 8),
            "add rsp, {frame}",
            frame = const SLOTS * 32,
            inout("rcx") io => _,
            out("rax") _, out("rdx") _, out("rsi") _, out("rdi") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _, out("r15") _,
            out("xmm0") _,
        );
    }
}

impl Adx {
    /// Twice `p`, in Jacobian coordinates.
    ///
    /// The width is a parameter only so that the curve arithmetic,
    /// which is generic over it, can call this: four limbs is what
    /// the caller must have, and what a held [`Adx`] stands for.
    ///
    /// The point goes in and comes out through a buffer of the
    /// caller's rather than by a pointer to the point itself:
    /// passing the point's own memory measured slower, since the
    /// result then has to be written where the caller named rather
    /// than wherever the compiler wanted it.
    #[inline(always)]
    pub(super) fn jacobian_double<const L: usize>(
        self,
        p: &Jacobian<L>,
    ) -> Jacobian<L> {
        debug_assert_eq!(L, 4);
        let mut io = [[0u64; 4]; 6];
        io[0][..L].copy_from_slice(&p.x.0);
        io[1][..L].copy_from_slice(&p.y.0);
        io[2][..L].copy_from_slice(&p.z.0);
        // SAFETY: `self` was minted by `probe`, which hands one out
        // only where the instructions are there, and the caller holds
        // one only for this prime, whose values are four limbs.
        unsafe {
            double(io.as_mut_ptr().cast());
        }
        let mut out = Jacobian {
            x: Uint::<L>::ZERO,
            y: Uint::<L>::ZERO,
            z: Uint::<L>::ZERO,
        };
        out.x.0.copy_from_slice(&io[3][..L]);
        out.y.0.copy_from_slice(&io[4][..L]);
        out.z.0.copy_from_slice(&io[5][..L]);
        out
    }

    /// `p + q`, `q` affine, in Jacobian coordinates. The cases the
    /// formula misses are settled by the caller, as they are in the
    /// portable one.
    #[inline(always)]
    pub(super) fn jacobian_add_affine<const L: usize>(
        self,
        p: &Jacobian<L>,
        q: &Affine<L>,
    ) -> Jacobian<L> {
        debug_assert_eq!(L, 4);
        let mut io = [[0u64; 4]; 8];
        io[0][..L].copy_from_slice(&p.x.0);
        io[1][..L].copy_from_slice(&p.y.0);
        io[2][..L].copy_from_slice(&p.z.0);
        io[3][..L].copy_from_slice(&q.x.0);
        io[4][..L].copy_from_slice(&q.y.0);
        // SAFETY: as in `jacobian_double`.
        unsafe {
            add_affine(io.as_mut_ptr().cast());
        }
        let mut out = Jacobian {
            x: Uint::<L>::ZERO,
            y: Uint::<L>::ZERO,
            z: Uint::<L>::ZERO,
        };
        out.x.0.copy_from_slice(&io[5][..L]);
        out.y.0.copy_from_slice(&io[6][..L]);
        out.z.0.copy_from_slice(&io[7][..L]);
        out
    }

    /// `a^-1` in the field, or zero for zero.
    #[inline(always)]
    pub(super) fn invert<const L: usize>(self, a: &Uint<L>) -> Uint<L> {
        debug_assert_eq!(L, 4);
        let mut io = [[0u64; 4]; 2];
        io[0][..L].copy_from_slice(&a.0);
        // SAFETY: as in `jacobian_double`.
        unsafe {
            invert(io.as_mut_ptr().cast());
        }
        let mut out = Uint::<L>::ZERO;
        out.0.copy_from_slice(&io[1][..L]);
        out
    }

    /// `p + q`, both Jacobian. The cases the formula misses are
    /// settled by the caller, as they are in the portable one.
    #[inline(always)]
    pub(super) fn jacobian_add<const L: usize>(
        self,
        p: &Jacobian<L>,
        q: &Jacobian<L>,
    ) -> Jacobian<L> {
        debug_assert_eq!(L, 4);
        let mut io = [[0u64; 4]; 9];
        io[0][..L].copy_from_slice(&p.x.0);
        io[1][..L].copy_from_slice(&p.y.0);
        io[2][..L].copy_from_slice(&p.z.0);
        io[3][..L].copy_from_slice(&q.x.0);
        io[4][..L].copy_from_slice(&q.y.0);
        io[5][..L].copy_from_slice(&q.z.0);
        // SAFETY: as in `jacobian_double`.
        unsafe {
            add(io.as_mut_ptr().cast());
        }
        let mut out = Jacobian {
            x: Uint::<L>::ZERO,
            y: Uint::<L>::ZERO,
            z: Uint::<L>::ZERO,
        };
        out.x.0.copy_from_slice(&io[6][..L]);
        out.y.0.copy_from_slice(&io[7][..L]);
        out.z.0.copy_from_slice(&io[8][..L]);
        out
    }
}
