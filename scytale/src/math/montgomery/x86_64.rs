//! The P-256 field's Montgomery product on the ADX and BMI2
//! instructions.
//!
//! The portable product carries one chain at a time through `u128`
//! sums. Here `mulx` multiplies without touching the flags, and
//! `adcx` and `adox` each carry in a flag of their own, so a row of
//! four products folds its low halves in on one chain and its high
//! halves on the other, and the processor runs the two side by side.
//!
//! The reduction multiplies by nothing it has to. The prime is
//! `2^256 - 2^224 + 2^192 + 2^96 - 1`, so `-p^-1 mod 2^64` is one and
//! the multiple of `p` that clears the low word `m` is `m` itself.
//! Adding `m p` and dropping the cleared word adds `m 2^32` two words
//! up, which is a pair of shifts, and `m (2^64 - 2^32 + 1)` four
//! words up, which is one `mulx` by the prime's top limb.
//!
//! Four rows of product and reduction, then one subtraction of `p`
//! chosen by `cmov`. No branch and no address depends on the values.

#![allow(unsafe_code)]

use core::arch::x86_64::__cpuid_count;

use super::P256_PRIME;
use crate::math::uint::Uint;
use crate::probe::Probe;

/// The product, where the processor has the instructions. A value
/// exists only by way of [`probe`], so holding one is the proof and
/// the call on it is safe.
#[derive(Clone, Copy)]
pub(crate) struct Adx(());

/// The product, where the processor reports ADX (CPUID leaf 7, EBX
/// bit 19) and BMI2 for `mulx` (bit 8). Asked once.
pub(crate) fn probe() -> Option<Adx> {
    ADX.yes(ask).then_some(Adx(()))
}

/// Kept: every field product asks.
static ADX: Probe = Probe::new();

fn ask() -> bool {
    let ebx = __cpuid_count(7, 0).ebx;
    ebx & (1 << 19) != 0 && ebx & (1 << 8) != 0
}

impl Adx {
    /// `a b / 2^256 mod p` for the P-256 prime, with `b` below `p`
    /// and `a` any four limbs; the result is below `p`.
    ///
    /// The width is a parameter only so that the curve arithmetic,
    /// which is generic over it, can call this without taking its
    /// values apart first: four limbs is what the caller must have,
    /// and what a held [`Adx`] stands for.
    #[inline(always)]
    pub(crate) fn mul<const L: usize>(
        self,
        a: &Uint<L>,
        b: &Uint<L>,
    ) -> Uint<L> {
        debug_assert_eq!(L, 4);
        let mut out = Uint::<L>::ZERO;
        // SAFETY: `self` was minted by `probe`, which hands one out
        // only where the instructions are there, and the caller holds
        // one only for this prime, whose values are four limbs.
        unsafe {
            mul(
                a.0.as_ptr(),
                b.0.as_ptr(),
                P256_PRIME.as_ptr(),
                out.0.as_mut_ptr(),
            );
        }
        out
    }
}

/// A row of product for limb `$i` of `b`, into the running value
/// `$w0..$w4` with `$z` as its sixth word, which comes in holding
/// anything and leaves holding the carries out of `$w4`.
#[rustfmt::skip]
macro_rules! row {
    ($i:literal, $w0:literal, $w1:literal, $w2:literal, $w3:literal,
     $w4:literal, $z:literal) => {
        concat!(
            // Clears both flags as well as the word.
            "xor ", $z, "d, ", $z, "d\n",
            "mov rdx, qword ptr [rcx + ", $i, " * 8]\n",
            "mulx r14, rax, qword ptr [rsi]\n",
            "adcx ", $w0, ", rax\n",
            "adox ", $w1, ", r14\n",
            "mulx r14, rax, qword ptr [rsi + 8]\n",
            "adcx ", $w1, ", rax\n",
            "adox ", $w2, ", r14\n",
            "mulx r14, rax, qword ptr [rsi + 16]\n",
            "adcx ", $w2, ", rax\n",
            "adox ", $w3, ", r14\n",
            "mulx r14, rax, qword ptr [rsi + 24]\n",
            "adcx ", $w3, ", rax\n",
            "adox ", $w4, ", r14\n",
            // Both chains' last carries into the sixth word.
            "adcx ", $w4, ", ", $z, "\n",
            "adox ", $z, ", ", $z, "\n",
            "adc ", $z, ", 0\n",
        )
    };
}

/// The reduction of the running value `$w0..$w4, $z` by its low word:
/// afterwards the value is `$w1..$w4, $z` and `$w0` is spare.
#[rustfmt::skip]
macro_rules! reduce {
    ($w0:literal, $w1:literal, $w2:literal, $w3:literal, $w4:literal,
     $z:literal) => {
        concat!(
            "mov rdx, ", $w0, "\n",
            "mov rax, ", $w0, "\n",
            "shl rax, 32\n",
            "mov r14, ", $w0, "\n",
            "shr r14, 32\n",
            "add ", $w1, ", rax\n",
            "adc ", $w2, ", r14\n",
            "mulx r14, rax, qword ptr [r15 + 24]\n",
            "adc ", $w3, ", rax\n",
            "adc ", $w4, ", r14\n",
            "adc ", $z, ", 0\n",
        )
    };
}

/// The product into `out`.
///
/// # Safety
/// Requires ADX and BMI2; `a`, `b`, `p` and `out` must each point at
/// four limbs, `b` below the prime at `p`.
#[inline(always)]
unsafe fn mul(a: *const u64, b: *const u64, p: *const u64, out: *mut u64) {
    unsafe {
        core::arch::asm!(
            // The first row has nothing to add into, so its products
            // go straight into the words, the high halves carried in
            // on one chain.
            "mov rdx, qword ptr [rcx]",
            "mulx r9, r8, qword ptr [rsi]",
            "mulx r10, rax, qword ptr [rsi + 8]",
            "mulx r11, r14, qword ptr [rsi + 16]",
            "mulx r12, r13, qword ptr [rsi + 24]",
            "add r9, rax",
            "adc r10, r14",
            "adc r11, r13",
            "adc r12, 0",
            "xor r13d, r13d",
            reduce!("r8", "r9", "r10", "r11", "r12", "r13"),
            row!(1, "r9", "r10", "r11", "r12", "r13", "r8"),
            reduce!("r9", "r10", "r11", "r12", "r13", "r8"),
            row!(2, "r10", "r11", "r12", "r13", "r8", "r9"),
            reduce!("r10", "r11", "r12", "r13", "r8", "r9"),
            row!(3, "r11", "r12", "r13", "r8", "r9", "r10"),
            reduce!("r11", "r12", "r13", "r8", "r9", "r10"),
            // The value is r12, r13, r8, r9 and a top word in r10, and
            // below twice the prime: subtract it once, and keep the
            // difference unless that borrowed out of the top word.
            "mov rax, r12",
            "sub rax, qword ptr [r15]",
            "mov r14, r13",
            "sbb r14, qword ptr [r15 + 8]",
            "mov rdx, r8",
            "sbb rdx, qword ptr [r15 + 16]",
            "mov r11, r9",
            "sbb r11, qword ptr [r15 + 24]",
            "sbb r10, 0",
            "cmovnc r12, rax",
            "cmovnc r13, r14",
            "cmovnc r8, rdx",
            "cmovnc r9, r11",
            "mov qword ptr [rdi], r12",
            "mov qword ptr [rdi + 8], r13",
            "mov qword ptr [rdi + 16], r8",
            "mov qword ptr [rdi + 24], r9",
            in("rsi") a,
            in("rcx") b,
            in("r15") p,
            in("rdi") out,
            out("rax") _, out("rdx") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _,
            options(nostack),
        );
    }
}

impl Adx {
    /// `a a / 2^256 mod p`, the square, for `a` any four limbs; the
    /// result is below `p`.
    ///
    /// The cross products appear twice in a square, so six products
    /// and one doubling stand in for twelve, and four more give the
    /// limbs' own squares: ten where the general product spends
    /// sixteen. The reduction is the product's.
    #[inline(always)]
    pub(crate) fn sqr<const L: usize>(self, a: &Uint<L>) -> Uint<L> {
        debug_assert_eq!(L, 4);
        let mut out = Uint::<L>::ZERO;
        // SAFETY: as in `mul`.
        unsafe {
            sqr(a.0.as_ptr(), out.0.as_mut_ptr());
        }
        out
    }
}

/// One reduction step of the square: the low word `$w0` says which
/// multiple of `p` clears it, and the value moves down one word.
/// `$rest` is every word above the four the multiple reaches, which
/// the carry walks through.
#[rustfmt::skip]
macro_rules! step {
    ($w0:literal, $w1:literal, $w2:literal, $w3:literal, $w4:literal
     $(, $rest:literal)*) => {
        concat!(
            "mov rdx, ", $w0, "\n",
            "mov rax, ", $w0, "\n",
            "shl rax, 32\n",
            "mov rcx, ", $w0, "\n",
            "shr rcx, 32\n",
            "add ", $w1, ", rax\n",
            "adc ", $w2, ", rcx\n",
            "mulx rcx, rax, rsi\n",
            "adc ", $w3, ", rax\n",
            "adc ", $w4, ", rcx\n",
            $( concat!("adc ", $rest, ", 0\n"), )*
        )
    };
}

/// The square into `out`.
///
/// # Safety
/// Requires ADX and BMI2; `a` and `out` must each point at four
/// limbs.
#[inline(always)]
unsafe fn sqr(a: *const u64, out: *mut u64) {
    unsafe {
        core::arch::asm!(
            // The cross products, each once: a0 against the three
            // above it, then a1 against two, then a2 against one.
            "mov rdx, qword ptr [rsi]",
            "mulx r10, r9, qword ptr [rsi + 8]",
            "mulx r11, rax, qword ptr [rsi + 16]",
            "add r10, rax",
            "mulx r12, rax, qword ptr [rsi + 24]",
            "adc r11, rax",
            "adc r12, 0",
            "xor r13d, r13d",
            "mov rdx, qword ptr [rsi + 8]",
            "mulx rcx, rax, qword ptr [rsi + 16]",
            "adcx r11, rax",
            "adox r12, rcx",
            "mulx rcx, rax, qword ptr [rsi + 24]",
            "adcx r12, rax",
            "adox r13, rcx",
            "mov r14d, 0",
            "mov rdx, qword ptr [rsi + 16]",
            "mulx rcx, rax, qword ptr [rsi + 24]",
            "adcx r13, rax",
            "adox r14, rcx",
            "mov eax, 0",
            "adcx r14, rax",
            "adox r14, rax",
            // Doubled, which is those products' other halves.
            "xor r15d, r15d",
            "add r9, r9",
            "adc r10, r10",
            "adc r11, r11",
            "adc r12, r12",
            "adc r13, r13",
            "adc r14, r14",
            "adc r15, 0",
            // Then each limb's own square on the diagonal.
            "mov rdx, qword ptr [rsi]",
            "mulx rcx, r8, rdx",
            "add r9, rcx",
            "mov rdx, qword ptr [rsi + 8]",
            "mulx rcx, rax, rdx",
            "adc r10, rax",
            "adc r11, rcx",
            "mov rdx, qword ptr [rsi + 16]",
            "mulx rcx, rax, rdx",
            "adc r12, rax",
            "adc r13, rcx",
            "mov rdx, qword ptr [rsi + 24]",
            "mulx rcx, rax, rdx",
            "adc r14, rax",
            "adc r15, rcx",
            // The prime's top limb, which the reduction multiplies
            // by; the pointer to the value is done with.
            "mov rsi, 0xffffffff00000001",
            step!("r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            step!("r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            step!("r10", "r11", "r12", "r13", "r14", "r15"),
            "mov r8d, 0",
            step!("r11", "r12", "r13", "r14", "r15", "r8"),
            // The value is r12, r13, r14, r15 with a top word in r8,
            // and below twice the prime.
            "mov rax, r12",
            "sub rax, -1",
            "mov rcx, r13",
            "mov rdx, 0xffffffff",
            "sbb rcx, rdx",
            "mov rdx, r14",
            "sbb rdx, 0",
            "mov r9, r15",
            "sbb r9, rsi",
            "sbb r8, 0",
            "cmovnc r12, rax",
            "cmovnc r13, rcx",
            "cmovnc r14, rdx",
            "cmovnc r15, r9",
            "mov qword ptr [rdi], r12",
            "mov qword ptr [rdi + 8], r13",
            "mov qword ptr [rdi + 16], r14",
            "mov qword ptr [rdi + 24], r15",
            inout("rsi") a => _,
            in("rdi") out,
            out("rax") _, out("rcx") _, out("rdx") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _, out("r15") _,
            options(nostack),
        );
    }
}

/// One product of the multiplier in `rdx` by the word at `$at` bytes
/// into the context: the low half on the carry chain into `$lo`, the
/// high half on the overflow chain into the word above it.
#[rustfmt::skip]
macro_rules! wide_product {
    ($at:literal, $lo:literal, $hi:literal) => {
        concat!(
            "mulx rcx, rax, qword ptr [rdi + ", $at, "]\n",
            "adcx ", $lo, ", rax\n",
            "adox ", $hi, ", rcx\n",
        )
    };
}

/// A row of products of one limb of `a` by every limb of `b`, then
/// the multiple of the modulus that clears the row's low word.
///
/// Both chains run at once: the products' low halves on the carry
/// flag, their high halves on the overflow flag. The window is eight
/// words, which is what a row of six products and what it is added to
/// can reach, and it rotates a place each time: the word the
/// reduction clears becomes the top of the next, already zero.
#[rustfmt::skip]
macro_rules! wide_step {
    ($i:literal, $w0:literal, $w1:literal, $w2:literal, $w3:literal,
     $w4:literal, $w5:literal, $w6:literal, $w7:literal) => {
        concat!(
            "mov rdx, qword ptr [rsi + ", $i, "]\n",
            "xor eax, eax\n",
            wide_product!(56, $w0, $w1),
            wide_product!(64, $w1, $w2),
            wide_product!(72, $w2, $w3),
            wide_product!(80, $w3, $w4),
            wide_product!(88, $w4, $w5),
            wide_product!(96, $w5, $w6),
            "mov eax, 0\n",
            "adcx ", $w6, ", rax\n",
            "adox ", $w7, ", rax\n",
            "adc ", $w7, ", 0\n",
            // The multiple of the modulus that clears the low word.
            // `imul` writes the flags, so the chains start again.
            "mov rdx, ", $w0, "\n",
            "imul rdx, qword ptr [rdi]\n",
            "xor eax, eax\n",
            wide_product!(8, $w0, $w1),
            wide_product!(16, $w1, $w2),
            wide_product!(24, $w2, $w3),
            wide_product!(32, $w3, $w4),
            wide_product!(40, $w4, $w5),
            wide_product!(48, $w5, $w6),
            "mov eax, 0\n",
            "adcx ", $w6, ", rax\n",
            "adox ", $w7, ", rax\n",
            "adc ", $w7, ", 0\n",
        )
    };
}

impl Adx {
    /// `a b / 2^384 mod n` for any six-limb odd `n`, with `b` below
    /// `n` and `a` any six limbs; the result is below `n`.
    ///
    /// `context` is the modulus's low-limb inverse, then its limbs,
    /// then `b`: one pointer for both of the things a row reads,
    /// which is what leaves a register for the window's eighth word.
    #[inline(always)]
    pub(crate) fn mul6<const L: usize>(
        self,
        a: &Uint<L>,
        context: &[u64; 13],
        modulus: &Uint<L>,
    ) -> Uint<L> {
        debug_assert_eq!(L, 6);
        // SAFETY: `self` was minted by `probe`, which hands one out
        // only where the instructions are; the caller holds one for a
        // six-limb modulus, and the context is as this asks.
        let (value, top) = unsafe { mul6_rows(a.0.as_ptr(), context.as_ptr()) };
        let mut out = Uint::<L>::ZERO;
        out.0.copy_from_slice(&value);
        // The rows leave a value below twice the modulus, so one
        // subtraction settles it: taken when it does not borrow, or
        // when the value overflowed the six words.
        let (reduced, borrow) = out.sub_borrow(modulus);
        out.cmov(&reduced, top | (1 - borrow));
        out
    }
}

/// The rows and reductions, leaving the value and the word above it.
///
/// # Safety
/// Requires ADX and BMI2; `a` must point at six limbs and `context`
/// at thirteen: the inverse, the modulus, then `b`.
#[inline(always)]
unsafe fn mul6_rows(a: *const u64, context: *const u64) -> ([u64; 6], u64) {
    let (v0, v1, v2, v3, v4, v5): (u64, u64, u64, u64, u64, u64);
    let (top, spare): (u64, u64);
    unsafe {
        core::arch::asm!(
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            wide_step!(0, "r8", "r9", "r10", "r11", "r12", "r13", "r14",
                       "r15"),
            wide_step!(8, "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                       "r8"),
            wide_step!(16, "r10", "r11", "r12", "r13", "r14", "r15", "r8",
                       "r9"),
            wide_step!(24, "r11", "r12", "r13", "r14", "r15", "r8", "r9",
                       "r10"),
            wide_step!(32, "r12", "r13", "r14", "r15", "r8", "r9", "r10",
                       "r11"),
            wide_step!(40, "r13", "r14", "r15", "r8", "r9", "r10", "r11",
                       "r12"),
            in("rsi") a,
            in("rdi") context,
            out("rax") _, out("rcx") _, out("rdx") _,
            lateout("r14") v0,
            lateout("r15") v1,
            lateout("r8") v2,
            lateout("r9") v3,
            lateout("r10") v4,
            lateout("r11") v5,
            lateout("r12") top,
            lateout("r13") spare,
            options(nostack),
        );
    }
    debug_assert_eq!(spare, 0);
    ([v0, v1, v2, v3, v4, v5], top)
}
