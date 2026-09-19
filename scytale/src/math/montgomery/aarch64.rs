//! The Montgomery product written out for A64.
//!
//! A64 has no equivalent of ADX: there is one carry flag, so a column
//! of products cannot fold its low and its high halves on two chains
//! at once the way [`x86_64`](super::x86_64) does. What it has
//! instead is registers, twenty-eight of them against x86-64's
//! fifteen. The whole running value, both operands and the modulus
//! stay in registers for the length of a product, so the rows here
//! spend no instructions on the loads and stores the portable code
//! leaves behind, and the two halves of each product go on one chain
//! in two passes: the low halves into the running value, then the
//! high halves one word up.
//!
//! `mul` and `sqr` are the P-256 field's, where the prime's shape
//! makes the reduction nearly free: `-p^-1 mod 2^64` is one, so the
//! multiple of `p` that clears the low word `m` is `m` itself, and
//! adding `m p` is a pair of shifts plus one product by the prime's
//! top limb. [`mul4`] is the same rows for any four-limb odd modulus,
//! which is either curve's group order, and [`mul6`] for any six-limb
//! one, which is all of P-384.
//!
//! Every instruction runs whatever the operands are, and the final
//! subtraction of the modulus is chosen by `csel`, so no branch and
//! no address depends on a value.

#![allow(unsafe_code)]

use crate::math::uint::Uint;

/// A row of the P-256 product: limb `$i` of `b` against every limb of
/// `a`, into the running value `$w0..$w4`. `$w5` comes in holding
/// anything and leaves holding what carried out of `$w4`.
///
/// The low halves go in first, then the high halves one word up.
/// Splitting it that way is what lets a single carry flag carry a
/// whole pass, and it is why the eight products are all issued before
/// either chain starts: nothing in a chain waits on a multiply.
#[rustfmt::skip]
macro_rules! row {
    ($i:literal, $w0:literal, $w1:literal, $w2:literal, $w3:literal,
     $w4:literal, $w5:literal) => {
        concat!(
            "ldr {bi}, [{b}, #", $i, " * 8]\n",
            "mul {l0}, {a0}, {bi}\n",
            "mul {l1}, {a1}, {bi}\n",
            "mul {l2}, {a2}, {bi}\n",
            "mul {l3}, {a3}, {bi}\n",
            "umulh {h0}, {a0}, {bi}\n",
            "umulh {h1}, {a1}, {bi}\n",
            "umulh {h2}, {a2}, {bi}\n",
            "umulh {h3}, {a3}, {bi}\n",
            "adds ", $w0, ", ", $w0, ", {l0}\n",
            "adcs ", $w1, ", ", $w1, ", {l1}\n",
            "adcs ", $w2, ", ", $w2, ", {l2}\n",
            "adcs ", $w3, ", ", $w3, ", {l3}\n",
            "adcs ", $w4, ", ", $w4, ", xzr\n",
            "adc ", $w5, ", xzr, xzr\n",
            "adds ", $w1, ", ", $w1, ", {h0}\n",
            "adcs ", $w2, ", ", $w2, ", {h1}\n",
            "adcs ", $w3, ", ", $w3, ", {h2}\n",
            "adcs ", $w4, ", ", $w4, ", {h3}\n",
            "adc ", $w5, ", ", $w5, ", xzr\n",
        )
    };
}

/// The P-256 reduction of the running value `$w0..$w5` by its low
/// word: afterwards the value is `$w1..$w5` and `$w0` is spare.
///
/// The word `m` to clear is `$w0` itself, and `m (p + 1)` shifted
/// down a word is `m 2^32` at the bottom, which is the two shifts,
/// and `m` by the prime's top limb three words up, which is the one
/// product. The low word cancels exactly, carry and all, so no carry
/// enters the chain below.
#[rustfmt::skip]
macro_rules! reduce {
    ($w0:literal, $w1:literal, $w2:literal, $w3:literal, $w4:literal,
     $w5:literal) => {
        concat!(
            "lsl {l0}, ", $w0, ", #32\n",
            "lsr {l1}, ", $w0, ", #32\n",
            "mul {l2}, ", $w0, ", {ptop}\n",
            "umulh {l3}, ", $w0, ", {ptop}\n",
            "adds ", $w1, ", ", $w1, ", {l0}\n",
            "adcs ", $w2, ", ", $w2, ", {l1}\n",
            "adcs ", $w3, ", ", $w3, ", {l2}\n",
            "adcs ", $w4, ", ", $w4, ", {l3}\n",
            "adc ", $w5, ", ", $w5, ", xzr\n",
        )
    };
}

/// `a b / 2^256 mod p` for the P-256 prime, with `b` below `p` and
/// `a` any four limbs; the result is below `p`.
///
/// The width is a parameter only so that the curve arithmetic, which
/// is generic over it, can call this without taking its values apart
/// first; four limbs is what the caller must have.
#[inline(always)]
pub(crate) fn mul<const L: usize>(a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
    debug_assert_eq!(L, 4);
    let mut out = Uint::<L>::ZERO;
    // SAFETY: the pointers are to four limbs each, as the width the
    // caller uses this at says, and nothing here leaves them.
    unsafe {
        mul_rows(a.0.as_ptr(), b.0.as_ptr(), out.0.as_mut_ptr());
    }
    out
}

/// `a a / 2^256 mod p`, the square.
///
/// The cross products appear twice in a square, so a written-out
/// square is worth six of the sixteen products. That is not what this
/// is: the rows above already keep everything in registers, and the
/// square is the product of a value with itself until it is measured
/// to be worth its own block.
#[inline(always)]
pub(crate) fn sqr<const L: usize>(a: &Uint<L>) -> Uint<L> {
    mul(a, a)
}

/// The P-256 product into `out`.
///
/// # Safety
/// `a`, `b` and `out` must each point at four limbs, `b` below the
/// prime.
#[inline(always)]
unsafe fn mul_rows(a: *const u64, b: *const u64, out: *mut u64) {
    unsafe {
        core::arch::asm!(
            // The prime's top limb, 2^64 - 2^32 + 1, which every
            // reduction multiplies by.
            "mov {ptop}, #0xffffffff00000000",
            "orr {ptop}, {ptop}, #1",
            "ldp {a0}, {a1}, [{a}]",
            "ldp {a2}, {a3}, [{a}, #16]",

            // The first row has nothing to add into, so the products
            // land in the words themselves.
            "ldr {bi}, [{b}]",
            "mul {t0}, {a0}, {bi}",
            "umulh {t1}, {a0}, {bi}",
            "mul {l1}, {a1}, {bi}",
            "umulh {h1}, {a1}, {bi}",
            "mul {l2}, {a2}, {bi}",
            "umulh {h2}, {a2}, {bi}",
            "mul {l3}, {a3}, {bi}",
            "umulh {h3}, {a3}, {bi}",
            "adds {t1}, {t1}, {l1}",
            "adcs {t2}, {h1}, {l2}",
            "adcs {t3}, {h2}, {l3}",
            "adc {t4}, {h3}, xzr",
            "mov {c}, xzr",
            reduce!("{t0}", "{t1}", "{t2}", "{t3}", "{t4}", "{c}"),
            row!(1, "{t1}", "{t2}", "{t3}", "{t4}", "{c}", "{t0}"),
            reduce!("{t1}", "{t2}", "{t3}", "{t4}", "{c}", "{t0}"),
            row!(2, "{t2}", "{t3}", "{t4}", "{c}", "{t0}", "{t1}"),
            reduce!("{t2}", "{t3}", "{t4}", "{c}", "{t0}", "{t1}"),
            row!(3, "{t3}", "{t4}", "{c}", "{t0}", "{t1}", "{t2}"),
            reduce!("{t3}", "{t4}", "{c}", "{t0}", "{t1}", "{t2}"),

            // The value is t4, c, t0, t1 with a top word in t2, and
            // below twice the prime: subtract it once, and keep the
            // difference unless that borrowed out of the top word.
            "mov {h0}, #-1",
            "mov {h1}, #0xffffffff",
            "subs {l0}, {t4}, {h0}",
            "sbcs {l1}, {c}, {h1}",
            "sbcs {l2}, {t0}, xzr",
            "sbcs {l3}, {t1}, {ptop}",
            "sbcs xzr, {t2}, xzr",
            "csel {t4}, {t4}, {l0}, cc",
            "csel {c}, {c}, {l1}, cc",
            "csel {t0}, {t0}, {l2}, cc",
            "csel {t1}, {t1}, {l3}, cc",
            "stp {t4}, {c}, [{out}]",
            "stp {t0}, {t1}, [{out}, #16]",

            a = in(reg) a,
            b = in(reg) b,
            out = in(reg) out,
            ptop = out(reg) _,
            a0 = out(reg) _, a1 = out(reg) _,
            a2 = out(reg) _, a3 = out(reg) _,
            t0 = out(reg) _, t1 = out(reg) _, t2 = out(reg) _,
            t3 = out(reg) _, t4 = out(reg) _, c = out(reg) _,
            l0 = out(reg) _, l1 = out(reg) _,
            l2 = out(reg) _, l3 = out(reg) _,
            h0 = out(reg) _, h1 = out(reg) _,
            h2 = out(reg) _, h3 = out(reg) _,
            bi = out(reg) _,
            options(nostack),
        );
    }
}

/// One pass of six products by `$m` over the running value: the six
/// results of `$op`, which is `mul` for the low halves and `umulh`
/// for the high ones, added into `$w0..$w5` on one carry chain, with
/// what falls out of the top going into `$w6` and `$w7`.
///
/// `mul`, `umulh` and the loads leave the flags alone, so the chain
/// runs through them and only four temporaries are needed: two
/// products are computed while the chain is still walking the two
/// before them.
///
/// The low halves reach two words above the six, since they are added
/// where the running value already is; the high halves sit one word
/// higher and reach only one. So each pass names its own tail: `open`
/// writes the word above, which comes in holding anything, `carry`
/// adds into it, and `high` has only the one word to finish in.
#[rustfmt::skip]
macro_rules! wide_pass {
    ($tail:ident, $op:literal, $m:literal, $w0:literal, $w1:literal,
     $w2:literal, $w3:literal, $w4:literal, $w5:literal,
     $($rest:literal),*) => {
        concat!(
            $op, " {l0}, ", $m, ", {b0}\n",
            $op, " {l1}, ", $m, ", {b1}\n",
            $op, " {l2}, ", $m, ", {b2}\n",
            $op, " {l3}, ", $m, ", {b3}\n",
            "adds ", $w0, ", ", $w0, ", {l0}\n",
            $op, " {l0}, ", $m, ", {b4}\n",
            "adcs ", $w1, ", ", $w1, ", {l1}\n",
            $op, " {l1}, ", $m, ", {b5}\n",
            "adcs ", $w2, ", ", $w2, ", {l2}\n",
            "adcs ", $w3, ", ", $w3, ", {l3}\n",
            "adcs ", $w4, ", ", $w4, ", {l0}\n",
            "adcs ", $w5, ", ", $w5, ", {l1}\n",
            tail!($tail, $($rest),*),
        )
    };
}

/// The end of a pass's carry chain, in the three shapes the steps
/// call for.
#[rustfmt::skip]
macro_rules! tail {
    (open, $w6:literal, $w7:literal) => {
        concat!(
            "adcs ", $w6, ", ", $w6, ", xzr\n",
            "adc ", $w7, ", xzr, xzr\n",
        )
    };
    (carry, $w6:literal, $w7:literal) => {
        concat!(
            "adcs ", $w6, ", ", $w6, ", xzr\n",
            "adc ", $w7, ", ", $w7, ", xzr\n",
        )
    };
    (high, $w6:literal) => {
        concat!("adc ", $w6, ", ", $w6, ", xzr\n")
    };
}

/// The same pass with the modulus as the multiplicand, which is in
/// memory rather than in registers: six more registers would not fit
/// beside the eight the running value takes, and a load that no
/// branch depends on costs less than a spill would.
#[rustfmt::skip]
macro_rules! wide_pass_n {
    ($tail:ident, $op:literal, $w0:literal, $w1:literal, $w2:literal,
     $w3:literal, $w4:literal, $w5:literal, $($rest:literal),*) => {
        concat!(
            "ldp {l0}, {l1}, [{n}]\n",
            "ldp {l2}, {l3}, [{n}, #16]\n",
            $op, " {l0}, {m}, {l0}\n",
            $op, " {l1}, {m}, {l1}\n",
            $op, " {l2}, {m}, {l2}\n",
            $op, " {l3}, {m}, {l3}\n",
            "adds ", $w0, ", ", $w0, ", {l0}\n",
            "adcs ", $w1, ", ", $w1, ", {l1}\n",
            "ldp {l0}, {l1}, [{n}, #32]\n",
            $op, " {l0}, {m}, {l0}\n",
            $op, " {l1}, {m}, {l1}\n",
            "adcs ", $w2, ", ", $w2, ", {l2}\n",
            "adcs ", $w3, ", ", $w3, ", {l3}\n",
            "adcs ", $w4, ", ", $w4, ", {l0}\n",
            "adcs ", $w5, ", ", $w5, ", {l1}\n",
            tail!($tail, $($rest),*),
        )
    };
}

/// One step of the six-limb product: limb `$i` of `a` against every
/// limb of `b`, then the multiple of the modulus that clears the low
/// word. Four passes, each its own carry chain, the low halves of a
/// set of products and then the high halves one word up.
///
/// The window is eight words, which is what a row of six products and
/// what it is added to can reach, and it rotates a place each step:
/// the word the reduction clears becomes the top of the next.
#[rustfmt::skip]
macro_rules! wide_step {
    ($i:literal, $w0:literal, $w1:literal, $w2:literal, $w3:literal,
     $w4:literal, $w5:literal, $w6:literal, $w7:literal) => {
        concat!(
            "ldr {ai}, [{a}, #", $i, " * 8]\n",
            wide_pass!(open, "mul", "{ai}", $w0, $w1, $w2, $w3, $w4,
                       $w5, $w6, $w7),
            wide_pass!(high, "umulh", "{ai}", $w1, $w2, $w3, $w4, $w5,
                       $w6, $w7),
            "mul {m}, ", $w0, ", {inv}\n",
            wide_pass_n!(carry, "mul", $w0, $w1, $w2, $w3, $w4, $w5,
                         $w6, $w7),
            wide_pass_n!(high, "umulh", $w1, $w2, $w3, $w4, $w5, $w6,
                         $w7),
        )
    };
}

/// `a b / 2^384 mod n` for any six-limb odd `n`, with `inv` the
/// negated inverse of its low word modulo `2^64`: all of P-384, field
/// and order alike, whose shaped reduction saves multiplications but
/// not as many as the registers here save loads.
///
/// The result is below the modulus; `a` may be any six limbs and `b`
/// must be below it.
#[inline(always)]
pub(crate) fn mul6<const L: usize>(
    a: &Uint<L>,
    b: &Uint<L>,
    modulus: &Uint<L>,
    inv: u64,
) -> Uint<L> {
    debug_assert_eq!(L, 6);
    let mut out = Uint::<L>::ZERO;
    // SAFETY: the three pointers are to six limbs each, as the width
    // the caller uses this at says, and `inv` is the modulus's.
    unsafe {
        mul6_rows(
            a.0.as_ptr(),
            b.0.as_ptr(),
            modulus.0.as_ptr(),
            inv,
            out.0.as_mut_ptr(),
        );
    }
    out
}

/// The six steps and the subtraction that settles them.
///
/// # Safety
/// `a`, `b`, `n` and `out` must each point at six limbs, `b` below
/// the modulus, and `inv` must be that modulus's.
#[inline(always)]
unsafe fn mul6_rows(
    a: *const u64,
    b: *const u64,
    n: *const u64,
    inv: u64,
    out: *mut u64,
) {
    unsafe {
        core::arch::asm!(
            "ldp {b0}, {b1}, [{b}]",
            "ldp {b2}, {b3}, [{b}, #16]",
            "ldp {b4}, {b5}, [{b}, #32]",
            "mov {t0}, xzr",
            "mov {t1}, xzr",
            "mov {t2}, xzr",
            "mov {t3}, xzr",
            "mov {t4}, xzr",
            "mov {t5}, xzr",
            "mov {t6}, xzr",
            wide_step!(0, "{t0}", "{t1}", "{t2}", "{t3}", "{t4}", "{t5}",
                       "{t6}", "{t7}"),
            wide_step!(1, "{t1}", "{t2}", "{t3}", "{t4}", "{t5}", "{t6}",
                       "{t7}", "{t0}"),
            wide_step!(2, "{t2}", "{t3}", "{t4}", "{t5}", "{t6}", "{t7}",
                       "{t0}", "{t1}"),
            wide_step!(3, "{t3}", "{t4}", "{t5}", "{t6}", "{t7}", "{t0}",
                       "{t1}", "{t2}"),
            wide_step!(4, "{t4}", "{t5}", "{t6}", "{t7}", "{t0}", "{t1}",
                       "{t2}", "{t3}"),
            wide_step!(5, "{t5}", "{t6}", "{t7}", "{t0}", "{t1}", "{t2}",
                       "{t3}", "{t4}"),

            // The value is t6, t7, t0, t1, t2, t3 with a top word in
            // t4, and below twice the modulus. The differences go in
            // the registers `b` is done with.
            "ldp {l0}, {l1}, [{n}]",
            "subs {b0}, {t6}, {l0}",
            "sbcs {b1}, {t7}, {l1}",
            "ldp {l0}, {l1}, [{n}, #16]",
            "sbcs {b2}, {t0}, {l0}",
            "sbcs {b3}, {t1}, {l1}",
            "ldp {l0}, {l1}, [{n}, #32]",
            "sbcs {b4}, {t2}, {l0}",
            "sbcs {b5}, {t3}, {l1}",
            "sbcs xzr, {t4}, xzr",
            "csel {t6}, {t6}, {b0}, cc",
            "csel {t7}, {t7}, {b1}, cc",
            "csel {t0}, {t0}, {b2}, cc",
            "csel {t1}, {t1}, {b3}, cc",
            "csel {t2}, {t2}, {b4}, cc",
            "csel {t3}, {t3}, {b5}, cc",
            "stp {t6}, {t7}, [{out}]",
            "stp {t0}, {t1}, [{out}, #16]",
            "stp {t2}, {t3}, [{out}, #32]",

            a = in(reg) a,
            b = in(reg) b,
            n = in(reg) n,
            inv = in(reg) inv,
            out = in(reg) out,
            b0 = out(reg) _, b1 = out(reg) _, b2 = out(reg) _,
            b3 = out(reg) _, b4 = out(reg) _, b5 = out(reg) _,
            t0 = out(reg) _, t1 = out(reg) _, t2 = out(reg) _,
            t3 = out(reg) _, t4 = out(reg) _, t5 = out(reg) _,
            t6 = out(reg) _, t7 = out(reg) _,
            l0 = out(reg) _, l1 = out(reg) _,
            l2 = out(reg) _, l3 = out(reg) _,
            m = out(reg) _, ai = out(reg) _,
            options(nostack),
        );
    }
}

/// One step of the four-limb product: limb `$i` of `a` against every
/// limb of `b`, then the multiple of the modulus that clears the low
/// word. Four passes of one carry chain each, the low halves of a set
/// of products and then the high halves one word up.
///
/// Both operands and the modulus are in registers, so a step reads
/// one word of `a` from memory and nothing else. The four temporaries
/// are shared between the passes: at six limbs there are not enough
/// registers to give each pass its own, and at four the pass is short
/// enough that the multiplies of the next one issue while the chain
/// of this one finishes.
#[rustfmt::skip]
macro_rules! narrow_step {
    ($i:literal, $w0:literal, $w1:literal, $w2:literal, $w3:literal,
     $w4:literal, $w5:literal) => {
        concat!(
            "ldr {ai}, [{a}, #", $i, " * 8]\n",
            "mul {l0}, {ai}, {b0}\n",
            "mul {l1}, {ai}, {b1}\n",
            "mul {l2}, {ai}, {b2}\n",
            "mul {l3}, {ai}, {b3}\n",
            "adds ", $w0, ", ", $w0, ", {l0}\n",
            "adcs ", $w1, ", ", $w1, ", {l1}\n",
            "adcs ", $w2, ", ", $w2, ", {l2}\n",
            "adcs ", $w3, ", ", $w3, ", {l3}\n",
            "adcs ", $w4, ", ", $w4, ", xzr\n",
            "adc ", $w5, ", xzr, xzr\n",
            "umulh {l0}, {ai}, {b0}\n",
            "umulh {l1}, {ai}, {b1}\n",
            "umulh {l2}, {ai}, {b2}\n",
            "umulh {l3}, {ai}, {b3}\n",
            "adds ", $w1, ", ", $w1, ", {l0}\n",
            "adcs ", $w2, ", ", $w2, ", {l1}\n",
            "adcs ", $w3, ", ", $w3, ", {l2}\n",
            "adcs ", $w4, ", ", $w4, ", {l3}\n",
            "adc ", $w5, ", ", $w5, ", xzr\n",
            // The multiple of the modulus that clears the low word.
            "mul {m}, ", $w0, ", {inv}\n",
            "mul {l0}, {m}, {n0}\n",
            "mul {l1}, {m}, {n1}\n",
            "mul {l2}, {m}, {n2}\n",
            "mul {l3}, {m}, {n3}\n",
            "adds ", $w0, ", ", $w0, ", {l0}\n",
            "adcs ", $w1, ", ", $w1, ", {l1}\n",
            "adcs ", $w2, ", ", $w2, ", {l2}\n",
            "adcs ", $w3, ", ", $w3, ", {l3}\n",
            "adcs ", $w4, ", ", $w4, ", xzr\n",
            "adc ", $w5, ", ", $w5, ", xzr\n",
            "umulh {l0}, {m}, {n0}\n",
            "umulh {l1}, {m}, {n1}\n",
            "umulh {l2}, {m}, {n2}\n",
            "umulh {l3}, {m}, {n3}\n",
            "adds ", $w1, ", ", $w1, ", {l0}\n",
            "adcs ", $w2, ", ", $w2, ", {l1}\n",
            "adcs ", $w3, ", ", $w3, ", {l2}\n",
            "adcs ", $w4, ", ", $w4, ", {l3}\n",
            "adc ", $w5, ", ", $w5, ", xzr\n",
        )
    };
}

/// `a b / 2^256 mod n` for any four-limb odd `n`, with `inv` the
/// negated inverse of its low word modulo `2^64`: the order of either
/// prime curve, where the field's shaped reduction does not apply.
///
/// The result is below the modulus; `a` may be any four limbs and `b`
/// must be below it.
#[inline(always)]
pub(crate) fn mul4<const L: usize>(
    a: &Uint<L>,
    b: &Uint<L>,
    modulus: &Uint<L>,
    inv: u64,
) -> Uint<L> {
    debug_assert_eq!(L, 4);
    let mut out = Uint::<L>::ZERO;
    // SAFETY: the three pointers are to four limbs each, as the width
    // the caller uses this at says, and `inv` is the modulus's.
    unsafe {
        mul4_rows(
            a.0.as_ptr(),
            b.0.as_ptr(),
            modulus.0.as_ptr(),
            inv,
            out.0.as_mut_ptr(),
        );
    }
    out
}

/// The four steps and the subtraction that settles them.
///
/// # Safety
/// `a`, `b`, `n` and `out` must each point at four limbs, `b` below
/// the modulus, and `inv` must be that modulus's.
#[inline(always)]
unsafe fn mul4_rows(
    a: *const u64,
    b: *const u64,
    n: *const u64,
    inv: u64,
    out: *mut u64,
) {
    unsafe {
        core::arch::asm!(
            "ldp {b0}, {b1}, [{b}]",
            "ldp {b2}, {b3}, [{b}, #16]",
            "ldp {n0}, {n1}, [{n}]",
            "ldp {n2}, {n3}, [{n}, #16]",
            "mov {t0}, xzr",
            "mov {t1}, xzr",
            "mov {t2}, xzr",
            "mov {t3}, xzr",
            "mov {t4}, xzr",
            narrow_step!(0, "{t0}", "{t1}", "{t2}", "{t3}", "{t4}", "{t5}"),
            narrow_step!(1, "{t1}", "{t2}", "{t3}", "{t4}", "{t5}", "{t0}"),
            narrow_step!(2, "{t2}", "{t3}", "{t4}", "{t5}", "{t0}", "{t1}"),
            narrow_step!(3, "{t3}", "{t4}", "{t5}", "{t0}", "{t1}", "{t2}"),

            // The steps leave a value below twice the modulus, so one
            // subtraction settles it: kept unless it borrowed out of
            // the top word.
            "subs {l0}, {t4}, {n0}",
            "sbcs {l1}, {t5}, {n1}",
            "sbcs {l2}, {t0}, {n2}",
            "sbcs {l3}, {t1}, {n3}",
            "sbcs xzr, {t2}, xzr",
            "csel {t4}, {t4}, {l0}, cc",
            "csel {t5}, {t5}, {l1}, cc",
            "csel {t0}, {t0}, {l2}, cc",
            "csel {t1}, {t1}, {l3}, cc",
            "stp {t4}, {t5}, [{out}]",
            "stp {t0}, {t1}, [{out}, #16]",

            a = in(reg) a,
            b = in(reg) b,
            n = in(reg) n,
            inv = in(reg) inv,
            out = in(reg) out,
            b0 = out(reg) _, b1 = out(reg) _,
            b2 = out(reg) _, b3 = out(reg) _,
            n0 = out(reg) _, n1 = out(reg) _,
            n2 = out(reg) _, n3 = out(reg) _,
            t0 = out(reg) _, t1 = out(reg) _, t2 = out(reg) _,
            t3 = out(reg) _, t4 = out(reg) _, t5 = out(reg) _,
            l0 = out(reg) _, l1 = out(reg) _,
            l2 = out(reg) _, l3 = out(reg) _,
            m = out(reg) _, ai = out(reg) _,
            options(nostack),
        );
    }
}
