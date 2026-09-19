//! The P-256 point operations written out for A64.
//!
//! The field product is written out for this processor in
//! [`montgomery::aarch64`](crate::math::montgomery::aarch64), but a
//! doubling is eight of those and sixteen modular additions, and each
//! product is an assembly block that clobbers nearly every register,
//! so the compiler spills the point around every one of them. The
//! same thing happened on x86-64, where it was measured: a doubling
//! of 1867 instructions where its eight products are 960.
//!
//! So a doubling is one block, start to finish. Its values live in a
//! frame on the stack, every operation reads and writes that frame,
//! and no register has to survive anything. The frame is `SLOTS`
//! values of four limbs; the caller puts the point in the first ones
//! and reads the result from the last ones.
//!
//! The arithmetic is the module's own, in the same order as
//! [`x86_64`](super::x86_64) does it: nothing here is a different
//! formula. No branch and no address depends on a value.
//!
//! # The registers
//!
//! Fixed throughout, since a block this size has no room for the
//! compiler to choose:
//!
//! ```text
//!   x0-x3    the held value, what one step leaves for the next
//!   x4-x9    the running value of a product
//!   x10-x17  temporaries
//!   x20-x23  the limbs of a product's left operand
//!   x24      one limb of its right operand
//!   x25      the prime's top limb, x26 its second
//!   x27      the caller's buffer
//!   x28      the frame
//! ```
//!
//! x18, x19, x29 and x30 are the platform's or the compiler's, which
//! leaves exactly the twenty-seven above.
//!
//! The frame register points into the frame rather than at its base.
//! A frame of twenty-one values is 672 bytes, which is further than
//! an offset reaches: `ldp` and `stp` go 512 bytes back, and a single
//! word only 256. Eight slots up is therefore as deep as the register
//! can sit, and from there every slot is in reach of both.

#![allow(unsafe_code)]

use crate::math::uint::Uint;

use super::{Affine, Jacobian};

/// Four-limb values in the frame a point operation works in.
const SLOTS: usize = 21;

/// One word of a slot of the frame, as an address. The 256 is where
/// the frame register sits above the frame's base, spelled out
/// because the assembler wants a number here.
#[rustfmt::skip]
macro_rules! at {
    ($i:literal, $k:literal) => {
        concat!("[x28, #", $i, " * 32 + ", $k, " - ", 256, "]")
    };
}

/// One word of a value in the caller's buffer.
#[rustfmt::skip]
macro_rules! io {
    ($i:literal, $k:literal) => {
        concat!("[x27, #", $i, " * 32 + ", $k, "]")
    };
}

/// A value of the caller's buffer into a slot of the frame.
#[rustfmt::skip]
macro_rules! take {
    ($i:literal, $slot:literal) => {
        concat!(
            "ldp x0, x1, ", io!($i, 0), "\n",
            "ldp x2, x3, ", io!($i, 16), "\n",
            "stp x0, x1, ", at!($slot, 0), "\n",
            "stp x2, x3, ", at!($slot, 16), "\n",
        )
    };
}

/// A slot of the frame back into the caller's buffer.
#[rustfmt::skip]
macro_rules! give {
    ($slot:literal, $i:literal) => {
        concat!(
            "ldp x0, x1, ", at!($slot, 0), "\n",
            "ldp x2, x3, ", at!($slot, 16), "\n",
            "stp x0, x1, ", io!($i, 0), "\n",
            "stp x2, x3, ", io!($i, 16), "\n",
        )
    };
}

/// One value copied to another slot of the frame.
#[rustfmt::skip]
macro_rules! keep {
    ($dst:literal, $src:literal) => {
        concat!(
            "ldp x10, x11, ", at!($src, 0), "\n",
            "ldp x12, x13, ", at!($src, 16), "\n",
            "stp x10, x11, ", at!($dst, 0), "\n",
            "stp x12, x13, ", at!($dst, 16), "\n",
        )
    };
}

/// The prime taken off the held value, which is below twice it and
/// has just carried out into the flags: kept unless that subtraction
/// borrowed while the value itself did not carry.
///
/// The prime's low word is all ones, so subtracting it is adding one,
/// and its third word is zero.
#[rustfmt::skip]
macro_rules! trim {
    () => {
        concat!(
            "adc x14, xzr, xzr\n",
            "adds x10, x0, #1\n",
            "sbcs x11, x1, x26\n",
            "sbcs x12, x2, xzr\n",
            "sbcs x13, x3, x25\n",
            "sbcs xzr, x14, xzr\n",
            "csel x0, x0, x10, cc\n",
            "csel x1, x1, x11, cc\n",
            "csel x2, x2, x12, cc\n",
            "csel x3, x3, x13, cc\n",
        )
    };
}

/// The prime put back on the held value, which has just borrowed out
/// into the flags. Its words are masked by the borrow first, since
/// the masking itself would clear the flag.
#[rustfmt::skip]
macro_rules! untrim {
    () => {
        concat!(
            "sbc x14, xzr, xzr\n",
            "and x15, x14, x26\n",
            "and x16, x14, x25\n",
            "adds x0, x0, x14\n",
            "adcs x1, x1, x15\n",
            "adcs x2, x2, xzr\n",
            "adc x3, x3, x16\n",
        )
    };
}

/// A slot of the frame into the held value, and back.
#[rustfmt::skip]
macro_rules! loadr {
    ($a:literal) => {
        concat!(
            "ldp x0, x1, ", at!($a, 0), "\n",
            "ldp x2, x3, ", at!($a, 16), "\n",
        )
    };
}

#[rustfmt::skip]
macro_rules! storer {
    ($dst:literal) => {
        concat!(
            "stp x0, x1, ", at!($dst, 0), "\n",
            "stp x2, x3, ", at!($dst, 16), "\n",
        )
    };
}

/// A slot of the frame added to the held value, which keeps it.
#[rustfmt::skip]
macro_rules! addr {
    ($b:literal) => {
        concat!(
            "ldp x10, x11, ", at!($b, 0), "\n",
            "ldp x12, x13, ", at!($b, 16), "\n",
            "adds x0, x0, x10\n",
            "adcs x1, x1, x11\n",
            "adcs x2, x2, x12\n",
            "adcs x3, x3, x13\n",
            trim!(),
        )
    };
}

/// The held value doubled.
#[rustfmt::skip]
macro_rules! dblr {
    () => {
        concat!(
            "adds x0, x0, x0\n",
            "adcs x1, x1, x1\n",
            "adcs x2, x2, x2\n",
            "adcs x3, x3, x3\n",
            trim!(),
        )
    };
}

/// The held value less a slot of the frame.
#[rustfmt::skip]
macro_rules! subr {
    ($b:literal) => {
        concat!(
            "ldp x10, x11, ", at!($b, 0), "\n",
            "ldp x12, x13, ", at!($b, 16), "\n",
            "subs x0, x0, x10\n",
            "sbcs x1, x1, x11\n",
            "sbcs x2, x2, x12\n",
            "sbcs x3, x3, x13\n",
            untrim!(),
        )
    };
}

/// `dst = a + b mod p`, every operand a slot of the frame.
#[rustfmt::skip]
macro_rules! fadd {
    ($dst:literal, $a:literal, $b:literal) => {
        concat!(
            loadr!($a),
            addr!($b),
            storer!($dst),
        )
    };
}

/// `dst = a - b mod p`.
#[rustfmt::skip]
macro_rules! fsub {
    ($dst:literal, $a:literal, $b:literal) => {
        concat!(
            loadr!($a),
            subr!($b),
            storer!($dst),
        )
    };
}

/// One row of the product: word `$i` of the slot `$b` against the
/// four limbs in `x20..x23`, folded into the running value.
///
/// The low halves go in first and the high halves one word up, since
/// A64 carries one chain at a time. `mul` and `umulh` leave the flags
/// alone, so every product of a pass is issued before its chain
/// starts and nothing in the chain waits on a multiply.
#[rustfmt::skip]
macro_rules! row {
    ($b:literal, $i:literal, $w0:literal, $w1:literal, $w2:literal,
     $w3:literal, $w4:literal, $w5:literal) => {
        concat!(
            "ldr x24, [x28, #", $b, " * 32 + ", $i, " * 8 - 256]\n",
            "mul x10, x20, x24\n",
            "mul x11, x21, x24\n",
            "mul x12, x22, x24\n",
            "mul x13, x23, x24\n",
            "umulh x14, x20, x24\n",
            "umulh x15, x21, x24\n",
            "umulh x16, x22, x24\n",
            "umulh x17, x23, x24\n",
            "adds ", $w0, ", ", $w0, ", x10\n",
            "adcs ", $w1, ", ", $w1, ", x11\n",
            "adcs ", $w2, ", ", $w2, ", x12\n",
            "adcs ", $w3, ", ", $w3, ", x13\n",
            "adcs ", $w4, ", ", $w4, ", xzr\n",
            "adc ", $w5, ", xzr, xzr\n",
            "adds ", $w1, ", ", $w1, ", x14\n",
            "adcs ", $w2, ", ", $w2, ", x15\n",
            "adcs ", $w3, ", ", $w3, ", x16\n",
            "adcs ", $w4, ", ", $w4, ", x17\n",
            "adc ", $w5, ", ", $w5, ", xzr\n",
        )
    };
}

/// The reduction of the running value by its low word, which moves
/// the value down one word and leaves `$w0` spare.
///
/// The prime is `2^256 - 2^224 + 2^192 + 2^96 - 1`, so the multiple
/// that clears the low word is that word itself, and adding it is two
/// shifts near the bottom and one product by the prime's top limb
/// three words up.
#[rustfmt::skip]
macro_rules! reduce {
    ($w0:literal, $w1:literal, $w2:literal, $w3:literal, $w4:literal,
     $w5:literal) => {
        concat!(
            "lsl x10, ", $w0, ", #32\n",
            "lsr x11, ", $w0, ", #32\n",
            "mul x12, ", $w0, ", x25\n",
            "umulh x13, ", $w0, ", x25\n",
            "adds ", $w1, ", ", $w1, ", x10\n",
            "adcs ", $w2, ", ", $w2, ", x11\n",
            "adcs ", $w3, ", ", $w3, ", x12\n",
            "adcs ", $w4, ", ", $w4, ", x13\n",
            "adc ", $w5, ", ", $w5, ", xzr\n",
        )
    };
}

/// `a b / 2^256 mod p`, the four rows and their reductions, leaving
/// the value in `x8, x9, x4, x5` with a top word in `x6`. The body is
/// separate from its ending so that the result can either go back to
/// the frame or stay held.
#[rustfmt::skip]
macro_rules! fmul_body {
    ($a:literal, $b:literal) => {
        concat!(
            "ldp x20, x21, ", at!($a, 0), "\n",
            "ldp x22, x23, ", at!($a, 16), "\n",
            // The first row has nothing to add into, so the products
            // land in the words themselves.
            "ldr x24, ", at!($b, 0), "\n",
            "mul x4, x20, x24\n",
            "umulh x5, x20, x24\n",
            "mul x10, x21, x24\n",
            "umulh x14, x21, x24\n",
            "mul x11, x22, x24\n",
            "umulh x15, x22, x24\n",
            "mul x12, x23, x24\n",
            "umulh x16, x23, x24\n",
            "adds x5, x5, x10\n",
            "adcs x6, x14, x11\n",
            "adcs x7, x15, x12\n",
            "adc x8, x16, xzr\n",
            "mov x9, xzr\n",
            reduce!("x4", "x5", "x6", "x7", "x8", "x9"),
            row!($b, 1, "x5", "x6", "x7", "x8", "x9", "x4"),
            reduce!("x5", "x6", "x7", "x8", "x9", "x4"),
            row!($b, 2, "x6", "x7", "x8", "x9", "x4", "x5"),
            reduce!("x6", "x7", "x8", "x9", "x4", "x5"),
            row!($b, 3, "x7", "x8", "x9", "x4", "x5", "x6"),
            reduce!("x7", "x8", "x9", "x4", "x5", "x6"),
        )
    };
}

/// The conditional subtraction that ends a product: the value is
/// below twice the prime, so one subtraction settles it.
#[rustfmt::skip]
macro_rules! settle {
    () => {
        concat!(
            "adds x10, x8, #1\n",
            "sbcs x11, x9, x26\n",
            "sbcs x12, x4, xzr\n",
            "sbcs x13, x5, x25\n",
            "sbcs xzr, x6, xzr\n",
            "csel x8, x8, x10, cc\n",
            "csel x9, x9, x11, cc\n",
            "csel x4, x4, x12, cc\n",
            "csel x5, x5, x13, cc\n",
        )
    };
}

/// The product, into a slot of the frame.
#[rustfmt::skip]
macro_rules! fmul {
    ($dst:literal, $a:literal, $b:literal) => {
        concat!(
            fmul_body!($a, $b),
            settle!(),
            "stp x8, x9, ", at!($dst, 0), "\n",
            "stp x4, x5, ", at!($dst, 16), "\n",
        )
    };
}

/// The product, held in `x0..x3` for the next step to take.
#[rustfmt::skip]
macro_rules! fmul_held {
    ($a:literal, $b:literal) => {
        concat!(
            fmul_body!($a, $b),
            settle!(),
            "mov x0, x8\n",
            "mov x1, x9\n",
            "mov x2, x4\n",
            "mov x3, x5\n",
        )
    };
}

/// The square, which is the product of a value with itself until a
/// written-out square is measured to be worth its own block: the
/// cross products would save six of the sixteen, and the rows here
/// spend nothing on loads to save them from.
#[rustfmt::skip]
macro_rules! fsqr {
    ($dst:literal, $a:literal) => { fmul!($dst, $a, $a) };
}

#[rustfmt::skip]
macro_rules! fsqr_held {
    ($a:literal) => { fmul_held!($a, $a) };
}

/// `dst` squared `$n` times in place, as a counted loop. The count
/// lives in the frame's last slot, every register being spoken for;
/// nothing that uses this macro uses that slot.
#[rustfmt::skip]
macro_rules! sqrn {
    ($dst:literal, $n:literal) => {
        concat!(
            "mov x24, #", $n, "\n",
            "str x24, ", at!(20, 0), "\n",
            "2:\n",
            fsqr!($dst, $dst),
            "ldr x24, ", at!(20, 0), "\n",
            "sub x24, x24, #1\n",
            "str x24, ", at!(20, 0), "\n",
            "cbnz x24, 2b\n",
        )
    };
}

/// What every block begins with: the frame, addressed from its
/// middle, and the two words of the prime the trimming needs.
#[rustfmt::skip]
macro_rules! enter {
    () => {
        concat!(
            "sub sp, sp, #{frame}\n",
            "add x28, sp, #", 256, "\n",
            "mov x25, #0xffffffff00000000\n",
            "orr x25, x25, #1\n",
            "mov x26, #0xffffffff\n",
        )
    };
}

/// The inverse of the value at `io`, into the value above it: `a` to
/// the power `p - 2`, which is `a^-1` for everything but zero, and
/// zero for that.
///
/// The exponent is `[32 ones][31 zeros][1][96 zeros][94 ones][0][1]`,
/// so the chain builds `a^(2^k - 1)` for `k` of 2, 4, 8, 16 and 32,
/// and then walks the exponent in those runs: 255 squarings and 13
/// multiplications, against the 295 operations a window slid over the
/// same exponent costs, and all of it in one block.
///
/// # Safety
/// `io` must point at two values of four limbs, the first below the
/// prime.
#[rustfmt::skip]
unsafe fn invert(io: *mut u64) {
    unsafe {
        core::arch::asm!(
            enter!(),
            take!(0, 0),
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
            give!(1, 1),
            "add sp, sp, #{frame}",
            frame = const SLOTS * 32,
            inout("x27") io => _,
            out("x0") _, out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _, out("x20") _, out("x21") _,
            out("x22") _, out("x23") _, out("x24") _, out("x25") _,
            out("x26") _, out("x28") _,
        );
    }
}

/// Twice the point in the first three values at `io`, into the three
/// above them. The formula is [`super::Engine::jacobian_double`]'s,
/// with each step's result kept in registers where the next step
/// takes it.
///
/// # Safety
/// `io` must point at six values of four limbs, the first three the
/// point's coordinates, each below the prime.
#[rustfmt::skip]
unsafe fn double(io: *mut u64) {
    unsafe {
        core::arch::asm!(
            enter!(),
            take!(0, 0),
            take!(1, 1),
            take!(2, 2),
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
            give!(10, 3),
            give!(11, 4),
            give!(12, 5),
            "add sp, sp, #{frame}",
            frame = const SLOTS * 32,
            inout("x27") io => _,
            out("x0") _, out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _, out("x20") _, out("x21") _,
            out("x22") _, out("x23") _, out("x24") _, out("x25") _,
            out("x26") _, out("x28") _,
        );
    }
}

/// The sum of the point in the first three values at `io` and the
/// affine point in the two above them, into the three above those.
/// The formula is [`super::Engine::jacobian_add_affine`]'s, and the
/// cases it misses are the caller's, as they are there.
///
/// # Safety
/// `io` must point at eight values of four limbs, the first five the
/// two points' coordinates, each below the prime.
#[rustfmt::skip]
unsafe fn add_affine(io: *mut u64) {
    unsafe {
        core::arch::asm!(
            enter!(),
            take!(0, 0),
            take!(1, 1),
            take!(2, 2),
            take!(3, 3),
            take!(4, 4),
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
            give!(15, 5),
            give!(16, 6),
            give!(17, 7),
            "add sp, sp, #{frame}",
            frame = const SLOTS * 32,
            inout("x27") io => _,
            out("x0") _, out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _, out("x20") _, out("x21") _,
            out("x22") _, out("x23") _, out("x24") _, out("x25") _,
            out("x26") _, out("x28") _,
        );
    }
}

/// The sum of the two points at `io`, into the three values above
/// them. The formula is [`super::Engine::jacobian_add`]'s, and the
/// cases it misses are the caller's, as they are there.
///
/// # Safety
/// `io` must point at nine values of four limbs, the first six the
/// two points' coordinates, each below the prime.
#[rustfmt::skip]
unsafe fn add(io: *mut u64) {
    unsafe {
        core::arch::asm!(
            enter!(),
            take!(0, 0),
            take!(1, 1),
            take!(2, 2),
            take!(3, 3),
            take!(4, 4),
            take!(5, 5),
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
            give!(18, 6),
            give!(19, 7),
            give!(20, 8),
            "add sp, sp, #{frame}",
            frame = const SLOTS * 32,
            inout("x27") io => _,
            out("x0") _, out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _, out("x20") _, out("x21") _,
            out("x22") _, out("x23") _, out("x24") _, out("x25") _,
            out("x26") _, out("x28") _,
        );
    }
}

/// Twice `p`, in Jacobian coordinates.
///
/// The width is a parameter only so that the curve arithmetic, which
/// is generic over it, can call this: four limbs is what the caller
/// must have.
///
/// The point goes in and comes out through a buffer of the caller's
/// rather than by a pointer to the point itself, as on x86-64, where
/// passing the point's own memory measured slower.
#[inline(always)]
pub(super) fn jacobian_double<const L: usize>(p: &Jacobian<L>) -> Jacobian<L> {
    debug_assert_eq!(L, 4);
    let mut io = [[0u64; 4]; 6];
    io[0][..L].copy_from_slice(&p.x.0);
    io[1][..L].copy_from_slice(&p.y.0);
    io[2][..L].copy_from_slice(&p.z.0);
    // SAFETY: the buffer is the six values the block reads and
    // writes, and the caller's width is four limbs.
    unsafe {
        double(io.as_mut_ptr().cast());
    }
    out_of(&io[3], &io[4], &io[5])
}

/// `p + q`, `q` affine, in Jacobian coordinates. The cases the
/// formula misses are settled by the caller, as they are in the
/// portable one.
#[inline(always)]
pub(super) fn jacobian_add_affine<const L: usize>(
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
    out_of(&io[5], &io[6], &io[7])
}

/// `p + q`, both Jacobian. The cases the formula misses are settled
/// by the caller, as they are in the portable one.
#[inline(always)]
pub(super) fn jacobian_add<const L: usize>(
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
    out_of(&io[6], &io[7], &io[8])
}

/// `a^-1` in the field, or zero for zero.
#[inline(always)]
pub(super) fn invert_field<const L: usize>(a: &Uint<L>) -> Uint<L> {
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

/// The three values a block leaves, as a point.
#[inline(always)]
fn out_of<const L: usize>(
    x: &[u64; 4],
    y: &[u64; 4],
    z: &[u64; 4],
) -> Jacobian<L> {
    let mut out = Jacobian {
        x: Uint::<L>::ZERO,
        y: Uint::<L>::ZERO,
        z: Uint::<L>::ZERO,
    };
    out.x.0.copy_from_slice(&x[..L]);
    out.y.0.copy_from_slice(&y[..L]);
    out.z.0.copy_from_slice(&z[..L]);
    out
}
