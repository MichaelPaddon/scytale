//! AES on the x86_64 AES instructions.
//!
//! These types can only be constructed on a CPU that has the instructions,
//! which [`supported`] reports. Naming them directly is for callers who have
//! already established that; everything else should use the parent module's
//! names, which check once and choose.
//!
//! Unlike a T-table cipher this is constant time with respect to the key.
//! The round transformation is a single instruction with no data dependent
//! memory access, so nothing about the key is visible in the cache.
//!
//! The kernels are hand written assembly, fully unrolled: every round key
//! is named by a fixed offset, so the round sequence is straight line code
//! with no loop bookkeeping. The key schedule uses intrinsics, which is not
//! a hot path and reads better as expressions.

use core::arch::asm;
use core::arch::x86_64::*;

use zeroize::Zeroize;

use crate::symmetric::block_cipher::{
    BlockDecrypt, BlockEncrypt, InvalidKeyLength, KeyInit,
};

/// The AES block size in bytes.
pub const BLOCK_SIZE: usize = 16;

/// Blocks processed per iteration of the bulk loop.
///
/// `aesenc` takes several cycles to produce a result but accepts a new one
/// every cycle, so a single chain of dependent rounds leaves most of that
/// throughput idle. Eight independent blocks cover the latency.
const WIDTH: usize = 8;

/// Whether this CPU has the AES instructions.
///
/// The answer cannot change while the process runs, so it is worked out
/// once and remembered.
pub fn supported() -> bool {
    use std::sync::OnceLock;
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| is_x86_feature_detected!("aes"))
}

/// A fully unrolled 8 block kernel.
///
/// The register lines are written out so that the round keys
/// are the only repetition, which is what lets the whole round
/// sequence be straight line code. A loop over the keys costs
/// an add, a decrement and a branch per round.
macro_rules! kernel8 {
    (
        $name:ident, $round:literal, $last:literal,
        [$($key:literal),+], $final:literal
    ) => {
        /// # Safety
        ///
        /// The CPU must have the AES instructions. `rk` must
        /// hold the whole schedule and `data` 8 blocks.
        #[inline(always)]
        unsafe fn $name(rk: *const u8, data: *mut u8) {
            // SAFETY: the caller guarantees the instructions
            // and both ranges. Round keys are read with
            // movdqu because the non-VEX forms need a sixteen
            // byte aligned memory operand.
            unsafe {
                asm!(
                    "movdqu xmm8, [{rk}]",
                    "movdqu xmm0, [{d} + 0x00]",
                    "movdqu xmm1, [{d} + 0x10]",
                    "movdqu xmm2, [{d} + 0x20]",
                    "movdqu xmm3, [{d} + 0x30]",
                    "movdqu xmm4, [{d} + 0x40]",
                    "movdqu xmm5, [{d} + 0x50]",
                    "movdqu xmm6, [{d} + 0x60]",
                    "movdqu xmm7, [{d} + 0x70]",
                    "pxor xmm0, xmm8",
                    "pxor xmm1, xmm8",
                    "pxor xmm2, xmm8",
                    "pxor xmm3, xmm8",
                    "pxor xmm4, xmm8",
                    "pxor xmm5, xmm8",
                    "pxor xmm6, xmm8",
                    "pxor xmm7, xmm8",
                    $(
                        concat!("movdqu xmm8, [{rk} + ", $key, "]"),
                        concat!($round, " xmm0, xmm8"),
                        concat!($round, " xmm1, xmm8"),
                        concat!($round, " xmm2, xmm8"),
                        concat!($round, " xmm3, xmm8"),
                        concat!($round, " xmm4, xmm8"),
                        concat!($round, " xmm5, xmm8"),
                        concat!($round, " xmm6, xmm8"),
                        concat!($round, " xmm7, xmm8"),
                    )+
                    concat!("movdqu xmm8, [{rk} + ", $final, "]"),
                    concat!($last, " xmm0, xmm8"),
                    concat!($last, " xmm1, xmm8"),
                    concat!($last, " xmm2, xmm8"),
                    concat!($last, " xmm3, xmm8"),
                    concat!($last, " xmm4, xmm8"),
                    concat!($last, " xmm5, xmm8"),
                    concat!($last, " xmm6, xmm8"),
                    concat!($last, " xmm7, xmm8"),
                    "movdqu [{d} + 0x00], xmm0",
                    "movdqu [{d} + 0x10], xmm1",
                    "movdqu [{d} + 0x20], xmm2",
                    "movdqu [{d} + 0x30], xmm3",
                    "movdqu [{d} + 0x40], xmm4",
                    "movdqu [{d} + 0x50], xmm5",
                    "movdqu [{d} + 0x60], xmm6",
                    "movdqu [{d} + 0x70], xmm7",
                    rk = in(reg) rk,
                    d = in(reg) data,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm7") _, out("xmm8") _,
                    options(nostack),
                );
            }
        }
    };
}

/// A fully unrolled 4 block kernel.
///
/// The register lines are written out so that the round keys
/// are the only repetition, which is what lets the whole round
/// sequence be straight line code. A loop over the keys costs
/// an add, a decrement and a branch per round.
macro_rules! kernel4 {
    (
        $name:ident, $round:literal, $last:literal,
        [$($key:literal),+], $final:literal
    ) => {
        /// # Safety
        ///
        /// The CPU must have the AES instructions. `rk` must
        /// hold the whole schedule and `data` 4 blocks.
        #[inline(always)]
        unsafe fn $name(rk: *const u8, data: *mut u8) {
            // SAFETY: the caller guarantees the instructions
            // and both ranges. Round keys are read with
            // movdqu because the non-VEX forms need a sixteen
            // byte aligned memory operand.
            unsafe {
                asm!(
                    "movdqu xmm8, [{rk}]",
                    "movdqu xmm0, [{d} + 0x00]",
                    "movdqu xmm1, [{d} + 0x10]",
                    "movdqu xmm2, [{d} + 0x20]",
                    "movdqu xmm3, [{d} + 0x30]",
                    "pxor xmm0, xmm8",
                    "pxor xmm1, xmm8",
                    "pxor xmm2, xmm8",
                    "pxor xmm3, xmm8",
                    $(
                        concat!("movdqu xmm8, [{rk} + ", $key, "]"),
                        concat!($round, " xmm0, xmm8"),
                        concat!($round, " xmm1, xmm8"),
                        concat!($round, " xmm2, xmm8"),
                        concat!($round, " xmm3, xmm8"),
                    )+
                    concat!("movdqu xmm8, [{rk} + ", $final, "]"),
                    concat!($last, " xmm0, xmm8"),
                    concat!($last, " xmm1, xmm8"),
                    concat!($last, " xmm2, xmm8"),
                    concat!($last, " xmm3, xmm8"),
                    "movdqu [{d} + 0x00], xmm0",
                    "movdqu [{d} + 0x10], xmm1",
                    "movdqu [{d} + 0x20], xmm2",
                    "movdqu [{d} + 0x30], xmm3",
                    rk = in(reg) rk,
                    d = in(reg) data,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm7") _, out("xmm8") _,
                    options(nostack),
                );
            }
        }
    };
}

/// A fully unrolled 2 block kernel.
///
/// The register lines are written out so that the round keys
/// are the only repetition, which is what lets the whole round
/// sequence be straight line code. A loop over the keys costs
/// an add, a decrement and a branch per round.
macro_rules! kernel2 {
    (
        $name:ident, $round:literal, $last:literal,
        [$($key:literal),+], $final:literal
    ) => {
        /// # Safety
        ///
        /// The CPU must have the AES instructions. `rk` must
        /// hold the whole schedule and `data` 2 blocks.
        #[inline(always)]
        unsafe fn $name(rk: *const u8, data: *mut u8) {
            // SAFETY: the caller guarantees the instructions
            // and both ranges. Round keys are read with
            // movdqu because the non-VEX forms need a sixteen
            // byte aligned memory operand.
            unsafe {
                asm!(
                    "movdqu xmm8, [{rk}]",
                    "movdqu xmm0, [{d} + 0x00]",
                    "movdqu xmm1, [{d} + 0x10]",
                    "pxor xmm0, xmm8",
                    "pxor xmm1, xmm8",
                    $(
                        concat!("movdqu xmm8, [{rk} + ", $key, "]"),
                        concat!($round, " xmm0, xmm8"),
                        concat!($round, " xmm1, xmm8"),
                    )+
                    concat!("movdqu xmm8, [{rk} + ", $final, "]"),
                    concat!($last, " xmm0, xmm8"),
                    concat!($last, " xmm1, xmm8"),
                    "movdqu [{d} + 0x00], xmm0",
                    "movdqu [{d} + 0x10], xmm1",
                    rk = in(reg) rk,
                    d = in(reg) data,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm7") _, out("xmm8") _,
                    options(nostack),
                );
            }
        }
    };
}

/// A fully unrolled 1 block kernel.
///
/// The register lines are written out so that the round keys
/// are the only repetition, which is what lets the whole round
/// sequence be straight line code. A loop over the keys costs
/// an add, a decrement and a branch per round.
macro_rules! kernel1 {
    (
        $name:ident, $round:literal, $last:literal,
        [$($key:literal),+], $final:literal
    ) => {
        /// # Safety
        ///
        /// The CPU must have the AES instructions. `rk` must
        /// hold the whole schedule and `data` 1 blocks.
        #[inline(always)]
        unsafe fn $name(rk: *const u8, data: *mut u8) {
            // SAFETY: the caller guarantees the instructions
            // and both ranges. Round keys are read with
            // movdqu because the non-VEX forms need a sixteen
            // byte aligned memory operand.
            unsafe {
                asm!(
                    "movdqu xmm8, [{rk}]",
                    "movdqu xmm0, [{d} + 0x00]",
                    "pxor xmm0, xmm8",
                    $(
                        concat!("movdqu xmm8, [{rk} + ", $key, "]"),
                        concat!($round, " xmm0, xmm8"),
                    )+
                    concat!("movdqu xmm8, [{rk} + ", $final, "]"),
                    concat!($last, " xmm0, xmm8"),
                    "movdqu [{d} + 0x00], xmm0",
                    rk = in(reg) rk,
                    d = in(reg) data,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm7") _, out("xmm8") _,
                    options(nostack),
                );
            }
        }
    };
}

kernel8!(
    e128_8, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90"], "0xa0"
);
kernel4!(
    e128_4, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90"], "0xa0"
);
kernel2!(
    e128_2, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90"], "0xa0"
);
kernel1!(
    e128_1, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90"], "0xa0"
);
kernel8!(
    d128_8, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90"], "0xa0"
);
kernel4!(
    d128_4, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90"], "0xa0"
);
kernel2!(
    d128_2, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90"], "0xa0"
);
kernel1!(
    d128_1, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90"], "0xa0"
);
kernel8!(
    e192_8, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0"], "0xc0"
);
kernel4!(
    e192_4, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0"], "0xc0"
);
kernel2!(
    e192_2, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0"], "0xc0"
);
kernel1!(
    e192_1, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0"], "0xc0"
);
kernel8!(
    d192_8, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0"], "0xc0"
);
kernel4!(
    d192_4, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0"], "0xc0"
);
kernel2!(
    d192_2, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0"], "0xc0"
);
kernel1!(
    d192_1, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0"], "0xc0"
);
kernel8!(
    e256_8, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0", "0xc0", "0xd0"], "0xe0"
);
kernel4!(
    e256_4, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0", "0xc0", "0xd0"], "0xe0"
);
kernel2!(
    e256_2, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0", "0xc0", "0xd0"], "0xe0"
);
kernel1!(
    e256_1, "aesenc", "aesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0", "0xc0", "0xd0"], "0xe0"
);
kernel8!(
    d256_8, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0", "0xc0", "0xd0"], "0xe0"
);
kernel4!(
    d256_4, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0", "0xc0", "0xd0"], "0xe0"
);
kernel2!(
    d256_2, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0", "0xc0", "0xd0"], "0xe0"
);
kernel1!(
    d256_1, "aesdec", "aesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0", "0xc0", "0xd0"], "0xe0"
);

/// Walk a buffer through the widest kernel that fits, repeatedly.
///
/// Each key size and direction gets its own driver so the calls are direct
/// and inline. Reaching the kernels through a table of function pointers
/// costs an indirect call per group of blocks and stops them inlining at
/// all, which is worth more than it sounds on short buffers.
macro_rules! driver {
    ($name:ident, $w8:ident, $w4:ident, $w2:ident, $w1:ident) => {
        /// # Safety
        ///
        /// The CPU must have the AES instructions, `rk` must be the
        /// schedule these kernels were built for, and `data` must hold
        /// `blocks` whole blocks.
        #[inline(always)]
        unsafe fn $name(rk: *const u8, data: *mut u8, blocks: usize) {
            // SAFETY: each call gets a pointer to at least as many whole
            // blocks as its kernel touches, and blocks are contiguous.
            unsafe {
                let mut i = 0;
                while i + 8 <= blocks {
                    $w8(rk, data.add(i * BLOCK_SIZE));
                    i += 8;
                }
                if i + 4 <= blocks {
                    $w4(rk, data.add(i * BLOCK_SIZE));
                    i += 4;
                }
                if i + 2 <= blocks {
                    $w2(rk, data.add(i * BLOCK_SIZE));
                    i += 2;
                }
                if i < blocks {
                    $w1(rk, data.add(i * BLOCK_SIZE));
                }
            }
        }
    };
}

driver!(encrypt_128, e128_8, e128_4, e128_2, e128_1);
driver!(decrypt_128, d128_8, d128_4, d128_2, d128_1);
driver!(encrypt_192, e192_8, e192_4, e192_2, e192_1);
driver!(decrypt_192, d192_8, d192_4, d192_2, d192_1);
driver!(encrypt_256, e256_8, e256_4, e256_2, e256_1);
driver!(decrypt_256, d256_8, d256_4, d256_2, d256_1);

/// Splice the low halves of two round key registers together.
///
/// AES-192's six word key blocks do not line up with sixteen byte round
/// keys, so half of its round keys are built from two registers.
#[inline(always)]
unsafe fn splice<const MASK: i32>(a: __m128i, b: __m128i) -> __m128i {
    // SAFETY: shuffle_pd is SSE2, which is baseline on this target.
    unsafe {
        _mm_castpd_si128(_mm_shuffle_pd::<MASK>(
            _mm_castsi128_pd(a),
            _mm_castsi128_pd(b),
        ))
    }
}

/// One step of the AES-128 and AES-256 key schedules.
#[inline(always)]
unsafe fn assist(a: __m128i, b: __m128i) -> __m128i {
    // SAFETY: every intrinsic here is SSE2.
    unsafe {
        let b = _mm_shuffle_epi32(b, 0xff);
        let c = _mm_slli_si128(a, 4);
        let a = _mm_xor_si128(a, c);
        let c = _mm_slli_si128(c, 4);
        let a = _mm_xor_si128(a, c);
        let c = _mm_slli_si128(c, 4);
        let a = _mm_xor_si128(a, c);
        _mm_xor_si128(a, b)
    }
}

/// Expand an AES-128 key into its eleven round keys.
///
/// # Safety
///
/// The CPU must have the AES instructions, and `rk` must be a sixteen byte
/// aligned pointer to eleven round keys.
#[target_feature(enable = "aes")]
unsafe fn expand_128(key: &[u8; 16], rk: *mut __m128i) {
    // SAFETY: the caller guarantees the instructions and the destination;
    // sixteen bytes of key are read, which is its size.
    unsafe {
        let mut t = _mm_loadu_si128(key.as_ptr().cast());
        _mm_store_si128(rk, t);
        t = assist(t, _mm_aeskeygenassist_si128(t, 0x01));
        _mm_store_si128(rk.add(1), t);
        t = assist(t, _mm_aeskeygenassist_si128(t, 0x02));
        _mm_store_si128(rk.add(2), t);
        t = assist(t, _mm_aeskeygenassist_si128(t, 0x04));
        _mm_store_si128(rk.add(3), t);
        t = assist(t, _mm_aeskeygenassist_si128(t, 0x08));
        _mm_store_si128(rk.add(4), t);
        t = assist(t, _mm_aeskeygenassist_si128(t, 0x10));
        _mm_store_si128(rk.add(5), t);
        t = assist(t, _mm_aeskeygenassist_si128(t, 0x20));
        _mm_store_si128(rk.add(6), t);
        t = assist(t, _mm_aeskeygenassist_si128(t, 0x40));
        _mm_store_si128(rk.add(7), t);
        t = assist(t, _mm_aeskeygenassist_si128(t, 0x80));
        _mm_store_si128(rk.add(8), t);
        t = assist(t, _mm_aeskeygenassist_si128(t, 0x1b));
        _mm_store_si128(rk.add(9), t);
        t = assist(t, _mm_aeskeygenassist_si128(t, 0x36));
        _mm_store_si128(rk.add(10), t);
    }
}

/// One step of the AES-192 key schedule.
#[inline(always)]
unsafe fn assist_192(t1: &mut __m128i, t2: __m128i, t3: &mut __m128i) {
    // SAFETY: every intrinsic here is SSE2.
    unsafe {
        let t2 = _mm_shuffle_epi32(t2, 0x55);
        let mut c = _mm_slli_si128(*t1, 4);
        *t1 = _mm_xor_si128(*t1, c);
        c = _mm_slli_si128(c, 4);
        *t1 = _mm_xor_si128(*t1, c);
        c = _mm_slli_si128(c, 4);
        *t1 = _mm_xor_si128(*t1, c);
        *t1 = _mm_xor_si128(*t1, t2);

        let spread = _mm_shuffle_epi32(*t1, 0xff);
        let c = _mm_slli_si128(*t3, 4);
        *t3 = _mm_xor_si128(*t3, c);
        *t3 = _mm_xor_si128(*t3, spread);
    }
}

/// Expand an AES-192 key into its thirteen round keys.
///
/// # Safety
///
/// The CPU must have the AES instructions, and `rk` must be a sixteen byte
/// aligned pointer to thirteen round keys.
#[target_feature(enable = "aes")]
unsafe fn expand_192(key: &[u8; 24], rk: *mut __m128i) {
    // SAFETY: the caller guarantees the instructions and the destination.
    // The second load takes eight bytes, so only the 24 bytes of key are
    // read.
    unsafe {
        let mut t1 = _mm_loadu_si128(key.as_ptr().cast());
        let mut t3 = _mm_loadl_epi64(key.as_ptr().add(16).cast());
        _mm_store_si128(rk, t1);
        let prev = t3;
        assist_192(
            &mut t1,
            _mm_aeskeygenassist_si128(t3, 0x01),
            &mut t3,
        );
        _mm_store_si128(rk.add(1), splice::<0>(prev, t1));
        _mm_store_si128(rk.add(2), splice::<1>(t1, t3));
        assist_192(
            &mut t1,
            _mm_aeskeygenassist_si128(t3, 0x02),
            &mut t3,
        );
        _mm_store_si128(rk.add(3), t1);
        _mm_store_si128(rk.add(4), t3);
        let prev = t3;
        assist_192(
            &mut t1,
            _mm_aeskeygenassist_si128(t3, 0x04),
            &mut t3,
        );
        _mm_store_si128(rk.add(4), splice::<0>(prev, t1));
        _mm_store_si128(rk.add(5), splice::<1>(t1, t3));
        assist_192(
            &mut t1,
            _mm_aeskeygenassist_si128(t3, 0x08),
            &mut t3,
        );
        _mm_store_si128(rk.add(6), t1);
        _mm_store_si128(rk.add(7), t3);
        let prev = t3;
        assist_192(
            &mut t1,
            _mm_aeskeygenassist_si128(t3, 0x10),
            &mut t3,
        );
        _mm_store_si128(rk.add(7), splice::<0>(prev, t1));
        _mm_store_si128(rk.add(8), splice::<1>(t1, t3));
        assist_192(
            &mut t1,
            _mm_aeskeygenassist_si128(t3, 0x20),
            &mut t3,
        );
        _mm_store_si128(rk.add(9), t1);
        _mm_store_si128(rk.add(10), t3);
        let prev = t3;
        assist_192(
            &mut t1,
            _mm_aeskeygenassist_si128(t3, 0x40),
            &mut t3,
        );
        _mm_store_si128(rk.add(10), splice::<0>(prev, t1));
        _mm_store_si128(rk.add(11), splice::<1>(t1, t3));
        assist_192(
            &mut t1,
            _mm_aeskeygenassist_si128(t3, 0x80),
            &mut t3,
        );
        _mm_store_si128(rk.add(12), t1);
    }
}

/// The second AES-256 step, which substitutes without rotating.
#[inline(always)]
unsafe fn assist_256(t1: __m128i, t3: __m128i) -> __m128i {
    // SAFETY: the caller is a function that requires the AES feature.
    unsafe {
        let b = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(t1, 0x00), 0xaa);
        let c = _mm_slli_si128(t3, 4);
        let t3 = _mm_xor_si128(t3, c);
        let c = _mm_slli_si128(c, 4);
        let t3 = _mm_xor_si128(t3, c);
        let c = _mm_slli_si128(c, 4);
        let t3 = _mm_xor_si128(t3, c);
        _mm_xor_si128(t3, b)
    }
}

/// Expand an AES-256 key into its fifteen round keys.
///
/// # Safety
///
/// The CPU must have the AES instructions, and `rk` must be a sixteen byte
/// aligned pointer to fifteen round keys.
#[target_feature(enable = "aes")]
unsafe fn expand_256(key: &[u8; 32], rk: *mut __m128i) {
    // SAFETY: the caller guarantees the instructions and the destination;
    // 32 bytes of key are read, which is its size.
    unsafe {
        let mut t1 = _mm_loadu_si128(key.as_ptr().cast());
        let mut t3 = _mm_loadu_si128(key.as_ptr().add(16).cast());
        _mm_store_si128(rk, t1);
        _mm_store_si128(rk.add(1), t3);
        t1 = assist(t1, _mm_aeskeygenassist_si128(t3, 0x01));
        _mm_store_si128(rk.add(2), t1);
        t3 = assist_256(t1, t3);
        _mm_store_si128(rk.add(3), t3);
        t1 = assist(t1, _mm_aeskeygenassist_si128(t3, 0x02));
        _mm_store_si128(rk.add(4), t1);
        t3 = assist_256(t1, t3);
        _mm_store_si128(rk.add(5), t3);
        t1 = assist(t1, _mm_aeskeygenassist_si128(t3, 0x04));
        _mm_store_si128(rk.add(6), t1);
        t3 = assist_256(t1, t3);
        _mm_store_si128(rk.add(7), t3);
        t1 = assist(t1, _mm_aeskeygenassist_si128(t3, 0x08));
        _mm_store_si128(rk.add(8), t1);
        t3 = assist_256(t1, t3);
        _mm_store_si128(rk.add(9), t3);
        t1 = assist(t1, _mm_aeskeygenassist_si128(t3, 0x10));
        _mm_store_si128(rk.add(10), t1);
        t3 = assist_256(t1, t3);
        _mm_store_si128(rk.add(11), t3);
        t1 = assist(t1, _mm_aeskeygenassist_si128(t3, 0x20));
        _mm_store_si128(rk.add(12), t1);
        t3 = assist_256(t1, t3);
        _mm_store_si128(rk.add(13), t3);
        t1 = assist(t1, _mm_aeskeygenassist_si128(t3, 0x40));
        _mm_store_si128(rk.add(14), t1);
    }
}

/// Turn an encryption schedule into a decryption one.
///
/// The order reverses, and every key but the first and last passes through
/// InvMixColumns, which is what lets decryption use the same round
/// structure as encryption.
///
/// # Safety
///
/// The CPU must have the AES instructions, and both pointers must be
/// sixteen byte aligned and cover `rounds + 1` round keys.
#[target_feature(enable = "aes")]
unsafe fn invert_schedule(ek: *const __m128i, dk: *mut __m128i, rounds: usize) {
    // SAFETY: the caller guarantees the instructions and both ranges.
    unsafe {
        _mm_store_si128(dk, _mm_load_si128(ek.add(rounds)));
        for i in 1..rounds {
            let k = _mm_load_si128(ek.add(rounds - i));
            _mm_store_si128(dk.add(i), _mm_aesimc_si128(k));
        }
        _mm_store_si128(dk.add(rounds), _mm_load_si128(ek));
    }
}

macro_rules! define_aes {
    (
        $enc:ident, $dec:ident, $key_size:expr, $bytes:expr, $rounds:expr,
        $expand:ident, $enc_set:ident, $dec_set:ident, $bits:expr
    ) => {
        // Aligned so the round keys can be read with aligned loads,
        // which lets each one fold into the round instruction instead of
        // costing a separate move.
        #[doc = concat!("AES-", $bits, " encryption only.")]
        #[repr(align(16))]
        pub struct $enc {
            rk: [u8; $bytes],
        }

        #[doc = concat!("AES-", $bits, " decryption only.")]
        #[repr(align(16))]
        pub struct $dec {
            rk: [u8; $bytes],
        }

        impl $enc {
            /// The key length in bytes.
            pub const KEY_SIZE: usize = $key_size;
            /// The block length in bytes.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;
            /// Blocks kept in flight.
            pub const PARALLEL_BLOCKS: usize = WIDTH;

            /// Expand `key` into an encryption schedule.
            ///
            /// # Panics
            ///
            /// If the CPU has no AES instructions. Naming this type asserts
            /// that it does; the parent module's type of the same name
            /// checks and falls back instead.
            pub fn new(key: &[u8; $key_size]) -> Self {
                assert!(supported(), "AES instructions are not available");
                let mut this = Self { rk: [0u8; $bytes] };
                // SAFETY: support was just checked; rk is $bytes long and
                // aligned by the type.
                unsafe { $expand(key, this.rk.as_mut_ptr().cast()) };
                this
            }

            /// The expanded schedule, for a sibling backend that shares
            /// it. VAES reads exactly these bytes.
            pub(super) fn schedule(&self) -> &[u8] {
                &self.rk
            }

            /// Encrypt whole blocks in place, returning bytes consumed.
            pub fn encrypt(&self, data: &mut [u8]) -> usize {
                let blocks = data.len() / BLOCK_SIZE;
                if blocks == 0 {
                    return 0;
                }
                // SAFETY: the schedule exists, so the instructions do,
                // and the buffer holds that many whole blocks.
                unsafe {
                    $enc_set(self.rk.as_ptr(), data.as_mut_ptr(), blocks)
                };
                blocks * BLOCK_SIZE
            }

            /// Encrypt exactly one block in place.
            pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                // SAFETY: as for encrypt.
                unsafe {
                    $enc_set(self.rk.as_ptr(), block.as_mut_ptr(), 1)
                };
            }
        }

        impl $dec {
            /// The key length in bytes.
            pub const KEY_SIZE: usize = $key_size;
            /// The block length in bytes.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;
            /// Blocks kept in flight.
            pub const PARALLEL_BLOCKS: usize = WIDTH;

            /// Expand `key` into a decryption schedule.
            ///
            /// # Panics
            ///
            /// If the CPU has no AES instructions.
            pub fn new(key: &[u8; $key_size]) -> Self {
                assert!(supported(), "AES instructions are not available");
                let mut ek = Self { rk: [0u8; $bytes] };
                let mut this = Self { rk: [0u8; $bytes] };
                // SAFETY: support was just checked; both schedules are
                // $bytes long and aligned by the type.
                unsafe {
                    $expand(key, ek.rk.as_mut_ptr().cast());
                    invert_schedule(
                        ek.rk.as_ptr().cast(),
                        this.rk.as_mut_ptr().cast(),
                        $rounds,
                    );
                }
                this
            }

            /// The expanded schedule, for a sibling backend that shares
            /// it.
            pub(super) fn schedule(&self) -> &[u8] {
                &self.rk
            }

            /// Decrypt whole blocks in place, returning bytes consumed.
            pub fn decrypt(&self, data: &mut [u8]) -> usize {
                let blocks = data.len() / BLOCK_SIZE;
                if blocks == 0 {
                    return 0;
                }
                // SAFETY: as for the encryption side.
                unsafe {
                    $dec_set(self.rk.as_ptr(), data.as_mut_ptr(), blocks)
                };
                blocks * BLOCK_SIZE
            }

            /// Decrypt exactly one block in place.
            pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                // SAFETY: as for decrypt.
                unsafe {
                    $dec_set(self.rk.as_ptr(), block.as_mut_ptr(), 1)
                };
            }
        }

        impl Drop for $enc {
            fn drop(&mut self) {
                self.rk.zeroize();
            }
        }

        impl Drop for $dec {
            fn drop(&mut self) {
                self.rk.zeroize();
            }
        }

        impl core::fmt::Debug for $enc {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                // Never format round keys.
                f.write_str(concat!(stringify!($enc), " { .. }"))
            }
        }

        impl core::fmt::Debug for $dec {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                f.write_str(concat!(stringify!($dec), " { .. }"))
            }
        }

        impl KeyInit for $enc {
            fn try_new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                let key: &[u8; $key_size] = key
                    .try_into()
                    .map_err(|_| InvalidKeyLength { got: key.len() })?;
                Ok(Self::new(key))
            }
        }

        impl KeyInit for $dec {
            fn try_new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                let key: &[u8; $key_size] = key
                    .try_into()
                    .map_err(|_| InvalidKeyLength { got: key.len() })?;
                Ok(Self::new(key))
            }
        }

        impl BlockEncrypt for $enc {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = WIDTH;

            fn encrypt(&self, data: &mut [u8]) -> usize {
                $enc::encrypt(self, data)
            }
        }

        impl BlockDecrypt for $dec {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = WIDTH;

            fn decrypt(&self, data: &mut [u8]) -> usize {
                $dec::decrypt(self, data)
            }
        }
    };
}

define_aes!(
    Aes128Enc, Aes128Dec, 16, 176, 10, expand_128,
    encrypt_128, decrypt_128, "128"
);
define_aes!(
    Aes192Enc, Aes192Dec, 24, 208, 12, expand_192,
    encrypt_192, decrypt_192, "192"
);
define_aes!(
    Aes256Enc, Aes256Dec, 32, 240, 14, expand_256,
    encrypt_256, decrypt_256, "256"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::arch::portable::ttable;

    /// xorshift64*, so a divergence is reproducible from the seed.
    struct Rng(u64);

    impl Rng {
        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                let b = x.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
        }
    }

    /// FIPS-197 Appendix C.1, C.2 and C.3.
    #[test]
    fn fips_197_all_key_sizes() {
        if !supported() {
            return;
        }
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd,
            0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];

        let mut block = plaintext;
        Aes128Enc::new(&key).encrypt_block(&mut block);
        assert_eq!(block, expected);
        Aes128Dec::new(&key).decrypt_block(&mut block);
        assert_eq!(block, plaintext);

        let key192: [u8; 24] = core::array::from_fn(|i| i as u8);
        let expected192 = [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf,
            0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
        ];
        let mut block = plaintext;
        Aes192Enc::new(&key192).encrypt_block(&mut block);
        assert_eq!(block, expected192, "AES-192");
        Aes192Dec::new(&key192).decrypt_block(&mut block);
        assert_eq!(block, plaintext);

        let key256: [u8; 32] = core::array::from_fn(|i| i as u8);
        let expected256 = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc,
            0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];
        let mut block = plaintext;
        Aes256Enc::new(&key256).encrypt_block(&mut block);
        assert_eq!(block, expected256, "AES-256");
        Aes256Dec::new(&key256).decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }

    /// The two implementations must agree exactly, at every length that
    /// exercises the wide kernel, its tail, and the boundary between them.
    macro_rules! check_against_portable {
        ($enc:ident, $dec:ident, $pe:path, $len:expr, $seed:expr) => {{
            let mut rng = Rng($seed);
            for blocks in [0usize, 1, 2, 7, 8, 9, 15, 16, 17, 64, 100] {
                let mut key = [0u8; $len];
                rng.fill(&mut key);
                let mut plaintext = vec![0u8; blocks * BLOCK_SIZE];
                rng.fill(&mut plaintext);

                let mut ours = plaintext.clone();
                let mut theirs = plaintext.clone();
                assert_eq!(
                    $enc::new(&key).encrypt(&mut ours),
                    blocks * BLOCK_SIZE
                );
                <$pe>::new(&key).encrypt(&mut theirs);
                assert_eq!(
                    ours, theirs,
                    "{} bit encrypt differs at {} blocks",
                    $len * 8, blocks
                );

                $dec::new(&key).decrypt(&mut ours);
                assert_eq!(
                    ours, plaintext,
                    "{} bit decrypt failed at {} blocks",
                    $len * 8, blocks
                );
            }
        }};
    }

    /// Every length here exercises the wide kernel, its tail, or the
    /// boundary between them.
    #[test]
    fn agrees_with_the_portable_implementation() {
        if !supported() {
            return;
        }
        check_against_portable!(
            Aes128Enc, Aes128Dec, ttable::Aes128Enc, 16,
            0x0123_4567_89ab_cdef
        );
        check_against_portable!(
            Aes192Enc, Aes192Dec, ttable::Aes192Enc, 24,
            0xfedc_ba98_7654_3210
        );
        check_against_portable!(
            Aes256Enc, Aes256Dec, ttable::Aes256Enc, 32,
            0x2468_ace0_1357_9bdf
        );
    }

    #[test]
    fn partial_trailing_block_is_left_alone() {
        if !supported() {
            return;
        }
        let aes = Aes128Enc::new(&[0u8; 16]);
        let mut data = [0xccu8; BLOCK_SIZE + 5];
        assert_eq!(aes.encrypt(&mut data), BLOCK_SIZE);
        assert_eq!(&data[BLOCK_SIZE..], &[0xcc; 5]);
    }

    #[test]
    fn bulk_matches_block_at_a_time() {
        if !supported() {
            return;
        }
        let aes = Aes128Enc::new(&[0x2bu8; 16]);
        let mut bulk = [0u8; BLOCK_SIZE * 20];
        for (i, b) in bulk.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut one = bulk;

        aes.encrypt(&mut bulk);
        for block in one.as_chunks_mut::<BLOCK_SIZE>().0 {
            aes.encrypt_block(block);
        }
        assert_eq!(bulk, one);
    }

    #[test]
    fn schedules_are_wiped_on_drop() {
        if !supported() {
            return;
        }
        let mut slot =
            core::mem::MaybeUninit::new(Aes128Enc::new(&[0xab; 16]));
        let ptr = slot.as_mut_ptr();
        let bytes = ptr.cast::<u8>();
        let len = core::mem::size_of::<Aes128Enc>();
        // SAFETY: slot holds an initialized value of exactly this size.
        let live = unsafe { core::slice::from_raw_parts(bytes, len) };
        assert!(live.iter().any(|&b| b != 0));
        // SAFETY: the value is never read as a value again.
        unsafe { core::ptr::drop_in_place(ptr) };
        // SAFETY: the storage is ours and still allocated.
        let dead = unsafe { core::slice::from_raw_parts(bytes, len) };
        assert!(dead.iter().all(|&b| b == 0), "key material survived");
    }
}
