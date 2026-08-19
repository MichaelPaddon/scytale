//! AES on the ARMv8 Cryptographic Extension.
//!
//! These types can only be constructed on a CPU that has the instructions,
//! which [`supported`] reports. Naming them directly is for callers who have
//! already established that; everything else should use the parent module's
//! names, which check once and choose.
//!
//! Unlike a T-table cipher this is constant time with respect to the key.
//! The round transformation is a single instruction with no data dependent
//! memory access, and the key schedule takes its substitution from the same
//! instruction rather than from a table, so nothing about the key is visible
//! in the cache.
//!
//! The round structure is not the x86 one. `aese` exclusive-ors the round
//! key on the way in, where `aesenc` does it on the way out, so a round is
//! `aese` followed by `aesmc`, there is no separate whitening step before
//! the first round, and the last round key is applied with a plain `eor`:
//!
//! ```text
//! for i in 0..rounds - 1 { aese(state, rk[i]); aesmc(state) }
//! aese(state, rk[rounds - 1])
//! state ^= rk[rounds]
//! ```
//!
//! Decryption is the same shape with `aesd` and `aesimc` over an inverted
//! schedule.

use core::arch::aarch64::*;
use core::arch::asm;

use zeroize::Zeroize;

use crate::symmetric::block_cipher::{
    BlockDecrypt, BlockEncrypt, InvalidKeyLength, KeyInit,
};

/// The AES block size in bytes.
pub const BLOCK_SIZE: usize = 16;

/// Blocks processed per iteration of the bulk loop.
///
/// Enough independent blocks to cover the round latency, with the whole
/// schedule held in registers beside them: fifteen round keys and eight
/// blocks still leave nine of the thirty-two vector registers spare. The
/// figure is a reasonable one rather than a measured one, since the only
/// ARMv8 hardware this has run on is an emulator.
const WIDTH: usize = 8;

/// Whether this CPU has the AES instructions.
///
/// The answer cannot change while the process runs, so it is worked out
/// once and remembered.
pub fn supported() -> bool {
    use std::sync::OnceLock;
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| std::arch::is_aarch64_feature_detected!("aes"))
}

/// A fully unrolled 8 block kernel.
///
/// The round keys are loaded once, into registers of their own, and
/// the rounds themselves touch memory only for the blocks. Each
/// block's pair of instructions is kept together and writing the
/// same register, because a core that fuses the pair only does so
/// when it is written that way.
///
/// Every key register is declared clobbered whether or not this key
/// size reaches it, so that one macro serves all three schedule
/// lengths.
macro_rules! kernel8 {
    (
        $name:ident, $round:literal, $mix:literal,
        [$(($kn:literal, $ko:literal)),+], ($pn:literal, $po:literal),
        ($fn:literal, $fo:literal)
    ) => {
        /// # Safety
        ///
        /// The CPU must have the AES instructions. `rk` must hold
        /// the whole schedule and `data` 8 blocks.
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn $name(rk: *const u8, data: *mut u8) {
            // SAFETY: the caller guarantees the instructions and
            // both ranges.
            unsafe {
                asm!(
                    "ldr q0, [{d}, #0x00]",
                    "ldr q1, [{d}, #0x10]",
                    "ldr q2, [{d}, #0x20]",
                    "ldr q3, [{d}, #0x30]",
                    "ldr q4, [{d}, #0x40]",
                    "ldr q5, [{d}, #0x50]",
                    "ldr q6, [{d}, #0x60]",
                    "ldr q7, [{d}, #0x70]",
                    $(
                        concat!("ldr q", $kn, ", [{rk}, #", $ko, "]"),
                    )+
                    concat!("ldr q", $pn, ", [{rk}, #", $po, "]"),
                    concat!("ldr q", $fn, ", [{rk}, #", $fo, "]"),
                    $(
                        concat!($round, " v0.16b, v", $kn, ".16b"),
                        concat!($mix, " v0.16b, v0.16b"),
                        concat!($round, " v1.16b, v", $kn, ".16b"),
                        concat!($mix, " v1.16b, v1.16b"),
                        concat!($round, " v2.16b, v", $kn, ".16b"),
                        concat!($mix, " v2.16b, v2.16b"),
                        concat!($round, " v3.16b, v", $kn, ".16b"),
                        concat!($mix, " v3.16b, v3.16b"),
                        concat!($round, " v4.16b, v", $kn, ".16b"),
                        concat!($mix, " v4.16b, v4.16b"),
                        concat!($round, " v5.16b, v", $kn, ".16b"),
                        concat!($mix, " v5.16b, v5.16b"),
                        concat!($round, " v6.16b, v", $kn, ".16b"),
                        concat!($mix, " v6.16b, v6.16b"),
                        concat!($round, " v7.16b, v", $kn, ".16b"),
                        concat!($mix, " v7.16b, v7.16b"),
                    )+
                    concat!($round, " v0.16b, v", $pn, ".16b"),
                    concat!($round, " v1.16b, v", $pn, ".16b"),
                    concat!($round, " v2.16b, v", $pn, ".16b"),
                    concat!($round, " v3.16b, v", $pn, ".16b"),
                    concat!($round, " v4.16b, v", $pn, ".16b"),
                    concat!($round, " v5.16b, v", $pn, ".16b"),
                    concat!($round, " v6.16b, v", $pn, ".16b"),
                    concat!($round, " v7.16b, v", $pn, ".16b"),
                    concat!("eor v0.16b, v0.16b, v", $fn, ".16b"),
                    concat!("eor v1.16b, v1.16b, v", $fn, ".16b"),
                    concat!("eor v2.16b, v2.16b, v", $fn, ".16b"),
                    concat!("eor v3.16b, v3.16b, v", $fn, ".16b"),
                    concat!("eor v4.16b, v4.16b, v", $fn, ".16b"),
                    concat!("eor v5.16b, v5.16b, v", $fn, ".16b"),
                    concat!("eor v6.16b, v6.16b, v", $fn, ".16b"),
                    concat!("eor v7.16b, v7.16b, v", $fn, ".16b"),
                    "str q0, [{d}, #0x00]",
                    "str q1, [{d}, #0x10]",
                    "str q2, [{d}, #0x20]",
                    "str q3, [{d}, #0x30]",
                    "str q4, [{d}, #0x40]",
                    "str q5, [{d}, #0x50]",
                    "str q6, [{d}, #0x60]",
                    "str q7, [{d}, #0x70]",
                    rk = in(reg) rk,
                    d = in(reg) data,
                    out("v0") _, out("v1") _, out("v2") _,
                    out("v3") _, out("v4") _, out("v5") _,
                    out("v6") _, out("v7") _, out("v16") _,
                    out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _,
                    out("v23") _, out("v24") _, out("v25") _,
                    out("v26") _, out("v27") _, out("v28") _,
                    out("v29") _, out("v30") _,
                    options(nostack),
                );
            }
        }
    };
}

/// A fully unrolled 4 block kernel.
///
/// The round keys are loaded once, into registers of their own, and
/// the rounds themselves touch memory only for the blocks. Each
/// block's pair of instructions is kept together and writing the
/// same register, because a core that fuses the pair only does so
/// when it is written that way.
///
/// Every key register is declared clobbered whether or not this key
/// size reaches it, so that one macro serves all three schedule
/// lengths.
macro_rules! kernel4 {
    (
        $name:ident, $round:literal, $mix:literal,
        [$(($kn:literal, $ko:literal)),+], ($pn:literal, $po:literal),
        ($fn:literal, $fo:literal)
    ) => {
        /// # Safety
        ///
        /// The CPU must have the AES instructions. `rk` must hold
        /// the whole schedule and `data` 4 blocks.
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn $name(rk: *const u8, data: *mut u8) {
            // SAFETY: the caller guarantees the instructions and
            // both ranges.
            unsafe {
                asm!(
                    "ldr q0, [{d}, #0x00]",
                    "ldr q1, [{d}, #0x10]",
                    "ldr q2, [{d}, #0x20]",
                    "ldr q3, [{d}, #0x30]",
                    $(
                        concat!("ldr q", $kn, ", [{rk}, #", $ko, "]"),
                    )+
                    concat!("ldr q", $pn, ", [{rk}, #", $po, "]"),
                    concat!("ldr q", $fn, ", [{rk}, #", $fo, "]"),
                    $(
                        concat!($round, " v0.16b, v", $kn, ".16b"),
                        concat!($mix, " v0.16b, v0.16b"),
                        concat!($round, " v1.16b, v", $kn, ".16b"),
                        concat!($mix, " v1.16b, v1.16b"),
                        concat!($round, " v2.16b, v", $kn, ".16b"),
                        concat!($mix, " v2.16b, v2.16b"),
                        concat!($round, " v3.16b, v", $kn, ".16b"),
                        concat!($mix, " v3.16b, v3.16b"),
                    )+
                    concat!($round, " v0.16b, v", $pn, ".16b"),
                    concat!($round, " v1.16b, v", $pn, ".16b"),
                    concat!($round, " v2.16b, v", $pn, ".16b"),
                    concat!($round, " v3.16b, v", $pn, ".16b"),
                    concat!("eor v0.16b, v0.16b, v", $fn, ".16b"),
                    concat!("eor v1.16b, v1.16b, v", $fn, ".16b"),
                    concat!("eor v2.16b, v2.16b, v", $fn, ".16b"),
                    concat!("eor v3.16b, v3.16b, v", $fn, ".16b"),
                    "str q0, [{d}, #0x00]",
                    "str q1, [{d}, #0x10]",
                    "str q2, [{d}, #0x20]",
                    "str q3, [{d}, #0x30]",
                    rk = in(reg) rk,
                    d = in(reg) data,
                    out("v0") _, out("v1") _, out("v2") _,
                    out("v3") _, out("v16") _, out("v17") _,
                    out("v18") _, out("v19") _, out("v20") _,
                    out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _,
                    out("v27") _, out("v28") _, out("v29") _,
                    out("v30") _,
                    options(nostack),
                );
            }
        }
    };
}

/// A fully unrolled 2 block kernel.
///
/// The round keys are loaded once, into registers of their own, and
/// the rounds themselves touch memory only for the blocks. Each
/// block's pair of instructions is kept together and writing the
/// same register, because a core that fuses the pair only does so
/// when it is written that way.
///
/// Every key register is declared clobbered whether or not this key
/// size reaches it, so that one macro serves all three schedule
/// lengths.
macro_rules! kernel2 {
    (
        $name:ident, $round:literal, $mix:literal,
        [$(($kn:literal, $ko:literal)),+], ($pn:literal, $po:literal),
        ($fn:literal, $fo:literal)
    ) => {
        /// # Safety
        ///
        /// The CPU must have the AES instructions. `rk` must hold
        /// the whole schedule and `data` 2 blocks.
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn $name(rk: *const u8, data: *mut u8) {
            // SAFETY: the caller guarantees the instructions and
            // both ranges.
            unsafe {
                asm!(
                    "ldr q0, [{d}, #0x00]",
                    "ldr q1, [{d}, #0x10]",
                    $(
                        concat!("ldr q", $kn, ", [{rk}, #", $ko, "]"),
                    )+
                    concat!("ldr q", $pn, ", [{rk}, #", $po, "]"),
                    concat!("ldr q", $fn, ", [{rk}, #", $fo, "]"),
                    $(
                        concat!($round, " v0.16b, v", $kn, ".16b"),
                        concat!($mix, " v0.16b, v0.16b"),
                        concat!($round, " v1.16b, v", $kn, ".16b"),
                        concat!($mix, " v1.16b, v1.16b"),
                    )+
                    concat!($round, " v0.16b, v", $pn, ".16b"),
                    concat!($round, " v1.16b, v", $pn, ".16b"),
                    concat!("eor v0.16b, v0.16b, v", $fn, ".16b"),
                    concat!("eor v1.16b, v1.16b, v", $fn, ".16b"),
                    "str q0, [{d}, #0x00]",
                    "str q1, [{d}, #0x10]",
                    rk = in(reg) rk,
                    d = in(reg) data,
                    out("v0") _, out("v1") _, out("v16") _,
                    out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _,
                    out("v23") _, out("v24") _, out("v25") _,
                    out("v26") _, out("v27") _, out("v28") _,
                    out("v29") _, out("v30") _,
                    options(nostack),
                );
            }
        }
    };
}

/// A fully unrolled 1 block kernel.
///
/// The round keys are loaded once, into registers of their own, and
/// the rounds themselves touch memory only for the blocks. Each
/// block's pair of instructions is kept together and writing the
/// same register, because a core that fuses the pair only does so
/// when it is written that way.
///
/// Every key register is declared clobbered whether or not this key
/// size reaches it, so that one macro serves all three schedule
/// lengths.
macro_rules! kernel1 {
    (
        $name:ident, $round:literal, $mix:literal,
        [$(($kn:literal, $ko:literal)),+], ($pn:literal, $po:literal),
        ($fn:literal, $fo:literal)
    ) => {
        /// # Safety
        ///
        /// The CPU must have the AES instructions. `rk` must hold
        /// the whole schedule and `data` 1 block.
        #[target_feature(enable = "aes")]
        #[inline]
        unsafe fn $name(rk: *const u8, data: *mut u8) {
            // SAFETY: the caller guarantees the instructions and
            // both ranges.
            unsafe {
                asm!(
                    "ldr q0, [{d}, #0x00]",
                    $(
                        concat!("ldr q", $kn, ", [{rk}, #", $ko, "]"),
                    )+
                    concat!("ldr q", $pn, ", [{rk}, #", $po, "]"),
                    concat!("ldr q", $fn, ", [{rk}, #", $fo, "]"),
                    $(
                        concat!($round, " v0.16b, v", $kn, ".16b"),
                        concat!($mix, " v0.16b, v0.16b"),
                    )+
                    concat!($round, " v0.16b, v", $pn, ".16b"),
                    concat!("eor v0.16b, v0.16b, v", $fn, ".16b"),
                    "str q0, [{d}, #0x00]",
                    rk = in(reg) rk,
                    d = in(reg) data,
                    out("v0") _, out("v16") _, out("v17") _,
                    out("v18") _, out("v19") _, out("v20") _,
                    out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _,
                    out("v27") _, out("v28") _, out("v29") _,
                    out("v30") _,
                    options(nostack),
                );
            }
        }
    };
}

kernel8!(
    e128_8, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80")],
    (25, "0x90"), (26, "0xa0")
);
kernel4!(
    e128_4, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80")],
    (25, "0x90"), (26, "0xa0")
);
kernel2!(
    e128_2, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80")],
    (25, "0x90"), (26, "0xa0")
);
kernel1!(
    e128_1, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80")],
    (25, "0x90"), (26, "0xa0")
);
kernel8!(
    d128_8, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80")],
    (25, "0x90"), (26, "0xa0")
);
kernel4!(
    d128_4, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80")],
    (25, "0x90"), (26, "0xa0")
);
kernel2!(
    d128_2, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80")],
    (25, "0x90"), (26, "0xa0")
);
kernel1!(
    d128_1, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80")],
    (25, "0x90"), (26, "0xa0")
);
kernel8!(
    e192_8, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0")],
    (27, "0xb0"), (28, "0xc0")
);
kernel4!(
    e192_4, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0")],
    (27, "0xb0"), (28, "0xc0")
);
kernel2!(
    e192_2, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0")],
    (27, "0xb0"), (28, "0xc0")
);
kernel1!(
    e192_1, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0")],
    (27, "0xb0"), (28, "0xc0")
);
kernel8!(
    d192_8, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0")],
    (27, "0xb0"), (28, "0xc0")
);
kernel4!(
    d192_4, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0")],
    (27, "0xb0"), (28, "0xc0")
);
kernel2!(
    d192_2, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0")],
    (27, "0xb0"), (28, "0xc0")
);
kernel1!(
    d192_1, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0")],
    (27, "0xb0"), (28, "0xc0")
);
kernel8!(
    e256_8, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0"), (27, "0xb0"),
     (28, "0xc0")],
    (29, "0xd0"), (30, "0xe0")
);
kernel4!(
    e256_4, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0"), (27, "0xb0"),
     (28, "0xc0")],
    (29, "0xd0"), (30, "0xe0")
);
kernel2!(
    e256_2, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0"), (27, "0xb0"),
     (28, "0xc0")],
    (29, "0xd0"), (30, "0xe0")
);
kernel1!(
    e256_1, "aese", "aesmc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0"), (27, "0xb0"),
     (28, "0xc0")],
    (29, "0xd0"), (30, "0xe0")
);
kernel8!(
    d256_8, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0"), (27, "0xb0"),
     (28, "0xc0")],
    (29, "0xd0"), (30, "0xe0")
);
kernel4!(
    d256_4, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0"), (27, "0xb0"),
     (28, "0xc0")],
    (29, "0xd0"), (30, "0xe0")
);
kernel2!(
    d256_2, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0"), (27, "0xb0"),
     (28, "0xc0")],
    (29, "0xd0"), (30, "0xe0")
);
kernel1!(
    d256_1, "aesd", "aesimc",
    [(16, "0x00"), (17, "0x10"), (18, "0x20"), (19, "0x30"),
     (20, "0x40"), (21, "0x50"), (22, "0x60"), (23, "0x70"),
     (24, "0x80"), (25, "0x90"), (26, "0xa0"), (27, "0xb0"),
     (28, "0xc0")],
    (29, "0xd0"), (30, "0xe0")
);
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
        #[target_feature(enable = "aes")]
        #[inline]
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

/// Substitute all four bytes of a word.
///
/// There is no key generation instruction on this target, and a table
/// would index the substitution with key material, which is the leak these
/// backends exist to avoid. `aese` against a zero key is
/// `ShiftRows(SubBytes(x))`, and with the word in all four columns
/// ShiftRows moves each row within a set of equal bytes, so what comes
/// back is the substitution alone.
///
/// # Safety
///
/// The CPU must have the AES instructions.
#[target_feature(enable = "aes")]
unsafe fn sub_word(word: u32) -> u32 {
    // These intrinsics are safe to call from a function that carries the
    // feature they need, which this one does.
    let spread = vreinterpretq_u8_u32(vdupq_n_u32(word));
    let substituted = vaeseq_u8(spread, vdupq_n_u8(0));
    vgetq_lane_u32(vreinterpretq_u32_u8(substituted), 0)
}

/// Expand a key into its round keys, as FIPS-197 section 5.2 defines it.
///
/// `key` is `nk` words long and `rk` receives `rounds + 1` round keys.
/// Words are held big endian, the order the standard writes them in and
/// the order the round keys are read back in.
///
/// # Safety
///
/// The CPU must have the AES instructions, and `rk` must have room for
/// `rounds + 1` round keys.
#[target_feature(enable = "aes")]
unsafe fn expand(
    key: &[u8],
    rk: &mut [u8],
    nk: usize,
    rounds: usize,
) {
    /// Round constants, one per application of the substitution.
    const RCON: [u32; 11] = [
        0x0000_0000,
        0x0100_0000,
        0x0200_0000,
        0x0400_0000,
        0x0800_0000,
        0x1000_0000,
        0x2000_0000,
        0x4000_0000,
        0x8000_0000,
        0x1b00_0000,
        0x3600_0000,
    ];

    let words = 4 * (rounds + 1);
    let mut w = [0u32; 60];

    for (i, word) in w.iter_mut().take(nk).enumerate() {
        let bytes: [u8; 4] = [
            key[4 * i],
            key[4 * i + 1],
            key[4 * i + 2],
            key[4 * i + 3],
        ];
        *word = u32::from_be_bytes(bytes);
    }

    for i in nk..words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            // SAFETY: the caller guarantees the instructions.
            temp = unsafe { sub_word(temp.rotate_left(8)) } ^ RCON[i / nk];
        } else if nk > 6 && i % nk == 4 {
            // SAFETY: as above.
            temp = unsafe { sub_word(temp) };
        }
        w[i] = w[i - nk] ^ temp;
    }

    for (i, word) in w.iter().take(words).enumerate() {
        rk[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
}

/// Turn an encryption schedule into a decryption one.
///
/// The order reverses, and every round key but the first and last passes
/// through InvMixColumns, which is what lets decryption use the same round
/// structure as encryption.
///
/// # Safety
///
/// The CPU must have the AES instructions, and both schedules must cover
/// `rounds + 1` round keys.
#[target_feature(enable = "aes")]
unsafe fn invert_schedule(ek: &[u8], dk: &mut [u8], rounds: usize) {
    // SAFETY: the caller guarantees the instructions and that both
    // schedules hold rounds + 1 round keys, which is what is indexed.
    unsafe {
        let at = |s: &[u8], i: usize| vld1q_u8(s[i * 16..].as_ptr());

        vst1q_u8(dk.as_mut_ptr(), at(ek, rounds));
        for i in 1..rounds {
            let key = at(ek, rounds - i);
            vst1q_u8(dk[i * 16..].as_mut_ptr(), vaesimcq_u8(key));
        }
        vst1q_u8(dk[rounds * 16..].as_mut_ptr(), at(ek, 0));
    }
}

macro_rules! define_aes {
    (
        $enc:ident, $dec:ident, $key_size:expr, $bytes:expr, $rounds:expr,
        $nk:expr, $enc_set:ident, $dec_set:ident, $bits:expr
    ) => {
        // Aligned so the round keys are loaded from a known offset within
        // a cache line rather than straddling one.
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
                // SAFETY: support was just checked; rk is $bytes long,
                // which is rounds + 1 round keys.
                unsafe { expand(key, &mut this.rk, $nk, $rounds) };
                this
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
                // $bytes long, which is rounds + 1 round keys.
                unsafe {
                    expand(key, &mut ek.rk, $nk, $rounds);
                    invert_schedule(&ek.rk, &mut this.rk, $rounds);
                }
                this
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
    Aes128Enc, Aes128Dec, 16, 176, 10, 4,
    encrypt_128, decrypt_128, "128"
);
define_aes!(
    Aes192Enc, Aes192Dec, 24, 208, 12, 6,
    encrypt_192, decrypt_192, "192"
);
define_aes!(
    Aes256Enc, Aes256Dec, 32, 240, 14, 8,
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

    /// The substitution the key schedule is built on, against the values
    /// FIPS-197 gives for the S-box.
    #[test]
    fn sub_word_is_the_s_box() {
        if !supported() {
            return;
        }
        // SAFETY: support was just checked.
        unsafe {
            assert_eq!(sub_word(0x0000_0000), 0x6363_6363);
            assert_eq!(sub_word(0x5353_5353), 0xeded_eded);
            // S-box of 0x00, 0x01, 0x02, 0x03.
            assert_eq!(sub_word(0x0001_0203), 0x637c_777b);
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
            for blocks in [0usize, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 64, 100]
            {
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
