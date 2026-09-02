//! ChaCha20 with AVX2 on x86-64.
//!
//! Four blocks at a time: each block's state is four rows of four
//! words, one row to a 128-bit half of a `ymm` register, so a
//! register holds the same row of two blocks and every instruction
//! does two blocks' worth. Two such sets run interleaved, which gives
//! the processor independent work to overlap. A column round is one
//! quarter round on the four rows; the diagonal round is the same
//! after rotating three rows within each half, which `vpshufd` does
//! per half exactly as needed.
//!
//! Rotates by 16 and 8 are byte shuffles; 12 and 7 are a shift each
//! way and an or. No memory access depends on the key.

#![allow(unsafe_code)]

use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

use super::{Backend, Cipher, Sealed, BLOCK_SIZE};

/// ChaCha20 with AVX2.
pub type ChaCha20 = Cipher<Avx2>;

/// Whether the processor and operating system support AVX2: the
/// instructions (leaf 7, EBX bit 5) and the OS saving the upper
/// register halves (XCR0 bits 1 and 2), as for VAES.
pub(crate) fn has_avx2() -> bool {
    let leaf1 = __cpuid(1);
    let osxsave = leaf1.ecx & (1 << 27) != 0;
    let avx = leaf1.ecx & (1 << 28) != 0;
    if !(osxsave && avx) {
        return false;
    }
    let avx2 = __cpuid_count(7, 0).ebx & (1 << 5) != 0;
    // SAFETY: OSXSAVE was just confirmed, so XGETBV is available.
    let xcr0 = unsafe { _xgetbv(0) };
    avx2 && xcr0 & 0b110 == 0b110
}

/// The keystream generator with AVX2.
pub struct Avx2;

impl Sealed for Avx2 {}

impl Backend for Avx2 {
    fn supported() -> bool {
        has_avx2()
    }

    unsafe fn xor(
        key: &[u32; 8],
        nonce: &[u32; 3],
        counter: u32,
        data: &mut [u8],
    ) {
        xor(key, nonce, counter, data)
    }
}

/// Blocks one pass of the assembly handles.
const GROUP: usize = 4;

/// Sixteen-byte aligned tables the shuffles and the block counters
/// come from.
#[repr(align(32))]
struct Aligned([u8; 32]);

/// Rotate each word left by 16, as a byte shuffle.
static ROTATE16: Aligned = Aligned([
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, //
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
]);

/// Rotate each word left by 8, as a byte shuffle.
static ROTATE8: Aligned = Aligned([
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, //
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
]);

/// The counter row's per-half increments: the second half of a
/// register is the block after the first.
#[repr(align(32))]
struct Counters([u32; 8]);
static COUNTERS: [Counters; 2] = [
    Counters([0, 0, 0, 0, 1, 0, 0, 0]),
    Counters([2, 0, 0, 0, 3, 0, 0, 0]),
];

/// The state rows for a group, laid out for `vbroadcasti128`.
fn rows(key: &[u32; 8], nonce: &[u32; 3], counter: u32) -> [u32; 16] {
    let mut rows = [0u32; 16];
    rows[..4].copy_from_slice(&super::CONSTANTS);
    rows[4..12].copy_from_slice(key);
    rows[12] = counter;
    rows[13..].copy_from_slice(nonce);
    rows
}

/// Xors keystream from `counter` into `data`, a whole number of
/// blocks.
///
/// # Safety
/// Requires AVX2.
unsafe fn xor(key: &[u32; 8], nonce: &[u32; 3], counter: u32, data: &mut [u8]) {
    debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
    let mut counter = counter;
    let mut chunks = data.chunks_exact_mut(BLOCK_SIZE * GROUP);
    for group in &mut chunks {
        let state = rows(key, nonce, counter);
        group4(&state, group.as_mut_ptr());
        counter = counter.wrapping_add(GROUP as u32);
    }
    let rest = chunks.into_remainder();
    if !rest.is_empty() {
        // A short group: keystream into a scratch buffer, then only
        // as much of it as is wanted.
        let mut scratch = [0u8; BLOCK_SIZE * GROUP];
        let state = rows(key, nonce, counter);
        group4(&state, scratch.as_mut_ptr());
        for (d, k) in rest.iter_mut().zip(&scratch) {
            *d ^= k;
        }
    }
}

/// Twenty rounds on the four rows of set `$a..$d`.
#[rustfmt::skip]
macro_rules! quarter {
    ($a:literal, $b:literal, $c:literal, $d:literal, $t:literal) => {
        concat!(
            "vpaddd ", $a, ", ", $a, ", ", $b, "\n",
            "vpxor ", $d, ", ", $d, ", ", $a, "\n",
            "vpshufb ", $d, ", ", $d, ", ymm14\n",
            "vpaddd ", $c, ", ", $c, ", ", $d, "\n",
            "vpxor ", $b, ", ", $b, ", ", $c, "\n",
            "vpslld ", $t, ", ", $b, ", 12\n",
            "vpsrld ", $b, ", ", $b, ", 20\n",
            "vpor ", $b, ", ", $b, ", ", $t, "\n",
            "vpaddd ", $a, ", ", $a, ", ", $b, "\n",
            "vpxor ", $d, ", ", $d, ", ", $a, "\n",
            "vpshufb ", $d, ", ", $d, ", ymm15\n",
            "vpaddd ", $c, ", ", $c, ", ", $d, "\n",
            "vpxor ", $b, ", ", $b, ", ", $c, "\n",
            "vpslld ", $t, ", ", $b, ", 7\n",
            "vpsrld ", $b, ", ", $b, ", 25\n",
            "vpor ", $b, ", ", $b, ", ", $t, "\n",
        )
    };
}

/// Rotates rows so the diagonals line up as columns, and back.
#[rustfmt::skip]
macro_rules! diagonal {
    ($b:literal, $c:literal, $d:literal, $bi:literal, $di:literal) => {
        concat!(
            "vpshufd ", $b, ", ", $b, ", ", $bi, "\n",
            "vpshufd ", $c, ", ", $c, ", 0x4e\n",
            "vpshufd ", $d, ", ", $d, ", ", $di, "\n",
        )
    };
}

/// Xors one set's two blocks into `data` at the given offsets: the
/// low halves are one block, the high halves the next.
#[rustfmt::skip]
macro_rules! output {
    ($a:literal, $b:literal, $c:literal, $d:literal,
     $ax:literal, $bx:literal, $cx:literal, $dx:literal, $off:literal) => {
        concat!(
            "vpxor xmm8, ", $ax, ", [{data} + ", $off, "]\n",
            "vpxor xmm9, ", $bx, ", [{data} + ", $off, " + 16]\n",
            "vpxor xmm10, ", $cx, ", [{data} + ", $off, " + 32]\n",
            "vpxor xmm11, ", $dx, ", [{data} + ", $off, " + 48]\n",
            "vmovdqu [{data} + ", $off, "], xmm8\n",
            "vmovdqu [{data} + ", $off, " + 16], xmm9\n",
            "vmovdqu [{data} + ", $off, " + 32], xmm10\n",
            "vmovdqu [{data} + ", $off, " + 48], xmm11\n",
            "vextracti128 xmm8, ", $a, ", 1\n",
            "vextracti128 xmm9, ", $b, ", 1\n",
            "vextracti128 xmm10, ", $c, ", 1\n",
            "vextracti128 xmm11, ", $d, ", 1\n",
            "vpxor xmm8, xmm8, [{data} + ", $off, " + 64]\n",
            "vpxor xmm9, xmm9, [{data} + ", $off, " + 80]\n",
            "vpxor xmm10, xmm10, [{data} + ", $off, " + 96]\n",
            "vpxor xmm11, xmm11, [{data} + ", $off, " + 112]\n",
            "vmovdqu [{data} + ", $off, " + 64], xmm8\n",
            "vmovdqu [{data} + ", $off, " + 80], xmm9\n",
            "vmovdqu [{data} + ", $off, " + 96], xmm10\n",
            "vmovdqu [{data} + ", $off, " + 112], xmm11\n",
        )
    };
}

/// Four blocks from `state`, xored into the 256 bytes at `data`.
///
/// Set one is ymm0 to ymm3 (blocks 0 and 1), set two ymm4 to ymm7
/// (blocks 2 and 3); ymm8 to ymm11 are temporaries, ymm12 and ymm13
/// hold the counter increments, ymm14 and ymm15 the shuffles.
///
/// # Safety
/// Requires AVX2; `data` must point at 256 writable bytes.
unsafe fn group4(state: &[u32; 16], data: *mut u8) {
    core::arch::asm!(
        "vmovdqa ymm14, [{rot16}]",
        "vmovdqa ymm15, [{rot8}]",
        "vmovdqa ymm12, [{counters}]",
        "vmovdqa ymm13, [{counters} + 32]",
        "vbroadcasti128 ymm0, [{state}]",
        "vbroadcasti128 ymm1, [{state} + 16]",
        "vbroadcasti128 ymm2, [{state} + 32]",
        "vbroadcasti128 ymm3, [{state} + 48]",
        "vpaddd ymm7, ymm3, ymm13",
        "vpaddd ymm3, ymm3, ymm12",
        "vmovdqa ymm4, ymm0",
        "vmovdqa ymm5, ymm1",
        "vmovdqa ymm6, ymm2",
        "mov {n}, 10",
        "2:",
        quarter!("ymm0", "ymm1", "ymm2", "ymm3", "ymm8"),
        quarter!("ymm4", "ymm5", "ymm6", "ymm7", "ymm9"),
        diagonal!("ymm1", "ymm2", "ymm3", "0x39", "0x93"),
        diagonal!("ymm5", "ymm6", "ymm7", "0x39", "0x93"),
        quarter!("ymm0", "ymm1", "ymm2", "ymm3", "ymm8"),
        quarter!("ymm4", "ymm5", "ymm6", "ymm7", "ymm9"),
        diagonal!("ymm1", "ymm2", "ymm3", "0x93", "0x39"),
        diagonal!("ymm5", "ymm6", "ymm7", "0x93", "0x39"),
        "dec {n}",
        "jnz 2b",
        // Add the input back. The counter rows take their increments
        // again, since the broadcast row is the base counter.
        "vbroadcasti128 ymm8, [{state}]",
        "vbroadcasti128 ymm9, [{state} + 16]",
        "vbroadcasti128 ymm10, [{state} + 32]",
        "vbroadcasti128 ymm11, [{state} + 48]",
        "vpaddd ymm0, ymm0, ymm8",
        "vpaddd ymm1, ymm1, ymm9",
        "vpaddd ymm2, ymm2, ymm10",
        "vpaddd ymm4, ymm4, ymm8",
        "vpaddd ymm5, ymm5, ymm9",
        "vpaddd ymm6, ymm6, ymm10",
        "vpaddd ymm8, ymm11, ymm12",
        "vpaddd ymm9, ymm11, ymm13",
        "vpaddd ymm3, ymm3, ymm8",
        "vpaddd ymm7, ymm7, ymm9",
        output!(
            "ymm0", "ymm1", "ymm2", "ymm3", "xmm0", "xmm1", "xmm2", "xmm3", 0
        ),
        output!(
            "ymm4", "ymm5", "ymm6", "ymm7", "xmm4", "xmm5", "xmm6", "xmm7",
            128
        ),
        "vzeroupper",
        state = in(reg) state.as_ptr(),
        data = in(reg) data,
        rot16 = in(reg) ROTATE16.0.as_ptr(),
        rot8 = in(reg) ROTATE8.0.as_ptr(),
        counters = in(reg) COUNTERS[0].0.as_ptr(),
        n = out(reg) _,
        out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
        out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
        out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
        out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
        options(nostack),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::chacha20::tests::{
        check_known_answers, check_matches_portable,
    };
    use crate::Error;

    #[test]
    fn known_answers() {
        if has_avx2() {
            check_known_answers::<Avx2>();
        }
    }

    #[test]
    fn matches_portable() {
        if has_avx2() {
            check_matches_portable::<Avx2>();
        }
    }

    #[test]
    fn probe_agrees_with_constructor() {
        let result = ChaCha20::try_new(&[0u8; 32]);
        assert_eq!(result.is_ok(), has_avx2());
        if !has_avx2() {
            assert_eq!(result.err(), Some(Error::NotSupported));
        }
    }
}
