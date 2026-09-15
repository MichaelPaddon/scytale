//! ChaCha20 with AVX2 on x86-64.
//!
//! Eight blocks at a time where there are eight: each `ymm` register
//! holds one word of the state for all eight blocks, so a column
//! round and a diagonal round are the same instructions on a
//! different choice of registers and nothing is moved between them.
//! That uses every register, and the rotations by 12 and 7 want a
//! scratch one, so the last word is set aside in memory while they
//! run. Eight words of one block are then gathered side by side and
//! stored.
//!
//! What is left, fewer than eight blocks, goes four at a time: each
//! block's state is four rows of four words, one row to a 128-bit half
//! of a register, so a register holds the same row of two blocks. Two
//! such sets run interleaved, which gives the processor independent
//! work to overlap. A column round is one quarter round on the four
//! rows; the diagonal round is the same after rotating three rows
//! within each half, which `vpshufd` does per half exactly as needed.
//! The eight-block loop measured about a third faster than this one
//! on long messages, which is the shuffles and the extraction it does
//! without.
//!
//! Rotates by 16 and 8 are byte shuffles; 12 and 7 are a shift each
//! way and an or. No memory access depends on the key.

#![allow(unsafe_code)]

use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

use zeroize::Zeroize;

use super::{BLOCK_SIZE, Backend, Cipher, Sealed};
use crate::align::At32;
use crate::probe::Probe;

/// ChaCha20 with AVX2.
pub type ChaCha20 = Cipher<Avx2>;

/// Whether the processor and operating system support AVX2: the
/// instructions (leaf 7, EBX bit 5) and the OS saving the upper
/// register halves (XCR0 bits 1 and 2), as for VAES.
pub(crate) fn has_avx2() -> bool {
    AVX2.yes(ask_avx2)
}

/// Kept: ChaCha20-Poly1305 takes a cipher for every message.
static AVX2: Probe = Probe::new();

fn ask_avx2() -> bool {
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
// No public constructor: a value exists only by way of `probe`.
#[derive(Clone, Copy)]
pub struct Avx2(());

impl Sealed for Avx2 {}

impl Backend for Avx2 {
    fn probe() -> Option<Self> {
        has_avx2().then_some(Avx2(()))
    }

    fn xor(
        self,
        key: &[u32; 8],
        nonce: &[u32; 3],
        counter: u32,
        data: &mut [u8],
    ) {
        // SAFETY: `self` was minted by `probe`, which confirmed the
        // instructions.
        unsafe { xor(key, nonce, counter, data) }
    }
}

/// Blocks one pass of the narrower loop handles.
const GROUP: usize = 4;

/// Blocks one pass of the wider loop handles.
const WIDE: usize = 8;

/// Rotate each word left by 16, as a byte shuffle.
static ROTATE16: At32<[u8; 32]> = At32([
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, //
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
]);

/// Rotate each word left by 8, as a byte shuffle.
static ROTATE8: At32<[u8; 32]> = At32([
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, //
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
]);

static COUNTERS: [At32<[u32; 8]>; 2] = [
    At32([0, 0, 0, 0, 1, 0, 0, 0]),
    At32([2, 0, 0, 0, 3, 0, 0, 0]),
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
    unsafe {
        debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
        let mut counter = counter;
        let mut wide = data.chunks_exact_mut(BLOCK_SIZE * WIDE);
        if wide.len() > 0 {
            let mut words = Words::new(key, nonce);
            let mut spill = At32([0u8; 32]);
            for group in &mut wide {
                words.count_from(counter);
                group8(&words, &mut spill, group.as_mut_ptr());
                counter = counter.wrapping_add(WIDE as u32);
            }
            spill.0.zeroize();
            words.0.0.zeroize();
        }
        let data = wide.into_remainder();
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
}

/// The state of eight blocks laid out word by word: sixteen rows of
/// eight words, each row one register's worth, the same word of every
/// block side by side.
struct Words(At32<[[u32; 8]; 16]>);

impl Words {
    /// Everything but the counters, which [`count_from`] fills.
    ///
    /// [`count_from`]: Words::count_from
    fn new(key: &[u32; 8], nonce: &[u32; 3]) -> Self {
        let rows = rows(key, nonce, 0);
        Words(At32(rows.map(|word| [word; 8])))
    }

    /// Block `i` of the eight counts from `counter + i`.
    fn count_from(&mut self, counter: u32) {
        for (i, lane) in self.0.0[12].iter_mut().enumerate() {
            *lane = counter.wrapping_add(i as u32);
        }
    }
}

/// One step of a half round across the four quarter rounds listed,
/// each as its words' registers: `a += b; d ^= a; d <<<= r` with a
/// byte shuffle, or `c += d; b ^= c; b <<<= r` by shifts, with ymm15
/// set aside in memory to serve as the scratch register.
#[rustfmt::skip]
macro_rules! step {
    (shuffle $mask:literal;
     $( ($a:literal, $b:literal, $c:literal, $d:literal) ),*) => {
        concat!(
            $( "vpaddd ", $a, ", ", $a, ", ", $b, "\n", )*
            $( "vpxor ", $d, ", ", $d, ", ", $a, "\n", )*
            $( "vpshufb ", $d, ", ", $d, ", [{", $mask, "}]\n", )*
        )
    };
    (shift $left:literal, $right:literal;
     $( ($a:literal, $b:literal, $c:literal, $d:literal) ),*) => {
        concat!(
            $( "vpaddd ", $c, ", ", $c, ", ", $d, "\n", )*
            $( "vpxor ", $b, ", ", $b, ", ", $c, "\n", )*
            "vmovdqa [{spill}], ymm15\n",
            $( concat!(
                "vpsrld ymm15, ", $b, ", ", $right, "\n",
                "vpslld ", $b, ", ", $b, ", ", $left, "\n",
                "vpor ", $b, ", ", $b, ", ymm15\n",
            ), )*
            "vmovdqa ymm15, [{spill}]\n",
        )
    };
}

/// A half round, column or diagonal, on the quarter rounds listed.
#[rustfmt::skip]
macro_rules! half {
    ($( $q:tt ),*) => {
        concat!(
            step!(shuffle "rot16"; $( $q ),*),
            step!(shift "12", "20"; $( $q ),*),
            step!(shuffle "rot8"; $( $q ),*),
            step!(shift "7", "25"; $( $q ),*),
        )
    };
}

/// Pairs words `$w0..$w3` of every block into two words of each,
/// block by block: afterwards each register holds its four words for
/// two blocks, the low half one block and the high half the block
/// four on. `$t` is scratch. Leaves blocks 0 and 4 in `$w0`, 1 and 5
/// in `$w3`, 2 and 6 in `$w1`, 3 and 7 in `$w2`.
#[rustfmt::skip]
macro_rules! gather {
    ($w0:literal, $w1:literal, $w2:literal, $w3:literal, $t:literal) => {
        concat!(
            "vpunpckhdq ", $t, ", ", $w0, ", ", $w1, "\n",
            "vpunpckldq ", $w0, ", ", $w0, ", ", $w1, "\n",
            "vpunpckhdq ", $w1, ", ", $w2, ", ", $w3, "\n",
            "vpunpckldq ", $w2, ", ", $w2, ", ", $w3, "\n",
            "vpunpckhqdq ", $w3, ", ", $w0, ", ", $w2, "\n",
            "vpunpcklqdq ", $w0, ", ", $w0, ", ", $w2, "\n",
            "vpunpckhqdq ", $w2, ", ", $t, ", ", $w1, "\n",
            "vpunpcklqdq ", $w1, ", ", $t, ", ", $w1, "\n",
        )
    };
}

/// Xors two blocks' halves of words, `$x` holding words 0 to 3 (or 8
/// to 11) and `$y` the next four, into the bytes at `$low` and
/// `$high`, the offsets of the block in the low halves and of the one
/// in the high halves. `$t` is scratch; `$x` is overwritten.
#[rustfmt::skip]
macro_rules! emit {
    ($x:literal, $y:literal, $t:literal, $low:literal, $high:literal) => {
        concat!(
            "vperm2i128 ", $t, ", ", $x, ", ", $y, ", 0x20\n",
            "vpxor ", $t, ", ", $t, ", [{data} + ", $low, "]\n",
            "vmovdqu [{data} + ", $low, "], ", $t, "\n",
            "vperm2i128 ", $x, ", ", $x, ", ", $y, ", 0x31\n",
            "vpxor ", $x, ", ", $x, ", [{data} + ", $high, "]\n",
            "vmovdqu [{data} + ", $high, "], ", $x, "\n",
        )
    };
}

/// Eight blocks from `words`, xored into the 512 bytes at `data`.
///
/// Register `ymm<i>` holds word `i` of all eight blocks, so a column
/// round and a diagonal round are the same instructions on different
/// registers, with nothing to rearrange between them. The rotations by
/// 12 and 7 need a scratch register and there are none left, so ymm15,
/// word 15, is set aside in `spill` for the length of each.
///
/// # Safety
/// Requires AVX2; `data` must point at 512 writable bytes.
unsafe fn group8(words: &Words, spill: &mut At32<[u8; 32]>, data: *mut u8) {
    unsafe {
        core::arch::asm!(
            "vmovdqa ymm0, [{words}]",
            "vmovdqa ymm1, [{words} + 32]",
            "vmovdqa ymm2, [{words} + 64]",
            "vmovdqa ymm3, [{words} + 96]",
            "vmovdqa ymm4, [{words} + 128]",
            "vmovdqa ymm5, [{words} + 160]",
            "vmovdqa ymm6, [{words} + 192]",
            "vmovdqa ymm7, [{words} + 224]",
            "vmovdqa ymm8, [{words} + 256]",
            "vmovdqa ymm9, [{words} + 288]",
            "vmovdqa ymm10, [{words} + 320]",
            "vmovdqa ymm11, [{words} + 352]",
            "vmovdqa ymm12, [{words} + 384]",
            "vmovdqa ymm13, [{words} + 416]",
            "vmovdqa ymm14, [{words} + 448]",
            "vmovdqa ymm15, [{words} + 480]",
            "mov {n}, 10",
            "2:",
            half!(
                ("ymm0", "ymm4", "ymm8", "ymm12"),
                ("ymm1", "ymm5", "ymm9", "ymm13"),
                ("ymm2", "ymm6", "ymm10", "ymm14"),
                ("ymm3", "ymm7", "ymm11", "ymm15")
            ),
            half!(
                ("ymm0", "ymm5", "ymm10", "ymm15"),
                ("ymm1", "ymm6", "ymm11", "ymm12"),
                ("ymm2", "ymm7", "ymm8", "ymm13"),
                ("ymm3", "ymm4", "ymm9", "ymm14")
            ),
            "dec {n}",
            "jnz 2b",
            // The input back in, word by word.
            "vpaddd ymm0, ymm0, [{words}]",
            "vpaddd ymm1, ymm1, [{words} + 32]",
            "vpaddd ymm2, ymm2, [{words} + 64]",
            "vpaddd ymm3, ymm3, [{words} + 96]",
            "vpaddd ymm4, ymm4, [{words} + 128]",
            "vpaddd ymm5, ymm5, [{words} + 160]",
            "vpaddd ymm6, ymm6, [{words} + 192]",
            "vpaddd ymm7, ymm7, [{words} + 224]",
            "vpaddd ymm8, ymm8, [{words} + 256]",
            "vpaddd ymm9, ymm9, [{words} + 288]",
            "vpaddd ymm10, ymm10, [{words} + 320]",
            "vpaddd ymm11, ymm11, [{words} + 352]",
            "vpaddd ymm12, ymm12, [{words} + 384]",
            "vpaddd ymm13, ymm13, [{words} + 416]",
            "vpaddd ymm14, ymm14, [{words} + 448]",
            "vpaddd ymm15, ymm15, [{words} + 480]",
            // Words 0 to 11 into blocks, with word 15 set aside so its
            // register is the scratch, and the first half of every
            // block out.
            "vmovdqa [{spill}], ymm15",
            gather!("ymm0", "ymm1", "ymm2", "ymm3", "ymm15"),
            gather!("ymm4", "ymm5", "ymm6", "ymm7", "ymm15"),
            emit!("ymm0", "ymm4", "ymm15", 0, 256),
            emit!("ymm3", "ymm7", "ymm15", 64, 320),
            emit!("ymm1", "ymm5", "ymm15", 128, 384),
            emit!("ymm2", "ymm6", "ymm15", 192, 448),
            gather!("ymm8", "ymm9", "ymm10", "ymm11", "ymm15"),
            // Then words 12 to 15, with a spent register as scratch,
            // and the second half of every block out.
            "vmovdqa ymm15, [{spill}]",
            gather!("ymm12", "ymm13", "ymm14", "ymm15", "ymm0"),
            emit!("ymm8", "ymm12", "ymm0", 32, 288),
            emit!("ymm11", "ymm15", "ymm0", 96, 352),
            emit!("ymm9", "ymm13", "ymm0", 160, 416),
            emit!("ymm10", "ymm14", "ymm0", 224, 480),
            "vzeroupper",
            words = in(reg) words.0.0.as_ptr(),
            spill = in(reg) spill.0.as_mut_ptr(),
            data = in(reg) data,
            rot16 = in(reg) ROTATE16.0.as_ptr(),
            rot8 = in(reg) ROTATE8.0.as_ptr(),
            n = out(reg) _,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
            out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
            options(nostack),
        );
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
    unsafe {
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
                "ymm0", "ymm1", "ymm2", "ymm3", "xmm0", "xmm1", "xmm2",
                "xmm3", 0
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::cipher::chacha20::tests::{
        check_known_answers, check_matches_portable,
    };

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
        let result = ChaCha20::try_new(&crate::Key::from([0u8; 32]));
        assert_eq!(result.is_ok(), has_avx2());
        if !has_avx2() {
            assert_eq!(result.err(), Some(Error::NotSupported));
        }
    }
}
