//! AES implementations for x86-64.
//!
//! [`aesni`] uses the AES-NI instructions on 128-bit registers;
//! [`vaes`] uses the VAES extension on 256-bit registers. Both check
//! for their instructions at run time and share the key schedule here.

#![allow(unsafe_code)]

pub mod aesni;
pub mod vaes;

use core::arch::x86_64::{
    __cpuid, __cpuid_count, __m128i, _mm_aesimc_si128,
    _mm_aeskeygenassist_si128, _mm_cvtsi128_si32, _mm_loadu_si128,
    _mm_set1_epi32, _mm_storeu_si128, _xgetbv,
};
use zeroize::ZeroizeOnDrop;

use super::{expand_words, KeySize, MAX_WORDS};

/// Whether the processor reports AES-NI (CPUID leaf 1, ECX bit 25).
pub(super) fn has_aesni() -> bool {
    __cpuid(1).ecx & (1 << 25) != 0
}

/// Whether the processor and operating system support VAES on 256-bit
/// registers: VAES (leaf 7, ECX bit 9), AVX2 (leaf 7, EBX bit 5), and
/// the OS saving the upper register halves (XCR0 bits 1 and 2).
pub(super) fn has_vaes256() -> bool {
    let leaf1 = __cpuid(1);
    let osxsave = leaf1.ecx & (1 << 27) != 0;
    let avx = leaf1.ecx & (1 << 28) != 0;
    if !(osxsave && avx && has_aesni()) {
        return false;
    }
    let leaf7 = __cpuid_count(7, 0);
    let avx2 = leaf7.ebx & (1 << 5) != 0;
    let vaes = leaf7.ecx & (1 << 9) != 0;
    // SAFETY: OSXSAVE was just confirmed, so XGETBV is available.
    let xcr0 = unsafe { _xgetbv(0) };
    avx2 && vaes && xcr0 & 0b110 == 0b110
}

/// Expanded encryption and decryption round keys, as words in memory
/// order; the round loops load them straight from memory.
#[derive(Clone, ZeroizeOnDrop)]
struct RoundKeys {
    enc: [u32; MAX_WORDS],
    dec: [u32; MAX_WORDS],
    #[zeroize(skip)]
    size: KeySize,
}

/// `SubWord` via `aeskeygenassist`, which applies the S-box to lanes
/// 1 and 3 of its input; broadcasting `w` puts it in every lane.
///
/// # Safety
/// Requires AES-NI.
#[target_feature(enable = "aes")]
unsafe fn sub_word(w: u32) -> u32 {
    let v = _mm_set1_epi32(w as i32);
    _mm_cvtsi128_si32(_mm_aeskeygenassist_si128::<0>(v)) as u32
}

/// The shared key expansion with the hardware S-box, then the inverse
/// keys for the equivalent inverse cipher.
///
/// # Safety
/// Requires AES-NI.
#[target_feature(enable = "aes")]
unsafe fn expand(key: &[u8], size: KeySize) -> RoundKeys {
    let rounds = size.rounds();
    let enc = expand_words(key, size, |w| sub_word(w));

    // Decryption runs the round keys backwards, with the inner ones
    // passed through InvMixColumns so `aesdec` can use them directly.
    let mut dec = [0u32; MAX_WORDS];
    dec[..4].copy_from_slice(&enc[4 * rounds..4 * rounds + 4]);
    for r in 1..rounds {
        let src = 4 * (rounds - r);
        // SAFETY: both slices are four words; unaligned access.
        let k = _mm_loadu_si128(enc[src..].as_ptr() as *const __m128i);
        let k = _mm_aesimc_si128(k);
        _mm_storeu_si128(dec[4 * r..].as_mut_ptr() as *mut __m128i, k);
    }
    dec[4 * rounds..4 * rounds + 4].copy_from_slice(&enc[..4]);

    RoundKeys { enc, dec, size }
}
