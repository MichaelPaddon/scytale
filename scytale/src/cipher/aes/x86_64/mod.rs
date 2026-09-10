//! AES implementations for x86-64.
//!
//! [`aesni`] uses the AES-NI instructions on 128-bit registers;
//! [`vaes`] uses the VAES extension on 256-bit registers. Both check
//! for their instructions at run time and share the key schedule here.

#![allow(unsafe_code)]

pub mod aesni;
pub mod vaes;

use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};
use zeroize::ZeroizeOnDrop;

use core::any::Any;

use super::{Aes, Aes128, Aes192, Aes256, KeySize, MAX_WORDS, expand_words};
use crate::cipher::{BlockCipher, is};

/// Whether the processor reports AES-NI (CPUID leaf 1, ECX bit 25)
/// and `pshufb`, which comes with SSSE3 (bit 9).
///
/// The counter loop uses `pshufb` and the cipher itself does not, but
/// the two have arrived together on every processor ever built, so
/// they are asked for together. A machine with one and not the other
/// takes the portable path, rather than every call carrying a branch
/// for hardware that does not exist.
pub(crate) fn has_aesni() -> bool {
    let features = __cpuid(1).ecx;
    features & (1 << 25) != 0 && features & (1 << 9) != 0
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

/// A cipher whose expanded key the AES instructions can read.
///
/// Implemented by the implementations that run on them and by the
/// dispatching types over those, which answer `None` when the
/// processor sent them to portable code instead. A mode with a loop
/// of its own over the cipher and something else asks this when it is
/// built.
pub(crate) trait Keyed {
    /// The keys the rounds run forwards under.
    fn schedule(&self) -> Option<Schedule<'_>>;

    /// The keys the rounds run backwards under, for a mode with a
    /// loop of its own over decryption.
    fn decryption(&self) -> Option<Schedule<'_>>;
}

/// A borrowed view of an expanded encryption key.
///
/// What a loop written straight against the AES instructions needs,
/// and nothing else: where the round keys are and how many rounds
/// there are. The lifetime is the cipher's, so such a loop cannot
/// outlive the key it runs under, and the key itself never leaves the
/// crate.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Schedule<'a> {
    keys: &'a [u32; MAX_WORDS],
    rounds: usize,
}

impl<'a> Schedule<'a> {
    fn new(keys: &'a RoundKeys) -> Self {
        Schedule {
            keys: &keys.enc,
            rounds: keys.size.rounds(),
        }
    }

    /// The same for the equivalent inverse cipher, whose keys run
    /// backwards and have been through `InvMixColumns`.
    fn inverse(keys: &'a RoundKeys) -> Self {
        Schedule {
            keys: &keys.dec,
            rounds: keys.size.rounds(),
        }
    }

    /// The first round key; the rest follow it, sixteen bytes apart.
    pub(crate) fn keys(&self) -> *const u32 {
        self.keys.as_ptr()
    }

    /// Rounds, so `rounds + 1` round keys.
    pub(crate) fn rounds(&self) -> usize {
        self.rounds
    }
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
/// Written out rather than reached through an intrinsic, and not
/// because of speed: an intrinsic names the 128-bit vector type, and
/// on a target built without SSE that type cannot be lowered at all,
/// so the crate would not compile for bare metal. The instruction
/// itself is happy there, since naming a register in assembly asks
/// nothing of the compiler.
///
/// # Safety
/// Requires AES-NI.
unsafe fn sub_word(w: u32) -> u32 {
    unsafe {
        let out: u32;
        core::arch::asm!(
            "movd            xmm0, {w:e}",
            // Into every lane, so lane 0 of the result is the one wanted.
            "pshufd          xmm0, xmm0, 0",
            "aeskeygenassist xmm0, xmm0, 0",
            "movd            {out:e}, xmm0",
            w = in(reg) w,
            out = out(reg) out,
            out("xmm0") _,
            options(pure, nomem, nostack, preserves_flags),
        );
        out
    }
}

/// The shared key expansion with the hardware S-box, then the inverse
/// keys for the equivalent inverse cipher.
///
/// # Safety
/// Requires AES-NI.
unsafe fn expand(key: &[u8], size: KeySize) -> RoundKeys {
    unsafe {
        let rounds = size.rounds();
        let enc = expand_words(key, size, |w| sub_word(w));

        // Decryption runs the round keys backwards, with the inner ones
        // passed through InvMixColumns so `aesdec` can use them directly.
        let mut dec = [0u32; MAX_WORDS];
        dec[..4].copy_from_slice(&enc[4 * rounds..4 * rounds + 4]);
        for r in 1..rounds {
            let src = 4 * (rounds - r);
            // SAFETY: both slices are four words, and `movdqu` asks
            // nothing of their alignment.
            core::arch::asm!(
                "movdqu xmm0, [{src}]",
                "aesimc xmm0, xmm0",
                "movdqu [{dst}], xmm0",
                src = in(reg) enc[src..].as_ptr(),
                dst = in(reg) dec[4 * r..].as_mut_ptr(),
                out("xmm0") _,
                options(nostack),
            );
        }
        dec[4 * rounds..4 * rounds + 4].copy_from_slice(&enc[..4]);

        RoundKeys { enc, dec, size }
    }
}

/// How to reach the round keys of the cipher a mode was built over.
pub(crate) type Keys<C> = for<'a> fn(&'a C) -> Option<Schedule<'a>>;

/// The same, either way round: `true` asks for the keys decryption
/// runs under.
pub(crate) type KeysEitherWay<C> =
    for<'a> fn(&'a C, bool) -> Option<Schedule<'a>>;

/// Every cipher here whose expanded key these instructions can read.
///
/// The dispatching widths and the generic type over them come first,
/// because that is what a caller normally names; the implementations
/// beneath them are here too, for a caller that named one directly.
/// The portable ciphers are not, because their schedules are nothing
/// these instructions could load.
///
/// One list, because a mode that missed an entry would quietly take
/// its portable path for a cipher it could have run its own loop over,
/// and nothing would fail.
macro_rules! keyed {
    ($mac:ident) => {
        $mac!(
            Aes128,
            Aes192,
            Aes256,
            Aes<16>,
            Aes<24>,
            Aes<32>,
            aesni::Aes<16>,
            aesni::Aes<24>,
            aesni::Aes<32>,
            vaes::Aes<16>,
            vaes::Aes<24>,
            vaes::Aes<32>,
        );
    };
}

/// Answers [`keys`] for one group of types.
macro_rules! forwards {
    ($($ty:ty),* $(,)?) => {
        $(
            if is::<$ty, C>() {
                return Some(|cipher| {
                    let any = cipher as &dyn Any;
                    any.downcast_ref::<$ty>().and_then(Keyed::schedule)
                });
            }
        )*
    };
}

/// Answers [`keys_either_way`] for one group of types.
macro_rules! either_way {
    ($($ty:ty),* $(,)?) => {
        $(
            if is::<$ty, C>() {
                return Some(|cipher, backwards| {
                    let any = cipher as &dyn Any;
                    let cipher = any.downcast_ref::<$ty>()?;
                    if backwards {
                        Keyed::decryption(cipher)
                    } else {
                        Keyed::schedule(cipher)
                    }
                });
            }
        )*
    };
}

/// How to reach `C`'s round keys, or `None` if `C` is not a cipher
/// whose keys these instructions could read.
///
/// Asked once, when a mode is built. `C` is a type parameter, so every
/// comparison is a constant and all but one folds away.
pub(crate) fn keys<C: BlockCipher>() -> Option<Keys<C>> {
    keyed!(forwards);
    None
}

/// As [`keys`], for a mode with a loop over decryption as well.
pub(crate) fn keys_either_way<C: BlockCipher>() -> Option<KeysEitherWay<C>> {
    keyed!(either_way);
    None
}
