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

use super::{Aes, Aes128, Aes192, Aes256, KeySize, MAX_WORDS};
use crate::cipher::{BlockCipher, is};
use crate::probe::Probe;

/// Whether the processor reports AES-NI (CPUID leaf 1, ECX bit 25)
/// and `pshufb`, which comes with SSSE3 (bit 9).
///
/// The counter loop uses `pshufb` and the cipher itself does not, but
/// the two have arrived together on every processor ever built, so
/// they are asked for together. A machine with one and not the other
/// takes the portable path, rather than every call carrying a branch
/// for hardware that does not exist.
pub(crate) fn has_aesni() -> bool {
    AESNI.yes(ask_aesni)
}

/// Kept, because a key expansion asks: GCM-SIV derives a key for
/// every message it encrypts, and `cpuid` serialises the pipeline.
static AESNI: Probe = Probe::new();

fn ask_aesni() -> bool {
    let features = __cpuid(1).ecx;
    features & (1 << 25) != 0 && features & (1 << 9) != 0
}

/// Whether the processor has AES-NI *and* AVX, with the operating
/// system saving its state: AES-NI and SSSE3 as above, then OSXSAVE
/// and AVX (leaf 1, ECX bits 27 and 28) and XCR0 bits 1 and 2.
///
/// AES-NI does not imply AVX. A loop written in the VEX encodings --
/// `vmovdqu`, `vpxor`, `vaesenc` -- needs both, and asking only for
/// AES-NI puts an illegal instruction on every Westmere and on the
/// whole Silvermont and Goldmont line, which have the cipher and not
/// the encoding. Any suite whose assembly is VEX-encoded asks this
/// rather than [`has_aesni`].
pub(crate) fn has_aesni_avx() -> bool {
    AESNI_AVX.yes(ask_aesni_avx)
}

/// Kept, as [`AESNI`] is: a mode asks when it is built, and that is
/// once per key.
static AESNI_AVX: Probe = Probe::new();

fn ask_aesni_avx() -> bool {
    let wanted = (1 << 27) | (1 << 28);
    if !has_aesni() || __cpuid(1).ecx & wanted != wanted {
        return false;
    }
    // SAFETY: OSXSAVE was just confirmed, so XGETBV is available.
    let xcr0 = unsafe { _xgetbv(0) };
    xcr0 & 0b110 == 0b110
}

/// Whether the processor and operating system support VAES on 256-bit
/// registers: VAES (leaf 7, ECX bit 9), AVX2 (leaf 7, EBX bit 5), and
/// the OS saving the upper register halves (XCR0 bits 1 and 2).
pub(super) fn has_vaes256() -> bool {
    VAES256.yes(ask_vaes256)
}

/// Kept, as [`AESNI`] is, and asked more dearly: three questions of
/// the processor rather than one.
static VAES256: Probe = Probe::new();

fn ask_vaes256() -> bool {
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

// The key schedule, written for the instructions rather than as a
// word loop with a hardware S-box dropped in. `aeskeygenassist` does
// `SubWord` and `RotWord` on the lane it is pointed at and folds the
// round constant in; what remains is the running XOR down the four
// words of a round key, which three shift-and-XOR steps do in place.
// Nothing leaves the vector registers until a round key is whole and
// is stored. The old form moved each word out to a general register
// and back again, ten times a key, and that was most of the cost of
// building one, which GCM-SIV pays for every message.
//
// Legacy SSE encodings throughout, as in `aesni`: this runs wherever
// AES-NI does, which does not imply AVX.

/// Three shift-and-XOR steps: XORs each word of `xmm1` into every
/// word above it, which is the running sum FIPS 197 section 5.2
/// forms one word at a time.
macro_rules! fold {
    ($r:literal) => {
        concat!(
            "movdqa xmm4, ",
            $r,
            "\n",
            "pslldq xmm4, 4\n",
            "pxor ",
            $r,
            ", xmm4\n",
            "movdqa xmm4, ",
            $r,
            "\n",
            "pslldq xmm4, 4\n",
            "pxor ",
            $r,
            ", xmm4\n",
            "movdqa xmm4, ",
            $r,
            "\n",
            "pslldq xmm4, 4\n",
            "pxor ",
            $r,
            ", xmm4\n",
        )
    };
}

/// One AES-128 round key from the one before it: the assist on
/// the last word, broadcast, folded in.
macro_rules! step128 {
    ($rcon:literal, $off:literal) => {
        concat!(
            "aeskeygenassist xmm2, xmm1, ",
            $rcon,
            "\n",
            "pshufd xmm2, xmm2, 0xff\n",
            fold!("xmm1"),
            "pxor xmm1, xmm2\n",
            "movdqu [{out} + ",
            $off,
            "], xmm1\n",
        )
    };
}

/// AES-128: ten round keys after the key itself.
///
/// # Safety
/// Requires AES-NI. `key` must point at 16 readable bytes and `out`
/// at 176 writable ones.
unsafe fn expand128(key: *const u8, out: *mut u32) {
    unsafe {
        core::arch::asm!(
            "movdqu xmm1, [{key}]",
            "movdqu [{out}], xmm1",
            step128!("0x01", "16"),
            step128!("0x02", "32"),
            step128!("0x04", "48"),
            step128!("0x08", "64"),
            step128!("0x10", "80"),
            step128!("0x20", "96"),
            step128!("0x40", "112"),
            step128!("0x80", "128"),
            step128!("0x1b", "144"),
            step128!("0x36", "160"),
            key = in(reg) key,
            out = in(reg) out,
            out("xmm1") _, out("xmm2") _, out("xmm4") _,
            options(nostack),
        );
    }
}

/// Six words of AES-192 schedule from the six before them. `xmm1`
/// holds four words and `xmm3` two, in its low half; the assist is
/// on the last of the six, so lane 1 of `xmm3`. After the four are
/// folded, their last word is broadcast into the two.
macro_rules! step192 {
    ($rcon:literal, $off:literal, $store:literal) => {
        concat!(
            "aeskeygenassist xmm2, xmm3, ",
            $rcon,
            "\n",
            "pshufd xmm2, xmm2, 0x55\n",
            fold!("xmm1"),
            "pxor xmm1, xmm2\n",
            "movdqu [{out} + ",
            $off,
            "], xmm1\n",
            "pshufd xmm2, xmm1, 0xff\n",
            "movdqa xmm4, xmm3\n",
            "pslldq xmm4, 4\n",
            "pxor xmm3, xmm4\n",
            "pxor xmm3, xmm2\n",
            $store,
        )
    };
}

/// AES-192: fifty-two words, six at a step, so the last step wants
/// only four and the two it would go on to make are not stored.
///
/// # Safety
/// Requires AES-NI. `key` must point at 24 readable bytes and `out`
/// at 208 writable ones.
unsafe fn expand192(key: *const u8, out: *mut u32) {
    unsafe {
        core::arch::asm!(
            "movdqu xmm1, [{key}]",
            "movq xmm3, [{key} + 16]",
            "movdqu [{out}], xmm1",
            "movq [{out} + 16], xmm3",
            step192!("0x01", "24", "movq [{out} + 40], xmm3\n"),
            step192!("0x02", "48", "movq [{out} + 64], xmm3\n"),
            step192!("0x04", "72", "movq [{out} + 88], xmm3\n"),
            step192!("0x08", "96", "movq [{out} + 112], xmm3\n"),
            step192!("0x10", "120", "movq [{out} + 136], xmm3\n"),
            step192!("0x20", "144", "movq [{out} + 160], xmm3\n"),
            step192!("0x40", "168", "movq [{out} + 184], xmm3\n"),
            step192!("0x80", "192", ""),
            key = in(reg) key,
            out = in(reg) out,
            out("xmm1") _, out("xmm2") _, out("xmm3") _, out("xmm4") _,
            options(nostack),
        );
    }
}

/// Two AES-256 round keys from the two before them. The first takes
/// the rotated assist with the round constant, as AES-128 does; the
/// second takes the plain `SubWord`, which the assist leaves in lane
/// 2 (`0xaa`), with no constant.
macro_rules! step256 {
    ($rcon:literal, $off:literal, $second:expr) => {
        concat!(
            "aeskeygenassist xmm2, xmm3, ",
            $rcon,
            "\n",
            "pshufd xmm2, xmm2, 0xff\n",
            fold!("xmm1"),
            "pxor xmm1, xmm2\n",
            "movdqu [{out} + ",
            $off,
            "], xmm1\n",
            $second,
        )
    };
}

/// The second round key of a [`step256`] pair.
macro_rules! step256b {
    ($off:literal) => {
        concat!(
            "aeskeygenassist xmm2, xmm1, 0\n",
            "pshufd xmm2, xmm2, 0xaa\n",
            fold!("xmm3"),
            "pxor xmm3, xmm2\n",
            "movdqu [{out} + ",
            $off,
            "], xmm3\n",
        )
    };
}

/// AES-256: fourteen round keys after the two the key itself makes.
///
/// # Safety
/// Requires AES-NI. `key` must point at 32 readable bytes and `out`
/// at 240 writable ones.
unsafe fn expand256(key: *const u8, out: *mut u32) {
    unsafe {
        core::arch::asm!(
            "movdqu xmm1, [{key}]",
            "movdqu xmm3, [{key} + 16]",
            "movdqu [{out}], xmm1",
            "movdqu [{out} + 16], xmm3",
            step256!("0x01", "32", step256b!("48")),
            step256!("0x02", "64", step256b!("80")),
            step256!("0x04", "96", step256b!("112")),
            step256!("0x08", "128", step256b!("144")),
            step256!("0x10", "160", step256b!("176")),
            step256!("0x20", "192", step256b!("208")),
            step256!("0x40", "224", ""),
            key = in(reg) key,
            out = in(reg) out,
            out("xmm1") _, out("xmm2") _, out("xmm3") _, out("xmm4") _,
            options(nostack),
        );
    }
}

/// The inverse schedule: the round keys backwards, the inner ones
/// through `InvMixColumns` so that `aesdec` can take them as they
/// are. Copies the first and last, which are not transformed.
///
/// # Safety
/// Requires AES-NI. Both pointers must address `4 * (rounds + 1)`
/// words.
unsafe fn invert(enc: *const u32, dec: *mut u32, rounds: usize) {
    unsafe {
        let last = enc.add(4 * rounds);
        core::arch::asm!(
            "movdqu xmm0, [{last}]",
            "movdqu [{dec}], xmm0",
            "movdqu xmm0, [{enc}]",
            "movdqu [{dec} + {tail}], xmm0",
            // Round `rounds - 1` down to 1, into `dec` slots 1 up.
            "2:",
            "sub {src}, 16",
            "add {dec}, 16",
            "movdqu xmm0, [{src}]",
            "aesimc xmm0, xmm0",
            "movdqu [{dec}], xmm0",
            "dec {n}",
            "jnz 2b",
            enc = in(reg) enc,
            last = in(reg) last,
            src = inout(reg) last => _,
            dec = inout(reg) dec => _,
            tail = in(reg) 16 * rounds,
            n = inout(reg) rounds - 1 => _,
            out("xmm0") _,
            options(nostack),
        );
    }
}

impl RoundKeys {
    /// The expanded key both ways round.
    ///
    /// # Safety
    /// Requires AES-NI.
    unsafe fn new(key: &[u8], size: KeySize) -> Self {
        let mut keys = RoundKeys {
            enc: [0; MAX_WORDS],
            dec: [0; MAX_WORDS],
            size,
        };
        // SAFETY: the caller confirmed the instructions, and both
        // arrays hold `MAX_WORDS`, which is the widest schedule.
        unsafe {
            let (k, enc) = (key.as_ptr(), keys.enc.as_mut_ptr());
            match size {
                KeySize::Aes128 => expand128(k, enc),
                KeySize::Aes192 => expand192(k, enc),
                KeySize::Aes256 => expand256(k, enc),
            }
            invert(keys.enc.as_ptr(), keys.dec.as_mut_ptr(), size.rounds());
        }
        keys
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::expand_words;
    use crate::cipher::aes::portable::bitsliced::sub_word;

    /// The schedule built in registers is the schedule FIPS 197
    /// section 5.2 writes out word by word, at every width. The
    /// inverse half is exercised by every decryption test; here only
    /// its untransformed ends are checked, so that a wrong copy shows
    /// up as itself.
    #[test]
    fn the_schedule_is_the_standard_one() {
        for (len, size) in [
            (16, KeySize::Aes128),
            (24, KeySize::Aes192),
            (32, KeySize::Aes256),
        ] {
            for i in 0..100u32 {
                let key: std::vec::Vec<u8> = (0..len)
                    .map(|j| (i.wrapping_mul(97).wrapping_add(j * 31)) as u8)
                    .collect();
                let want = expand_words(&key, size, sub_word);
                // SAFETY: the test runs only where the probe says so.
                let keys = if has_aesni() {
                    unsafe { RoundKeys::new(&key, size) }
                } else {
                    return;
                };
                assert_eq!(keys.enc, want, "{size:?} key {i}");
                let rounds = size.rounds();
                assert_eq!(keys.dec[..4], want[4 * rounds..4 * rounds + 4]);
                assert_eq!(keys.dec[4 * rounds..4 * rounds + 4], want[..4]);
                assert_eq!(keys.dec[4 * rounds + 4..], want[4 * rounds + 4..]);
            }
        }
    }

    /// The kept answers are the processor's own, and they are kept:
    /// a key expansion asks on every call, and GCM-SIV expands a key
    /// for every message.
    #[test]
    fn the_probes_keep_what_the_processor_said() {
        assert_eq!(has_aesni(), ask_aesni());
        assert_eq!(has_vaes256(), ask_vaes256());
        assert!(AESNI.asked());
        assert!(VAES256.asked());
    }
}
