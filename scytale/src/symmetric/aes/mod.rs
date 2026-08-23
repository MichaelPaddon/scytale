//! AES (FIPS 197) block cipher.
//!
//! [`Aes`] runs the best implementation the processor supports:
//! hardware instructions where present, otherwise constant-time
//! portable code. To use a particular one, name it: [`portable::Aes`],
//! [`portable::bitsliced::Aes`], `x86_64::aesni::Aes`,
//! `x86_64::vaes::Aes`, `aarch64::armv8::Aes`, `riscv64::zkn::Aes` or
//! `riscv64::zvkned::Aes` (the hardware ones exist only on their
//! architecture).
//!
//! Every implementation wipes its expanded key when dropped.
//!
//! ```
//! use scytale::symmetric::aes::{portable, Aes};
//!
//! # fn main() -> Result<(), scytale::symmetric::Error> {
//! let fastest = Aes::try_new(&[0u8; 16])?;
//! let portable = portable::Aes::try_new(&[0u8; 16])?;
//!
//! let mut a = [0u8; 16];
//! let mut b = a;
//! fastest.encrypt_block(&mut a);
//! portable.encrypt_block(&mut b);
//! assert_eq!(a, b);
//! # Ok(())
//! # }
//! ```

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
pub mod portable;
#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::symmetric::{BlockCipher, Error};

/// AES block size in bytes.
pub const BLOCK_SIZE: usize = 16;

/// Words in the longest key schedule (AES-256: 15 round keys).
pub(crate) const MAX_WORDS: usize = 60;

/// Key size, which fixes the number of rounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeySize {
    Aes128,
    Aes192,
    Aes256,
}

impl KeySize {
    pub(crate) fn for_key(key: &[u8]) -> Result<Self, Error> {
        match key.len() {
            16 => Ok(KeySize::Aes128),
            24 => Ok(KeySize::Aes192),
            32 => Ok(KeySize::Aes256),
            n => Err(Error::InvalidKeyLength(n)),
        }
    }

    pub(crate) fn rounds(self) -> usize {
        match self {
            KeySize::Aes128 => 10,
            KeySize::Aes192 => 12,
            KeySize::Aes256 => 14,
        }
    }
}

/// Key expansion (FIPS 197 section 5.2), shared by every
/// implementation; each supplies its own `SubWord`.
///
/// Words are the little-endian view of four consecutive key bytes,
/// the order in which the hardware instructions see the state. On
/// such a word `RotWord` is a rotate right by 8 and the round constant
/// goes in the low byte. Unused words at the end stay zero.
pub(crate) fn expand_words(
    key: &[u8],
    size: KeySize,
    sub_word: impl Fn(u32) -> u32,
) -> [u32; MAX_WORDS] {
    let nk = key.len() / 4;
    let words = 4 * (size.rounds() + 1);

    let mut w = [0u32; MAX_WORDS];
    for (w, k) in w.iter_mut().zip(key.chunks_exact(4)) {
        *w = u32::from_le_bytes([k[0], k[1], k[2], k[3]]);
    }
    let mut rcon: u32 = 1;
    for i in nk..words {
        let mut t = w[i - 1];
        if i % nk == 0 {
            t = sub_word(t.rotate_right(8)) ^ rcon;
            // Multiply by x in GF(2^8).
            rcon = (rcon << 1) ^ if rcon & 0x80 != 0 { 0x11b } else { 0 };
        } else if nk > 6 && i % nk == 4 {
            t = sub_word(t);
        }
        w[i] = w[i - nk] ^ t;
    }
    w
}

/// The implementation the processor gets, chosen once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Choice {
    Vaes,
    AesNi,
    Armv8,
    Zvkned,
    Zkn,
    Bitsliced,
}

/// Candidates in order of preference: hardware, fastest first, then
/// the constant-time portable code. The table-driven portable code is
/// never chosen automatically because it leaks through cache timing.
const CHOICES: [Choice; 6] = [
    Choice::Vaes,
    Choice::AesNi,
    Choice::Armv8,
    Choice::Zvkned,
    Choice::Zkn,
    Choice::Bitsliced,
];

/// The probe result: 0 until probed, then one plus the index into
/// `CHOICES`. Probing is idempotent, so a race between two first
/// callers is harmless.
static PROBED: AtomicU8 = AtomicU8::new(0);

/// Asks the processor once; afterwards a single atomic load.
fn probe() -> Choice {
    match PROBED.load(Ordering::Relaxed) {
        0 => {
            let found = CHOICES
                .into_iter()
                .enumerate()
                .find(|&(_, c)| supported(c))
                .unwrap_or((5, Choice::Bitsliced));
            PROBED.store(found.0 as u8 + 1, Ordering::Relaxed);
            found.1
        }
        n => CHOICES
            .get(usize::from(n) - 1)
            .copied()
            .unwrap_or(Choice::Bitsliced),
    }
}

/// Asks the processor directly whether it supports `choice`.
fn supported(choice: Choice) -> bool {
    match choice {
        #[cfg(target_arch = "x86_64")]
        Choice::Vaes => x86_64::has_vaes256(),
        #[cfg(target_arch = "x86_64")]
        Choice::AesNi => x86_64::has_aesni(),
        #[cfg(target_arch = "aarch64")]
        Choice::Armv8 => aarch64::armv8::has_aes(),
        #[cfg(target_arch = "riscv64")]
        Choice::Zvkned => riscv64::has_zvkned(),
        #[cfg(target_arch = "riscv64")]
        Choice::Zkn => riscv64::has_zkn(),
        Choice::Bitsliced => true,
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

/// AES using the best implementation the processor supports: the
/// fastest hardware instructions if there are any, otherwise the
/// constant-time bitsliced code. Security comes before speed, so the
/// faster table-driven [`portable::Aes`] is never chosen here; use it
/// by name if its trade-off suits you.
///
/// The processor is probed once, the first time a key is expanded;
/// every later [`Aes::try_new`] reads the cached answer, and each
/// call then dispatches with a single predictable branch.
#[derive(Clone)]
pub struct Aes(Inner);

// Each variant is that implementation's key schedule; the bitsliced
// one is twice the size of the others and there is no heap to box it.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum Inner {
    #[cfg(target_arch = "x86_64")]
    Vaes(x86_64::vaes::Aes),
    #[cfg(target_arch = "x86_64")]
    AesNi(x86_64::aesni::Aes),
    #[cfg(target_arch = "aarch64")]
    Armv8(aarch64::armv8::Aes),
    #[cfg(target_arch = "riscv64")]
    Zvkned(riscv64::zvkned::Aes),
    #[cfg(target_arch = "riscv64")]
    Zkn(riscv64::zkn::Aes),
    Bitsliced(portable::bitsliced::Aes),
}

/// Applies a method to whichever implementation is in use.
macro_rules! dispatch {
    ($self:expr, $aes:ident => $body:expr) => {
        match &$self.0 {
            #[cfg(target_arch = "x86_64")]
            Inner::Vaes($aes) => $body,
            #[cfg(target_arch = "x86_64")]
            Inner::AesNi($aes) => $body,
            #[cfg(target_arch = "aarch64")]
            Inner::Armv8($aes) => $body,
            #[cfg(target_arch = "riscv64")]
            Inner::Zvkned($aes) => $body,
            #[cfg(target_arch = "riscv64")]
            Inner::Zkn($aes) => $body,
            Inner::Bitsliced($aes) => $body,
        }
    };
}

impl fmt::Debug for Aes {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes")
            .field("rounds", &self.rounds())
            .finish()
    }
}

impl Aes {
    /// Expands `key`, which must be 16, 24 or 32 bytes long, with the
    /// best implementation the processor supports.
    // The hardware constructors skip their own processor check because
    // the probe has already made it.
    #[allow(unsafe_code)]
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        // SAFETY: `probe` only names hardware after confirming the
        // processor supports it.
        let inner = unsafe {
            match probe() {
                #[cfg(target_arch = "x86_64")]
                Choice::Vaes => {
                    Inner::Vaes(x86_64::vaes::Aes::new_unchecked(key)?)
                }
                #[cfg(target_arch = "x86_64")]
                Choice::AesNi => {
                    Inner::AesNi(x86_64::aesni::Aes::new_unchecked(key)?)
                }
                #[cfg(target_arch = "aarch64")]
                Choice::Armv8 => {
                    Inner::Armv8(aarch64::armv8::Aes::new_unchecked(key)?)
                }
                #[cfg(target_arch = "riscv64")]
                Choice::Zvkned => {
                    Inner::Zvkned(riscv64::zvkned::Aes::new_unchecked(key)?)
                }
                #[cfg(target_arch = "riscv64")]
                Choice::Zkn => {
                    Inner::Zkn(riscv64::zkn::Aes::new_unchecked(key)?)
                }
                _ => Inner::Bitsliced(portable::bitsliced::Aes::try_new(key)?),
            }
        };
        Ok(Aes(inner))
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        dispatch!(self, aes => aes.rounds())
    }

    /// Encrypts one block in place.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        dispatch!(self, aes => aes.encrypt_block(block))
    }

    /// Decrypts one block in place.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        dispatch!(self, aes => aes.decrypt_block(block))
    }

    /// Encrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of 16; nothing is changed
    /// otherwise.
    pub fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        dispatch!(self, aes => aes.encrypt_blocks(data))
    }

    /// Decrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of 16; nothing is changed
    /// otherwise.
    pub fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        dispatch!(self, aes => aes.decrypt_blocks(data))
    }
}

impl BlockCipher for Aes {
    const BLOCK_SIZE: usize = BLOCK_SIZE;

    fn try_new(key: &[u8]) -> Result<Self, Error> {
        Aes::try_new(key)
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        Aes::encrypt_blocks(self, data)
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        Aes::decrypt_blocks(self, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    /// Compiles only if every implementation wipes its key on drop.
    #[test]
    fn every_implementation_zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<portable::Aes>();
        wipes::<portable::bitsliced::Aes>();
        #[cfg(target_arch = "x86_64")]
        {
            wipes::<x86_64::aesni::Aes>();
            wipes::<x86_64::vaes::Aes>();
        }
        #[cfg(target_arch = "aarch64")]
        wipes::<aarch64::armv8::Aes>();
        #[cfg(target_arch = "riscv64")]
        {
            wipes::<riscv64::zkn::Aes>();
            wipes::<riscv64::zvkned::Aes>();
        }
    }

    #[test]
    fn expansion_matches_fips197_appendix_a() {
        use portable::ttable::tables::SBOX;
        let sub = |w: u32| {
            u32::from_le_bytes(w.to_le_bytes().map(|b| SBOX[b as usize]))
        };
        // FIPS 197 A.1: last round key of the AES-128 example.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
            0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let w = expand_words(&key, KeySize::Aes128, sub);
        let mut last = [0u8; 16];
        for (c, word) in last.chunks_exact_mut(4).zip(&w[40..44]) {
            c.copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(
            last,
            [
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f,
                0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6
            ]
        );
        assert_eq!(w[44..], [0; 16], "unused words stay zero");
    }

    #[test]
    fn picks_best_supported() {
        let aes = Aes::try_new(&[0; 16]).unwrap();
        let chosen = probe();
        assert_ne!(PROBED.load(Ordering::Relaxed), 0);
        assert_eq!(probe(), chosen);
        assert!(supported(chosen));
        let faster = CHOICES.iter().take_while(|&&c| c != chosen);
        assert!(faster.clone().all(|&c| !supported(c)), "{chosen:?}");
        let matches = match (&aes.0, chosen) {
            #[cfg(target_arch = "x86_64")]
            (Inner::Vaes(_), Choice::Vaes) => true,
            #[cfg(target_arch = "x86_64")]
            (Inner::AesNi(_), Choice::AesNi) => true,
            #[cfg(target_arch = "aarch64")]
            (Inner::Armv8(_), Choice::Armv8) => true,
            #[cfg(target_arch = "riscv64")]
            (Inner::Zvkned(_), Choice::Zvkned) => true,
            #[cfg(target_arch = "riscv64")]
            (Inner::Zkn(_), Choice::Zkn) => true,
            (Inner::Bitsliced(_), Choice::Bitsliced) => true,
            _ => false,
        };
        assert!(matches, "{aes:?} vs {chosen:?}");
    }

    #[test]
    fn matches_portable() {
        let key = [0x5au8; 32];
        for klen in [16, 24, 32] {
            let aes = Aes::try_new(&key[..klen]).unwrap();
            let sw = portable::Aes::try_new(&key[..klen]).unwrap();
            assert_eq!(aes.rounds(), sw.rounds());

            let mut data = [0u8; 17 * BLOCK_SIZE];
            for (i, x) in data.iter_mut().enumerate() {
                *x = i as u8;
            }
            let mut expected = data;
            sw.encrypt_blocks(&mut expected).unwrap();
            aes.encrypt_blocks(&mut data).unwrap();
            assert_eq!(data, expected);
            aes.decrypt_blocks(&mut data).unwrap();

            let mut block = [7u8; BLOCK_SIZE];
            let mut block2 = block;
            sw.encrypt_block(&mut block2);
            aes.encrypt_block(&mut block);
            assert_eq!(block, block2);
            aes.decrypt_block(&mut block);
            assert_eq!(block, [7u8; BLOCK_SIZE]);
        }
    }

    #[test]
    fn errors_pass_through() {
        assert_eq!(
            Aes::try_new(&[0; 20]).unwrap_err(),
            Error::InvalidKeyLength(20)
        );
        let aes = Aes::try_new(&[0; 16]).unwrap();
        assert_eq!(
            aes.encrypt_blocks(&mut [0; 17]).unwrap_err(),
            Error::NotBlockAligned(17)
        );
    }
}
