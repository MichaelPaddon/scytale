//! AES (FIPS 197) block cipher.
//!
//! The key width is the type: [`Aes128`], [`Aes192`] and [`Aes256`]
//! are [`Aes<16>`](Aes), `Aes<24>` and `Aes<32>`, and each takes a key
//! of exactly its width. [`Aes`] runs the best implementation the
//! processor supports: hardware instructions where present, otherwise
//! the constant-time portable code. To use a particular one, name it:
//! [`portable::bitsliced::Aes`], [`portable::ttable::Aes`],
//! `x86_64::aesni::Aes`, `x86_64::vaes::Aes`, `aarch64::armv8::Aes`,
//! `riscv64::zkn::Aes` or `riscv64::zvkned::Aes` (the hardware ones
//! exist only on their architecture), with the same width parameter.
//!
//! Every implementation wipes its expanded key when dropped.
//!
//! ```
//! use scytale::cipher::aes::{portable, Aes128};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let fastest = Aes128::try_new(&[0u8; 16])?;
//! let bitsliced = portable::bitsliced::Aes::<16>::try_new(&[0u8; 16])?;
//!
//! let mut a = [0u8; 16];
//! let mut b = a;
//! fastest.encrypt_block(&mut a);
//! bitsliced.encrypt_block(&mut b);
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

use crate::cipher::BlockCipher;
use crate::{BlockType, Error, KeyType};

/// AES block size in bytes.
pub const BLOCK_SIZE: usize = 16;

/// AES with a 128-bit key.
pub type Aes128 = Aes<16>;
/// AES with a 192-bit key.
pub type Aes192 = Aes<24>;
/// AES with a 256-bit key.
pub type Aes256 = Aes<32>;

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
    /// The size of a `key`. A width the type system already fixed
    /// to 16, 24 or 32 never reaches the error.
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
/// faster [`portable::ttable::Aes`] is never chosen here; name it
/// yourself if its trade-off suits you.
///
/// The processor is probed once, the first time a key is expanded;
/// every later [`Aes::try_new`] reads the cached answer, and each
/// call then dispatches with a single predictable branch.
///
/// `K` is the key width in bytes: 16, 24 or 32, and nothing else
/// compiles. [`Aes128`], [`Aes192`] and [`Aes256`] name the three.
#[derive(Clone)]
pub struct Aes<const K: usize>(Inner<K>);

// Each variant is that implementation's key schedule; the bitsliced
// one is twice the size of the others and there is no heap to box it.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum Inner<const K: usize> {
    #[cfg(target_arch = "x86_64")]
    Vaes(x86_64::vaes::Aes<K>),
    #[cfg(target_arch = "x86_64")]
    AesNi(x86_64::aesni::Aes<K>),
    #[cfg(target_arch = "aarch64")]
    Armv8(aarch64::armv8::Aes<K>),
    #[cfg(target_arch = "riscv64")]
    Zvkned(riscv64::zvkned::Aes<K>),
    #[cfg(target_arch = "riscv64")]
    Zkn(riscv64::zkn::Aes<K>),
    Bitsliced(portable::bitsliced::Aes<K>),
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

impl<const K: usize> fmt::Debug for Aes<K> {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes")
            .field("rounds", &self.rounds())
            .finish()
    }
}

impl<const K: usize> Aes<K> {
    /// Expands `key` with the best implementation the processor
    /// supports.
    ///
    /// A width other than 16, 24 or 32 is refused when the type is
    /// instantiated, at compile time.
    // The hardware constructors skip their own processor check because
    // the probe has already made it.
    #[allow(unsafe_code)]
    pub fn try_new(key: &[u8; K]) -> Result<Self, Error> {
        const {
            assert!(
                K == 16 || K == 24 || K == 32,
                "AES keys are 16, 24 or 32 bytes"
            )
        };
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

    /// Encrypts every block in place, independently (ECB).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        dispatch!(self, aes => aes.encrypt_blocks(blocks))
    }

    /// Decrypts every block in place, independently (ECB).
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        dispatch!(self, aes => aes.decrypt_blocks(blocks))
    }
}

impl<const K: usize> BlockType for Aes<K> {
    type Block = [u8; BLOCK_SIZE];

    fn zero_block() -> Self::Block {
        [0; BLOCK_SIZE]
    }
}

impl<const K: usize> KeyType for Aes<K> {
    type Key = [u8; K];

    fn zero_key() -> Self::Key {
        [0; K]
    }
}

impl<const K: usize> BlockCipher for Aes<K> {
    fn try_new(key: &Self::Key) -> Result<Self, Error> {
        Aes::try_new(key)
    }

    fn encrypt_block(&self, block: &mut Self::Block) {
        Aes::encrypt_block(self, block)
    }

    fn decrypt_block(&self, block: &mut Self::Block) {
        Aes::decrypt_block(self, block)
    }

    fn encrypt_blocks(&self, blocks: &mut [Self::Block]) {
        Aes::encrypt_blocks(self, blocks)
    }

    fn decrypt_blocks(&self, blocks: &mut [Self::Block]) {
        Aes::decrypt_blocks(self, blocks)
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
        wipes::<portable::ttable::Aes<16>>();
        wipes::<portable::bitsliced::Aes<16>>();
        #[cfg(target_arch = "x86_64")]
        {
            wipes::<x86_64::aesni::Aes<16>>();
            wipes::<x86_64::vaes::Aes<16>>();
        }
        #[cfg(target_arch = "aarch64")]
        wipes::<aarch64::armv8::Aes<16>>();
        #[cfg(target_arch = "riscv64")]
        {
            wipes::<riscv64::zkn::Aes<16>>();
            wipes::<riscv64::zvkned::Aes<16>>();
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
    fn matches_ttable() {
        matches_ttable_for::<16>();
        matches_ttable_for::<24>();
        matches_ttable_for::<32>();
    }

    fn matches_ttable_for<const K: usize>() {
        let key = [0x5au8; K];
        {
            let aes = Aes::try_new(&key).unwrap();
            let sw = portable::ttable::Aes::try_new(&key).unwrap();
            assert_eq!(aes.rounds(), sw.rounds());

            let mut data = [[0u8; BLOCK_SIZE]; 17];
            for (i, x) in data.as_flattened_mut().iter_mut().enumerate() {
                *x = i as u8;
            }
            let mut expected = data;
            sw.encrypt_blocks(&mut expected);
            aes.encrypt_blocks(&mut data);
            assert_eq!(data, expected);
            aes.decrypt_blocks(&mut data);

            let mut block = [7u8; BLOCK_SIZE];
            let mut block2 = block;
            sw.encrypt_block(&mut block2);
            aes.encrypt_block(&mut block);
            assert_eq!(block, block2);
            aes.decrypt_block(&mut block);
            assert_eq!(block, [7u8; BLOCK_SIZE]);
        }
    }
}
