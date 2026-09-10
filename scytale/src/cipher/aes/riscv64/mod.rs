//! AES implementations for RISC-V (RV64).
//!
//! [`zkn`] uses the scalar cryptography extension (Zkne/Zknd) and
//! [`zvkned`] the vector cryptography extension (Zvkned). Both probe
//! for their instructions at run time.

// The implementations below need unsafe; they inherit this.
#![allow(unsafe_code)]

pub mod zkn;
pub mod zvkned;

use core::any::Any;

use super::{Aes, Aes128, Aes192, Aes256, MAX_WORDS};
use crate::arch::riscv64::{
    EXT_ZKND, EXT_ZKNE, EXT_ZVBB, EXT_ZVKB, EXT_ZVKNED, IMA_V, extensions,
    vector_bytes,
};
use crate::cipher::{BlockCipher, is};

/// A cipher whose expanded key the vector AES instructions can read.
///
/// Implemented by [`zvkned`], whose key schedule is the standard one a
/// vector round can load, and by the dispatching types over it, which
/// answer `None` when the processor sent them somewhere else. A mode
/// with a loop of its own over the cipher and something more asks this
/// when it is built.
///
/// [`zkn`] does not implement it: it keeps its round keys as 64-bit
/// halves for the scalar instructions, which is not a layout a vector
/// load can take, so a mode over that cipher uses the portable
/// construction instead.
///
/// There is no backwards form yet. Every mode with assembly here --
/// counter mode, GCM, GCM-SIV -- runs the cipher forwards only; a
/// `decryption` will join this when the first one that needs it does.
pub(crate) trait Keyed {
    /// The keys the rounds run forwards under.
    fn schedule(&self) -> Option<Schedule<'_>>;
}

/// A borrowed view of an expanded key.
///
/// What a loop written straight against the vector AES instructions
/// needs, and nothing else: where the round keys are and how many
/// rounds there are. The lifetime is the cipher's, so such a loop
/// cannot outlive the key it runs under, and the key itself never
/// leaves the crate.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Schedule<'a> {
    keys: &'a [u32; MAX_WORDS],
    rounds: usize,
}

impl<'a> Schedule<'a> {
    pub(super) fn new(keys: &'a [u32; MAX_WORDS], rounds: usize) -> Self {
        Schedule { keys, rounds }
    }

    /// The first round key; the rest follow it, sixteen bytes apart.
    ///
    /// The loops load fifteen of them whatever the key size, because
    /// the register numbers cannot be chosen at run time, so this
    /// points at the whole array rather than at the valid part of it.
    pub(crate) fn keys(&self) -> *const u32 {
        self.keys.as_ptr()
    }

    /// Rounds, so `rounds + 1` round keys are the live ones.
    pub(crate) fn rounds(&self) -> usize {
        self.rounds
    }
}

/// Whether the scalar AES instructions (Zkne and Zknd) are available.
pub(crate) fn has_zkn() -> bool {
    zkn_present(extensions())
}

/// Whether `ext` reports the scalar AES instructions.
fn zkn_present(ext: u64) -> bool {
    let want = EXT_ZKNE | EXT_ZKND;
    ext & want == want
}

/// Whether the vector AES instructions are available: the vector
/// extension, Zvkned, and registers of at least 128 bits, which the
/// 128-bit element groups need.
pub(crate) fn has_zvkned() -> bool {
    let ext = extensions();
    zvkned_present(ext, vector_bytes(ext))
}

/// Whether `ext` reports the vector AES instructions, on a processor
/// whose vector registers are `bytes` wide.
fn zvkned_present(ext: u64, bytes: usize) -> bool {
    let want = IMA_V | EXT_ZVKNED;
    ext & want == want && bytes >= 16
}

/// Whether the vector byte reverse `vrev8.v` is here. It belongs to
/// Zvbb, and also to Zvkb, the subset of Zvbb that the vector
/// cryptography sets pull in: a processor with Zvkn has Zvkb and need
/// not have the whole of Zvbb, so either answer will do.
///
/// The counter loop uses it and the cipher does not, so it is asked
/// for separately. RVA23 requires Zvbb, so a machine that conforms to
/// the profile has it; one that does not takes the shared loop.
pub(crate) fn has_vrev8() -> bool {
    vrev8_present(extensions())
}

/// Whether `ext` reports the vector byte reverse.
fn vrev8_present(ext: u64) -> bool {
    ext & IMA_V != 0 && ext & (EXT_ZVBB | EXT_ZVKB) != 0
}

/// How to reach the round keys of the cipher a mode was built over.
pub(crate) type Keys<C> = for<'a> fn(&'a C) -> Option<Schedule<'a>>;

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
            zvkned::Aes<16>,
            zvkned::Aes<24>,
            zvkned::Aes<32>,
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

/// How to reach `C`'s round keys, or `None` if `C` is not a cipher
/// whose keys these instructions could read.
///
/// Asked once, when a mode is built. `C` is a type parameter, so every
/// comparison is a constant and all but one folds away.
pub(crate) fn keys<C: BlockCipher>() -> Option<Keys<C>> {
    keyed!(forwards);
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::riscv64::profile;

    #[test]
    fn probes_agree_with_constructors() {
        assert_eq!(zkn::Aes::<16>::supported(), has_zkn());
        assert_eq!(zvkned::Aes::<16>::supported(), has_zvkned());
    }

    /// What each kind of real processor is offered. A bit set is all
    /// the probes look at, so these are the answers themselves rather
    /// than a sample of them.
    #[test]
    fn the_scalar_cipher_needs_both_halves_of_zkn() {
        assert!(zkn_present(profile::ZKN));
        // A profile with the vector set and no scalar one, which is
        // every vector profile: Zvkn does not imply Zkn.
        assert!(!zkn_present(profile::ZVKNG));
        // Encryption without decryption is not enough, and the crate
        // uses the pair for one cipher object.
        assert!(!zkn_present(EXT_ZKNE));
        assert!(!zkn_present(EXT_ZKND));
    }

    #[test]
    fn the_vector_cipher_needs_registers_wide_enough() {
        assert!(zvkned_present(profile::ZVKN, 16));
        assert!(zvkned_present(profile::ZVKN, 64));
        // A 64-bit vector register cannot hold a block.
        assert!(!zvkned_present(profile::ZVKN, 8));
        // Zkn's vector unit is not a vector AES.
        assert!(!zvkned_present(profile::RVA23, 16));
        assert!(!zvkned_present(profile::ZKN, 0));
    }

    /// The counter loop's byte reverse is in Zvbb and in Zvkb, and a
    /// processor with the vector cryptography set has the second
    /// without necessarily having the first.
    #[test]
    fn the_byte_reverse_comes_from_either_extension() {
        assert!(vrev8_present(profile::ZVKN));
        assert!(vrev8_present(profile::RVA23));
        assert!(vrev8_present(IMA_V | EXT_ZVBB));
        assert!(vrev8_present(IMA_V | EXT_ZVKB));
        // Neither half on its own.
        assert!(!vrev8_present(IMA_V));
        assert!(!vrev8_present(EXT_ZVKB));
    }
}
