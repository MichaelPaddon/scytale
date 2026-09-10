//! AES implementations for aarch64.
//!
//! [`armv8`] uses the ARMv8 cryptography extension.

pub mod armv8;

use core::any::Any;

use super::{Aes, Aes128, Aes192, Aes256, MAX_WORDS};
use crate::cipher::{BlockCipher, is};

/// A cipher whose expanded key the AES instructions can read.
///
/// Implemented by the implementation that runs on them and by the
/// dispatching types over it, which answer `None` when the processor
/// sent them to portable code instead. A mode with a loop of its own
/// over the cipher and something else asks this when it is built.
pub(crate) trait Keyed {
    /// The keys the rounds run forwards under.
    fn schedule(&self) -> Option<Schedule<'_>>;

    /// The keys the rounds run backwards under, for a mode with a
    /// loop of its own over decryption.
    fn decryption(&self) -> Option<Schedule<'_>>;
}

/// A borrowed view of an expanded key.
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
    pub(super) fn new(keys: &'a [u32; MAX_WORDS], rounds: usize) -> Self {
        Schedule { keys, rounds }
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
            armv8::Aes<16>,
            armv8::Aes<24>,
            armv8::Aes<32>,
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
