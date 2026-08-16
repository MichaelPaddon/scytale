//! The block cipher interface.
//!
//! Encryption and decryption are separate traits because they need separate
//! key schedules. A caller that only ever encrypts, which is every counter
//! based mode, should not pay to derive a decryption schedule it never uses.

use core::fmt;

/// A key was rejected because its length is not one the cipher accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidKeyLength {
    /// The length that was supplied, in bytes.
    pub got: usize,
}

impl fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key length: {} bytes", self.got)
    }
}

impl core::error::Error for InvalidKeyLength {}

/// Something that can be keyed from a byte string of run-time length.
///
/// Key lengths are not always fixed: Blowfish accepts anything from 32 to
/// 448 bits, so the interface cannot assume a compile-time size. Ciphers
/// with a single fixed key size also offer an inherent `new` taking a
/// fixed-size array, where a wrong length is a compile error instead.
pub trait KeyInit: Sized {
    /// Key the cipher, failing if it does not accept this key length.
    fn try_new(key: &[u8]) -> Result<Self, InvalidKeyLength>;
}

/// A block cipher's encryption direction.
///
/// The bulk call is the primitive. Handing over a large buffer is what lets
/// a pipelined or vectorized implementation keep several blocks in flight;
/// feeding one block at a time leaves most of that hardware idle.
pub trait BlockEncrypt {
    /// The block length in bytes.
    const BLOCK_SIZE: usize;

    /// How many blocks this implementation keeps in flight at once.
    ///
    /// Modes use this to size the buffers they hand over. A scalar
    /// implementation reports 1; an AES-NI one reports 8.
    const PARALLEL_BLOCKS: usize;

    /// Encrypt whole blocks in place, returning how many bytes were consumed.
    ///
    /// The count is always a multiple of [`Self::BLOCK_SIZE`]. Any trailing
    /// partial block is left untouched, so a caller streaming arbitrary
    /// chunks can carry the remainder into the next call.
    fn encrypt(&self, data: &mut [u8]) -> usize;
}

/// A block cipher's decryption direction.
pub trait BlockDecrypt {
    /// The block length in bytes.
    const BLOCK_SIZE: usize;

    /// How many blocks this implementation keeps in flight at once.
    const PARALLEL_BLOCKS: usize;

    /// Decrypt whole blocks in place, returning how many bytes were consumed.
    ///
    /// Behaves like [`BlockEncrypt::encrypt`] in every other respect.
    fn decrypt(&self, data: &mut [u8]) -> usize;
}
