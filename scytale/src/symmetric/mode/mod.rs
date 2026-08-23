//! Modes of operation, generic over any [`BlockCipher`].
//!
//! A block cipher on its own only transforms one block. A mode says
//! how to carry that over a message: how blocks chain, how a nonce
//! enters, and, for the authenticated modes, how a tag is computed.
//!
//! [`BlockCipher`]: crate::symmetric::BlockCipher

pub mod cbc;

pub use cbc::Cbc;

/// Largest block size the modes support.
///
/// A mode keeps a chaining block or counter on the stack, which needs
/// a fixed upper bound. Sixteen bytes covers AES and every other
/// block cipher in current use.
pub(crate) const MAX_BLOCK_SIZE: usize = 16;

/// Blocks handed to the cipher in one bulk call, where a mode can use
/// the bulk path. Matches the interleave the implementations use.
pub(crate) const LANES: usize = 8;

/// XORs `src` into `dst`, over as many bytes as both have.
#[inline]
pub(crate) fn xor(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}
