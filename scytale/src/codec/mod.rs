//! How bytes are written as text.
//!
//! Keys, tags, signatures and ciphertexts leave a program as text
//! more often than not: [`hex`] on a command line or in a test
//! vector, [`base64`] in a protocol field, and [`pem`], which is
//! base64 between two lines that say what it is, in a key file. The
//! key types read and write PEM themselves; this module is for the
//! caller who has the text and does not yet know what it holds, or
//! who has bytes of their own to carry.
//!
//! Every encoder and decoder here runs in time that depends on the
//! length of its input and on nothing else, since a key passes
//! through them. A lookup table indexed by a secret byte would put
//! that byte in the cache's timing, so there are none; each
//! character is computed from its value with arithmetic and masks.
//!
//! Every decoder is strict. A string that decodes two ways is two
//! strings, and a decoder that accepts either lets a second party
//! disagree about what was said, so hex takes both cases but no
//! prefix, no separators and no odd digit, and base64 takes only the
//! canonical form of RFC 4648. PEM alone is lenient, about whitespace
//! and nothing else, because RFC 7468 asks for that and a file
//! copied through a terminal needs it.
//!
//! ```
//! use scytale::codec::{base64, hex};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut text = [0u8; 8];
//! let n = hex::encode(&[0xde, 0xad, 0xbe, 0xef], &mut text)?;
//! assert_eq!(&text[..n], b"deadbeef");
//!
//! let mut bytes = [0u8; 4];
//! let n = hex::decode(b"DEADbeef", &mut bytes)?;
//! assert_eq!(&bytes[..n], &[0xde, 0xad, 0xbe, 0xef]);
//!
//! let n = base64::encode(&bytes, &mut text)?;
//! assert_eq!(&text[..n], b"3q2+7w==");
//! # Ok(())
//! # }
//! ```
//!
//! Each function writes into the front of a buffer the caller
//! supplies and returns the length written, or
//! [`Error::OutputTooSmall`](crate::Error::OutputTooSmall) with the
//! length it needs; `encoded_len` in each says that length ahead of
//! time. A malformed string is
//! [`Error::InvalidEncoding`](crate::Error::InvalidEncoding), which
//! says nothing about where the fault was.

pub mod base64;
pub mod hex;
pub mod pem;

/// `0xff` when `x == y`, `0` otherwise, for `x` and `y` below 256.
#[inline]
pub(crate) const fn eq(x: u32, y: u32) -> u32 {
    ((x ^ y).wrapping_sub(1) >> 8) & 0xff
}

/// `0xff` when `x > y`, `0` otherwise, for `x` and `y` below 256.
#[inline]
pub(crate) const fn gt(x: u32, y: u32) -> u32 {
    (y.wrapping_sub(x) >> 8) & 0xff
}

/// `0xff` when `x >= y`, `0` otherwise, for `x` and `y` below 256.
#[inline]
pub(crate) const fn ge(x: u32, y: u32) -> u32 {
    gt(x, y.wrapping_sub(1))
}

/// `0xff` when `x < y`, `0` otherwise, for `x` and `y` below 256.
#[inline]
pub(crate) const fn lt(x: u32, y: u32) -> u32 {
    gt(y, x)
}

/// `0xff` when `x <= y`, `0` otherwise, for `x` and `y` below 256.
#[inline]
pub(crate) const fn le(x: u32, y: u32) -> u32 {
    ge(y, x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_agree_with_the_operators() {
        for x in 0..256u32 {
            for y in 0..256u32 {
                assert_eq!(eq(x, y) == 0xff, x == y, "{x} {y}");
                assert_eq!(gt(x, y) == 0xff, x > y, "{x} {y}");
                assert_eq!(ge(x, y) == 0xff, x >= y, "{x} {y}");
                assert_eq!(lt(x, y) == 0xff, x < y, "{x} {y}");
                assert_eq!(le(x, y) == 0xff, x <= y, "{x} {y}");
            }
        }
    }
}
