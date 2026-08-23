//! Modes of operation, generic over any [`BlockCipher`].
//!
//! A block cipher on its own only transforms one block. A mode says
//! how to carry that over a message: how blocks chain, how a nonce
//! enters, and, for the authenticated modes, how a tag is computed.
//!
//! [`BlockCipher`]: crate::symmetric::BlockCipher

use crate::symmetric::Error;

pub mod cbc;
pub mod cfb1;
pub mod cfb128;
pub mod cfb8;
pub mod ofb;

pub use cbc::Cbc;
pub use cfb1::Cfb1;
pub use cfb128::Cfb128;
pub use cfb8::Cfb8;
pub use ofb::Ofb;

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

/// Shifts `register` left by one byte, bringing `byte` in at the end.
///
/// This is the feedback step of CFB8: the segment just produced joins
/// the register and the oldest byte falls off.
#[inline]
pub(crate) fn shift_in_byte(register: &mut [u8], byte: u8) {
    let last = register.len() - 1;
    register.copy_within(1.., 0);
    register[last] = byte;
}

/// Shifts `register` left by one bit, bringing `bit` in at the end.
///
/// The feedback step of CFB1. Bits are numbered from the most
/// significant end, as the standard does, so the register shifts
/// towards its most significant bit.
#[inline]
pub(crate) fn shift_in_bit(register: &mut [u8], bit: u8) {
    let mut carry = bit & 1;
    for byte in register.iter_mut().rev() {
        let next = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
}

/// Reads bit `i` of `data`, counting from the most significant bit of
/// the first byte, as the standard numbers them.
#[inline]
pub(crate) fn bit(data: &[u8], i: usize) -> u8 {
    (data[i / 8] >> (7 - i % 8)) & 1
}

/// Writes bit `i` of `data`; see [`bit`].
#[inline]
pub(crate) fn set_bit(data: &mut [u8], i: usize, value: u8) {
    let mask = 1 << (7 - i % 8);
    if value & 1 == 1 {
        data[i / 8] |= mask;
    } else {
        data[i / 8] &= !mask;
    }
}

/// Copies `iv` into a fixed-size register, checking its length.
pub(crate) fn register_from(
    iv: &[u8],
    size: usize,
) -> Result<[u8; MAX_BLOCK_SIZE], Error> {
    if iv.len() != size {
        return Err(Error::InvalidNonceLength(iv.len()));
    }
    let mut register = [0u8; MAX_BLOCK_SIZE];
    register[..size].copy_from_slice(iv);
    Ok(register)
}
