//! Modes of operation, generic over any [`BlockCipher`].
//!
//! A block cipher on its own only transforms one block. A mode says
//! how to carry that over a message: how blocks chain, how a nonce
//! enters, and, for the authenticated modes, how a tag is computed.
//!
//! [`BlockCipher`]: crate::symmetric::BlockCipher

pub mod cbc;
pub mod cfb1;
pub mod cfb128;
pub mod cfb8;
pub mod ctr;
pub mod ff1;
pub mod ff3_1;
pub mod gcm;
pub mod gcm_siv;
pub(crate) mod ghash;
pub mod kw;
pub mod kwp;
pub mod nonce;
pub mod ofb;
pub(crate) mod polyval;
pub mod xpn;
pub mod xts;

pub use cbc::Cbc;
pub use cfb1::Cfb1;
pub use cfb128::Cfb128;
pub use cfb8::Cfb8;
pub use ctr::Ctr;
pub use ff1::Ff1;
pub use ff3_1::Ff3_1;
pub use gcm::Gcm;
pub use gcm_siv::GcmSiv;
pub use kw::Kw;
pub use kwp::Kwp;
pub use nonce::Nonces;
pub use ofb::Ofb;
pub use xpn::Xpn;
pub use xts::Xts;

/// Blocks handed to the cipher in one bulk call.
///
/// The implementations interleave eight blocks, so anything from
/// eight up keeps them busy; the gain from a larger group is in
/// calling into the assembly less often. Measured on this machine,
/// going from eight to sixteen was worth about a sixth of counter
/// mode's throughput and a fifth of cipher block chaining's
/// decryption, and going further gained little more. Each block of
/// group costs a block of stack in the modes that keep a scratch
/// buffer.
pub(crate) const LANES: usize = 16;

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
