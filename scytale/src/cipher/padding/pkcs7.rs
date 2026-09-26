//! PKCS#7 padding (RFC 5652 section 6.3): the last block is filled
//! with `n` bytes each of value `n`, where `n` is the count added, 1
//! to the block size. A message that already fills its last block
//! gets a whole block of padding, so there is always something to
//! remove.
//!
//! [`unpad`] reads the whole last block in time that depends on the
//! block size alone; where the padding was wrong, and how wrong, is
//! not in its timing. What it reports is [`Error::InvalidPadding`],
//! whose documentation says what the caller must do about that.

use crate::Error;
use crate::codec::{eq, ge, le};

/// The length a message of `len` bytes has once padded to `block`:
/// the next multiple of `block` above `len`, always at least one
/// byte more.
pub const fn padded_len(len: usize, block: usize) -> usize {
    (len / block + 1) * block
}

/// Pads the message in `buf[..len]` in place, returning its padded
/// length, [`padded_len`] of the two. `buf` must have room for it,
/// or [`Error::OutputTooSmall`] says how much; `block` must be 1 to
/// 255, or it is [`Error::InvalidLength`].
pub fn pad(buf: &mut [u8], len: usize, block: usize) -> Result<usize, Error> {
    if !(1..=255).contains(&block) {
        return Err(Error::InvalidLength(block));
    }
    if len > buf.len() {
        return Err(Error::InvalidLength(len));
    }
    let padded = padded_len(len, block);
    let tail = buf
        .get_mut(len..padded)
        .ok_or(Error::OutputTooSmall(padded))?;
    tail.fill((padded - len) as u8);
    Ok(padded)
}

/// The length of the message inside padded `buf`, which must be a
/// whole number of blocks and at least one. `block` must be 1 to
/// 255, or it is [`Error::InvalidLength`]; anything else wrong is
/// [`Error::InvalidPadding`] and nothing more.
pub fn unpad(buf: &[u8], block: usize) -> Result<usize, Error> {
    if !(1..=255).contains(&block) {
        return Err(Error::InvalidLength(block));
    }
    if buf.is_empty() || !buf.len().is_multiple_of(block) {
        return Err(Error::InvalidPadding);
    }
    let last = &buf[buf.len() - block..];
    let n = u32::from(last[block - 1]);
    // Every byte of the block is read and compared whether or not it
    // is part of the padding; the masks decide whether the comparison
    // counts, so the block's contents never steer a branch.
    let mut valid = ge(n, 1) & le(n, block as u32);
    for (i, &byte) in last.iter().rev().enumerate() {
        let in_padding = le((i + 1) as u32, n);
        valid &= eq(u32::from(byte), n) | !in_padding;
    }
    if core::hint::black_box(valid) & 0xff == 0 {
        return Err(Error::InvalidPadding);
    }
    Ok(buf.len() - n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_5652_shape() {
        // Three bytes in a block of eight gain five bytes of 5; eight
        // bytes gain a whole block of 8.
        let mut buf = [0xaau8; 16];
        assert_eq!(pad(&mut buf, 3, 8), Ok(8));
        assert_eq!(&buf[..8], &[0xaa, 0xaa, 0xaa, 5, 5, 5, 5, 5]);
        assert_eq!(unpad(&buf[..8], 8), Ok(3));
        let mut buf = [0xaau8; 16];
        assert_eq!(pad(&mut buf, 8, 8), Ok(16));
        assert_eq!(&buf[8..], &[8; 8]);
        assert_eq!(unpad(&buf, 8), Ok(8));
        let mut buf = [0u8; 8];
        assert_eq!(pad(&mut buf, 0, 8), Ok(8));
        assert_eq!(buf, [8; 8]);
        assert_eq!(unpad(&buf, 8), Ok(0));
    }

    #[test]
    fn round_trips_every_length() {
        for block in [1usize, 8, 16, 255] {
            let mut buf = [0u8; 512];
            for len in 0..=255 {
                buf.fill(0x5a);
                let n = pad(&mut buf, len, block).unwrap();
                assert_eq!(n, padded_len(len, block), "{block} {len}");
                assert_eq!(n % block, 0);
                assert!(n > len && n - len <= block);
                assert_eq!(unpad(&buf[..n], block), Ok(len), "{block} {len}");
                assert!(buf[..len].iter().all(|&b| b == 0x5a));
            }
        }
    }

    #[test]
    fn every_bad_last_block() {
        // A count of zero, a count over the block, a count that the
        // bytes before do not match, one byte short of the count.
        let block = 8;
        let mut buf = [0u8; 8];
        assert_eq!(unpad(&buf, block), Err(Error::InvalidPadding));
        buf[7] = 9;
        assert_eq!(unpad(&buf, block), Err(Error::InvalidPadding));
        buf = [3, 3, 3, 3, 3, 3, 2, 3];
        assert_eq!(unpad(&buf, block), Err(Error::InvalidPadding));
        buf = [0, 0, 0, 0, 0, 3, 3, 3];
        assert_eq!(unpad(&buf, block), Ok(5));
        buf = [0, 0, 0, 0, 3, 0, 3, 3];
        assert_eq!(unpad(&buf, block), Err(Error::InvalidPadding));
        // The bytes before the padding do not matter.
        buf = [7, 7, 7, 7, 7, 7, 7, 1];
        assert_eq!(unpad(&buf, block), Ok(7));
        // Exhaustively for a two-byte block: only [x, 1] and [2, 2]
        // are valid.
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let expected = match (a, b) {
                    (_, 1) => Ok(1),
                    (2, 2) => Ok(0),
                    _ => Err(Error::InvalidPadding),
                };
                assert_eq!(unpad(&[a, b], 2), expected, "{a} {b}");
            }
        }
    }

    #[test]
    fn checks_the_shape() {
        let mut buf = [0u8; 16];
        assert_eq!(pad(&mut buf, 0, 0), Err(Error::InvalidLength(0)));
        assert_eq!(pad(&mut buf, 0, 256), Err(Error::InvalidLength(256)));
        assert_eq!(pad(&mut buf, 17, 8), Err(Error::InvalidLength(17)));
        assert_eq!(pad(&mut buf, 16, 8), Err(Error::OutputTooSmall(24)));
        assert_eq!(pad(&mut buf, 9, 8), Ok(16));
        assert_eq!(unpad(&buf, 0), Err(Error::InvalidLength(0)));
        assert_eq!(unpad(&buf, 256), Err(Error::InvalidLength(256)));
        assert_eq!(unpad(&[], 8), Err(Error::InvalidPadding));
        assert_eq!(unpad(&buf[..12], 8), Err(Error::InvalidPadding));
    }
}
