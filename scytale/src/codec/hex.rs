//! Hexadecimal: two digits per byte, most significant first.
//!
//! [`encode`] writes lower case. [`decode`] takes either case, and
//! nothing else: no `0x`, no whitespace or separators, and an even
//! number of digits, since an odd one leaves a nibble that could be
//! read at either end. Both run in time that depends only on the
//! length; which digits they were is never a lookup.

use crate::Error;

use super::{gt, lt};

/// The length [`encode`] writes for `bytes` bytes.
pub const fn encoded_len(bytes: usize) -> usize {
    bytes * 2
}

/// Writes `bytes` as lower-case hex into the front of `out`,
/// returning the length, [`encoded_len`] of the input.
pub fn encode(bytes: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let needed = encoded_len(bytes.len());
    let out = out.get_mut(..needed).ok_or(Error::OutputTooSmall(needed))?;
    for (byte, pair) in bytes.iter().zip(out.chunks_exact_mut(2)) {
        pair[0] = digit(u32::from(byte >> 4));
        pair[1] = digit(u32::from(byte & 0x0f));
    }
    Ok(needed)
}

/// Decodes `text` into the front of `out`, returning the length,
/// half that of the input. Anything that is not an even run of hex
/// digits is [`Error::InvalidEncoding`].
pub fn decode(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::InvalidEncoding);
    }
    let needed = text.len() / 2;
    let out = out.get_mut(..needed).ok_or(Error::OutputTooSmall(needed))?;
    // Every digit is read whether or not an earlier one was bad, so
    // the time says nothing about where a fault was, and the byte is
    // built from masked values rather than a table.
    let mut valid = 0xff;
    for (pair, byte) in text.chunks_exact(2).zip(out.iter_mut()) {
        let (hi, hi_ok) = value(u32::from(pair[0]));
        let (lo, lo_ok) = value(u32::from(pair[1]));
        valid &= hi_ok & lo_ok;
        *byte = ((hi << 4) | lo) as u8;
    }
    if core::hint::black_box(valid) == 0 {
        // The bytes written so far are from a string that was not
        // hex, and are not returned.
        out.fill(0);
        return Err(Error::InvalidEncoding);
    }
    Ok(needed)
}

/// The lower-case digit for a nibble, computed rather than looked
/// up: `0`..`9` are 48 up, `a`..`f` a further 39 along.
#[inline]
fn digit(nibble: u32) -> u8 {
    (nibble + u32::from(b'0') + (gt(nibble, 9) & 39)) as u8
}

/// The value of a digit in either case, and `0xff` when it is one
/// or `0` when it is not, both without branching on the character.
#[inline]
fn value(c: u32) -> (u32, u32) {
    // `0`..`9` are 48..57; XOR with 48 maps them to 0..9 and every
    // other character to 10 or more.
    let num = c ^ 0x30;
    let is_num = lt(num, 10);
    // `A`..`F` are 65..70 and `a`..`f` 97..102; clearing bit 5 folds
    // the cases together, and 55 below `A` is 10. The masks want a
    // value below 256, which the wrap of a small character breaks.
    let alpha = (c & !0x20).wrapping_sub(55) & 0xff;
    let is_alpha = lt(alpha, 16) & gt(alpha, 9);
    ((is_num & num) | (is_alpha & alpha), is_num | is_alpha)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_byte() {
        let bytes: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut text = [0u8; 512];
        let n = encode(&bytes, &mut text).unwrap();
        assert_eq!(n, 512);
        let mut back = [0u8; 256];
        assert_eq!(decode(&text, &mut back), Ok(256));
        assert_eq!(back, bytes);
    }

    #[test]
    fn rfc_4648_vectors() {
        let cases: [(&[u8], &[u8]); 3] = [
            (b"", b""),
            (b"foobar", b"666F6F626172"),
            (b"\x00\xff\x7f", b"00FF7F"),
        ];
        let mut text = [0u8; 16];
        let mut bytes = [0u8; 8];
        for (raw, upper) in cases {
            let n = encode(raw, &mut text).unwrap();
            assert_eq!(text[..n], upper.to_ascii_lowercase()[..]);
            let n = decode(upper, &mut bytes).unwrap();
            assert_eq!(&bytes[..n], raw);
            let n = decode(&text[..2 * raw.len()], &mut bytes).unwrap();
            assert_eq!(&bytes[..n], raw);
        }
    }

    #[test]
    fn accepts_only_hex_digits() {
        let mut out = [0u8; 4];
        for c in 0..=255u8 {
            let text = [b'0', c];
            let is_digit = c.is_ascii_hexdigit();
            assert_eq!(decode(&text, &mut out).is_ok(), is_digit, "{c:#04x}");
        }
        for bad in [&b"0"[..], b"abc", b"0x00", b"00 00", b"00\n", b" 00"] {
            assert_eq!(decode(bad, &mut out), Err(Error::InvalidEncoding));
        }
        assert_eq!(decode(b"", &mut out), Ok(0));
    }

    #[test]
    fn wipes_output_on_failure() {
        let mut out = [0u8; 2];
        assert_eq!(decode(b"ffzz", &mut out), Err(Error::InvalidEncoding));
        assert_eq!(out, [0, 0]);
    }

    #[test]
    fn sizes_the_output() {
        let mut out = [0u8; 3];
        assert_eq!(encode(&[0; 2], &mut out), Err(Error::OutputTooSmall(4)));
        let short = decode(b"00112233", &mut out);
        assert_eq!(short, Err(Error::OutputTooSmall(4)));
        assert_eq!(encoded_len(5), 10);
    }
}
