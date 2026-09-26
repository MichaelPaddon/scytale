//! Base64 (RFC 4648 section 4): the standard alphabet, `+` and `/`,
//! padded with `=` to a multiple of four characters.
//!
//! [`decode`] takes the canonical form and nothing else: padding
//! present and no more than two characters of it, the bits beyond
//! the last byte zero, no line breaks or other whitespace. Each of
//! those is a way for two strings to mean the same bytes, which is a
//! way for two parties to disagree about what was signed. The
//! reading inside a PEM file skips whitespace, because RFC 7468 says
//! to, and is the one place that does.
//!
//! Both directions run in time that depends only on the length. The
//! alphabet is never indexed by a value; each character is computed
//! from its sextet with masks, and each sextet from its character.

use crate::Error;

use super::{eq, ge, le, lt};

/// The length [`encode`] writes for `bytes` bytes: four characters
/// for every three bytes, the last group padded.
pub const fn encoded_len(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

/// Writes `bytes` as base64 into the front of `out`, returning the
/// length, [`encoded_len`] of the input.
pub fn encode(bytes: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let needed = encoded_len(bytes.len());
    let out = out.get_mut(..needed).ok_or(Error::OutputTooSmall(needed))?;
    for (group, text) in bytes.chunks(3).zip(out.chunks_exact_mut(4)) {
        let mut quantum = [0u8; 3];
        quantum[..group.len()].copy_from_slice(group);
        let bits = u32::from_be_bytes([0, quantum[0], quantum[1], quantum[2]]);
        // A group short of three bytes still fills one more character
        // than it has bytes; the rest are padding.
        for (i, c) in text.iter_mut().enumerate() {
            *c = if i <= group.len() {
                character((bits >> (18 - 6 * i)) & 0x3f)
            } else {
                b'='
            };
        }
    }
    Ok(needed)
}

/// Decodes canonical base64 into the front of `out`, returning the
/// length. Anything that is not exactly the encoding of some bytes,
/// whitespace included, is [`Error::InvalidEncoding`].
pub fn decode(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    decode_with(text, out, false)
}

/// [`decode`] that skips space, tab, carriage return and line feed
/// wherever they fall, for PEM.
pub(crate) fn decode_lenient(
    text: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    decode_with(text, out, true)
}

fn decode_with(
    text: &[u8],
    out: &mut [u8],
    skip_space: bool,
) -> Result<usize, Error> {
    let needed = decoded_len(text, skip_space)?;
    let out = out.get_mut(..needed).ok_or(Error::OutputTooSmall(needed))?;
    // The structure -- where padding falls, where the string ends --
    // is read with ordinary branches, since a string's shape is not a
    // secret. The characters themselves go through masks, and one
    // that is not in the alphabet is remembered rather than acted on,
    // so the time says nothing about which it was.
    let mut n = 0;
    let mut quantum = [0u32; 4];
    let mut have = 0;
    let mut pad = 0;
    let mut done = false;
    let mut valid = 0xff;
    for &c in text {
        if skip_space && is_space(c) {
            continue;
        }
        if done {
            return Err(Error::InvalidEncoding);
        }
        if c == b'=' {
            // Padding fills out the final quantum, which must already
            // hold at least two characters.
            if have < 2 {
                return Err(Error::InvalidEncoding);
            }
            pad += 1;
        } else {
            if pad > 0 {
                return Err(Error::InvalidEncoding);
            }
            let (v, ok) = sextet(u32::from(c));
            valid &= ok;
            quantum[have] = v;
        }
        have += 1;
        if have < 4 {
            continue;
        }
        let bytes = [
            (quantum[0] << 2 | quantum[1] >> 4) as u8,
            (quantum[1] << 4 | quantum[2] >> 2) as u8,
            (quantum[2] << 6 | quantum[3]) as u8,
        ];
        let take = 3 - pad;
        // The bits beyond the last byte must be zero, or two
        // different strings decode to the same bytes.
        let unused = match pad {
            0 => 0,
            1 => quantum[2] & 0x03,
            _ => quantum[1] & 0x0f,
        };
        if unused != 0 {
            return Err(Error::InvalidEncoding);
        }
        out[n..n + take].copy_from_slice(&bytes[..take]);
        n += take;
        done = pad > 0;
        have = 0;
        quantum = [0; 4];
    }
    if have != 0 || core::hint::black_box(valid) == 0 {
        out.fill(0);
        return Err(Error::InvalidEncoding);
    }
    debug_assert_eq!(n, needed);
    Ok(n)
}

/// The bytes `text` decodes to if it is well formed: three for every
/// four characters, less one for each padding character. A count
/// that is not a multiple of four, or a character outside the
/// alphabet, is refused here, so that a string that is not base64
/// at all is never reported as merely too long; where the padding
/// falls is checked when the string is decoded.
fn decoded_len(text: &[u8], skip_space: bool) -> Result<usize, Error> {
    let mut chars = 0usize;
    let mut pad = 0;
    let mut valid = 0xff;
    for &c in text {
        if skip_space && is_space(c) {
            continue;
        }
        chars += 1;
        if c == b'=' {
            pad += 1;
        } else {
            valid &= sextet(u32::from(c)).1;
        }
    }
    if !chars.is_multiple_of(4) || pad > 2 || core::hint::black_box(valid) == 0
    {
        return Err(Error::InvalidEncoding);
    }
    Ok(chars / 4 * 3 - pad)
}

/// The character for a sextet, by which range of the alphabet it
/// falls in: 26 capitals, 26 small letters, 10 digits, then the two
/// symbols.
#[inline]
fn character(x: u32) -> u8 {
    let upper = lt(x, 26) & (x + u32::from(b'A'));
    let lower = ge(x, 26) & lt(x, 52) & (x + u32::from(b'a') - 26);
    // Digits start 52 in and at 48 out: four below.
    let digit = ge(x, 52) & lt(x, 62) & x.wrapping_sub(4);
    let plus = eq(x, 62) & u32::from(b'+');
    let slash = eq(x, 63) & u32::from(b'/');
    (upper | lower | digit | plus | slash) as u8
}

/// The sextet for a character, and `0xff` when the character is in
/// the alphabet or `0` when it is not.
#[inline]
fn sextet(c: u32) -> (u32, u32) {
    let upper = ge(c, u32::from(b'A')) & le(c, u32::from(b'Z'));
    let lower = ge(c, u32::from(b'a')) & le(c, u32::from(b'z'));
    let digit = ge(c, u32::from(b'0')) & le(c, u32::from(b'9'));
    let plus = eq(c, u32::from(b'+'));
    let slash = eq(c, u32::from(b'/'));
    // The subtractions wrap for a character below the range, where
    // the mask beside them is zero anyway.
    let value = (upper & c.wrapping_sub(u32::from(b'A')))
        | (lower & c.wrapping_sub(u32::from(b'a') - 26))
        | (digit & c.wrapping_add(4))
        | (plus & 62)
        | (slash & 63);
    (value, upper | lower | digit | plus | slash)
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors() {
        let cases: [(&[u8], &[u8]); 7] = [
            (b"", b""),
            (b"f", b"Zg=="),
            (b"fo", b"Zm8="),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg=="),
            (b"fooba", b"Zm9vYmE="),
            (b"foobar", b"Zm9vYmFy"),
        ];
        let mut text = [0u8; 8];
        let mut bytes = [0u8; 6];
        for (raw, encoded) in cases {
            let n = encode(raw, &mut text).unwrap();
            assert_eq!(&text[..n], encoded);
            assert_eq!(n, encoded_len(raw.len()));
            let n = decode(encoded, &mut bytes).unwrap();
            assert_eq!(&bytes[..n], raw);
        }
    }

    #[test]
    fn round_trips_every_sextet_and_length() {
        let bytes: [u8; 96] = core::array::from_fn(|i| {
            // Bytes whose sextets walk the whole alphabet.
            let s = (4 * i) as u32;
            (s << 2 | (s + 1) >> 4) as u8
        });
        let mut text = [0u8; 128];
        let mut back = [0u8; 96];
        for len in 0..=bytes.len() {
            let n = encode(&bytes[..len], &mut text).unwrap();
            let m = decode(&text[..n], &mut back).unwrap();
            assert_eq!(&back[..m], &bytes[..len], "{len}");
        }
    }

    #[test]
    fn accepts_only_the_alphabet() {
        let mut out = [0u8; 4];
        for c in 0..=255u8 {
            let text = [b'A', b'A', b'A', c];
            // Padding is a valid last character too.
            let in_alphabet = c.is_ascii_alphanumeric()
                || c == b'+'
                || c == b'/'
                || c == b'=';
            let got = decode(&text, &mut out);
            assert_eq!(got.is_ok(), in_alphabet, "{c:#04x}");
        }
    }

    #[test]
    fn refuses_every_non_canonical_form() {
        let mut out = [0u8; 8];
        // A stray character, missing padding, too much padding, a
        // character after padding, another quantum after padding, a
        // lone character, one padding character short, nonzero
        // unused bits both ways, whitespace anywhere, the URL
        // alphabet.
        for bad in [
            &b"AQ*D"[..],
            b"AQI",
            b"A===",
            b"AQ=D",
            b"AQ==AQID",
            b"A",
            b"AQ=",
            b"AR==",
            b"AQL=",
            b"AQID\n",
            b"AQ ID",
            b" AQID",
            b"-QID",
            b"_QID",
        ] {
            assert_eq!(
                decode(bad, &mut out),
                Err(Error::InvalidEncoding),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn lenient_reading_skips_only_whitespace() {
        let mut out = [0u8; 8];
        for text in [&b"AQID"[..], b"AQ\nID", b" A Q I D ", b"AQID\r\n"] {
            assert_eq!(decode_lenient(text, &mut out), Ok(3), "{text:?}");
            assert_eq!(&out[..3], &[1, 2, 3]);
        }
        assert_eq!(
            decode_lenient(b"AQ*D", &mut out),
            Err(Error::InvalidEncoding)
        );
    }

    #[test]
    fn wipes_output_on_failure() {
        let mut out = [0u8; 8];
        assert_eq!(decode(b"AQIDAQ*D", &mut out), Err(Error::InvalidEncoding));
        assert_eq!(out, [0; 8]);
    }

    #[test]
    fn sizes_the_output() {
        let mut out = [0u8; 3];
        assert_eq!(encode(&[0; 3], &mut out), Err(Error::OutputTooSmall(4)));
        let got = decode(b"AQIDBA==", &mut out);
        assert_eq!(got, Err(Error::OutputTooSmall(4)));
        assert_eq!(encoded_len(0), 0);
        assert_eq!(encoded_len(1), 4);
        assert_eq!(encoded_len(3), 4);
        assert_eq!(encoded_len(4), 8);
    }
}
