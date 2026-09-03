//! PEM (RFC 7468): DER in base64 between two armour lines that
//! name what it is. Private to the crate, as [`der`](crate::der) is;
//! the key types expose the format.
//!
//! Reading follows the RFC's advice: lenient about whitespace,
//! strict about everything else. Line ends may be LF or CRLF, lines
//! may be any length, and blank lines and whitespace before the
//! first armour line and after the last are ignored, which is what a
//! file copied through a terminal comes with. Everything else is
//! refused as [`Error::InvalidEncoding`]: a label the caller did not
//! ask for, an END that does not match its BEGIN, anything between
//! the armour lines that is not base64 or whitespace, which is how
//! the header lines of a legacy encrypted key are caught, bad or
//! missing padding, and anything but whitespace after the END line,
//! which is how a second block is.
//!
//! Writing produces what OpenSSL produces: LF line ends and 64
//! characters of base64 per line, so a key that came from OpenSSL
//! goes back out byte for byte.

use crate::Error;

const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";

/// Characters per line of base64, the RFC 7468 width.
const LINE: usize = 64;

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The length [`encode`] writes for a DER of `der_len` bytes under
/// `label`.
pub(crate) fn encoded_len(label: &str, der_len: usize) -> usize {
    let base64 = der_len.div_ceil(3) * 4;
    let lines = base64.div_ceil(LINE);
    BEGIN.len()
        + label.len()
        + DASHES.len()
        + 1
        + base64
        + lines
        + END.len()
        + label.len()
        + DASHES.len()
        + 1
}

/// Writes `der` as a PEM block under `label` into the front of
/// `out`, returning the length. `out` must be at least
/// [`encoded_len`] long; every caller sizes it first, and the debug
/// assertion holds where they have.
pub(crate) fn encode(label: &str, der: &[u8], out: &mut [u8]) -> usize {
    debug_assert!(out.len() >= encoded_len(label, der.len()));
    let mut n = 0;
    let mut put = |bytes: &[u8]| {
        out[n..n + bytes.len()].copy_from_slice(bytes);
        n += bytes.len();
    };
    put(BEGIN);
    put(label.as_bytes());
    put(DASHES);
    put(b"\n");
    // 48 bytes of DER make one 64-character line.
    for chunk in der.chunks(LINE / 4 * 3) {
        for group in chunk.chunks(3) {
            let mut quantum = [0u8; 3];
            quantum[..group.len()].copy_from_slice(group);
            let bits =
                u32::from_be_bytes([0, quantum[0], quantum[1], quantum[2]]);
            let mut text = [b'='; 4];
            for (i, c) in text.iter_mut().enumerate().take(group.len() + 1) {
                *c = ALPHABET[(bits >> (18 - 6 * i)) as usize & 0x3f];
            }
            put(&text);
        }
        put(b"\n");
    }
    put(END);
    put(label.as_bytes());
    put(DASHES);
    put(b"\n");
    n
}

/// Reads one PEM block whose label is one of `labels`, decoding
/// the DER into the front of `out`. Returns which label it was, as
/// an index into `labels`, and the DER's length. A block whose DER
/// would not fit `out` is refused as malformed: `out` is sized for
/// the largest key its caller can take, so anything larger is not
/// one.
pub(crate) fn decode(
    labels: &[&str],
    pem: &[u8],
    out: &mut [u8],
) -> Result<(usize, usize), Error> {
    let s = trim(pem);
    let s = s.strip_prefix(BEGIN).ok_or(Error::InvalidEncoding)?;
    let (which, s) = labels
        .iter()
        .enumerate()
        .find_map(|(i, label)| {
            s.strip_prefix(label.as_bytes())
                .and_then(|s| s.strip_prefix(DASHES))
                .map(|s| (i, s))
        })
        .ok_or(Error::InvalidEncoding)?;
    let end = find(s, END).ok_or(Error::InvalidEncoding)?;
    let body = &s[..end];
    let tail = s[end + END.len()..]
        .strip_prefix(labels[which].as_bytes())
        .and_then(|s| s.strip_prefix(DASHES))
        .ok_or(Error::InvalidEncoding)?;
    if !tail.iter().all(|&c| is_space(c)) {
        return Err(Error::InvalidEncoding);
    }
    let n = base64(body, out)?;
    Ok((which, n))
}

/// Base64 to bytes, standard alphabet, padding required and its
/// unused bits zero, whitespace anywhere. Non-canonical input is a
/// file that has been edited, and is refused.
fn base64(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut n = 0;
    let mut quantum = [0u8; 4];
    let mut have = 0;
    let mut pad = 0;
    let mut done = false;
    for &c in text {
        if is_space(c) {
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
            quantum[have] = value(c)?;
        }
        have += 1;
        if have < 4 {
            continue;
        }
        let bytes = [
            quantum[0] << 2 | quantum[1] >> 4,
            quantum[1] << 4 | quantum[2] >> 2,
            quantum[2] << 6 | quantum[3],
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
        out.get_mut(n..n + take)
            .ok_or(Error::InvalidEncoding)?
            .copy_from_slice(&bytes[..take]);
        n += take;
        done = pad > 0;
        have = 0;
        quantum = [0; 4];
    }
    if have != 0 {
        return Err(Error::InvalidEncoding);
    }
    Ok(n)
}

fn value(c: u8) -> Result<u8, Error> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return Err(Error::InvalidEncoding),
    };
    Ok(v)
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| !is_space(c)).unwrap_or(s.len());
    let end = s.iter().rposition(|&c| !is_space(c)).map_or(0, |i| i + 1);
    &s[start..end.max(start)]
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::format;
    use std::string::String;

    const LABELS: &[&str] = &["PRIVATE KEY", "RSA PRIVATE KEY"];

    /// A block under `label` around `body`, with `nl` for line ends.
    fn block(label: &str, body: &str, nl: &str) -> String {
        format!(
            "-----BEGIN {label}-----{nl}{body}{nl}-----END {label}-----{nl}"
        )
    }

    #[test]
    fn round_trips_every_length() {
        let der: [u8; 200] = core::array::from_fn(|i| i as u8);
        let mut pem = [0u8; 400];
        let mut back = [0u8; 200];
        for len in 0..=der.len() {
            let n = encode("PRIVATE KEY", &der[..len], &mut pem);
            assert_eq!(n, encoded_len("PRIVATE KEY", len), "{len}");
            let (which, m) = decode(LABELS, &pem[..n], &mut back).unwrap();
            assert_eq!(which, 0);
            assert_eq!(&back[..m], &der[..len], "{len}");
        }
    }

    #[test]
    fn writes_what_openssl_writes() {
        // 48 bytes fill exactly one line; 49 spill one character.
        let der = [0x00u8; 49];
        let mut pem = [0u8; 256];
        let n = encode("PUBLIC KEY", &der[..48], &mut pem);
        let line = "A".repeat(64);
        assert_eq!(pem[..n], *block("PUBLIC KEY", &line, "\n").as_bytes());
        let n = encode("PUBLIC KEY", &der, &mut pem);
        let two = format!("{line}\nAA==");
        assert_eq!(pem[..n], *block("PUBLIC KEY", &two, "\n").as_bytes());
        assert_eq!(encoded_len("PUBLIC KEY", 44), 113);
        assert_eq!(encoded_len("PRIVATE KEY", 48), 119);
    }

    #[test]
    fn reads_leniently() {
        let mut out = [0u8; 8];
        let lf = block("RSA PRIVATE KEY", "AQID", "\n");
        let crlf = block("RSA PRIVATE KEY", "AQID", "\r\n");
        let padded = format!("\n\n  {}  \n\n", lf);
        let split = block("RSA PRIVATE KEY", "AQ\nI\nD\n", "\n");
        let bare = block("RSA PRIVATE KEY", "AQID", "");
        let spaced = block("RSA PRIVATE KEY", " A Q I D ", "\n");
        for pem in [&lf, &crlf, &padded, &split, &bare, &spaced] {
            let got = decode(LABELS, pem.as_bytes(), &mut out);
            assert_eq!(got, Ok((1, 3)), "{pem:?}");
            assert_eq!(&out[..3], &[1, 2, 3]);
        }
    }

    #[test]
    fn refuses_everything_else() {
        let mut out = [0u8; 8];
        let good = block("PRIVATE KEY", "AQID", "\n");
        let headers =
            "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAQID";
        let bad = [
            // The wrong label, and mismatched labels.
            block("PUBLIC KEY", "AQID", "\n"),
            block("ENCRYPTED PRIVATE KEY", "AQID", "\n"),
            good.replace("END PRIVATE", "END RSA PRIVATE"),
            // A legacy encrypted key's headers.
            block("RSA PRIVATE KEY", headers, "\n"),
            // Two blocks; text after the end; no end; no begin.
            format!("{good}{good}"),
            format!("{good}x"),
            String::from("-----BEGIN PRIVATE KEY-----\nAQID\n"),
            String::from("AQID\n-----END PRIVATE KEY-----\n"),
            String::new(),
            // Base64 faults: a stray character, missing padding, too
            // much padding, a character after padding, another
            // quantum after padding, a lone character, one padding
            // character short, nonzero unused bits both ways.
            block("PRIVATE KEY", "AQ*D", "\n"),
            block("PRIVATE KEY", "AQI", "\n"),
            block("PRIVATE KEY", "A===", "\n"),
            block("PRIVATE KEY", "AQ=D", "\n"),
            block("PRIVATE KEY", "AQ==AQID", "\n"),
            block("PRIVATE KEY", "A", "\n"),
            block("PRIVATE KEY", "AQ=", "\n"),
            block("PRIVATE KEY", "AR==", "\n"),
            block("PRIVATE KEY", "AQL=", "\n"),
            // More DER than the buffer, which no key of the width
            // can be.
            block("PRIVATE KEY", "AQIDBAUGBwgJ", "\n"),
        ];
        for pem in &bad {
            assert_eq!(
                decode(LABELS, pem.as_bytes(), &mut out),
                Err(Error::InvalidEncoding),
                "{pem:?}"
            );
        }
    }

    #[test]
    fn every_padding_shape() {
        let mut out = [0u8; 8];
        let cases: [(&[u8], &[u8]); 3] =
            [(b"AQ==", &[1]), (b"AQI=", &[1, 2]), (b"AQID", &[1, 2, 3])];
        for (text, bytes) in cases {
            assert_eq!(base64(text, &mut out), Ok(bytes.len()));
            assert_eq!(&out[..bytes.len()], bytes);
        }
        assert_eq!(base64(b"", &mut out), Ok(0));
    }
}
