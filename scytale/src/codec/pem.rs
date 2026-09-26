//! PEM (RFC 7468): DER in base64 between two armour lines that
//! name what it is.
//!
//! The key types read and write their own PEM, so most callers never
//! come here. [`decode`] is for the caller who has a block and does
//! not know what it holds: it returns the label, and
//! [`KeyInfo`](crate::KeyInfo) reads the DER to say which key type
//! to hand it to. [`encode`] is for a DER of the caller's own.
//!
//! Reading follows the RFC's advice: lenient about whitespace,
//! strict about everything else. Line ends may be LF or CRLF, lines
//! may be any length, and blank lines and whitespace before the
//! first armour line and after the last are ignored, which is what a
//! file copied through a terminal comes with. Everything else is
//! refused as [`Error::InvalidEncoding`]: an END that does not match
//! its BEGIN, anything between the armour lines that is not base64
//! or whitespace, which is how the header lines of a legacy encrypted
//! key are caught, bad or missing padding, and anything but
//! whitespace after the END line, which is how a second block is.
//!
//! Writing produces what OpenSSL produces: LF line ends and 64
//! characters of base64 per line, so a key that came from OpenSSL
//! goes back out byte for byte.

use crate::Error;

use super::base64;

const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";

/// Characters per line of base64, the RFC 7468 width.
const LINE: usize = 64;

/// Bytes of DER that make one line.
const LINE_BYTES: usize = LINE / 4 * 3;

/// The length [`encode`] writes for a DER of `der_len` bytes under
/// `label`.
pub const fn encoded_len(label: &str, der_len: usize) -> usize {
    let base64 = base64::encoded_len(der_len);
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
/// `out`, returning the length, [`encoded_len`] of the two.
pub fn encode(label: &str, der: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let needed = encoded_len(label, der.len());
    if out.len() < needed {
        return Err(Error::OutputTooSmall(needed));
    }
    Ok(encode_exact(label, der, out))
}

/// [`encode`] into a buffer already known to be long enough, for the
/// key types whose PEM is a fixed-size array; the debug assertion
/// holds where they have sized it.
pub(crate) fn encode_exact(label: &str, der: &[u8], out: &mut [u8]) -> usize {
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
    for chunk in der.chunks(LINE_BYTES) {
        let mut line = [0u8; LINE];
        // A chunk is at most LINE_BYTES, so the line always fits.
        let m = base64::encode(chunk, &mut line).unwrap_or(0);
        put(&line[..m]);
        put(b"\n");
    }
    put(END);
    put(label.as_bytes());
    put(DASHES);
    put(b"\n");
    n
}

/// Reads one PEM block, decoding the DER into the front of `out`.
/// Returns the label between `-----BEGIN ` and `-----`, borrowed
/// from `pem`, and the DER's length.
pub fn decode<'a>(
    pem: &'a [u8],
    out: &mut [u8],
) -> Result<(&'a str, usize), Error> {
    let s = trim(pem);
    let s = s.strip_prefix(BEGIN).ok_or(Error::InvalidEncoding)?;
    let label_len = find(s, DASHES).ok_or(Error::InvalidEncoding)?;
    let (label, s) = s.split_at(label_len);
    // RFC 7468's label is printable ASCII, with spaces and hyphens
    // inside it; nothing else is one, so nothing else is looked for.
    if label.is_empty() || !label.iter().all(|&c| (0x20..0x7f).contains(&c)) {
        return Err(Error::InvalidEncoding);
    }
    let s = &s[DASHES.len()..];
    let end = find(s, END).ok_or(Error::InvalidEncoding)?;
    let body = &s[..end];
    let tail = s[end + END.len()..]
        .strip_prefix(label)
        .and_then(|s| s.strip_prefix(DASHES))
        .ok_or(Error::InvalidEncoding)?;
    if !tail.iter().all(|&c| is_space(c)) {
        return Err(Error::InvalidEncoding);
    }
    let n = base64::decode_lenient(body, out)?;
    // The label was checked to be ASCII above.
    let label =
        core::str::from_utf8(label).map_err(|_| Error::InvalidEncoding)?;
    Ok((label, n))
}

/// [`decode`] for a key type that knows which labels it reads:
/// returns which of `labels` the block carried, as an index, and the
/// DER's length. Any other label is refused, and so is a block whose
/// DER would not fit `out`, as malformed: `out` is sized for the
/// largest key its caller can take, so anything larger is not one.
pub(crate) fn decode_one_of(
    labels: &[&str],
    pem: &[u8],
    out: &mut [u8],
) -> Result<(usize, usize), Error> {
    let (label, n) = decode(pem, out).map_err(|e| match e {
        Error::OutputTooSmall(_) => Error::InvalidEncoding,
        other => other,
    })?;
    let which = labels
        .iter()
        .position(|&l| l == label)
        .ok_or(Error::InvalidEncoding)?;
    Ok((which, n))
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
            let n = encode("PRIVATE KEY", &der[..len], &mut pem).unwrap();
            assert_eq!(n, encoded_len("PRIVATE KEY", len), "{len}");
            let (label, m) = decode(&pem[..n], &mut back).unwrap();
            assert_eq!(label, "PRIVATE KEY");
            assert_eq!(&back[..m], &der[..len], "{len}");
            let (which, m) =
                decode_one_of(LABELS, &pem[..n], &mut back).unwrap();
            assert_eq!((which, m), (0, len));
        }
    }

    #[test]
    fn writes_what_openssl_writes() {
        // 48 bytes fill exactly one line; 49 spill one character.
        let der = [0x00u8; 49];
        let mut pem = [0u8; 256];
        let n = encode("PUBLIC KEY", &der[..48], &mut pem).unwrap();
        let line = "A".repeat(64);
        assert_eq!(pem[..n], *block("PUBLIC KEY", &line, "\n").as_bytes());
        let n = encode("PUBLIC KEY", &der, &mut pem).unwrap();
        let two = format!("{line}\nAA==");
        assert_eq!(pem[..n], *block("PUBLIC KEY", &two, "\n").as_bytes());
        assert_eq!(encoded_len("PUBLIC KEY", 44), 113);
        assert_eq!(encoded_len("PRIVATE KEY", 48), 119);
        let mut short = [0u8; 100];
        assert_eq!(
            encode("PUBLIC KEY", &der, &mut short),
            Err(Error::OutputTooSmall(encoded_len("PUBLIC KEY", 49)))
        );
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
            let got = decode(pem.as_bytes(), &mut out);
            assert_eq!(got, Ok(("RSA PRIVATE KEY", 3)), "{pem:?}");
            assert_eq!(&out[..3], &[1, 2, 3]);
            let got = decode_one_of(LABELS, pem.as_bytes(), &mut out);
            assert_eq!(got, Ok((1, 3)), "{pem:?}");
        }
    }

    #[test]
    fn returns_any_label() {
        let mut out = [0u8; 8];
        for label in ["CERTIFICATE", "X", "EC PRIVATE KEY", "A-B C"] {
            let pem = block(label, "AQID", "\n");
            let got = decode(pem.as_bytes(), &mut out);
            assert_eq!(got, Ok((label, 3)), "{label}");
            // A key type that does not read it refuses it.
            let got = decode_one_of(LABELS, pem.as_bytes(), &mut out);
            assert_eq!(got, Err(Error::InvalidEncoding), "{label}");
        }
    }

    #[test]
    fn refuses_everything_else() {
        let mut out = [0u8; 8];
        let good = block("PRIVATE KEY", "AQID", "\n");
        let headers =
            "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAQID";
        let bad = [
            // Mismatched labels; an empty one; one that is not text.
            good.replace("END PRIVATE", "END RSA PRIVATE"),
            block("", "AQID", "\n"),
            block("\u{e9}", "AQID", "\n"),
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
        ];
        for pem in &bad {
            assert_eq!(
                decode(pem.as_bytes(), &mut out),
                Err(Error::InvalidEncoding),
                "{pem:?}"
            );
        }
        // More DER than the buffer: the caller who sized it for a
        // key is told it is no key, the caller who did not is told
        // the size.
        let big = block("PRIVATE KEY", "AQIDBAUGBwgJ", "\n");
        assert_eq!(
            decode(big.as_bytes(), &mut out),
            Err(Error::OutputTooSmall(9))
        );
        assert_eq!(
            decode_one_of(LABELS, big.as_bytes(), &mut out),
            Err(Error::InvalidEncoding)
        );
    }
}
