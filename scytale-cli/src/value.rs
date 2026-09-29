//! Byte-valued options: keys, nonces, tags, salts and the rest.
//!
//! Every such option takes `PREFIX:REST`, and nothing without a
//! prefix, so a script never has a value read the wrong way:
//!
//! - `hex:00ff..` is hex, either case, no `0x`, no separators and
//!   an even count of digits;
//! - `file:PATH` is the raw bytes of the file, every one of them;
//! - `fd:N` is the raw bytes read to the end of descriptor N, for
//!   `3< keyfile` in a script;
//! - `env:NAME` is the variable's value, as hex, since a variable
//!   cannot hold every byte;
//! - `str:TEXT` is the text itself, allowed for additional data,
//!   labels, salts and the like, and refused for a key, since a key
//!   typed as text is a password without a key derivation.
//!
//! The bytes come back in a buffer that wipes itself. The length is
//! checked here against what the algorithm's table entry says,
//! before any cryptographic call, and a value of another length is
//! refused with both lengths in the message and none of the bytes:
//! nothing is padded or cut to fit.

use std::fs::File;
use std::io::Read;

use scytale::codec::hex;
use scytale::{BlockType, ByteArray, KeyType};
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::names::Len;

/// The bytes the option `option` names in `spec`. `text` says
/// whether `str:` is allowed.
pub fn parse(
    spec: &str,
    option: &str,
    text: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let Some((prefix, rest)) = spec.split_once(':') else {
        let shown = shorten(spec);
        return Err(usage!(
            "{option} \"{shown}\": a value needs a prefix saying how to \
             read it: hex:{shown} for hex, file:PATH for a file's bytes, \
             fd:N for a descriptor, env:NAME for a variable holding hex\
             {}",
            if text {
                ", str:TEXT for the text itself"
            } else {
                ""
            }
        ));
    };
    match prefix {
        "hex" => from_hex(rest, option),
        "file" => {
            let mut bytes = Zeroizing::new(Vec::new());
            File::open(rest)
                .and_then(|mut f| f.read_to_end(&mut bytes))
                .map_err(|e| usage!("{option} file:{rest}: {e}"))?;
            Ok(bytes)
        }
        "fd" => {
            let fd: i32 = rest.parse().map_err(|_| {
                usage!("{option} fd:{rest}: a descriptor is a small number")
            })?;
            let mut bytes = Zeroizing::new(Vec::new());
            descriptor(fd)?
                .read_to_end(&mut bytes)
                .map_err(|e| usage!("{option} fd:{fd}: {e}"))?;
            Ok(bytes)
        }
        "env" => {
            let value = std::env::var(rest).map_err(|_| {
                usage!("{option} env:{rest}: {rest} is not set")
            })?;
            let value = Zeroizing::new(value);
            from_hex(&value, &format!("{option} env:{rest}:"))
        }
        "str" if text => Ok(Zeroizing::new(rest.as_bytes().to_vec())),
        "str" => Err(usage!(
            "{option} str:...: str: is for text such as --aad or --label, \
             not for a key; a key from a password comes from scytale kdf \
             pbkdf2"
        )),
        _ => Err(usage!(
            "{option} {prefix}:...: unknown prefix; hex:, file:, fd:, env:\
             {}",
            if text { " or str:" } else { "" }
        )),
    }
}

/// The first few characters of a value, for a message; never a
/// whole one, which may be a key.
fn shorten(spec: &str) -> String {
    let mut s: String = spec.chars().take(8).collect();
    if spec.chars().count() > 8 {
        s.push_str("..");
    }
    s
}

fn from_hex(text: &str, option: &str) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(c) = text.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(usage!(
            "{option} hex:...: \"{c}\" is not a hex digit; hex is 0-9 and \
             a-f, with no 0x and no separators"
        ));
    }
    if !text.len().is_multiple_of(2) {
        return Err(usage!(
            "{option} hex:...: an odd count of hex digits ({}); two per \
             byte",
            text.len()
        ));
    }
    let mut bytes = Zeroizing::new(vec![0u8; text.len() / 2]);
    hex::decode(text.as_bytes(), &mut bytes)
        .map_err(|_| usage!("{option} hex:...: not hex"))?;
    Ok(bytes)
}

#[cfg(unix)]
fn descriptor(fd: i32) -> Result<File> {
    use std::os::unix::io::FromRawFd;
    // SAFETY: the descriptor was named by the caller, who owns it;
    // this process takes it over and closes it when done reading,
    // which is what a script that opened it for us expects.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
fn descriptor(fd: i32) -> Result<File> {
    Err(usage!("fd:{fd}: descriptors by number are a unix feature"))
}

/// Checks `bytes` is a length `len` allows for `option` under
/// `algorithm`.
pub fn check(
    bytes: &[u8],
    len: Len,
    option: &str,
    algorithm: &str,
) -> Result<()> {
    if len.allows(bytes.len()) {
        return Ok(());
    }
    let n = bytes.len();
    Err(match len {
        Len::None => usage!("{algorithm} takes no {option}"),
        _ => usage!(
            "{option} is {n} byte{}; {algorithm} takes {}",
            if n == 1 { "" } else { "s" },
            len.describe()
        ),
    })
}

/// The bytes of `option`, checked against `len`.
pub fn checked(
    spec: &str,
    option: &str,
    len: Len,
    algorithm: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = parse(spec, option, false)?;
    check(&bytes, len, option, algorithm)?;
    Ok(bytes)
}

/// A key for `K`, of the length `K` fixes, from `option`.
pub fn key<K: KeyType>(
    spec: &str,
    option: &str,
    algorithm: &str,
) -> Result<K::Key> {
    let mut key = K::zero_key();
    let want = Len::Exact(key.as_ref().len());
    let bytes = checked(spec, option, want, algorithm)?;
    key.as_mut().copy_from_slice(&bytes);
    Ok(key)
}

/// A block for `C`, of the length `C` fixes: an IV or a tweak.
pub fn block<C: BlockType>(
    spec: &str,
    option: &str,
    algorithm: &str,
) -> Result<C::Block> {
    let mut block = C::zero_block();
    let want = Len::Exact(block.as_ref().len());
    let bytes = checked(spec, option, want, algorithm)?;
    block.as_mut().copy_from_slice(&bytes);
    Ok(block)
}

/// A fixed-size array, wiped when dropped by the caller.
pub fn array<const N: usize>(
    spec: &str,
    option: &str,
    algorithm: &str,
) -> Result<[u8; N]> {
    let bytes = checked(spec, option, Len::Exact(N), algorithm)?;
    let mut out = <[u8; N]>::zeroed();
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Text-valued bytes, `str:` allowed: additional data, a label, a
/// salt. Empty when the option was not given.
pub fn text(spec: Option<&str>, option: &str) -> Result<Zeroizing<Vec<u8>>> {
    match spec {
        Some(spec) => parse(spec, option, true),
        None => Ok(Zeroizing::new(Vec::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fail::Fail;

    fn err<T>(r: Result<T>) -> String {
        match r {
            Err(Fail::Usage(s)) => s,
            _ => panic!("expected a usage error"),
        }
    }

    #[test]
    fn every_prefix() {
        assert_eq!(&parse("hex:00FF", "-k", false).unwrap()[..], &[0, 255]);
        assert_eq!(&parse("str:ab", "--aad", true).unwrap()[..], b"ab");
        assert!(err(parse("str:ab", "--key", false)).contains("pbkdf2"));
    }

    // A file and the environment: wasm has neither to hand.
    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn file_and_environment() {
        let dir = std::env::temp_dir().join("scytale-value-test");
        std::fs::write(&dir, [1, 2, 3]).unwrap();
        let spec = format!("file:{}", dir.display());
        assert_eq!(&parse(&spec, "-k", false).unwrap()[..], &[1, 2, 3]);
        std::fs::remove_file(&dir).unwrap();
        // SAFETY: nothing else in this test binary reads the
        // environment concurrently by this name.
        unsafe { std::env::set_var("SCYTALE_VALUE_TEST", "0a0b") };
        let got = parse("env:SCYTALE_VALUE_TEST", "-k", false).unwrap();
        assert_eq!(&got[..], &[10, 11]);
        let e = err(parse("env:SCYTALE_UNSET_VARIABLE", "--key", false));
        assert!(e.contains("SCYTALE_UNSET_VARIABLE is not set"), "{e}");
        let e = err(parse("file:/nonexistent/x", "--key", false));
        assert!(e.starts_with("--key file:/nonexistent/x:"), "{e}");
    }

    #[test]
    fn says_what_is_wrong() {
        let e = err(parse("00ff", "--key", false));
        assert!(e.contains("hex:00ff for hex"), "{e}");
        assert!(!e.contains("str:"), "{e}");
        let e = err(parse("0123456789abcdef0123", "--aad", true));
        assert!(e.contains("\"01234567..\""), "{e}");
        assert!(e.contains("str:TEXT"), "{e}");
        let e = err(parse("hex:0", "--key", false));
        assert!(e.contains("odd count of hex digits (1)"), "{e}");
        let e = err(parse("hex:0x00", "--key", false));
        assert!(e.contains("\"x\" is not a hex digit"), "{e}");
        let e = err(parse("hex:00 ff", "--key", false));
        assert!(e.contains("\" \" is not a hex digit"), "{e}");
        let e = err(parse("bin:00", "--key", false));
        assert!(e.contains("unknown prefix"), "{e}");
        let e = err(parse("fd:x", "--key", false));
        assert!(e.contains("small number"), "{e}");
    }

    #[test]
    fn lengths_are_exact() {
        use scytale::cipher::aes::Aes128;
        let e = err(key::<Aes128>("hex:00", "--key", "aes-128-gcm"));
        assert_eq!(e, "--key is 1 byte; aes-128-gcm takes 16 bytes");
        let long = format!("hex:{}", "00".repeat(32));
        let e = err(key::<Aes128>(&long, "--key", "aes-128-gcm"));
        assert_eq!(e, "--key is 32 bytes; aes-128-gcm takes 16 bytes");
        let sixteen = format!("hex:{}", "00".repeat(16));
        assert!(key::<Aes128>(&sixteen, "-k", "x").is_ok());
        let range = Len::Range(7, 13);
        let e = err(checked("hex:00", "--nonce", range, "aes-128-ccm"));
        assert_eq!(e, "--nonce is 1 byte; aes-128-ccm takes 7 to 13 bytes");
        let e = err(check(&[0; 16], Len::None, "--iv", "aes-128-ecb"));
        assert_eq!(e, "aes-128-ecb takes no --iv");
        assert!(array::<12>("hex:000000", "--nonce", "x").is_err());
        assert!(array::<3>("hex:000000", "--nonce", "x").is_ok());
    }
}
