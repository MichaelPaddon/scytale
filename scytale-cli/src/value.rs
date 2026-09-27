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
//! The bytes come back in a buffer that wipes itself, and the length
//! is the caller's to check: an algorithm fixes what it takes, and a
//! key of another length is refused, never padded or cut.

use std::fs::File;
use std::io::Read;

use scytale::codec::hex;
use scytale::{BlockType, ByteArray, KeyType};
use zeroize::Zeroizing;

use crate::fail::{Result, usage};

/// The bytes an option names. `what` is the option, for the message
/// when it is malformed; `text` says whether `str:` is allowed.
pub fn parse(spec: &str, what: &str, text: bool) -> Result<Zeroizing<Vec<u8>>> {
    let Some((prefix, rest)) = spec.split_once(':') else {
        return Err(usage!(
            "{what}: expected hex:, file:, fd:, env: or str: before the value"
        ));
    };
    match prefix {
        "hex" => from_hex(rest, what),
        "file" => {
            let mut bytes = Zeroizing::new(Vec::new());
            File::open(rest)
                .and_then(|mut f| f.read_to_end(&mut bytes))
                .map_err(|e| usage!("{what}: {rest}: {e}"))?;
            Ok(bytes)
        }
        "fd" => {
            let fd: i32 = rest
                .parse()
                .map_err(|_| usage!("{what}: fd:{rest} is not a descriptor"))?;
            let mut bytes = Zeroizing::new(Vec::new());
            descriptor(fd)?
                .read_to_end(&mut bytes)
                .map_err(|e| usage!("{what}: fd:{fd}: {e}"))?;
            Ok(bytes)
        }
        "env" => {
            let value = std::env::var(rest)
                .map_err(|_| usage!("{what}: ${rest} is not set"))?;
            let value = Zeroizing::new(value);
            from_hex(&value, what)
        }
        "str" if text => Ok(Zeroizing::new(rest.as_bytes().to_vec())),
        "str" => Err(usage!("{what}: str: is not allowed for a key")),
        _ => Err(usage!("{what}: unknown prefix {prefix}:")),
    }
}

fn from_hex(text: &str, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(vec![0u8; text.len() / 2]);
    hex::decode(text.as_bytes(), &mut bytes)
        .map_err(|_| usage!("{what}: not hex: an even count of 0-9, a-f"))?;
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

/// Checks `bytes` is exactly `len` long.
pub fn exact(bytes: &[u8], len: usize, what: &str) -> Result<()> {
    if bytes.len() == len {
        Ok(())
    } else {
        Err(usage!("{what} must be {len} bytes, got {}", bytes.len()))
    }
}

/// A key for `K`, of the length `K` fixes.
pub fn key<K: KeyType>(spec: &str, what: &str) -> Result<K::Key> {
    let bytes = parse(spec, what, false)?;
    let mut key = K::zero_key();
    exact(&bytes, key.as_ref().len(), what)?;
    key.as_mut().copy_from_slice(&bytes);
    Ok(key)
}

/// A block for `C`, of the length `C` fixes: an IV or a tweak.
pub fn block<C: BlockType>(spec: &str, what: &str) -> Result<C::Block> {
    let bytes = parse(spec, what, false)?;
    let mut block = C::zero_block();
    exact(&bytes, block.as_ref().len(), what)?;
    block.as_mut().copy_from_slice(&bytes);
    Ok(block)
}

/// A fixed-size array, wiped when dropped by the caller.
pub fn array<const N: usize>(spec: &str, what: &str) -> Result<[u8; N]> {
    let bytes = parse(spec, what, false)?;
    exact(&bytes, N, what)?;
    let mut out = <[u8; N]>::zeroed();
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Text-valued bytes, `str:` allowed: additional data, a label, a
/// salt. Empty when the option was not given.
pub fn text(spec: Option<&str>, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    match spec {
        Some(spec) => parse(spec, what, true),
        None => Ok(Zeroizing::new(Vec::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fail::Fail;

    fn is_usage<T>(r: Result<T>) -> bool {
        matches!(r, Err(Fail::Usage(_)))
    }

    #[test]
    fn every_prefix() {
        assert_eq!(&parse("hex:00FF", "k", false).unwrap()[..], &[0, 255]);
        assert_eq!(&parse("str:ab", "k", true).unwrap()[..], b"ab");
        assert!(is_usage(parse("str:ab", "k", false)));
    }

    // A file and the environment: wasm has neither to hand.
    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn file_and_environment() {
        let dir = std::env::temp_dir().join("scytale-value-test");
        std::fs::write(&dir, [1, 2, 3]).unwrap();
        let spec = format!("file:{}", dir.display());
        assert_eq!(&parse(&spec, "k", false).unwrap()[..], &[1, 2, 3]);
        std::fs::remove_file(&dir).unwrap();
        // SAFETY: nothing else in this test binary reads the
        // environment concurrently by this name.
        unsafe { std::env::set_var("SCYTALE_VALUE_TEST", "0a0b") };
        let got = parse("env:SCYTALE_VALUE_TEST", "k", false).unwrap();
        assert_eq!(&got[..], &[10, 11]);
    }

    #[test]
    fn refuses_the_malformed() {
        for bad in ["00ff", "hex:0", "hex:0x00", "hex:00 ff", "bin:00"] {
            assert!(is_usage(parse(bad, "k", false)), "{bad}");
        }
        assert!(is_usage(parse("file:/nonexistent/x", "k", false)));
        assert!(is_usage(parse("fd:x", "k", false)));
        assert!(is_usage(parse("env:SCYTALE_UNSET_VARIABLE", "k", false)));
    }

    #[test]
    fn lengths_are_exact() {
        use scytale::cipher::aes::Aes128;
        assert!(key::<Aes128>("hex:00", "key").is_err());
        let k = key::<Aes128>(&format!("hex:{}", "00".repeat(16)), "key");
        assert!(k.is_ok());
        let long = format!("hex:{}", "00".repeat(32));
        assert!(is_usage(key::<Aes128>(&long, "k")));
        assert!(array::<12>("hex:000000", "nonce").is_err());
        assert!(array::<3>("hex:000000", "nonce").is_ok());
    }
}
