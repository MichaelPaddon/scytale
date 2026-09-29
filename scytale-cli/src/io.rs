//! Where bytes come from and go to.
//!
//! Input is a file or standard input; output a file or standard
//! output. A command that can work a chunk at a time does, through
//! [`stream`] and [`stream_aligned`], so a pipe of any length goes
//! through in fixed memory; one that needs the whole message reads
//! it with [`read_all`]. Text output is hex with a newline; binary
//! output is the bytes.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use clap::Args;
use scytale::codec::hex;

use crate::fail::{Fail, Result};

/// `--hex` and `--raw`, on every command that writes bytes; which is
/// the default is the command's to say.
#[derive(Args, Clone, Copy)]
pub struct Format {
    /// Write hex and a newline
    #[arg(long, conflicts_with = "raw")]
    pub hex: bool,
    /// Write the raw bytes
    #[arg(long)]
    pub raw: bool,
}

impl Format {
    /// Whether to write hex, given what the command does without
    /// either flag.
    pub fn as_hex(self, default_hex: bool) -> bool {
        if self.hex {
            true
        } else if self.raw {
            false
        } else {
            default_hex
        }
    }
}

/// Bytes read at a time when streaming.
pub const CHUNK: usize = 64 * 1024;

/// The input a command reads: `path`, or standard input without one.
pub fn input(path: Option<&Path>) -> Result<Box<dyn Read>> {
    Ok(match path {
        Some(path) => Box::new(open(path)?),
        None => Box::new(io::stdin().lock()),
    })
}

fn open(path: &Path) -> Result<File> {
    File::open(path)
        .map_err(|e| Fail::Other(format!("{}: {e}", path.display())))
}

/// All of the input.
pub fn read_all(path: Option<&Path>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input(path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The output a command writes: `path`, or standard output without
/// one. A `secret` file is created readable by its owner alone.
pub fn output(path: Option<&Path>, secret: bool) -> Result<Box<dyn Write>> {
    Ok(match path {
        Some(path) => Box::new(create(path, secret)?),
        None => Box::new(io::stdout().lock()),
    })
}

fn create(path: &Path, secret: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    options
        .open(path)
        .map_err(|e| Fail::Other(format!("{}: {e}", path.display())))
}

/// Writes `bytes` as hex and a newline, or as they are.
pub fn write(out: &mut dyn Write, bytes: &[u8], as_hex: bool) -> Result<()> {
    if as_hex {
        let mut text = vec![0u8; hex::encoded_len(bytes.len())];
        hex::encode(bytes, &mut text)?;
        out.write_all(&text)?;
        out.write_all(b"\n")?;
    } else {
        out.write_all(bytes)?;
    }
    Ok(out.flush()?)
}

/// Reads `input` a chunk at a time and hands each to `f`.
pub fn for_each_chunk(
    input: &mut dyn Read,
    mut f: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        f(&buf[..n])?;
    }
}

/// Transforms `input` to `out` a chunk at a time through `f`, for a
/// cipher that takes any length at any point.
pub fn stream(
    input: &mut dyn Read,
    out: &mut dyn Write,
    mut f: impl FnMut(&mut [u8]) -> Result<()>,
) -> Result<()> {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            return Ok(out.flush()?);
        }
        f(&mut buf[..n])?;
        out.write_all(&buf[..n])?;
    }
}

/// As [`stream`] for a cipher that takes whole blocks: `f` is handed
/// a whole number of `block`s each time, and at least `hold` bytes
/// are kept back until the end, so that a last block that needs
/// other treatment -- padding to strip -- is never handed over.
/// Returns what was held back, less than `hold + block` bytes, for
/// the caller to finish.
pub fn stream_aligned(
    input: &mut dyn Read,
    out: &mut dyn Write,
    block: usize,
    hold: usize,
    mut f: impl FnMut(&mut [u8]) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; CHUNK + hold + block];
    let mut pending = 0;
    loop {
        let n = input.read(&mut buf[pending..])?;
        if n == 0 {
            break;
        }
        pending += n;
        let usable = pending.saturating_sub(hold) / block * block;
        if usable > 0 {
            f(&mut buf[..usable])?;
            out.write_all(&buf[..usable])?;
            buf.copy_within(usable..pending, 0);
            pending -= usable;
        }
    }
    Ok(buf[..pending].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_streaming_holds_back_what_it_is_told() {
        let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        for (hold, block) in [(0, 16), (16, 16), (0, 1), (8, 8)] {
            let mut out = Vec::new();
            let mut seen = 0;
            let rest = stream_aligned(
                &mut &data[..],
                &mut out,
                block,
                hold,
                |chunk| {
                    assert_eq!(chunk.len() % block, 0);
                    seen += chunk.len();
                    Ok(())
                },
            )
            .unwrap();
            assert!(rest.len() < hold + block, "{hold} {block}");
            assert!(rest.len() >= hold.min(data.len()));
            assert_eq!(seen + rest.len(), data.len());
            assert_eq!(&out[..], &data[..seen]);
            assert_eq!(&rest[..], &data[seen..]);
        }
    }

    #[test]
    fn hex_output() {
        let mut out = Vec::new();
        write(&mut out, &[0xab, 0xcd], true).unwrap();
        assert_eq!(out, b"abcd\n");
        out.clear();
        write(&mut out, &[0xab, 0xcd], false).unwrap();
        assert_eq!(out, [0xab, 0xcd]);
    }
}
