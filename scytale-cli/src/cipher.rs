//! `scytale cipher`: the unauthenticated modes, stdin to stdout.
//!
//! Nothing here authenticates. A script that needs to know a message
//! is what was encrypted wants `scytale aead`; these are for a
//! protocol that brings its own MAC, a disk, a key to wrap, or a
//! format to preserve.

use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use scytale::cipher::BlockCipher;
use scytale::cipher::aes::{Aes128, Aes192, Aes256};
use scytale::cipher::chacha20::ChaCha20;
use scytale::cipher::mode::alphabet::DIGITS;
use scytale::cipher::mode::{
    Alphabet, Cbc, Cfb1, Cfb8, Cfb128, Ctr, Ff1, Ff3_1, Kw, Kwp, Ofb, Xts,
};
use scytale::cipher::padding::pkcs7;
use scytale::{ByteArray, Error, Key};
use zeroize::Zeroize;

use crate::fail::{Result, usage};
use crate::{io, value};

/// The ciphers and modes, as `--algorithm` names them.
pub const NAMES: [&str; 37] = [
    "aes-128-ecb",
    "aes-192-ecb",
    "aes-256-ecb",
    "aes-128-cbc",
    "aes-192-cbc",
    "aes-256-cbc",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb1",
    "aes-192-cfb1",
    "aes-256-cfb1",
    "aes-128-cfb8",
    "aes-192-cfb8",
    "aes-256-cfb8",
    "aes-128-cfb128",
    "aes-192-cfb128",
    "aes-256-cfb128",
    "aes-128-ofb",
    "aes-192-ofb",
    "aes-256-ofb",
    "aes-128-xts",
    "aes-192-xts",
    "aes-256-xts",
    "aes-128-kw",
    "aes-192-kw",
    "aes-256-kw",
    "aes-128-kwp",
    "aes-192-kwp",
    "aes-256-kwp",
    "chacha20",
    "ff1-aes-128",
    "ff1-aes-192",
    "ff1-aes-256",
    "ff3-1-aes-128",
    "ff3-1-aes-192",
    "ff3-1-aes-256",
];

/// Runs `$body` with `$C` bound to the AES width `$bits` names.
macro_rules! with_aes {
    ($bits:expr, $C:ident => $body:expr) => {
        match $bits {
            "128" => {
                type $C = Aes128;
                $body
            }
            "192" => {
                type $C = Aes192;
                $body
            }
            "256" => {
                type $C = Aes256;
                $body
            }
            other => Err(usage!("no AES of {other} bits")),
        }
    };
}

pub(crate) use with_aes;

#[derive(Subcommand)]
pub enum CipherOp {
    /// Encrypt the input
    Encrypt(CipherArgs),
    /// Decrypt the input
    Decrypt(CipherArgs),
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Padding {
    /// PKCS#7, what openssl enc and CMS use
    Pkcs7,
    /// None: the input must be whole blocks
    None,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct CipherArgs {
    /// The cipher and mode: aes-256-ctr, chacha20, ff1-aes-128, ...
    #[arg(short, long)]
    algorithm: String,
    /// The key (hex:, file:, fd:, env:); XTS takes two, concatenated
    #[arg(short, long)]
    key: String,
    /// The IV, counter block or XTS tweak, one block
    #[arg(long)]
    iv: Option<String>,
    /// The nonce, for chacha20 (12 bytes)
    #[arg(short, long)]
    nonce: Option<String>,
    /// The initial block counter, for chacha20
    #[arg(long, default_value_t = 0)]
    counter: u32,
    /// Padding, for ecb, cbc and cfb128
    #[arg(long)]
    padding: Option<Padding>,
    /// The characters that are numerals, for ff1 and ff3-1
    #[arg(long)]
    alphabet: Option<String>,
    /// The tweak, for ff1 (any length) and ff3-1 (7 bytes)
    #[arg(long)]
    tweak: Option<String>,
    /// The file to transform; standard input without one
    file: Option<PathBuf>,
    /// Write to this file rather than standard output
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: CipherOp) -> Result<()> {
    let (args, encrypt) = match op {
        CipherOp::Encrypt(args) => (args, true),
        CipherOp::Decrypt(args) => (args, false),
    };
    let name = args.algorithm.as_str();
    if let Some(rest) = name.strip_prefix("aes-") {
        let (bits, mode) = rest
            .split_once('-')
            .ok_or_else(|| usage!("unknown cipher {name}"))?;
        return with_aes!(bits, C => aes::<C>(mode, &args, encrypt));
    }
    if name == "chacha20" {
        return chacha20(&args);
    }
    for (prefix, ff3) in [("ff1-aes-", false), ("ff3-1-aes-", true)] {
        if let Some(bits) = name.strip_prefix(prefix) {
            return with_aes!(bits, C => fpe::<C>(&args, encrypt, ff3));
        }
    }
    Err(usage!("unknown cipher {name}"))
}

/// One AES mode, by name.
fn aes<C>(mode: &str, args: &CipherArgs, encrypt: bool) -> Result<()>
where
    C: BlockCipher<Block = [u8; 16]>,
{
    let refuse = |what: &str, given: bool| -> Result<()> {
        if given {
            Err(usage!("{mode} takes no {what}"))
        } else {
            Ok(())
        }
    };
    refuse("--nonce", args.nonce.is_some())?;
    refuse("--alphabet", args.alphabet.is_some())?;
    refuse("--tweak", args.tweak.is_some())?;
    if !matches!(mode, "ecb" | "cbc" | "cfb128") {
        refuse("--padding", args.padding.is_some())?;
    }
    let iv = || -> Result<C::Block> {
        let iv = args
            .iv
            .as_deref()
            .ok_or_else(|| usage!("{mode} needs --iv"))?;
        value::block::<C>(iv, "iv")
    };
    let mut input = io::input(args.file.as_deref())?;
    let mut out = io::output(args.out.as_deref(), false)?;
    let input = &mut *input;
    let out = &mut *out;
    match mode {
        "ecb" => {
            refuse("--iv", args.iv.is_some())?;
            let cipher = C::new(&value::key::<C>(&args.key, "key")?);
            blocks(args, encrypt, input, out, |chunk| {
                let (blocks, _) = <[u8; 16]>::split_mut(chunk);
                if encrypt {
                    cipher.encrypt(blocks);
                } else {
                    cipher.decrypt(blocks);
                }
                Ok(())
            })
        }
        "cbc" => {
            let cbc = Cbc::<C>::new(&value::key::<C>(&args.key, "key")?);
            let iv = iv()?;
            if encrypt {
                let mut e = cbc.encryptor(&iv);
                blocks(args, encrypt, input, out, |c| Ok(e.update(c)?))
            } else {
                let mut d = cbc.decryptor(&iv);
                blocks(args, encrypt, input, out, |c| Ok(d.update(c)?))
            }
        }
        "cfb128" => {
            let cfb = Cfb128::<C>::new(&value::key::<C>(&args.key, "key")?);
            let iv = iv()?;
            if encrypt {
                let mut e = cfb.encryptor(&iv);
                blocks(args, encrypt, input, out, |c| Ok(e.update(c)?))
            } else {
                let mut d = cfb.decryptor(&iv);
                blocks(args, encrypt, input, out, |c| Ok(d.update(c)?))
            }
        }
        "cfb8" => {
            let cfb = Cfb8::<C>::new(&value::key::<C>(&args.key, "key")?);
            let iv = iv()?;
            if encrypt {
                let mut e = cfb.encryptor(&iv);
                io::stream(input, out, |c| {
                    e.update(c);
                    Ok(())
                })
            } else {
                let mut d = cfb.decryptor(&iv);
                io::stream(input, out, |c| {
                    d.update(c);
                    Ok(())
                })
            }
        }
        "cfb1" => {
            let cfb = Cfb1::<C>::new(&value::key::<C>(&args.key, "key")?);
            let iv = iv()?;
            let mut data = read_all(input)?;
            let bits = data.len() * 8;
            if encrypt {
                cfb.encrypt(&iv, &mut data, bits)?;
            } else {
                cfb.decrypt(&iv, &mut data, bits)?;
            }
            io::write(out, &data, false)
        }
        "ofb" => {
            let ofb = Ofb::<C>::new(&value::key::<C>(&args.key, "key")?);
            let mut s = ofb.stream(&iv()?);
            io::stream(input, out, |c| {
                s.update(c);
                Ok(())
            })
        }
        "ctr" => {
            let ctr = Ctr::<C>::new(&value::key::<C>(&args.key, "key")?);
            let mut s = ctr.stream(&iv()?);
            io::stream(input, out, |c| {
                s.update(c);
                Ok(())
            })
        }
        "xts" => {
            // Two keys of the cipher's width, one after the other,
            // as openssl takes them.
            let both = value::parse(&args.key, "key", false)?;
            let width = C::zero_key().as_ref().len();
            value::exact(&both, 2 * width, "xts key (two keys)")?;
            let mut k1 = C::zero_key();
            let mut k2 = C::zero_key();
            k1.as_mut().copy_from_slice(&both[..width]);
            k2.as_mut().copy_from_slice(&both[width..]);
            let xts = Xts::<C>::try_new(&k1, &k2)?;
            let tweak = iv()?;
            let mut data = read_all(input)?;
            if encrypt {
                xts.encrypt(&tweak, &mut data)?;
            } else {
                xts.decrypt(&tweak, &mut data)?;
            }
            io::write(out, &data, false)
        }
        "kw" | "kwp" => {
            refuse("--iv", args.iv.is_some())?;
            let key = value::key::<C>(&args.key, "key")?;
            let data = read_all(input)?;
            let mut wrapped = vec![0u8; data.len() + 16];
            let n = match (mode, encrypt) {
                ("kw", true) => Kw::<C>::new(&key).wrap(&data, &mut wrapped),
                ("kw", false) => Kw::<C>::new(&key).unwrap(&data, &mut wrapped),
                (_, true) => Kwp::<C>::new(&key).wrap(&data, &mut wrapped),
                (_, false) => Kwp::<C>::new(&key).unwrap(&data, &mut wrapped),
            }?;
            io::write(out, &wrapped[..n], false)
        }
        other => Err(usage!("unknown AES mode {other}")),
    }
}

/// Runs a whole-block mode over the input, adding padding on the way
/// in and removing it on the way out unless `--padding none`.
fn blocks(
    args: &CipherArgs,
    encrypt: bool,
    input: &mut dyn std::io::Read,
    out: &mut dyn Write,
    mut f: impl FnMut(&mut [u8]) -> Result<()>,
) -> Result<()> {
    const BLOCK: usize = 16;
    let padded = args.padding.unwrap_or(Padding::Pkcs7) == Padding::Pkcs7;
    // Decrypting with padding, the last block is held back so it can
    // be unpadded before it is written.
    let hold = if padded && !encrypt { BLOCK } else { 0 };
    let mut rest = io::stream_aligned(input, out, BLOCK, hold, &mut f)?;
    match (padded, encrypt) {
        (true, true) => {
            let len = rest.len();
            rest.resize(pkcs7::padded_len(len, BLOCK), 0);
            pkcs7::pad(&mut rest, len, BLOCK)?;
            f(&mut rest)?;
        }
        (true, false) => {
            if rest.len() != BLOCK {
                return Err(Error::InvalidPadding.into());
            }
            f(&mut rest)?;
            let n = pkcs7::unpad(&rest, BLOCK)?;
            rest.truncate(n);
        }
        (false, _) => {
            if !rest.is_empty() {
                return Err(Error::NotBlockAligned(rest.len()).into());
            }
        }
    }
    io::write(out, &rest, false)
}

/// ChaCha20, where encryption and decryption are the one operation.
fn chacha20(args: &CipherArgs) -> Result<()> {
    if args.iv.is_some() {
        return Err(usage!("chacha20 takes --nonce, not --iv"));
    }
    let key = Key::from(value::array::<32>(&args.key, "key")?);
    let nonce = args
        .nonce
        .as_deref()
        .ok_or_else(|| usage!("chacha20 needs --nonce"))?;
    let nonce = value::array::<12>(nonce, "nonce")?;
    let cipher = ChaCha20::new(&key);
    let mut stream = cipher.stream(&nonce, args.counter);
    let mut input = io::input(args.file.as_deref())?;
    let mut out = io::output(args.out.as_deref(), false)?;
    io::stream(&mut *input, &mut *out, |c| Ok(stream.update(c)?))
}

/// FF1 or FF3-1 over lines of text in the alphabet.
fn fpe<C>(args: &CipherArgs, encrypt: bool, ff3: bool) -> Result<()>
where
    C: BlockCipher<Block = [u8; 16]>,
{
    if args.iv.is_some() || args.nonce.is_some() || args.padding.is_some() {
        return Err(usage!("a format-preserving mode takes --tweak alone"));
    }
    let alphabet = match &args.alphabet {
        Some(a) => Alphabet::try_new(a)?,
        None => DIGITS,
    };
    let key = value::key::<C>(&args.key, "key")?;
    let tweak = value::text(args.tweak.as_deref(), "tweak")?;
    let mut raw = read_all(&mut *io::input(args.file.as_deref())?)?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| usage!("the input is not UTF-8 text"))?;
    let mut out = io::output(args.out.as_deref(), false)?;
    let mut symbols = Vec::new();
    let mut line_out = Vec::new();
    macro_rules! each_line {
        ($apply:expr) => {
            for line in text.lines() {
                symbols.resize(line.chars().count(), 0);
                alphabet.encode(line, &mut symbols)?;
                $apply(&mut symbols)?;
                line_out.resize(symbols.len() * 4, 0);
                let n = alphabet.decode(&symbols, &mut line_out)?;
                out.write_all(&line_out[..n])?;
                out.write_all(b"\n")?;
            }
        };
    }
    if ff3 {
        let tweak: &[u8; 7] = (&tweak[..])
            .try_into()
            .map_err(|_| usage!("ff3-1 takes a 7-byte --tweak"))?;
        let mode = Ff3_1::<C>::try_new(&key, alphabet.radix())?;
        each_line!(|s: &mut Vec<u16>| if encrypt {
            mode.encrypt(tweak, s)
        } else {
            mode.decrypt(tweak, s)
        });
    } else {
        let mode = Ff1::<C>::try_new(&key, alphabet.radix())?;
        each_line!(|s: &mut Vec<u16>| if encrypt {
            mode.encrypt(&tweak, s)
        } else {
            mode.decrypt(&tweak, s)
        });
    }
    out.flush()?;
    // Both held the plaintext.
    symbols.zeroize();
    raw.zeroize();
    Ok(())
}

fn read_all(input: &mut dyn std::io::Read) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;
    Ok(data)
}
