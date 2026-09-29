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

use crate::fail::{Result, usage, verify};
use crate::names::{self, Entry};
use crate::{io, value};

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
            other => Err($crate::fail::usage!("no AES of {other} bits")),
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
    /// Wrap a key with aes-*-kw or aes-*-kwp
    Wrap(WrapArgs),
    /// Unwrap a key with aes-*-kw or aes-*-kwp
    Unwrap(WrapArgs),
}

impl CipherOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        match self {
            CipherOp::Encrypt(a) => format!("encrypt {}", a.algorithm),
            CipherOp::Decrypt(a) => format!("decrypt {}", a.algorithm),
            CipherOp::Wrap(a) => format!("wrap {}", a.algorithm),
            CipherOp::Unwrap(a) => format!("unwrap {}", a.algorithm),
        }
    }
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
    pub algorithm: String,
    /// The key (hex:, file:, fd:, env:)
    #[arg(short, long)]
    key: String,
    /// The IV, first counter block or XTS tweak: one 16-byte block
    #[arg(long)]
    iv: Option<String>,
    /// The nonce, for chacha20 (12 bytes)
    #[arg(short, long)]
    nonce: Option<String>,
    /// The first block counter, for chacha20
    #[arg(long, default_value_t = 0)]
    counter: u32,
    /// Required for ecb, cbc and cfb128: pkcs7 or none
    #[arg(long)]
    padding: Option<Padding>,
    /// The second key, for xts
    #[arg(long)]
    tweak_key: Option<String>,
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

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct WrapArgs {
    /// The wrap: aes-128-kw, aes-256-kwp, ...
    pub algorithm: String,
    /// The wrapping key (hex:, file:, fd:, env:)
    #[arg(short, long)]
    key: String,
    /// The file holding the key to wrap or unwrap; standard input
    /// without one
    file: Option<PathBuf>,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: CipherOp) -> Result<()> {
    match op {
        CipherOp::Encrypt(args) => transform(&args, true),
        CipherOp::Decrypt(args) => transform(&args, false),
        CipherOp::Wrap(args) => wrap(&args, true),
        CipherOp::Unwrap(args) => wrap(&args, false),
    }
}

fn transform(args: &CipherArgs, encrypt: bool) -> Result<()> {
    let entry = names::CIPHER.find(&args.algorithm)?;
    let name = entry.name;
    if let Some(rest) = name.strip_prefix("aes-") {
        let (bits, mode) = rest.split_once('-').unwrap_or((rest, ""));
        if mode == "kw" || mode == "kwp" {
            return Err(usage!(
                "{name} wraps keys; scytale cipher {} does that",
                if encrypt { "wrap" } else { "unwrap" }
            ));
        }
        return with_aes!(bits, C => aes::<C>(entry, mode, args, encrypt));
    }
    if name == "chacha20" {
        return chacha20(entry, args);
    }
    let ff3 = name.starts_with("ff3-1-");
    let bits = name.rsplit('-').next().unwrap_or("");
    with_aes!(bits, C => fpe::<C>(entry, args, encrypt, ff3))
}

/// Refuses the options `name` does not take, naming what they are
/// for; `takes` lists the ones it does.
fn only(args: &CipherArgs, name: &str, takes: &[&str]) -> Result<()> {
    let given: [(&str, bool, &str); 7] = [
        ("--iv", args.iv.is_some(), "the block modes"),
        ("--nonce", args.nonce.is_some(), "chacha20"),
        ("--counter", args.counter != 0, "chacha20"),
        ("--padding", args.padding.is_some(), "ecb, cbc and cfb128"),
        ("--tweak-key", args.tweak_key.is_some(), "xts"),
        ("--alphabet", args.alphabet.is_some(), "ff1 and ff3-1"),
        ("--tweak", args.tweak.is_some(), "ff1 and ff3-1"),
    ];
    for (option, is_given, whose) in given {
        if is_given && !takes.contains(&option) {
            return Err(usage!(
                "{name} takes no {option}; that is for {whose}"
            ));
        }
    }
    Ok(())
}

/// One AES mode, by name.
fn aes<C>(
    entry: &Entry,
    mode: &str,
    args: &CipherArgs,
    encrypt: bool,
) -> Result<()>
where
    C: BlockCipher<Block = [u8; 16]>,
{
    let name = entry.name;
    let takes: &[&str] = match mode {
        "ecb" => &["--padding"],
        "cbc" | "cfb128" => &["--iv", "--padding"],
        "xts" => &["--iv", "--tweak-key"],
        _ => &["--iv"],
    };
    only(args, name, takes)?;
    let iv = || -> Result<C::Block> {
        let Some(iv) = args.iv.as_deref() else {
            return Err(usage!(
                "--iv is required: {}",
                match mode {
                    "ctr" => "the first counter block, 16 bytes",
                    "xts" => "the sector's tweak, 16 bytes",
                    _ => "one 16-byte block, never reused under a key",
                }
            ));
        };
        value::block::<C>(iv, "--iv", name)
    };
    let padding = || -> Result<bool> {
        match args.padding {
            Some(Padding::Pkcs7) => Ok(true),
            Some(Padding::None) => Ok(false),
            None => Err(usage!(
                "--padding is required for {mode}: pkcs7 (what openssl \
                 enc and CMS use) or none (whole 16-byte blocks only)"
            )),
        }
    };
    let key = || value::key::<C>(&args.key, "--key", name);
    let mut input = io::input(args.file.as_deref())?;
    let mut out = io::output(args.out.as_deref(), false)?;
    let input = &mut *input;
    let out = &mut *out;
    match mode {
        "ecb" => {
            let padded = padding()?;
            let cipher = C::new(&key()?);
            blocks(padded, encrypt, name, input, out, |chunk| {
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
            let padded = padding()?;
            let cbc = Cbc::<C>::new(&key()?);
            let iv = iv()?;
            if encrypt {
                let mut e = cbc.encryptor(&iv);
                blocks(padded, encrypt, name, input, out, |c| Ok(e.update(c)?))
            } else {
                let mut d = cbc.decryptor(&iv);
                blocks(padded, encrypt, name, input, out, |c| Ok(d.update(c)?))
            }
        }
        "cfb128" => {
            let padded = padding()?;
            let cfb = Cfb128::<C>::new(&key()?);
            let iv = iv()?;
            if encrypt {
                let mut e = cfb.encryptor(&iv);
                blocks(padded, encrypt, name, input, out, |c| Ok(e.update(c)?))
            } else {
                let mut d = cfb.decryptor(&iv);
                blocks(padded, encrypt, name, input, out, |c| Ok(d.update(c)?))
            }
        }
        "cfb8" => {
            let cfb = Cfb8::<C>::new(&key()?);
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
            let cfb = Cfb1::<C>::new(&key()?);
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
            let ofb = Ofb::<C>::new(&key()?);
            let mut s = ofb.stream(&iv()?);
            io::stream(input, out, |c| {
                s.update(c);
                Ok(())
            })
        }
        "ctr" => {
            let ctr = Ctr::<C>::new(&key()?);
            let mut s = ctr.stream(&iv()?);
            io::stream(input, out, |c| {
                s.update(c);
                Ok(())
            })
        }
        "xts" => {
            let k1 = key()?;
            let Some(second) = args.tweak_key.as_deref() else {
                return Err(usage!(
                    "--tweak-key is required: XTS runs two keys of {}, \
                     and they must differ",
                    entry.key.describe()
                ));
            };
            let k2 = value::key::<C>(second, "--tweak-key", name)?;
            let xts = Xts::<C>::try_new(&k1, &k2).map_err(|_| {
                usage!(
                    "--key and --tweak-key are the same {}; XTS needs \
                     two different keys",
                    entry.key.describe()
                )
            })?;
            let tweak = iv()?;
            let mut data = read_all(input)?;
            if data.len() < 16 {
                return Err(usage!(
                    "the input is {} bytes; XTS takes a sector of at \
                     least one 16-byte block",
                    data.len()
                ));
            }
            if encrypt {
                xts.encrypt(&tweak, &mut data)?;
            } else {
                xts.decrypt(&tweak, &mut data)?;
            }
            io::write(out, &data, false)
        }
        other => Err(usage!("no AES mode named \"{other}\"")),
    }
}

/// Runs a whole-block mode over the input, adding padding on the way
/// in and removing it on the way out when `padded`.
fn blocks(
    padded: bool,
    encrypt: bool,
    name: &str,
    input: &mut dyn std::io::Read,
    out: &mut dyn Write,
    mut f: impl FnMut(&mut [u8]) -> Result<()>,
) -> Result<()> {
    const BLOCK: usize = 16;
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
                return Err(verify!(
                    "the input is not whole 16-byte blocks, so it was not \
                     made by {name} with pkcs7 padding"
                ));
            }
            f(&mut rest)?;
            let n = pkcs7::unpad(&rest, BLOCK).map_err(|_| {
                verify!(
                    "the padding is not valid: wrong key, wrong IV, or an \
                     altered ciphertext"
                )
            })?;
            rest.truncate(n);
        }
        (false, _) => {
            if !rest.is_empty() {
                return Err(usage!(
                    "the input is not whole 16-byte blocks ({} left \
                     over), and --padding none takes nothing else; \
                     --padding pkcs7 fills the last block",
                    rest.len()
                ));
            }
        }
    }
    io::write(out, &rest, false)
}

/// ChaCha20, where encryption and decryption are the one operation.
fn chacha20(entry: &Entry, args: &CipherArgs) -> Result<()> {
    let name = entry.name;
    if args.iv.is_some() {
        return Err(usage!("chacha20 takes --nonce (12 bytes), not --iv"));
    }
    only(args, name, &["--nonce", "--counter"])?;
    let key = Key::from(value::array::<32>(&args.key, "--key", name)?);
    let Some(nonce) = args.nonce.as_deref() else {
        return Err(usage!(
            "--nonce is required: 12 bytes, never reused under a key"
        ));
    };
    let nonce = value::array::<12>(nonce, "--nonce", name)?;
    let cipher = ChaCha20::new(&key);
    let mut stream = cipher.stream(&nonce, args.counter);
    let mut input = io::input(args.file.as_deref())?;
    let mut out = io::output(args.out.as_deref(), false)?;
    io::stream(&mut *input, &mut *out, |c| Ok(stream.update(c)?))
}

/// FF1 or FF3-1 over lines of text in the alphabet.
fn fpe<C>(
    entry: &Entry,
    args: &CipherArgs,
    encrypt: bool,
    ff3: bool,
) -> Result<()>
where
    C: BlockCipher<Block = [u8; 16]>,
{
    let name = entry.name;
    only(args, name, &["--alphabet", "--tweak"])?;
    let alphabet = match &args.alphabet {
        Some(a) => Alphabet::try_new(a).map_err(|e| match e {
            Error::InvalidRadix(n) => {
                usage!("--alphabet has {n} characters; 2 to 65536 are needed")
            }
            Error::InvalidSymbol(c) => usage!(
                "--alphabet repeats \"{}\"; each numeral is one character",
                char::from_u32(c).unwrap_or('?')
            ),
            other => other.into(),
        })?,
        None => DIGITS,
    };
    let key = value::key::<C>(&args.key, "--key", name)?;
    let tweak = value::text(args.tweak.as_deref(), "--tweak")?;
    let mut raw = read_all(&mut *io::input(args.file.as_deref())?)?;
    let text = std::str::from_utf8(&raw).map_err(|_| {
        usage!("the input is not UTF-8 text; {name} works on lines of text")
    })?;
    let mut out = io::output(args.out.as_deref(), false)?;
    let mut symbols = Vec::new();
    let mut line_out = Vec::new();
    let mut lines = text.lines().enumerate();
    let mut next = |symbols: &mut Vec<u16>| -> Result<Option<usize>> {
        let Some((i, line)) = lines.next() else {
            return Ok(None);
        };
        symbols.resize(line.chars().count(), 0);
        alphabet.encode(line, symbols).map_err(|e| match e {
            Error::InvalidSymbol(c) => usage!(
                "line {}: \"{}\" is not in the alphabet {}",
                i + 1,
                char::from_u32(c).unwrap_or('?'),
                alphabet.symbols()
            ),
            other => other.into(),
        })?;
        Ok(Some(i + 1))
    };
    let mut emit = |symbols: &[u16], out: &mut dyn Write| -> Result<()> {
        line_out.resize(symbols.len() * 4, 0);
        let n = alphabet.decode(symbols, &mut line_out)?;
        out.write_all(&line_out[..n])?;
        Ok(out.write_all(b"\n")?)
    };
    let too_short = |line: usize| -> crate::fail::Fail {
        usage!(
            "line {line}: too few symbols for {name} in this alphabet to \
             encrypt safely; the domain must have at least a million \
             values"
        )
    };
    if ff3 {
        let tweak: &[u8; 7] = (&tweak[..]).try_into().map_err(|_| {
            usage!("--tweak is {} bytes; ff3-1 takes exactly 7", tweak.len())
        })?;
        let mode = Ff3_1::<C>::try_new(&key, alphabet.radix())?;
        while let Some(line) = next(&mut symbols)? {
            let r = if encrypt {
                mode.encrypt(tweak, &mut symbols)
            } else {
                mode.decrypt(tweak, &mut symbols)
            };
            r.map_err(|e| match e {
                Error::DomainTooSmall => too_short(line),
                other => other.into(),
            })?;
            emit(&symbols, &mut *out)?;
        }
    } else {
        let mode = Ff1::<C>::try_new(&key, alphabet.radix())?;
        while let Some(line) = next(&mut symbols)? {
            let r = if encrypt {
                mode.encrypt(&tweak, &mut symbols)
            } else {
                mode.decrypt(&tweak, &mut symbols)
            };
            r.map_err(|e| match e {
                Error::DomainTooSmall => too_short(line),
                other => other.into(),
            })?;
            emit(&symbols, &mut *out)?;
        }
    }
    out.flush()?;
    // Both held the plaintext.
    symbols.zeroize();
    raw.zeroize();
    Ok(())
}

/// KW and KWP.
fn wrap(args: &WrapArgs, wrap: bool) -> Result<()> {
    let entry = names::CIPHER.find(&args.algorithm)?;
    let name = entry.name;
    let Some((bits, mode)) =
        name.strip_prefix("aes-").and_then(|r| r.split_once('-'))
    else {
        return Err(usage!("{name} does not wrap keys; kw and kwp do"));
    };
    if mode != "kw" && mode != "kwp" {
        return Err(usage!(
            "{name} does not wrap keys; aes-{bits}-kw or aes-{bits}-kwp \
             does, and scytale cipher encrypt runs {mode}"
        ));
    }
    with_aes!(bits, C => {
        let key = value::key::<C>(&args.key, "--key", name)?;
        let data = io::read_all(args.file.as_deref())?;
        if mode == "kw" && (data.len() < 16 || data.len() % 8 != 0) {
            return Err(usage!(
                "the input is {} bytes; {name} takes whole 8-byte blocks, \
                 two or more, and kwp takes any length",
                data.len()
            ));
        }
        let least = if mode == "kw" { 24 } else { 16 };
        if !wrap && data.len() < least {
            return Err(usage!(
                "the input is {} bytes; a key {name} wrapped is at least \
                 {least}: the key, padded to 8-byte blocks, and 8 bytes of \
                 check value",
                data.len()
            ));
        }
        let mut buf = vec![0u8; data.len() + 16];
        let n = match (mode, wrap) {
            ("kw", true) => Kw::<C>::new(&key).wrap(&data, &mut buf),
            ("kw", false) => Kw::<C>::new(&key).unwrap(&data, &mut buf),
            (_, true) => Kwp::<C>::new(&key).wrap(&data, &mut buf),
            (_, false) => Kwp::<C>::new(&key).unwrap(&data, &mut buf),
        }
        .map_err(|e| match e {
            Error::AuthenticationFailed => verify!(
                "the check value did not verify: wrong key, or an altered \
                 wrapped key"
            ),
            other => other.into(),
        })?;
        let mut out = io::output(args.out.as_deref(), !wrap)?;
        io::write(&mut *out, &buf[..n], false)
    })
}

fn read_all(input: &mut dyn std::io::Read) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::Len;
    use scytale::KeyType;

    /// The table's key length is the type's, for every name.
    #[test]
    fn table_matches_types() {
        for entry in names::CIPHER.iter() {
            let n = if entry.name == "chacha20" {
                32
            } else {
                let bits = entry
                    .name
                    .split('-')
                    .find(|w| matches!(*w, "128" | "192" | "256"))
                    .unwrap_or("");
                with_aes!(bits, C => Ok::<usize, crate::fail::Fail>(
                    <C as KeyType>::zero_key().as_ref().len()
                ))
                .unwrap()
            };
            assert_eq!(entry.key, Len::Exact(n), "{}", entry.name);
        }
    }
}
