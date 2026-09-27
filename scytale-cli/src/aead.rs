//! `scytale aead`: authenticated encryption, the tag after the
//! ciphertext.
//!
//! Encryption with GCM or ChaCha20-Poly1305 streams: the ciphertext
//! goes out as it is made and the tag follows it. Decryption never
//! streams. The whole ciphertext is read, the tag checked, and only
//! then is any plaintext written, since a decryptor that hands out
//! plaintext before the tag is checked hands out something an
//! attacker chose.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::aead::{Aead, Ccm, ChaCha20Poly1305, Gcm, GcmSiv, SivKey, Xpn};
use scytale::cipher::BlockCipher;
use scytale::cipher::aes::{Aes128, Aes192, Aes256};
use zeroize::Zeroize;

use crate::cipher::with_aes;
use crate::fail::{Fail, Result, usage};
use crate::{io, value};

/// The constructions, as `--algorithm` names them.
pub const NAMES: [&str; 12] = [
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "aes-128-gcm-siv",
    "aes-256-gcm-siv",
    "aes-128-ccm",
    "aes-192-ccm",
    "aes-256-ccm",
    "aes-128-xpn",
    "aes-192-xpn",
    "aes-256-xpn",
    "chacha20-poly1305",
];

#[derive(Subcommand)]
pub enum AeadOp {
    /// Encrypt and tag the input
    Encrypt(AeadArgs),
    /// Check the tag and decrypt the input
    Decrypt(AeadArgs),
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct AeadArgs {
    /// The construction: aes-256-gcm, chacha20-poly1305, ...
    #[arg(short, long)]
    algorithm: String,
    /// The key (hex:, file:, fd:, env:)
    #[arg(short, long)]
    key: String,
    /// The nonce: 12 bytes, or 7 to 13 for ccm, 24 for xpn
    #[arg(short, long)]
    nonce: String,
    /// Additional data, authenticated but not encrypted (str: allowed)
    #[arg(long)]
    aad: Option<String>,
    /// Bytes of tag; 16, or fewer where the construction allows
    #[arg(long, default_value_t = 16)]
    tag_length: usize,
    /// The file to transform; standard input without one
    file: Option<PathBuf>,
    /// Write to this file rather than standard output
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: AeadOp) -> Result<()> {
    let (args, encrypt) = match op {
        AeadOp::Encrypt(args) => (args, true),
        AeadOp::Decrypt(args) => (args, false),
    };
    let name = args.algorithm.as_str();
    if name == "chacha20-poly1305" {
        return chacha20_poly1305(&args, encrypt);
    }
    let Some((bits, mode)) =
        name.strip_prefix("aes-").and_then(|r| r.split_once('-'))
    else {
        return Err(usage!("unknown aead {name}"));
    };
    match mode {
        "gcm" => with_aes!(bits, C => gcm::<C>(&args, encrypt)),
        "gcm-siv" => match bits {
            "128" => gcm_siv::<Aes128>(&args, encrypt),
            "256" => gcm_siv::<Aes256>(&args, encrypt),
            _ => Err(usage!("gcm-siv is defined for 128 and 256 bits")),
        },
        "ccm" => with_aes!(bits, C => ccm::<C>(&args, encrypt)),
        "xpn" => with_aes!(bits, C => xpn::<C>(&args, encrypt)),
        _ => Err(usage!("unknown aead {name}")),
    }
}

fn tag_length(
    args: &AeadArgs,
    allowed: impl Fn(usize) -> bool,
) -> Result<usize> {
    let n = args.tag_length;
    if allowed(n) {
        Ok(n)
    } else {
        Err(usage!(
            "--tag-length {n}: not a length this construction allows"
        ))
    }
}

/// Reads the whole input and splits the tag off the end.
fn read_sealed(args: &AeadArgs, tag_len: usize) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut data = io::read_all(args.file.as_deref())?;
    if data.len() < tag_len {
        return Err(usage!("the input is shorter than the tag"));
    }
    let tag = data.split_off(data.len() - tag_len);
    Ok((data, tag))
}

fn gcm<C: BlockCipher<Block = [u8; 16]>>(
    args: &AeadArgs,
    encrypt: bool,
) -> Result<()> {
    let key = value::key::<C>(&args.key, "key")?;
    let gcm = Gcm::<C>::new(&key);
    let nonce = value::parse(&args.nonce, "nonce", false)?;
    let aad = value::text(args.aad.as_deref(), "aad")?;
    let tag_len = tag_length(args, |n| (4..=16).contains(&n))?;
    let mut out = io::output(args.out.as_deref(), false)?;
    if encrypt {
        let mut input = io::input(args.file.as_deref())?;
        let mut e = gcm.encryptor(&nonce)?;
        e.aad(&aad)?;
        io::stream(&mut *input, &mut *out, |c| Ok(e.update(c)?))?;
        let tag = e.finalize();
        io::write(&mut *out, &tag[..tag_len], false)
    } else {
        let (mut data, tag) = read_sealed(args, tag_len)?;
        let mut d = gcm.decryptor(&nonce)?;
        d.aad(&aad)?;
        d.update(&mut data)?;
        if d.verify_truncated(&tag).is_err() {
            data.zeroize();
            return Err(Fail::Verify);
        }
        io::write(&mut *out, &data, false)
    }
}

fn chacha20_poly1305(args: &AeadArgs, encrypt: bool) -> Result<()> {
    let key = value::key::<ChaCha20Poly1305>(&args.key, "key")?;
    let aead = ChaCha20Poly1305::new(&key);
    let nonce = value::array::<12>(&args.nonce, "nonce")?;
    let aad = value::text(args.aad.as_deref(), "aad")?;
    tag_length(args, |n| n == 16)?;
    let mut out = io::output(args.out.as_deref(), false)?;
    if encrypt {
        let mut input = io::input(args.file.as_deref())?;
        let mut e = aead.encryptor(&nonce)?;
        e.aad(&aad)?;
        io::stream(&mut *input, &mut *out, |c| Ok(e.update(c)?))?;
        io::write(&mut *out, &e.finalize(), false)
    } else {
        let (mut data, tag) = read_sealed(args, 16)?;
        let tag: [u8; 16] =
            tag.as_slice().try_into().map_err(|_| Fail::Verify)?;
        let mut d = aead.decryptor(&nonce)?;
        d.aad(&aad)?;
        d.update(&mut data)?;
        if d.verify(&tag).is_err() {
            data.zeroize();
            return Err(Fail::Verify);
        }
        io::write(&mut *out, &data, false)
    }
}

/// The one-shot constructions: the whole input in memory, the tag
/// made or checked in the same call as the transform.
fn one_shot(
    args: &AeadArgs,
    encrypt: bool,
    tag_len: usize,
    f: impl FnOnce(&mut [u8], &mut [u8]) -> Result<()>,
) -> Result<()> {
    let mut out = io::output(args.out.as_deref(), false)?;
    if encrypt {
        let mut data = io::read_all(args.file.as_deref())?;
        let mut tag = vec![0u8; tag_len];
        f(&mut data, &mut tag)?;
        io::write(&mut *out, &data, false)?;
        io::write(&mut *out, &tag, false)
    } else {
        let (mut data, mut tag) = read_sealed(args, tag_len)?;
        // The library wipes the buffer on a failed check.
        f(&mut data, &mut tag)?;
        io::write(&mut *out, &data, false)
    }
}

fn gcm_siv<C>(args: &AeadArgs, encrypt: bool) -> Result<()>
where
    C: BlockCipher<Block = [u8; 16]>,
    C::Key: SivKey,
{
    let key = value::key::<C>(&args.key, "key")?;
    let aead = GcmSiv::<C>::new(&key);
    let nonce = value::array::<12>(&args.nonce, "nonce")?;
    let aad = value::text(args.aad.as_deref(), "aad")?;
    let tag_len = tag_length(args, |n| n == 16)?;
    one_shot(args, encrypt, tag_len, |data, tag| {
        let tag: &mut [u8; 16] = tag.try_into().map_err(|_| Fail::Verify)?;
        if encrypt {
            aead.encrypt(&nonce, &aad, data, tag)?;
        } else {
            aead.decrypt(&nonce, &aad, data, tag)?;
        }
        Ok(())
    })
}

fn ccm<C: BlockCipher<Block = [u8; 16]>>(
    args: &AeadArgs,
    encrypt: bool,
) -> Result<()> {
    let key = value::key::<C>(&args.key, "key")?;
    let aead = Ccm::<C>::new(&key);
    let nonce = value::parse(&args.nonce, "nonce", false)?;
    let aad = value::text(args.aad.as_deref(), "aad")?;
    let tag_len = tag_length(args, |n| (4..=16).contains(&n) && n % 2 == 0)?;
    one_shot(args, encrypt, tag_len, |data, tag| {
        if encrypt {
            aead.encrypt(&nonce, &aad, data, tag)?;
        } else {
            aead.decrypt(&nonce, &aad, data, tag)?;
        }
        Ok(())
    })
}

fn xpn<C: BlockCipher<Block = [u8; 16]>>(
    args: &AeadArgs,
    encrypt: bool,
) -> Result<()> {
    let key = value::key::<C>(&args.key, "key")?;
    let aead = Xpn::<C>::new(&key);
    let both = value::array::<24>(&args.nonce, "nonce (salt || frame)")?;
    let mut salt = [0u8; 12];
    let mut frame = [0u8; 12];
    salt.copy_from_slice(&both[..12]);
    frame.copy_from_slice(&both[12..]);
    let aad = value::text(args.aad.as_deref(), "aad")?;
    let tag_len = tag_length(args, |n| (4..=16).contains(&n))?;
    one_shot(args, encrypt, tag_len, |data, tag| {
        if encrypt {
            let mut full = [0u8; 16];
            aead.encrypt(&salt, &frame, &aad, data, &mut full)?;
            tag.copy_from_slice(&full[..tag.len()]);
        } else {
            aead.decrypt_truncated(&salt, &frame, &aad, data, tag)?;
        }
        Ok(())
    })
}
