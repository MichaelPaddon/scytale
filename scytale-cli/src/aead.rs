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
use crate::fail::{Result, usage, verify};
use crate::names::{self, Entry};
use crate::{io, value};

#[derive(Subcommand)]
pub enum AeadOp {
    /// Encrypt and tag the input
    Encrypt(AeadArgs),
    /// Check the tag and decrypt the input
    Decrypt(AeadArgs),
}

impl AeadOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        match self {
            AeadOp::Encrypt(a) => format!("encrypt {}", a.algorithm),
            AeadOp::Decrypt(a) => format!("decrypt {}", a.algorithm),
        }
    }
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct AeadArgs {
    /// The construction: aes-256-gcm, chacha20-poly1305, ...
    pub algorithm: String,
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
    let entry = names::AEAD.find(&args.algorithm)?;
    let name = entry.name;
    if !entry.tag.allows(args.tag_length) {
        return Err(usage!(
            "--tag-length {}: {name} takes a tag of {}",
            args.tag_length,
            entry.tag.describe()
        ));
    }
    if name == "chacha20-poly1305" {
        return chacha20_poly1305(entry, &args, encrypt);
    }
    let Some((bits, mode)) =
        name.strip_prefix("aes-").and_then(|r| r.split_once('-'))
    else {
        return Err(usage!("no AEAD named \"{name}\""));
    };
    match mode {
        "gcm" => with_aes!(bits, C => gcm::<C>(entry, &args, encrypt)),
        "gcm-siv" => match bits {
            "128" => gcm_siv::<Aes128>(entry, &args, encrypt),
            _ => gcm_siv::<Aes256>(entry, &args, encrypt),
        },
        "ccm" => with_aes!(bits, C => ccm::<C>(entry, &args, encrypt)),
        _ => with_aes!(bits, C => xpn::<C>(entry, &args, encrypt)),
    }
}

/// Reads the whole input and splits the tag off the end.
fn read_sealed(entry: &Entry, args: &AeadArgs) -> Result<(Vec<u8>, Vec<u8>)> {
    let tag_len = args.tag_length;
    let mut data = io::read_all(args.file.as_deref())?;
    if data.len() < tag_len {
        return Err(usage!(
            "the input is {} bytes, shorter than the {tag_len}-byte tag \
             {} appends",
            data.len(),
            entry.name
        ));
    }
    let tag = data.split_off(data.len() - tag_len);
    Ok((data, tag))
}

/// The nonce, checked against the table.
fn nonce(
    entry: &Entry,
    args: &AeadArgs,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    value::checked(&args.nonce, "--nonce", entry.nonce, entry.name)
}

fn gcm<C: BlockCipher<Block = [u8; 16]>>(
    entry: &Entry,
    args: &AeadArgs,
    encrypt: bool,
) -> Result<()> {
    let key = value::key::<C>(&args.key, "--key", entry.name)?;
    let nonce = nonce(entry, args)?;
    let aad = value::text(args.aad.as_deref(), "--aad")?;
    let gcm = Gcm::<C>::new(&key);
    let mut out = io::output(args.out.as_deref(), false)?;
    if encrypt {
        let mut input = io::input(args.file.as_deref())?;
        let mut e = gcm.encryptor(&nonce)?;
        e.aad(&aad)?;
        io::stream(&mut *input, &mut *out, |c| Ok(e.update(c)?))?;
        let tag = e.finalize();
        io::write(&mut *out, &tag[..args.tag_length], false)
    } else {
        let (mut data, tag) = read_sealed(entry, args)?;
        let mut d = gcm.decryptor(&nonce)?;
        d.aad(&aad)?;
        d.update(&mut data)?;
        if d.verify_truncated(&tag).is_err() {
            data.zeroize();
            return Err(not_authentic());
        }
        io::write(&mut *out, &data, false)
    }
}

fn not_authentic() -> crate::fail::Fail {
    verify!(
        "the message did not authenticate under this key, nonce and \
         additional data; nothing was written"
    )
}

fn chacha20_poly1305(
    entry: &Entry,
    args: &AeadArgs,
    encrypt: bool,
) -> Result<()> {
    let key = value::key::<ChaCha20Poly1305>(&args.key, "--key", entry.name)?;
    let nonce = value::array::<12>(&args.nonce, "--nonce", entry.name)?;
    let aad = value::text(args.aad.as_deref(), "--aad")?;
    let aead = ChaCha20Poly1305::new(&key);
    let mut out = io::output(args.out.as_deref(), false)?;
    if encrypt {
        let mut input = io::input(args.file.as_deref())?;
        let mut e = aead.encryptor(&nonce)?;
        e.aad(&aad)?;
        io::stream(&mut *input, &mut *out, |c| Ok(e.update(c)?))?;
        io::write(&mut *out, &e.finalize(), false)
    } else {
        let (mut data, tag) = read_sealed(entry, args)?;
        let tag: [u8; 16] =
            tag.as_slice().try_into().map_err(|_| not_authentic())?;
        let mut d = aead.decryptor(&nonce)?;
        d.aad(&aad)?;
        d.update(&mut data)?;
        if d.verify(&tag).is_err() {
            data.zeroize();
            return Err(not_authentic());
        }
        io::write(&mut *out, &data, false)
    }
}

/// The one-shot constructions: the whole input in memory, the tag
/// made or checked in the same call as the transform.
fn one_shot(
    entry: &Entry,
    args: &AeadArgs,
    encrypt: bool,
    f: impl FnOnce(&mut [u8], &mut [u8]) -> Result<()>,
) -> Result<()> {
    let mut out = io::output(args.out.as_deref(), false)?;
    if encrypt {
        let mut data = io::read_all(args.file.as_deref())?;
        let mut tag = vec![0u8; args.tag_length];
        f(&mut data, &mut tag)?;
        io::write(&mut *out, &data, false)?;
        io::write(&mut *out, &tag, false)
    } else {
        let (mut data, mut tag) = read_sealed(entry, args)?;
        // The library wipes the buffer on a failed check.
        f(&mut data, &mut tag)?;
        io::write(&mut *out, &data, false)
    }
}

fn gcm_siv<C>(entry: &Entry, args: &AeadArgs, encrypt: bool) -> Result<()>
where
    C: BlockCipher<Block = [u8; 16]>,
    C::Key: SivKey,
{
    let key = value::key::<C>(&args.key, "--key", entry.name)?;
    let nonce = value::array::<12>(&args.nonce, "--nonce", entry.name)?;
    let aad = value::text(args.aad.as_deref(), "--aad")?;
    let aead = GcmSiv::<C>::new(&key);
    one_shot(entry, args, encrypt, |data, tag| {
        let tag: &mut [u8; 16] = tag.try_into().map_err(|_| not_authentic())?;
        if encrypt {
            aead.encrypt(&nonce, &aad, data, tag)?;
        } else {
            aead.decrypt(&nonce, &aad, data, tag)?;
        }
        Ok(())
    })
}

fn ccm<C: BlockCipher<Block = [u8; 16]>>(
    entry: &Entry,
    args: &AeadArgs,
    encrypt: bool,
) -> Result<()> {
    let key = value::key::<C>(&args.key, "--key", entry.name)?;
    let nonce = nonce(entry, args)?;
    let aad = value::text(args.aad.as_deref(), "--aad")?;
    let aead = Ccm::<C>::new(&key);
    one_shot(entry, args, encrypt, |data, tag| {
        if encrypt {
            aead.encrypt(&nonce, &aad, data, tag)?;
        } else {
            aead.decrypt(&nonce, &aad, data, tag)?;
        }
        Ok(())
    })
}

fn xpn<C: BlockCipher<Block = [u8; 16]>>(
    entry: &Entry,
    args: &AeadArgs,
    encrypt: bool,
) -> Result<()> {
    let key = value::key::<C>(&args.key, "--key", entry.name)?;
    let both = value::array::<24>(&args.nonce, "--nonce", entry.name)?;
    let mut salt = [0u8; 12];
    let mut frame = [0u8; 12];
    salt.copy_from_slice(&both[..12]);
    frame.copy_from_slice(&both[12..]);
    let aad = value::text(args.aad.as_deref(), "--aad")?;
    let aead = Xpn::<C>::new(&key);
    one_shot(entry, args, encrypt, |data, tag| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::Len;

    /// The table's key length is the type's, for every name.
    #[test]
    fn table_matches_types() {
        for entry in names::AEAD.iter() {
            let n = if entry.name == "chacha20-poly1305" {
                32
            } else {
                let bits = &entry.name[4..7];
                with_aes!(bits, C => Ok::<usize, crate::fail::Fail>(
                    <C as scytale::KeyType>::zero_key().as_ref().len()
                ))
                .unwrap()
            };
            assert_eq!(entry.key, Len::Exact(n), "{}", entry.name);
        }
    }
}
