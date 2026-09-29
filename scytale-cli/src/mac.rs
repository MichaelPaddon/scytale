//! `scytale mac tag` and `scytale mac verify`: a tag over the input,
//! or a check of one.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::cipher::aes::{Aes128, Aes192, Aes256};
use scytale::constant_time;
use scytale::mac::Mac;
use scytale::mac::cmac::Cmac;
use scytale::mac::hmac::Hmac;
use scytale::mac::kmac::{Kmac128, Kmac256};
use scytale::mac::poly1305::Poly1305;

use crate::fail::{Result, usage, verify};
use crate::hash::with_hash;
use crate::io::Format;
use crate::names::{self, Entry};
use crate::{io, value};

#[derive(Subcommand)]
pub enum MacOp {
    /// A tag over the input
    Tag(TagArgs),
    /// Check the input against a tag
    Verify(VerifyArgs),
}

impl MacOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        match self {
            MacOp::Tag(a) => format!("tag {}", a.common.algorithm),
            MacOp::Verify(a) => format!("verify {}", a.common.algorithm),
        }
    }
}

#[derive(Args)]
pub struct Common {
    /// The MAC: hmac-sha256, cmac-aes-128, kmac256, poly1305, ...
    pub algorithm: String,
    /// The key (hex:, file:, fd:, env:)
    #[arg(short, long)]
    key: String,
    /// Bytes of tag, for kmac
    #[arg(short, long)]
    length: Option<usize>,
    /// The customization string, for kmac
    #[arg(long)]
    customization: Option<String>,
    /// The file to authenticate; standard input without one
    file: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct TagArgs {
    #[command(flatten)]
    common: Common,
    /// Hex by default
    #[command(flatten)]
    format: Format,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct VerifyArgs {
    #[command(flatten)]
    common: Common,
    /// The tag to check against (hex:, file:, fd:, env:)
    #[arg(short, long)]
    tag: String,
}

pub fn run(op: MacOp) -> Result<()> {
    match op {
        MacOp::Tag(args) => {
            let tag = tag(&args.common)?;
            let mut out = io::output(None, false)?;
            io::write(&mut *out, &tag, args.format.as_hex(true))
        }
        MacOp::Verify(args) => {
            let expected = value::parse(&args.tag, "--tag", false)?;
            let tag = tag(&args.common)?;
            if expected.len() != tag.len() {
                return Err(usage!(
                    "--tag is {} bytes; {} makes {}",
                    expected.len(),
                    args.common.algorithm,
                    names::Len::Exact(tag.len()).describe()
                ));
            }
            if constant_time::equal(&tag, &expected) {
                Ok(())
            } else {
                Err(verify!(
                    "the tag does not match: the key or the input differ \
                     from what made it"
                ))
            }
        }
    }
}

/// The tag over the input under the key.
fn tag(args: &Common) -> Result<Vec<u8>> {
    let entry = names::MAC.find(&args.algorithm)?;
    let name = entry.name;
    let kmac = name.starts_with("kmac");
    if !kmac && args.length.is_some() {
        return Err(usage!("{name} takes no --length; that is for kmac"));
    }
    if !kmac && args.customization.is_some() {
        return Err(usage!(
            "{name} takes no --customization; that is for kmac"
        ));
    }
    let mut input = io::input(args.file.as_deref())?;
    let input = &mut *input;
    if let Some(hash) = name.strip_prefix("hmac-") {
        let key = value::checked(&args.key, "--key", entry.key, name)?;
        return with_hash!(hash, H => {
            let mut mac = Hmac::<H>::new(&key);
            io::for_each_chunk(input, |c| {
                mac.update(c);
                Ok(())
            })?;
            Ok(mac.finalize().as_ref().to_vec())
        });
    }
    match name {
        "cmac-aes-128" => cmac::<Aes128>(entry, &args.key, input),
        "cmac-aes-192" => cmac::<Aes192>(entry, &args.key, input),
        "cmac-aes-256" => cmac::<Aes256>(entry, &args.key, input),
        "kmac128" | "kmac256" => {
            let key = value::checked(&args.key, "--key", entry.key, name)?;
            let custom =
                value::text(args.customization.as_deref(), "--customization")?;
            let default = if name == "kmac128" { 32 } else { 64 };
            let mut tag = vec![0u8; args.length.unwrap_or(default)];
            macro_rules! kmac {
                ($K:ident) => {{
                    let mut mac = $K::new(&key, &custom);
                    io::for_each_chunk(input, |c| {
                        mac.update(c);
                        Ok(())
                    })?;
                    mac.finalize_to(&mut tag);
                }};
            }
            if name == "kmac128" {
                kmac!(Kmac128)
            } else {
                kmac!(Kmac256)
            }
            Ok(tag)
        }
        "poly1305" => {
            let key = value::key::<Poly1305>(&args.key, "--key", name)?;
            let mut mac = Poly1305::new(&key);
            io::for_each_chunk(input, |c| {
                mac.update(c);
                Ok(())
            })?;
            Ok(mac.finalize().to_vec())
        }
        other => Err(usage!("no MAC named \"{other}\"")),
    }
}

fn cmac<C>(
    entry: &Entry,
    key: &str,
    input: &mut dyn std::io::Read,
) -> Result<Vec<u8>>
where
    C: scytale::cipher::BlockCipher<Block = [u8; 16]>,
{
    let key = value::key::<C>(key, "--key", entry.name)?;
    let mut mac = Cmac::<C>::new(&key);
    io::for_each_chunk(input, |c| {
        mac.update(c);
        Ok(())
    })?;
    Ok(mac.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::Len;

    /// Every name in the table runs, and the table's key length is
    /// the type's where the type fixes one.
    #[test]
    fn table_matches_dispatch() {
        for entry in names::MAC.iter() {
            let key = match entry.key {
                Len::Exact(n) => format!("hex:{}", "00".repeat(n)),
                _ => "hex:00".into(),
            };
            let args = Common {
                algorithm: entry.name.into(),
                key,
                length: None,
                customization: None,
                file: Some("/dev/null".into()),
            };
            let tag = tag(&args).unwrap();
            if let Len::Exact(n) = entry.output {
                assert_eq!(tag.len(), n, "{}", entry.name);
            }
        }
    }
}
