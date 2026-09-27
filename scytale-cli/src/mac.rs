//! `scytale mac`: a tag over the input, or a check of one.

use std::path::PathBuf;

use clap::Args;
use scytale::cipher::aes::{Aes128, Aes192, Aes256};
use scytale::constant_time;
use scytale::mac::Mac;
use scytale::mac::cmac::Cmac;
use scytale::mac::hmac::Hmac;
use scytale::mac::kmac::{Kmac128, Kmac256};
use scytale::mac::poly1305::Poly1305;

use crate::fail::{Fail, Result, usage};
use crate::hash::with_hash;
use crate::{io, value};

/// The MACs, as `--algorithm` names them.
pub const NAMES: [&str; 17] = [
    "hmac-sha1",
    "hmac-sha224",
    "hmac-sha256",
    "hmac-sha384",
    "hmac-sha512",
    "hmac-sha512-224",
    "hmac-sha512-256",
    "hmac-sha3-224",
    "hmac-sha3-256",
    "hmac-sha3-384",
    "hmac-sha3-512",
    "cmac-aes-128",
    "cmac-aes-192",
    "cmac-aes-256",
    "kmac128",
    "kmac256",
    "poly1305",
];

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct MacArgs {
    /// The MAC: hmac-sha256, cmac-aes-128, kmac256, poly1305, ...
    #[arg(short, long)]
    algorithm: String,
    /// The key (hex:, file:, fd:, env:)
    #[arg(short, long)]
    key: String,
    /// Check the input against this tag instead of printing one
    #[arg(long)]
    verify: Option<String>,
    /// Bytes of tag, for kmac
    #[arg(short, long)]
    length: Option<usize>,
    /// The customization string, for kmac
    #[arg(long)]
    customization: Option<String>,
    /// Write the raw tag rather than hex
    #[arg(long)]
    binary: bool,
    /// The file to authenticate; standard input without one
    file: Option<PathBuf>,
}

pub fn run(args: MacArgs) -> Result<()> {
    let name = args.algorithm.as_str();
    let mut input = io::input(args.file.as_deref())?;
    let tag = match name {
        n if n.starts_with("hmac-") => {
            // HMAC takes a key of any length; the library folds it.
            let key = value::parse(&args.key, "key", false)?;
            with_hash!(&n[5..], H => {
                let mut mac = Hmac::<H>::new(&key);
                io::for_each_chunk(&mut *input, |c| {
                mac.update(c);
                Ok(())
            })?;
                Ok(mac.finalize().as_ref().to_vec())
            })?
        }
        "cmac-aes-128" => cmac::<Aes128>(&args.key, &mut *input)?,
        "cmac-aes-192" => cmac::<Aes192>(&args.key, &mut *input)?,
        "cmac-aes-256" => cmac::<Aes256>(&args.key, &mut *input)?,
        "kmac128" | "kmac256" => {
            let key = value::parse(&args.key, "key", false)?;
            let custom = value::text(args.customization.as_deref(), "c")?;
            let default = if name == "kmac128" { 32 } else { 64 };
            let mut tag = vec![0u8; args.length.unwrap_or(default)];
            macro_rules! kmac {
                ($K:ident) => {{
                    let mut mac = $K::new(&key, &custom);
                    io::for_each_chunk(&mut *input, |c| {
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
            tag
        }
        "poly1305" => {
            let key = value::key::<Poly1305>(&args.key, "key")?;
            let mut mac = Poly1305::new(&key);
            io::for_each_chunk(&mut *input, |c| {
                mac.update(c);
                Ok(())
            })?;
            mac.finalize().to_vec()
        }
        other => return Err(usage!("unknown mac {other}")),
    };
    if name != "kmac128" && name != "kmac256" && args.length.is_some() {
        return Err(usage!("--length is for kmac only"));
    }
    match &args.verify {
        Some(expected) => {
            let expected = value::parse(expected, "verify", false)?;
            if constant_time::equal(&tag, &expected) {
                Ok(())
            } else {
                Err(Fail::Verify)
            }
        }
        None => {
            let mut out = io::output(None, false)?;
            io::write(&mut *out, &tag, !args.binary)
        }
    }
}

fn cmac<C>(key: &str, input: &mut dyn std::io::Read) -> Result<Vec<u8>>
where
    C: scytale::cipher::BlockCipher<Block = [u8; 16]>,
{
    let key = value::key::<C>(key, "key")?;
    let mut mac = Cmac::<C>::new(&key);
    io::for_each_chunk(input, |c| {
        mac.update(c);
        Ok(())
    })?;
    Ok(mac.finalize().to_vec())
}
