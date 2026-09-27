//! `scytale hash`: a digest of each input, and the hash-by-name
//! dispatch every other command that takes `--hash` shares.

use std::io::Write;
use std::path::PathBuf;

use clap::Args;
use scytale::hash::{Hash, Xof, XofReader};

use crate::fail::{Result, usage};
use crate::{io, value};

/// The hashes, as `--hash` names them.
pub const NAMES: [&str; 11] = [
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512-224",
    "sha512-256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
];

/// The extendable-output functions, which `hash` alone takes.
pub const XOF_NAMES: [&str; 4] =
    ["shake128", "shake256", "cshake128", "cshake256"];

/// Runs `$body` with `$H` bound to the hash type `$name` names.
macro_rules! with_hash {
    ($name:expr, $H:ident => $body:expr) => {
        match $name {
            "sha1" => {
                type $H = scytale::hash::sha1::Sha1;
                $body
            }
            "sha224" => {
                type $H = scytale::hash::sha2::Sha224;
                $body
            }
            "sha256" => {
                type $H = scytale::hash::sha2::Sha256;
                $body
            }
            "sha384" => {
                type $H = scytale::hash::sha2::Sha384;
                $body
            }
            "sha512" => {
                type $H = scytale::hash::sha2::Sha512;
                $body
            }
            "sha512-224" => {
                type $H = scytale::hash::sha2::Sha512_224;
                $body
            }
            "sha512-256" => {
                type $H = scytale::hash::sha2::Sha512_256;
                $body
            }
            "sha3-224" => {
                type $H = scytale::hash::sha3::Sha3_224;
                $body
            }
            "sha3-256" => {
                type $H = scytale::hash::sha3::Sha3_256;
                $body
            }
            "sha3-384" => {
                type $H = scytale::hash::sha3::Sha3_384;
                $body
            }
            "sha3-512" => {
                type $H = scytale::hash::sha3::Sha3_512;
                $body
            }
            other => Err($crate::fail::usage!("unknown hash {other}")),
        }
    };
}

pub(crate) use with_hash;

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct HashArgs {
    /// The hash: sha256, sha3-512, shake128, ... (`scytale list hash`)
    #[arg(short, long, default_value = "sha256")]
    algorithm: String,
    /// Bytes of output, for shake and cshake
    #[arg(short, long)]
    length: Option<usize>,
    /// The function name, for cshake
    #[arg(long)]
    function_name: Option<String>,
    /// The customization string, for cshake and kmac
    #[arg(long)]
    customization: Option<String>,
    /// Write the raw digest rather than hex
    #[arg(long)]
    binary: bool,
    /// The files to digest; standard input without any
    files: Vec<PathBuf>,
}

pub fn run(args: HashArgs) -> Result<()> {
    let mut out = io::output(None, false)?;
    let paths: Vec<Option<&std::path::Path>> = if args.files.is_empty() {
        vec![None]
    } else {
        args.files.iter().map(|p| Some(p.as_path())).collect()
    };
    for path in paths {
        let digest = digest(&args, path)?;
        if args.binary {
            out.write_all(&digest)?;
        } else {
            let name = path.map_or("-".into(), |p| p.display().to_string());
            let mut text = vec![0u8; digest.len() * 2];
            scytale::codec::hex::encode(&digest, &mut text)?;
            out.write_all(&text)?;
            writeln!(out, "  {name}")?;
        }
    }
    Ok(out.flush()?)
}

fn digest(args: &HashArgs, path: Option<&std::path::Path>) -> Result<Vec<u8>> {
    let mut input = io::input(path)?;
    let name = args.algorithm.as_str();
    if XOF_NAMES.contains(&name) {
        let length =
            args.length.ok_or_else(|| usage!("{name} needs --length"))?;
        let function = value::text(args.function_name.as_deref(), "fn")?;
        let custom = value::text(args.customization.as_deref(), "custom")?;
        let mut out = vec![0u8; length];
        macro_rules! squeeze {
            ($xof:expr) => {{
                let mut xof = $xof;
                io::for_each_chunk(&mut *input, |chunk| {
                    xof.update(chunk);
                    Ok(())
                })?;
                xof.finalize_xof().squeeze(&mut out);
            }};
        }
        use scytale::hash::sha3::{CShake128, CShake256, Shake128, Shake256};
        match name {
            "shake128" => squeeze!(Shake128::default()),
            "shake256" => squeeze!(Shake256::default()),
            "cshake128" => squeeze!(CShake128::new(&function, &custom)),
            _ => squeeze!(CShake256::new(&function, &custom)),
        }
        return Ok(out);
    }
    if args.length.is_some() {
        return Err(usage!("--length is for shake and cshake only"));
    }
    with_hash!(name, H => {
        let mut hash = H::default();
        io::for_each_chunk(&mut *input, |chunk| {
            hash.update(chunk);
            Ok(())
        })?;
        Ok(hash.finalize().as_ref().to_vec())
    })
}
