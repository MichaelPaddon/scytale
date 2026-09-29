//! `scytale hash`: a digest of each input, and the hash-by-name
//! dispatch every other command that takes a hash shares.

use std::io::Write;
use std::path::PathBuf;

use clap::Args;
use scytale::hash::{Hash, Xof, XofReader};

use crate::fail::{Result, usage};
use crate::io::Format;
use crate::names::{self, Len};
use crate::{io, value};

/// Runs `$body` with `$H` bound to the hash type `$name` names, one
/// of [`names::HASHES`]; the name has been looked up in a table
/// already, so the last arm is never reached.
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
            other => Err($crate::fail::usage!("no hash named \"{other}\"")),
        }
    };
}

pub(crate) use with_hash;

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct HashArgs {
    /// The hash: sha256, sha3-512, shake128, ... (scytale list hash)
    pub algorithm: String,
    /// Bytes of output, for shake and cshake
    #[arg(short, long)]
    length: Option<usize>,
    /// The function name, for cshake
    #[arg(long)]
    function_name: Option<String>,
    /// The customization string, for cshake
    #[arg(long)]
    customization: Option<String>,
    /// Hex by default: "<digest>  <file>", one line each
    #[command(flatten)]
    format: Format,
    /// The files to digest; standard input without any
    files: Vec<PathBuf>,
}

pub fn run(args: HashArgs) -> Result<()> {
    let entry = names::HASH.find(&args.algorithm)?;
    let name = entry.name;
    let xof = entry.output == Len::Any;
    if xof && args.length.is_none() {
        return Err(usage!("{name} gives any length; say which with --length"));
    }
    if !xof && args.length.is_some() {
        return Err(usage!(
            "{name} takes no --length; that is for shake and cshake"
        ));
    }
    if !name.starts_with("cshake")
        && (args.function_name.is_some() || args.customization.is_some())
    {
        return Err(usage!(
            "{name} takes no --function-name or --customization; those \
             are cshake's"
        ));
    }
    let as_hex = args.format.as_hex(true);
    if !as_hex && args.files.len() > 1 {
        return Err(usage!(
            "--raw with {} files would run their digests together; one \
             file, or hex",
            args.files.len()
        ));
    }
    let mut out = io::output(None, false)?;
    let paths: Vec<Option<&std::path::Path>> = if args.files.is_empty() {
        vec![None]
    } else {
        args.files.iter().map(|p| Some(p.as_path())).collect()
    };
    for path in paths {
        let digest = digest(&args, name, xof, path)?;
        if as_hex {
            let shown = path.map_or("-".into(), |p| p.display().to_string());
            let mut text = vec![0u8; digest.len() * 2];
            scytale::codec::hex::encode(&digest, &mut text)?;
            out.write_all(&text)?;
            writeln!(out, "  {shown}")?;
        } else {
            out.write_all(&digest)?;
        }
    }
    Ok(out.flush()?)
}

fn digest(
    args: &HashArgs,
    name: &str,
    xof: bool,
    path: Option<&std::path::Path>,
) -> Result<Vec<u8>> {
    let mut input = io::input(path)?;
    if xof {
        let length = args.length.unwrap_or(0);
        let function =
            value::text(args.function_name.as_deref(), "--function-name")?;
        let custom =
            value::text(args.customization.as_deref(), "--customization")?;
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
    with_hash!(name, H => {
        let mut hash = H::default();
        io::for_each_chunk(&mut *input, |chunk| {
            hash.update(chunk);
            Ok(())
        })?;
        Ok(hash.finalize().as_ref().to_vec())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table's digest lengths are the types'.
    #[test]
    fn table_matches_types() {
        for name in names::HASHES {
            let n = with_hash!(name, H => Ok::<usize, crate::fail::Fail>(
                H::default().finalize().as_ref().len()
            ))
            .unwrap();
            assert_eq!(Some(n), names::digest_len(name), "{name}");
        }
    }
}
