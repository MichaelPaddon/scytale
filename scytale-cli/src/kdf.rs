//! `scytale kdf`: keys from keying material, or from a password.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::kdf::{hkdf, pbkdf2};
use zeroize::Zeroizing;

use crate::fail::Result;
use crate::hash::with_hash;
use crate::{io, value};

#[derive(Subcommand)]
pub enum KdfOp {
    /// Expand already-unguessable material into keys (RFC 5869)
    Hkdf(HkdfArgs),
    /// Turn a password into a key, slowly (RFC 8018)
    Pbkdf2(Pbkdf2Args),
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct HkdfArgs {
    /// The hash
    #[arg(short = 'H', long, default_value = "sha256")]
    hash: String,
    /// The input keying material (hex:, file:, fd:, env:)
    #[arg(long)]
    ikm: String,
    /// The salt (str: allowed); none without it
    #[arg(long)]
    salt: Option<String>,
    /// Context, may repeat; concatenated in order
    #[arg(long)]
    info: Vec<String>,
    /// Bytes of output
    #[arg(short, long)]
    length: usize,
    /// Write the raw key rather than hex
    #[arg(long)]
    binary: bool,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct Pbkdf2Args {
    /// The hash
    #[arg(short = 'H', long, default_value = "sha256")]
    hash: String,
    /// The password (str:, file:, fd:, env:, hex:)
    #[arg(long)]
    password: String,
    /// The salt (str: allowed)
    #[arg(long)]
    salt: String,
    /// Iterations
    #[arg(short, long)]
    iterations: u32,
    /// Bytes of output
    #[arg(short, long)]
    length: usize,
    /// Write the raw key rather than hex
    #[arg(long)]
    binary: bool,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: KdfOp) -> Result<()> {
    match op {
        KdfOp::Hkdf(args) => {
            let ikm = value::parse(&args.ikm, "ikm", false)?;
            let salt = value::text(args.salt.as_deref(), "salt")?;
            let info = args
                .info
                .iter()
                .map(|i| value::parse(i, "info", true))
                .collect::<Result<Vec<_>>>()?;
            let info: Vec<&[u8]> = info.iter().map(|i| &i[..]).collect();
            let mut okm = Zeroizing::new(vec![0u8; args.length]);
            with_hash!(args.hash.as_str(), H => {
                Ok(hkdf::derive::<H>(&salt, &ikm, &info, &mut okm)?)
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &okm, !args.binary)
        }
        KdfOp::Pbkdf2(args) => {
            let password = value::parse(&args.password, "password", true)?;
            let salt = value::parse(&args.salt, "salt", true)?;
            let mut key = Zeroizing::new(vec![0u8; args.length]);
            with_hash!(args.hash.as_str(), H => {
                Ok(pbkdf2::pbkdf2::<H>(
                    &password,
                    &salt,
                    args.iterations,
                    &mut key,
                )?)
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &key, !args.binary)
        }
    }
}
