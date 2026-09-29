//! `scytale kdf`: keys from keying material, or from a password.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::kdf::{hkdf, pbkdf2};
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::hash::with_hash;
use crate::io::Format;
use crate::{io, names, value};

#[derive(Subcommand)]
pub enum KdfOp {
    /// Expand already-unguessable material into keys (RFC 5869)
    Hkdf(HkdfArgs),
    /// Turn a password into a key, slowly (RFC 8018)
    Pbkdf2(Pbkdf2Args),
}

impl KdfOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        match self {
            KdfOp::Hkdf(a) => format!("hkdf {}", a.hash),
            KdfOp::Pbkdf2(a) => format!("pbkdf2 {}", a.hash),
        }
    }
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct HkdfArgs {
    /// The hash: sha256, sha512, sha3-256, ... (scytale list kdf)
    pub hash: String,
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
    /// Hex by default
    #[command(flatten)]
    format: Format,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct Pbkdf2Args {
    /// The hash: sha256, sha512, sha3-256, ... (scytale list kdf)
    pub hash: String,
    /// The password (str:, file:, fd:, env:, hex:)
    #[arg(long)]
    password: String,
    /// The salt (str: allowed)
    #[arg(long)]
    salt: String,
    /// Iterations; 600000 is the 2023 OWASP figure for sha256
    #[arg(short, long)]
    iterations: u32,
    /// Bytes of output
    #[arg(short, long)]
    length: usize,
    /// Hex by default
    #[command(flatten)]
    format: Format,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: KdfOp) -> Result<()> {
    match op {
        KdfOp::Hkdf(args) => {
            let hash = names::KDF.find(&args.hash)?.name;
            let ikm = value::parse(&args.ikm, "--ikm", false)?;
            let salt = value::text(args.salt.as_deref(), "--salt")?;
            let info = args
                .info
                .iter()
                .map(|i| value::parse(i, "--info", true))
                .collect::<Result<Vec<_>>>()?;
            let info: Vec<&[u8]> = info.iter().map(|i| &i[..]).collect();
            let mut okm = Zeroizing::new(vec![0u8; args.length]);
            with_hash!(hash, H => {
                hkdf::derive::<H>(&salt, &ikm, &info, &mut okm).map_err(|_| {
                    usage!(
                        "--length {}: HKDF over {hash} gives at most {} \
                         bytes",
                        args.length,
                        255 * names::digest_len(hash).unwrap_or(0)
                    )
                })
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &okm, args.format.as_hex(true))
        }
        KdfOp::Pbkdf2(args) => {
            let hash = names::KDF.find(&args.hash)?.name;
            if args.iterations == 0 {
                return Err(usage!(
                    "--iterations 0 would derive nothing; every guess \
                     should cost an attacker what it costs you"
                ));
            }
            let password = value::parse(&args.password, "--password", true)?;
            let salt = value::parse(&args.salt, "--salt", true)?;
            let mut key = Zeroizing::new(vec![0u8; args.length]);
            with_hash!(hash, H => {
                Ok(pbkdf2::pbkdf2::<H>(
                    &password,
                    &salt,
                    args.iterations,
                    &mut key,
                )?)
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &key, args.format.as_hex(true))
        }
    }
}
