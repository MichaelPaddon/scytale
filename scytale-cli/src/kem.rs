//! `scytale kem`: a shared secret carried in a ciphertext.
//!
//! Encapsulation makes two things, the ciphertext for the peer and
//! the secret to keep, so it writes the secret to a file of its own.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::Algorithm;
use scytale::random::CtrDrbg;
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::key::with_kem;
use crate::{io, key, value};

#[derive(Subcommand)]
pub enum KemOp {
    /// A ciphertext for a public key, and the secret it carries
    Encapsulate(EncapsulateArgs),
    /// The secret a ciphertext carries, with the private key
    Decapsulate(DecapsulateArgs),
}

#[derive(Args)]
pub struct EncapsulateArgs {
    /// The peer's public key file (PEM)
    #[arg(short, long)]
    public: PathBuf,
    /// Write the shared secret to this file, owner-readable
    #[arg(long)]
    secret_out: PathBuf,
    /// Write the secret and ciphertext as hex rather than raw bytes
    #[arg(long)]
    hex: bool,
    /// Write the ciphertext to this file rather than standard output
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct DecapsulateArgs {
    /// The private key file (PEM)
    #[arg(short, long)]
    key: PathBuf,
    /// Write the secret as hex rather than raw bytes
    #[arg(long)]
    hex: bool,
    /// The ciphertext file; standard input without one
    file: Option<PathBuf>,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: KemOp) -> Result<()> {
    match op {
        KemOp::Encapsulate(args) => {
            let (pem, algorithm) = key::read_public(&args.public)?;
            let mut rng = CtrDrbg::from_system()?;
            let (ciphertext, secret) = with_kem!(algorithm, m => {
                let public = m::PublicKey::try_from_pem(&pem)?;
                let (c, s) = public.encapsulate(&mut rng)?;
                (c.to_vec(), Zeroizing::new(s.to_vec()))
            }, _ => return Err(usage!("{algorithm} is not a KEM key")));
            let mut secret_out = io::output(Some(&args.secret_out), true)?;
            io::write(&mut *secret_out, &secret, args.hex)?;
            let mut out = io::output(args.out.as_deref(), false)?;
            io::write(&mut *out, &ciphertext, args.hex)
        }
        KemOp::Decapsulate(args) => {
            let (pem, algorithm) = key::read_private(&args.key)?;
            let ciphertext = io::read_all(args.file.as_deref())?;
            let secret = with_kem!(algorithm, m => {
                let private = m::PrivateKey::try_from_pem(&pem)?;
                value::exact(&ciphertext, m::CIPHERTEXT_SIZE, "ciphertext")?;
                let c: &[u8; m::CIPHERTEXT_SIZE] = ciphertext
                    .as_slice()
                    .try_into()
                    .map_err(|_| usage!("ciphertext"))?;
                Zeroizing::new(private.decapsulate(c).to_vec())
            }, _ => return Err(usage!("{algorithm} is not a KEM key")));
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &secret, args.hex)
        }
    }
}
