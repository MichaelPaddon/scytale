//! `scytale pke`: RSA-OAEP, a short message under a public key.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::Algorithm;
use scytale::pke::rsa;
use scytale::random::CtrDrbg;
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::hash::with_hash;
use crate::{io, key, value};

#[derive(Subcommand)]
pub enum PkeOp {
    /// Encrypt the input to a public key
    Encrypt(EncryptArgs),
    /// Decrypt the input with the private key
    Decrypt(DecryptArgs),
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct EncryptArgs {
    /// The public key file (PEM)
    #[arg(short, long)]
    public: PathBuf,
    /// The OAEP hash
    #[arg(short = 'H', long, default_value = "sha256")]
    hash: String,
    /// The OAEP label (str: allowed); empty without it
    #[arg(long)]
    label: Option<String>,
    /// The message file; standard input without one
    file: Option<PathBuf>,
    /// Write to this file rather than standard output
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct DecryptArgs {
    /// The private key file (PEM)
    #[arg(short, long)]
    key: PathBuf,
    /// The OAEP hash
    #[arg(short = 'H', long, default_value = "sha256")]
    hash: String,
    /// The OAEP label (str: allowed); empty without it
    #[arg(long)]
    label: Option<String>,
    /// The ciphertext file; standard input without one
    file: Option<PathBuf>,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: PkeOp) -> Result<()> {
    match op {
        PkeOp::Encrypt(args) => {
            let (pem, algorithm) = key::read_public(&args.public)?;
            if algorithm != Algorithm::Rsa {
                return Err(usage!("{algorithm} is not an encryption key"));
            }
            let public = rsa::PublicKey::try_from_pem(&pem)?;
            let label = value::text(args.label.as_deref(), "label")?;
            let message = Zeroizing::new(io::read_all(args.file.as_deref())?);
            let mut rng = CtrDrbg::from_system()?;
            let ciphertext = with_hash!(args.hash.as_str(), H => {
                Ok(public.encrypt_oaep::<H, _>(&mut rng, &label, &message)?)
            })?;
            let mut out = io::output(args.out.as_deref(), false)?;
            io::write(&mut *out, ciphertext.as_ref(), false)
        }
        PkeOp::Decrypt(args) => {
            let (pem, algorithm) = key::read_private(&args.key)?;
            if algorithm != Algorithm::Rsa {
                return Err(usage!("{algorithm} is not an encryption key"));
            }
            let private = rsa::PrivateKey::try_from_pem(&pem)?;
            let label = value::text(args.label.as_deref(), "label")?;
            let ciphertext = io::read_all(args.file.as_deref())?;
            let mut message = Zeroizing::new(vec![0u8; private.modulus_len()]);
            let n = with_hash!(args.hash.as_str(), H => {
                let n = private
                    .decrypt_oaep::<H>(&label, &ciphertext, &mut message)?;
                Ok(n)
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &message[..n], false)
        }
    }
}
