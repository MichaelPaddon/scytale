//! `scytale pke`: RSA-OAEP, a short message under a public key.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::Algorithm;
use scytale::pke::rsa;
use scytale::random::CtrDrbg;
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::hash::with_hash;
use crate::{io, key, names, value};

#[derive(Subcommand)]
pub enum PkeOp {
    /// Encrypt the input to a public key
    Encrypt(EncryptArgs),
    /// Decrypt the input with the private key
    Decrypt(DecryptArgs),
}

impl PkeOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        match self {
            PkeOp::Encrypt(a) => format!("encrypt {}", a.scheme),
            PkeOp::Decrypt(a) => format!("decrypt {}", a.scheme),
        }
    }
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct EncryptArgs {
    /// The scheme: rsa-oaep-sha256, rsa-oaep-sha512, ...
    pub scheme: String,
    /// The public key file (PEM)
    #[arg(short, long)]
    public: PathBuf,
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
    /// The scheme: rsa-oaep-sha256, rsa-oaep-sha512, ...
    pub scheme: String,
    /// The private key file (PEM)
    #[arg(short, long)]
    key: PathBuf,
    /// The OAEP label (str: allowed); empty without it
    #[arg(long)]
    label: Option<String>,
    /// The ciphertext file; standard input without one
    file: Option<PathBuf>,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

/// The hash a scheme name carries.
fn hash_of(scheme: &str) -> Result<(&'static str, &'static str)> {
    let name = names::PKE.find(scheme)?.name;
    let hash = name
        .strip_prefix("rsa-oaep-")
        .ok_or_else(|| usage!("no encryption scheme named \"{name}\""))?;
    Ok((name, hash))
}

pub fn run(op: PkeOp) -> Result<()> {
    match op {
        PkeOp::Encrypt(args) => {
            let (name, hash) = hash_of(&args.scheme)?;
            let pem = key::read_public(&args.public, &[Algorithm::Rsa], name)?;
            let public = rsa::PublicKey::try_from_pem(&pem)?;
            let label = value::text(args.label.as_deref(), "--label")?;
            let message = Zeroizing::new(io::read_all(args.file.as_deref())?);
            let mut rng = CtrDrbg::from_system()?;
            let digest = names::digest_len(hash).unwrap_or(0);
            let most = public.modulus_len().saturating_sub(2 * digest + 2);
            if message.len() > most {
                return Err(usage!(
                    "the message is {} bytes; {name} under this {}-bit key \
                     takes at most {most}: encrypt a key with it, and the \
                     message with the key",
                    message.len(),
                    public.bits()
                ));
            }
            let ciphertext = with_hash!(hash, H => {
                Ok(public.encrypt_oaep::<H, _>(&mut rng, &label, &message)?)
            })?;
            let mut out = io::output(args.out.as_deref(), false)?;
            io::write(&mut *out, ciphertext.as_ref(), false)
        }
        PkeOp::Decrypt(args) => {
            let (name, hash) = hash_of(&args.scheme)?;
            let pem = key::read_private(&args.key, &[Algorithm::Rsa], name)?;
            let private = rsa::PrivateKey::try_from_pem(&pem)?;
            let label = value::text(args.label.as_deref(), "--label")?;
            let ciphertext = io::read_all(args.file.as_deref())?;
            if ciphertext.len() != private.modulus_len() {
                return Err(usage!(
                    "the ciphertext is {} bytes; under this {}-bit key it \
                     is {}",
                    ciphertext.len(),
                    private.bits(),
                    private.modulus_len()
                ));
            }
            let mut message = Zeroizing::new(vec![0u8; private.modulus_len()]);
            let n = with_hash!(hash, H => {
                let n = private
                    .decrypt_oaep::<H>(&label, &ciphertext, &mut message)?;
                Ok(n)
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &message[..n], false)
        }
    }
}
