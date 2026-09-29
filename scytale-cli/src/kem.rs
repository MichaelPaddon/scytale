//! `scytale kem`: a shared secret carried in a ciphertext.
//!
//! Encapsulation makes two things, the ciphertext for the peer and
//! the secret to keep, so it writes the secret to a file of its own.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::random::CtrDrbg;
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::io::Format;
use crate::key::with_kem;
use crate::{io, key, names};

#[derive(Subcommand)]
pub enum KemOp {
    /// A ciphertext for a public key, and the secret it carries
    Encapsulate(EncapsulateArgs),
    /// The secret a ciphertext carries, with the private key
    Decapsulate(DecapsulateArgs),
}

impl KemOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        match self {
            KemOp::Encapsulate(a) => format!("encapsulate {}", a.algorithm),
            KemOp::Decapsulate(a) => format!("decapsulate {}", a.algorithm),
        }
    }
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct EncapsulateArgs {
    /// The KEM: ml-kem-512, ml-kem-768, ml-kem-1024
    pub algorithm: String,
    /// The peer's public key file (PEM)
    #[arg(short, long)]
    public: PathBuf,
    /// Write the shared secret to this file, owner-readable
    #[arg(long)]
    secret_out: PathBuf,
    /// Raw bytes by default, for the ciphertext and the secret
    #[command(flatten)]
    format: Format,
    /// Write the ciphertext to this file rather than standard output
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct DecapsulateArgs {
    /// The KEM: ml-kem-512, ml-kem-768, ml-kem-1024
    pub algorithm: String,
    /// The private key file (PEM)
    #[arg(short, long)]
    key: PathBuf,
    /// Hex by default
    #[command(flatten)]
    format: Format,
    /// The ciphertext file; standard input without one
    file: Option<PathBuf>,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: KemOp) -> Result<()> {
    match op {
        KemOp::Encapsulate(args) => {
            let name = names::KEM.find(&args.algorithm)?.name;
            let algorithm = key::pq_by_name(name)
                .ok_or_else(|| usage!("no KEM named \"{name}\""))?;
            let pem = key::read_public(&args.public, &[algorithm], name)?;
            let mut rng = CtrDrbg::from_system()?;
            let (ciphertext, secret) = with_kem!(algorithm, m => {
                let public = m::PublicKey::try_from_pem(&pem)?;
                let (c, s) = public.encapsulate(&mut rng)?;
                (c.to_vec(), Zeroizing::new(s.to_vec()))
            }, _ => return Err(usage!("no KEM named \"{name}\"")));
            let as_hex = args.format.as_hex(false);
            let mut secret_out = io::output(Some(&args.secret_out), true)?;
            io::write(&mut *secret_out, &secret, as_hex)?;
            let mut out = io::output(args.out.as_deref(), false)?;
            io::write(&mut *out, &ciphertext, as_hex)
        }
        KemOp::Decapsulate(args) => {
            let name = names::KEM.find(&args.algorithm)?.name;
            let algorithm = key::pq_by_name(name)
                .ok_or_else(|| usage!("no KEM named \"{name}\""))?;
            let pem = key::read_private(&args.key, &[algorithm], name)?;
            let ciphertext = io::read_all(args.file.as_deref())?;
            let secret = with_kem!(algorithm, m => {
                let private = m::PrivateKey::try_from_pem(&pem)?;
                if ciphertext.len() != m::CIPHERTEXT_SIZE {
                    return Err(usage!(
                        "the ciphertext is {} bytes; {name} makes {}",
                        ciphertext.len(),
                        m::CIPHERTEXT_SIZE
                    ));
                }
                let c: &[u8; m::CIPHERTEXT_SIZE] = ciphertext
                    .as_slice()
                    .try_into()
                    .map_err(|_| usage!("ciphertext"))?;
                Zeroizing::new(private.decapsulate(c).to_vec())
            }, _ => return Err(usage!("no KEM named \"{name}\"")));
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &secret, args.format.as_hex(true))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{key, names};

    #[test]
    fn table_matches_dispatch() {
        for entry in names::KEM.iter() {
            assert!(key::pq_by_name(entry.name).is_some(), "{}", entry.name);
        }
    }
}
