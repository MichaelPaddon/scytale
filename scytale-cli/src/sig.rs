//! `scytale sig`: signing a message and checking a signature.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use scytale::Algorithm;
use scytale::random::CtrDrbg;
use scytale::sig::{ecdsa, ed25519, rsa};

use crate::fail::{Result, usage};
use crate::hash::with_hash;
use crate::key::{self, with_pq_sig};
use crate::{io, value};

#[derive(Subcommand)]
pub enum SigOp {
    /// Sign the input with a private key
    Sign(SignArgs),
    /// Check a signature over the input with a public key
    Verify(VerifyArgs),
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RsaScheme {
    /// RSASSA-PSS, salted with a hash's worth of random bytes
    Pss,
    /// RSASSA-PKCS1-v1_5, deterministic
    Pkcs1,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct SignArgs {
    /// The private key file (PEM)
    #[arg(short, long)]
    key: PathBuf,
    /// The hash, for ecdsa and rsa
    #[arg(short = 'H', long, default_value = "sha256")]
    hash: String,
    /// The context string, for ed25519, ml-dsa and slh-dsa
    #[arg(long)]
    context: Option<String>,
    /// The RSA scheme
    #[arg(long, value_enum, default_value_t = RsaScheme::Pss)]
    rsa_scheme: RsaScheme,
    /// Write an ECDSA signature as r || s rather than DER
    #[arg(long)]
    raw: bool,
    /// Write the signature as hex rather than raw bytes
    #[arg(long)]
    hex: bool,
    /// The file to sign; standard input without one
    file: Option<PathBuf>,
    /// Write to this file rather than standard output
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct VerifyArgs {
    /// The public key file (PEM)
    #[arg(short, long)]
    public: PathBuf,
    /// The signature (hex:, file:, fd:, env:)
    #[arg(short, long)]
    signature: String,
    /// The hash, for ecdsa and rsa
    #[arg(short = 'H', long, default_value = "sha256")]
    hash: String,
    /// The context string, for ed25519, ml-dsa and slh-dsa
    #[arg(long)]
    context: Option<String>,
    /// The RSA scheme
    #[arg(long, value_enum, default_value_t = RsaScheme::Pss)]
    rsa_scheme: RsaScheme,
    /// Read an ECDSA signature as r || s rather than DER
    #[arg(long)]
    raw: bool,
    /// The signed file; standard input without one
    file: Option<PathBuf>,
}

pub fn run(op: SigOp) -> Result<()> {
    match op {
        SigOp::Sign(args) => sign(args),
        SigOp::Verify(args) => verify(args),
    }
}

fn sign(args: SignArgs) -> Result<()> {
    let (pem, algorithm) = key::read_private(&args.key)?;
    let message = io::read_all(args.file.as_deref())?;
    let context = value::text(args.context.as_deref(), "context")?;
    let hash = args.hash.as_str();
    let signature: Vec<u8> = match algorithm {
        Algorithm::Ed25519 => {
            let key = ed25519::PrivateKey::try_from_pem(&pem)?;
            match &args.context {
                Some(_) => key.sign_ctx(&context, &message)?.to_vec(),
                None => key.sign(&message).to_vec(),
            }
        }
        Algorithm::P256 => {
            let key = ecdsa::p256::PrivateKey::try_from_pem(&pem)?;
            let sig = with_hash!(hash, H => Ok(key.sign::<H>(&message)?))?;
            if args.raw {
                sig.to_vec()
            } else {
                let mut der = [0u8; 128];
                let n = ecdsa::p256::signature_der(&sig, &mut der)?;
                der[..n].to_vec()
            }
        }
        Algorithm::P384 => {
            let key = ecdsa::p384::PrivateKey::try_from_pem(&pem)?;
            let sig = with_hash!(hash, H => Ok(key.sign::<H>(&message)?))?;
            if args.raw {
                sig.to_vec()
            } else {
                let mut der = [0u8; 128];
                let n = ecdsa::p384::signature_der(&sig, &mut der)?;
                der[..n].to_vec()
            }
        }
        Algorithm::Rsa | Algorithm::RsaPss => {
            let key = rsa::PrivateKey::try_from_pem(&pem)?;
            let sig = match args.rsa_scheme {
                RsaScheme::Pss => {
                    let mut rng = CtrDrbg::from_system()?;
                    with_hash!(hash, H => {
                        Ok(key.sign_pss::<H, _>(&mut rng, &message)?)
                    })?
                }
                RsaScheme::Pkcs1 => {
                    with_hash!(hash, H => Ok(key.sign_pkcs1::<H>(&message)?))?
                }
            };
            sig.as_ref().to_vec()
        }
        other => with_pq_sig!(other, m => {
            let key = m::PrivateKey::try_from_pem(&pem)?;
            let mut rng = CtrDrbg::from_system()?;
            key.sign(&mut rng, &context, &message)?.to_vec()
        }, _ => return Err(usage!("{other} is not a signing key"))),
    };
    let mut out = io::output(args.out.as_deref(), false)?;
    io::write(&mut *out, &signature, args.hex)
}

fn verify(args: VerifyArgs) -> Result<()> {
    let (pem, algorithm) = key::read_public(&args.public)?;
    let message = io::read_all(args.file.as_deref())?;
    let context = value::text(args.context.as_deref(), "context")?;
    let signature = value::parse(&args.signature, "signature", false)?;
    let hash = args.hash.as_str();
    let fixed = |n: usize| -> Result<&[u8]> {
        value::exact(&signature, n, "signature")?;
        Ok(&signature[..])
    };
    match algorithm {
        Algorithm::Ed25519 => {
            let key = ed25519::PublicKey::try_from_pem(&pem)?;
            let sig = fixed(ed25519::SIGNATURE_SIZE)?;
            let sig = sig.try_into().map_err(|_| usage!("signature"))?;
            match &args.context {
                Some(_) => key.verify_ctx(&context, &message, sig)?,
                None => key.verify(&message, sig)?,
            }
        }
        Algorithm::P256 => {
            let key = ecdsa::p256::PublicKey::try_from_pem(&pem)?;
            let sig = if args.raw {
                let sig = fixed(ecdsa::p256::SIGNATURE_SIZE)?;
                sig.try_into().map_err(|_| usage!("signature"))?
            } else {
                ecdsa::p256::signature_from_der(&signature)?
            };
            with_hash!(hash, H => Ok(key.verify::<H>(&message, &sig)?))?
        }
        Algorithm::P384 => {
            let key = ecdsa::p384::PublicKey::try_from_pem(&pem)?;
            let sig = if args.raw {
                let sig = fixed(ecdsa::p384::SIGNATURE_SIZE)?;
                sig.try_into().map_err(|_| usage!("signature"))?
            } else {
                ecdsa::p384::signature_from_der(&signature)?
            };
            with_hash!(hash, H => Ok(key.verify::<H>(&message, &sig)?))?
        }
        Algorithm::Rsa | Algorithm::RsaPss => {
            let key = rsa::PublicKey::try_from_pem(&pem)?;
            match args.rsa_scheme {
                RsaScheme::Pss => with_hash!(hash, H => {
                    Ok(key.verify_pss::<H>(&message, &signature)?)
                })?,
                RsaScheme::Pkcs1 => with_hash!(hash, H => {
                    Ok(key.verify_pkcs1::<H>(&message, &signature)?)
                })?,
            }
        }
        other => with_pq_sig!(other, m => {
            let key = m::PublicKey::try_from_pem(&pem)?;
            let sig = fixed(m::SIGNATURE_SIZE)?;
            let sig = sig.try_into().map_err(|_| usage!("signature"))?;
            key.verify(&context, &message, sig)?
        }, _ => return Err(usage!("{other} is not a signing key"))),
    }
    Ok(())
}
