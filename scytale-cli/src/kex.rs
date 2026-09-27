//! `scytale kex`: a shared secret from a private key and a peer's
//! public one.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::Algorithm;
use scytale::kex::{ecdh, x25519};
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::{io, key};

#[derive(Subcommand)]
pub enum KexOp {
    /// The shared secret between a private key and a peer's public key
    Agree(AgreeArgs),
}

#[derive(Args)]
pub struct AgreeArgs {
    /// The private key file (PEM)
    #[arg(short, long)]
    key: PathBuf,
    /// The peer's public key file (PEM), on the same curve
    #[arg(short, long)]
    peer: PathBuf,
    /// Write the secret as hex rather than raw bytes
    #[arg(long)]
    hex: bool,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: KexOp) -> Result<()> {
    let KexOp::Agree(args) = op;
    let (private, algorithm) = key::read_private(&args.key)?;
    let (public, peer) = key::read_public(&args.peer)?;
    if algorithm != peer {
        return Err(usage!("{algorithm} key, {peer} peer: not the same curve"));
    }
    let secret: Zeroizing<Vec<u8>> = match algorithm {
        Algorithm::X25519 => {
            let private = x25519::PrivateKey::try_from_pem(&private)?;
            let public = x25519::PublicKey::try_from_pem(&public)?;
            Zeroizing::new(private.shared_secret(&public)?.to_vec())
        }
        Algorithm::P256 => {
            let private = ecdh::p256::PrivateKey::try_from_pem(&private)?;
            let public = ecdh::p256::PublicKey::try_from_pem(&public)?;
            Zeroizing::new(private.shared_secret(&public).to_vec())
        }
        Algorithm::P384 => {
            let private = ecdh::p384::PrivateKey::try_from_pem(&private)?;
            let public = ecdh::p384::PublicKey::try_from_pem(&public)?;
            Zeroizing::new(private.shared_secret(&public).to_vec())
        }
        other => return Err(usage!("{other} is not a key agreement key")),
    };
    let mut out = io::output(args.out.as_deref(), true)?;
    io::write(&mut *out, &secret, args.hex)
}
