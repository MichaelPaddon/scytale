//! `scytale key`: making, reading and describing key files.
//!
//! Keys travel as PEM, the private half as a `PRIVATE KEY` block
//! (PKCS#8) and the public half as `PUBLIC KEY`, which is what every
//! other tool reads and writes. The commands that take a key file
//! read its algorithm out of the file, so nothing has to be named
//! twice.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use scytale::random::CtrDrbg;
use scytale::{Algorithm, KeyInfo};
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::io;

/// The key algorithms `generate` takes; `rsa-N` for any N from 1024
/// to 8192.
pub const NAMES: [&str; 27] = [
    "ed25519",
    "x25519",
    "ecdsa-p256",
    "ecdsa-p384",
    "ecdh-p256",
    "ecdh-p384",
    "rsa-2048",
    "rsa-3072",
    "rsa-4096",
    "ml-kem-512",
    "ml-kem-768",
    "ml-kem-1024",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "slh-dsa-sha2-128s",
    "slh-dsa-sha2-128f",
    "slh-dsa-sha2-192s",
    "slh-dsa-sha2-192f",
    "slh-dsa-sha2-256s",
    "slh-dsa-sha2-256f",
    "slh-dsa-shake-128s",
    "slh-dsa-shake-128f",
    "slh-dsa-shake-192s",
    "slh-dsa-shake-192f",
    "slh-dsa-shake-256s",
    "slh-dsa-shake-256f",
];

/// Room for any PEM the library writes.
const PEM_ROOM: usize = 16 * 1024;

#[derive(Subcommand)]
pub enum KeyOp {
    /// Make a new private key, as PEM
    Generate(GenerateArgs),
    /// The public half of a private key, as PEM
    Public(PublicArgs),
    /// What a key file holds
    Show(ShowArgs),
}

#[derive(Args)]
pub struct GenerateArgs {
    /// The algorithm: ed25519, ecdsa-p256, rsa-3072, ml-kem-768, ...
    #[arg(short, long)]
    algorithm: String,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct PublicArgs {
    /// The private key file; standard input without one
    #[arg(long = "in")]
    input: Option<PathBuf>,
    /// Write to this file rather than standard output
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct ShowArgs {
    /// The key file; standard input without one
    #[arg(long = "in")]
    input: Option<PathBuf>,
}

/// Runs `$body` for each post-quantum signature set, with `$m` bound
/// to its module, for the `Algorithm` in `$alg`; `$else` otherwise.
macro_rules! with_pq_sig {
    ($alg:expr, $m:ident => $body:expr, _ => $else:expr) => {
        match $alg {
            Algorithm::MlDsa44 => {
                use scytale::sig::ml_dsa::ml_dsa_44 as $m;
                $body
            }
            Algorithm::MlDsa65 => {
                use scytale::sig::ml_dsa::ml_dsa_65 as $m;
                $body
            }
            Algorithm::MlDsa87 => {
                use scytale::sig::ml_dsa::ml_dsa_87 as $m;
                $body
            }
            Algorithm::SlhDsaSha2_128s => {
                use scytale::sig::slh_dsa::sha2_128s as $m;
                $body
            }
            Algorithm::SlhDsaSha2_128f => {
                use scytale::sig::slh_dsa::sha2_128f as $m;
                $body
            }
            Algorithm::SlhDsaSha2_192s => {
                use scytale::sig::slh_dsa::sha2_192s as $m;
                $body
            }
            Algorithm::SlhDsaSha2_192f => {
                use scytale::sig::slh_dsa::sha2_192f as $m;
                $body
            }
            Algorithm::SlhDsaSha2_256s => {
                use scytale::sig::slh_dsa::sha2_256s as $m;
                $body
            }
            Algorithm::SlhDsaSha2_256f => {
                use scytale::sig::slh_dsa::sha2_256f as $m;
                $body
            }
            Algorithm::SlhDsaShake128s => {
                use scytale::sig::slh_dsa::shake_128s as $m;
                $body
            }
            Algorithm::SlhDsaShake128f => {
                use scytale::sig::slh_dsa::shake_128f as $m;
                $body
            }
            Algorithm::SlhDsaShake192s => {
                use scytale::sig::slh_dsa::shake_192s as $m;
                $body
            }
            Algorithm::SlhDsaShake192f => {
                use scytale::sig::slh_dsa::shake_192f as $m;
                $body
            }
            Algorithm::SlhDsaShake256s => {
                use scytale::sig::slh_dsa::shake_256s as $m;
                $body
            }
            Algorithm::SlhDsaShake256f => {
                use scytale::sig::slh_dsa::shake_256f as $m;
                $body
            }
            _ => $else,
        }
    };
}

/// As [`with_pq_sig`] for the ML-KEM sets.
macro_rules! with_kem {
    ($alg:expr, $m:ident => $body:expr, _ => $else:expr) => {
        match $alg {
            Algorithm::MlKem512 => {
                use scytale::kem::ml_kem::ml_kem_512 as $m;
                $body
            }
            Algorithm::MlKem768 => {
                use scytale::kem::ml_kem::ml_kem_768 as $m;
                $body
            }
            Algorithm::MlKem1024 => {
                use scytale::kem::ml_kem::ml_kem_1024 as $m;
                $body
            }
            _ => $else,
        }
    };
}

pub(crate) use {with_kem, with_pq_sig};

/// A key file and what it holds.
pub fn read(path: Option<&Path>) -> Result<(Zeroizing<Vec<u8>>, KeyInfo)> {
    let pem = Zeroizing::new(io::read_all(path)?);
    let info = KeyInfo::try_from_pem(&pem).map_err(|e| {
        let name =
            path.map_or("standard input".into(), |p| p.display().to_string());
        usage!("{name}: not a key file: {e}")
    })?;
    Ok((pem, info))
}

/// A private key file, or a usage error.
pub fn read_private(path: &Path) -> Result<(Zeroizing<Vec<u8>>, Algorithm)> {
    let (pem, info) = read(Some(path))?;
    if !info.private {
        return Err(usage!(
            "{}: a public key, not a private one",
            path.display()
        ));
    }
    Ok((pem, info.algorithm))
}

/// A public key file, or a usage error.
pub fn read_public(path: &Path) -> Result<(Zeroizing<Vec<u8>>, Algorithm)> {
    let (pem, info) = read(Some(path))?;
    if info.private {
        return Err(usage!(
            "{}: a private key; `scytale key public` makes the public one",
            path.display()
        ));
    }
    Ok((pem, info.algorithm))
}

pub fn run(op: KeyOp) -> Result<()> {
    match op {
        KeyOp::Generate(args) => {
            let pem = generate(&args.algorithm)?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &pem, false)
        }
        KeyOp::Public(args) => {
            let (pem, info) = read(args.input.as_deref())?;
            if !info.private {
                return Err(usage!("the input is already a public key"));
            }
            let public = public(info.algorithm, &pem)?;
            let mut out = io::output(args.out.as_deref(), false)?;
            io::write(&mut *out, &public, false)
        }
        KeyOp::Show(args) => {
            let (pem, info) = read(args.input.as_deref())?;
            let half = if info.private { "private" } else { "public" };
            let detail = match (info.algorithm, info.private) {
                (Algorithm::Rsa | Algorithm::RsaPss, true) => {
                    let key =
                        scytale::sig::rsa::PrivateKey::try_from_pem(&pem)?;
                    format!(", {} bits", key.bits())
                }
                (Algorithm::Rsa | Algorithm::RsaPss, false) => {
                    let key = scytale::sig::rsa::PublicKey::try_from_pem(&pem)?;
                    format!(", {} bits", key.bits())
                }
                _ => String::new(),
            };
            println!("{} {half} key{detail}", info.algorithm);
            Ok(())
        }
    }
}

/// A fresh private key under `name`, as PEM.
fn generate(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut rng = CtrDrbg::from_system()?;
    let mut pem = Zeroizing::new(vec![0u8; PEM_ROOM]);
    macro_rules! into_pem {
        ($key:expr) => {{
            let n = $key.pem_bytes(&mut pem)?;
            pem.truncate(n);
            return Ok(pem);
        }};
    }
    match name {
        "ed25519" => {
            let key = scytale::sig::ed25519::PrivateKey::generate(&mut rng)?;
            Ok(Zeroizing::new(key.pem_bytes().to_vec()))
        }
        "x25519" => {
            let key = scytale::kex::x25519::PrivateKey::generate(&mut rng)?;
            Ok(Zeroizing::new(key.pem_bytes().to_vec()))
        }
        "ecdsa-p256" | "ecdh-p256" => {
            into_pem!(scytale::sig::ecdsa::p256::PrivateKey::generate(
                &mut rng
            )?)
        }
        "ecdsa-p384" | "ecdh-p384" => {
            into_pem!(scytale::sig::ecdsa::p384::PrivateKey::generate(
                &mut rng
            )?)
        }
        _ => {
            if let Some(bits) = name.strip_prefix("rsa-") {
                let bits: usize = bits
                    .parse()
                    .map_err(|_| usage!("rsa-N: N must be a bit count"))?;
                let key =
                    scytale::sig::rsa::PrivateKey::generate(&mut rng, bits)?;
                into_pem!(key);
            }
            let algorithm = by_name(name)?;
            with_kem!(algorithm, m => {
                into_pem!(m::PrivateKey::generate(&mut rng)?)
            }, _ => with_pq_sig!(algorithm, m => {
                into_pem!(m::PrivateKey::generate(&mut rng)?)
            }, _ => Err(usage!("unknown key algorithm {name}"))))
        }
    }
}

/// The post-quantum algorithm a `generate` name stands for.
fn by_name(name: &str) -> Result<Algorithm> {
    Ok(match name {
        "ml-kem-512" => Algorithm::MlKem512,
        "ml-kem-768" => Algorithm::MlKem768,
        "ml-kem-1024" => Algorithm::MlKem1024,
        "ml-dsa-44" => Algorithm::MlDsa44,
        "ml-dsa-65" => Algorithm::MlDsa65,
        "ml-dsa-87" => Algorithm::MlDsa87,
        "slh-dsa-sha2-128s" => Algorithm::SlhDsaSha2_128s,
        "slh-dsa-sha2-128f" => Algorithm::SlhDsaSha2_128f,
        "slh-dsa-sha2-192s" => Algorithm::SlhDsaSha2_192s,
        "slh-dsa-sha2-192f" => Algorithm::SlhDsaSha2_192f,
        "slh-dsa-sha2-256s" => Algorithm::SlhDsaSha2_256s,
        "slh-dsa-sha2-256f" => Algorithm::SlhDsaSha2_256f,
        "slh-dsa-shake-128s" => Algorithm::SlhDsaShake128s,
        "slh-dsa-shake-128f" => Algorithm::SlhDsaShake128f,
        "slh-dsa-shake-192s" => Algorithm::SlhDsaShake192s,
        "slh-dsa-shake-192f" => Algorithm::SlhDsaShake192f,
        "slh-dsa-shake-256s" => Algorithm::SlhDsaShake256s,
        "slh-dsa-shake-256f" => Algorithm::SlhDsaShake256f,
        _ => return Err(usage!("unknown key algorithm {name}")),
    })
}

/// The public half of the private key in `pem`, as PEM.
fn public(algorithm: Algorithm, pem: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; PEM_ROOM];
    macro_rules! into_pem {
        ($public:expr) => {{
            let n = $public.pem_bytes(&mut out)?;
            out.truncate(n);
            return Ok(out);
        }};
    }
    match algorithm {
        Algorithm::Ed25519 => {
            let key = scytale::sig::ed25519::PrivateKey::try_from_pem(pem)?;
            Ok(key.public_key().pem_bytes().to_vec())
        }
        Algorithm::X25519 => {
            let key = scytale::kex::x25519::PrivateKey::try_from_pem(pem)?;
            Ok(key.public_key().pem_bytes().to_vec())
        }
        Algorithm::P256 => {
            let key = scytale::sig::ecdsa::p256::PrivateKey::try_from_pem(pem)?;
            into_pem!(key.public_key())
        }
        Algorithm::P384 => {
            let key = scytale::sig::ecdsa::p384::PrivateKey::try_from_pem(pem)?;
            into_pem!(key.public_key())
        }
        Algorithm::Rsa | Algorithm::RsaPss => {
            let key = scytale::sig::rsa::PrivateKey::try_from_pem(pem)?;
            into_pem!(key.public_key())
        }
        other => with_kem!(other, m => {
            into_pem!(m::PrivateKey::try_from_pem(pem)?.public_key())
        }, _ => with_pq_sig!(other, m => {
            into_pem!(m::PrivateKey::try_from_pem(pem)?.public_key())
        }, _ => Err(usage!("{other}: no public half is defined")))),
    }
}
