//! `scytale`: the library from a shell.
//!
//! One subcommand per module of the library, so the tree here is
//! the tree there: `cipher`, `aead`, `hash`, `mac`, `kdf`, `key`,
//! `sig`, `kex`, `kem`, `pke` and `random`, with `list` to say what
//! each takes. No configuration file, no privileges, and nothing
//! that transforms bytes: every operation is the library's, and the
//! tool only carries bytes to it and back.
//!
//! Keys and every other byte-valued option are written `hex:..`,
//! `file:PATH`, `fd:N`, `env:NAME` or `str:TEXT`, and never bare,
//! so that a script cannot have one read the wrong way; `hex:` on a
//! command line is visible to every process on the machine, so a
//! key is better given as `file:` or `fd:`. See [`value`].
//!
//! Exit status is 0 on success, 1 when a tag, signature or padding
//! did not verify, 2 for a request that could not be carried out as
//! asked, and 3 for anything else; see [`fail`].

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod aead;
mod cipher;
mod fail;
mod hash;
mod help;
mod io;
mod kdf;
mod kem;
mod kex;
mod key;
mod mac;
mod pke;
mod random;
mod sig;
mod value;

#[derive(Parser)]
#[command(
    name = "scytale",
    version,
    about = "The scytale library from a shell"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// The algorithm names each command takes
    List {
        /// One of: cipher, aead, hash, mac, key
        family: Option<String>,
    },
    /// Random bytes
    Random(random::RandomArgs),
    /// A digest of each input
    Hash(hash::HashArgs),
    /// Unauthenticated encryption: AES modes, ChaCha20, FF1, FF3-1
    Cipher {
        #[command(subcommand)]
        op: cipher::CipherOp,
    },
    /// Authenticated encryption: GCM, GCM-SIV, CCM, XPN, ChaCha20-Poly1305
    Aead {
        #[command(subcommand)]
        op: aead::AeadOp,
    },
    /// A message authentication code, or a check of one
    Mac(mac::MacArgs),
    /// Key derivation: HKDF, PBKDF2
    Kdf {
        #[command(subcommand)]
        op: kdf::KdfOp,
    },
    /// Key files: generate, take the public half, describe
    Key {
        #[command(subcommand)]
        op: key::KeyOp,
    },
    /// Signatures: Ed25519, ECDSA, ML-DSA, SLH-DSA, RSA
    Sig {
        #[command(subcommand)]
        op: sig::SigOp,
    },
    /// Key agreement: X25519, ECDH
    Kex {
        #[command(subcommand)]
        op: kex::KexOp,
    },
    /// Key encapsulation: ML-KEM
    Kem {
        #[command(subcommand)]
        op: kem::KemOp,
    },
    /// Public-key encryption: RSA-OAEP
    Pke {
        #[command(subcommand)]
        op: pke::PkeOp,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("scytale: {e}");
            ExitCode::from(e.code() as u8)
        }
    }
}

fn run(command: Command) -> fail::Result<()> {
    match command {
        Command::List { family } => list(family.as_deref()),
        Command::Random(args) => random::run(args),
        Command::Hash(args) => hash::run(args),
        Command::Cipher { op } => cipher::run(op),
        Command::Aead { op } => aead::run(op),
        Command::Mac(args) => mac::run(args),
        Command::Kdf { op } => kdf::run(op),
        Command::Key { op } => key::run(op),
        Command::Sig { op } => sig::run(op),
        Command::Kex { op } => kex::run(op),
        Command::Kem { op } => kem::run(op),
        Command::Pke { op } => pke::run(op),
    }
}

/// The families whose algorithms have names, and the names.
const FAMILIES: [(&str, &[&str]); 6] = [
    ("cipher", &cipher::NAMES),
    ("aead", &aead::NAMES),
    ("hash", &hash::NAMES),
    ("xof", &hash::XOF_NAMES),
    ("mac", &mac::NAMES),
    ("key", &key::NAMES),
];

fn list(family: Option<&str>) -> fail::Result<()> {
    match family {
        Some(family) => {
            let (_, names) = FAMILIES
                .iter()
                .find(|(f, _)| *f == family)
                .ok_or_else(|| fail::usage!("no family {family}"))?;
            for name in names.iter() {
                println!("{name}");
            }
        }
        None => {
            for (family, names) in FAMILIES {
                for name in names {
                    println!("{family} {name}");
                }
            }
        }
    }
    Ok(())
}
