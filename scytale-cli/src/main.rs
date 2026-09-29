//! `scytale`: the library from a shell.
//!
//! One subcommand per module of the library, so the tree here is
//! the tree there: `cipher`, `aead`, `hash`, `mac`, `kdf`, `key`,
//! `sig`, `kex`, `kem`, `pke` and `random`, with `list` to say what
//! each takes. No configuration file, no privileges, and nothing
//! that transforms bytes: every operation is the library's, and the
//! tool only carries bytes to it and back.
//!
//! The algorithm is the operation. It is the first word after the
//! verb on every call, never an option and never defaulted, so a
//! script says what it does and a reader need not know a default.
//! Every name is in [`names`], with what it takes.
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

use clap::{Args, Parser, Subcommand};

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
mod names;
mod pke;
mod random;
mod sig;
mod value;

#[derive(Parser)]
#[command(
    name = "scytale",
    version,
    about = "The scytale library from a shell",
    after_help = help::VALUES
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// The algorithm names each command takes
    List(ListArgs),
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
    Mac {
        #[command(subcommand)]
        op: mac::MacOp,
    },
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

impl Command {
    /// The words a message about this call starts with: the command,
    /// the verb and the algorithm, as they were given.
    fn context(&self) -> String {
        match self {
            Command::List(_) => "list".into(),
            Command::Random(_) => "random".into(),
            Command::Hash(a) => format!("hash {}", a.algorithm),
            Command::Cipher { op } => format!("cipher {}", op.context()),
            Command::Aead { op } => format!("aead {}", op.context()),
            Command::Mac { op } => format!("mac {}", op.context()),
            Command::Kdf { op } => format!("kdf {}", op.context()),
            Command::Key { op } => format!("key {}", op.context()),
            Command::Sig { op } => format!("sig {}", op.context()),
            Command::Kex { op } => format!("kex {}", op.context()),
            Command::Kem { op } => format!("kem {}", op.context()),
            Command::Pke { op } => format!("pke {}", op.context()),
        }
    }
}

#[derive(Args)]
struct ListArgs {
    /// One of: hash, mac, aead, cipher, kdf, key, sig, kex, kem, pke
    family: Option<String>,
    /// Say what each name takes
    #[arg(long)]
    long: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let context = cli.command.context();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(fail::Fail::Quiet) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("scytale {context}: {e}");
            ExitCode::from(e.code() as u8)
        }
    }
}

fn run(command: Command) -> fail::Result<()> {
    match command {
        Command::List(args) => list(&args),
        Command::Random(args) => random::run(args),
        Command::Hash(args) => hash::run(args),
        Command::Cipher { op } => cipher::run(op),
        Command::Aead { op } => aead::run(op),
        Command::Mac { op } => mac::run(op),
        Command::Kdf { op } => kdf::run(op),
        Command::Key { op } => key::run(op),
        Command::Sig { op } => sig::run(op),
        Command::Kex { op } => kex::run(op),
        Command::Kem { op } => kem::run(op),
        Command::Pke { op } => pke::run(op),
    }
}

fn list(args: &ListArgs) -> fail::Result<()> {
    let families: Vec<&names::Family> = match &args.family {
        Some(wanted) => {
            let found = names::FAMILIES.iter().find(|f| f.name == wanted);
            let Some(family) = found else {
                let all: Vec<&str> =
                    names::FAMILIES.iter().map(|f| f.name).collect();
                return Err(fail::usage!(
                    "no family named \"{wanted}\"; one of {}",
                    all.join(", ")
                ));
            };
            vec![family]
        }
        None => names::FAMILIES.to_vec(),
    };
    let one = families.len() == 1;
    for family in families {
        for entry in family.iter() {
            if one {
                print!("{}", entry.name);
            } else {
                print!("{} {}", family.name, entry.name);
            }
            if args.long {
                let mut takes = Vec::new();
                for (what, len) in [
                    ("key", entry.key),
                    ("nonce", entry.nonce),
                    ("tag", entry.tag),
                    ("output", entry.output),
                ] {
                    if len != names::Len::None {
                        takes.push(format!("{what} {}", len.describe()));
                    }
                }
                if !entry.note.is_empty() {
                    takes.push(entry.note.to_owned());
                }
                if !takes.is_empty() {
                    print!("  {}", takes.join("; "));
                }
            }
            println!();
        }
    }
    Ok(())
}
