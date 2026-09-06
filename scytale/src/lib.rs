//! Portable cryptographic primitives.
//!
//! Symmetric ciphers and their modes, hashes, message
//! authentication, key derivation, key agreement, public-key
//! encryption, signatures and random numbers,
//! written to run anywhere Rust
//! does: `no_std`, no allocator, no cargo features to get wrong. Where
//! the processor has instructions for a primitive they are used,
//! chosen at run time, and there is always portable code behind them.
//!
//! | Module | What is in it |
//! | --- | --- |
//! | [`cipher`] | AES, ChaCha20, and the modes built on them |
//! | [`hash`] | SHA-2, SHA-3, SHAKE, and SHA-1 for old protocols |
//! | [`mac`] | HMAC over any hash, and Poly1305 |
//! | [`kdf`] | HKDF and PBKDF2 |
//! | [`kem`] | ML-KEM key encapsulation |
//! | [`kex`] | X25519 and ECDH key agreement |
//! | [`pke`] | RSA-OAEP public-key encryption |
//! | [`random`] | a CTR_DRBG generator and the entropy that seeds it |
//! | [`sig`] | Ed25519, ECDSA, ML-DSA, SLH-DSA and RSA signatures |
//! | [`Error`] | the one type every fallible call returns |
//!
//! # Example
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::hash::Hash;
//! use scytale::kdf::hkdf;
//! use scytale::mac::hmac::Hmac;
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::mode::{Gcm, Nonces};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // A session key, and a key for each job derived from it.
//! let secret = [0x42u8; 32];
//! let mut cipher_key = [0u8; 16];
//! let mut mac_key = [0u8; 32];
//! hkdf::derive::<Sha256>(b"salt", &secret, b"cipher", &mut cipher_key)?;
//! hkdf::derive::<Sha256>(b"salt", &secret, b"mac", &mut mac_key)?;
//!
//! // Authenticated encryption, with nonces that cannot repeat.
//! let gcm = Gcm::try_new(Aes128::try_new(&cipher_key)?)?;
//! let mut nonces = Nonces::new(7, 0);
//! let nonce = nonces.take()?;
//! let mut message = *b"attack at dawn";
//! let mut tag = [0u8; 16];
//! gcm.encrypt(&nonce, b"header", &mut message, &mut tag)?;
//! gcm.decrypt(&nonce, b"header", &mut message, &tag)?;
//! assert_eq!(&message, b"attack at dawn");
//!
//! // A digest, and a tag over the same bytes.
//! let digest = Sha256::digest(&message)?;
//! let mac = Hmac::<Sha256>::mac(&mac_key, &message)?;
//! assert_ne!(digest, mac);
//! # Ok(())
//! # }
//! ```
//!
//! # Guarantees
//!
//! These hold everywhere in the crate, so they need not be checked
//! primitive by primitive.
//!
//! - Every fallible call returns [`Error`], and no error says anything
//!   about a secret.
//! - A message that fails authentication is wiped before the error is
//!   returned, so unauthenticated plaintext is never handed back by a
//!   one-shot call. The incremental decryptors say so where they
//!   cannot promise this.
//! - Keys, and every state derived from one, are zeroed when dropped.
//! - Tags are compared in time that depends on their length and on
//!   nothing else.
//! - The implementation chosen at run time is never one that leaks
//!   through the cache; table-driven code exists, and must be asked
//!   for by name.
//! - `Debug` output never contains key material, so a state can be
//!   logged.
//! - A trait describing a value you hold, a hash, a MAC or a cipher,
//!   has no associated constants and is usable as a trait object once
//!   its types are named: `&mut dyn Hash<Output = [u8; 32]>`. Sizes
//!   are types, [`Block`](BlockType::Block) and [`Key`](KeyType::Key)
//!   among them, so a wrong length is a compile error. Only
//!   construction needs the concrete type.
//!
//! # Non-goals
//!
//! No protocols: TLS, SSH and their kin are built on these pieces,
//! not in here. No allocator, so every output goes into a buffer the
//! caller supplies. The
//! format-preserving modes, [`Ff1`](cipher::mode::Ff1) and
//! [`Ff3_1`](cipher::mode::Ff3_1), are not constant time, and say
//! so. The raw RSA primitives are offered, for building a scheme the
//! crate does not have and for the component test suites, but they
//! pad and check nothing and say so at length.
//!
//! # Rust version
//!
//! Rust 1.88 or later, as `rust-version` in `Cargo.toml` records.

#![no_std]
// Hardware implementations need intrinsics; they opt in per module.
#![deny(unsafe_code)]
// `chunks_exact(N)` reads better than `as_chunks::<N>()` and the
// compiler removes the length checks either way.
#![allow(clippy::chunks_exact_to_as_chunks)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod arch;
pub mod cipher;
mod der;
mod error;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod kex;
pub mod mac;
mod math;
mod pem;
pub mod pke;
pub mod random;
pub mod sig;

mod traits;
mod util;

pub use error::Error;
pub use traits::{BlockType, ByteArray, KeyType};
