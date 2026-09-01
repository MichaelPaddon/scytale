//! Public-key cryptography: key agreement, signatures, encryption.
//!
//! Everything here rests on a pair of keys, one published and one
//! kept, where symmetric cryptography rests on one shared secret.
//! [`x25519`] agrees on a secret with a peer; [`ed25519`] signs, and
//! is the scheme to pick unless a protocol names another; [`rsa`]
//! signs and encrypts for the protocols and certificates that ask
//! for it by name.
//!
//! A shared secret from key agreement is a curve point, not a key:
//! run it through [`hkdf`](crate::kdf::hkdf) and use the output.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::hkdf;
//! use scytale::publickey::{ed25519, x25519};
//! use scytale::random::{Random, Rng, System};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//!
//! // Key agreement: each party publishes one value and keeps one.
//! let mut alice = [0u8; x25519::KEY_SIZE];
//! let mut bob = [0u8; x25519::KEY_SIZE];
//! rng.fill(&mut alice)?;
//! rng.fill(&mut bob)?;
//! let shared = x25519::shared_secret(&alice, &x25519::public_key(&bob))?;
//! let mut key = [0u8; 32];
//! hkdf::derive::<Sha256>(b"", &shared, b"session v1", &mut key)?;
//!
//! // Signatures: made with the secret, checked with the public.
//! let mut secret = [0u8; ed25519::KEY_SIZE];
//! rng.fill(&mut secret)?;
//! let public = ed25519::public_key(&secret)?;
//! let signature = ed25519::sign(&secret, b"release v1.2")?;
//! ed25519::verify(&public, b"release v1.2", &signature)?;
//! assert!(ed25519::verify(&public, b"release v1.3", &signature).is_err());
//! # Ok(())
//! # }
//! ```

pub mod ed25519;
pub mod rsa;
pub mod x25519;
