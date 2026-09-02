//! Key establishment: two parties end up sharing a secret key.
//!
//! It comes in two shapes (NIST SP 800-56). Key agreement, where
//! both parties contribute a key pair and derive the same secret
//! that neither chose: [`x25519`]. And key transport, where one
//! party picks the secret and encrypts it to the other's public
//! key: [`rsa`], with OAEP. Agreement is the better default; when
//! the post-quantum encapsulation schemes land they will sit beside
//! these.
//!
//! A shared secret from key agreement is a curve point, not a key:
//! run it through [`hkdf`](crate::kdf::hkdf) and use the output.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::hkdf;
//! use scytale::kex::x25519;
//! use scytale::random::{Random, Rng, System};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//!
//! // Each party publishes one value and keeps one.
//! let mut alice = [0u8; x25519::KEY_SIZE];
//! let mut bob = [0u8; x25519::KEY_SIZE];
//! rng.fill(&mut alice)?;
//! rng.fill(&mut bob)?;
//! let shared = x25519::shared_secret(&alice, &x25519::public_key(&bob))?;
//! let mut key = [0u8; 32];
//! hkdf::derive::<Sha256>(b"", &shared, b"session v1", &mut key)?;
//! # Ok(())
//! # }
//! ```

pub mod rsa;
pub mod x25519;
