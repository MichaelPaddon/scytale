//! Key agreement: both parties contribute a key pair and derive the
//! same secret, one that neither of them chose.
//!
//! The scheme here is [`x25519`]. When one side must instead pick
//! the secret and encrypt it to the other, that is public-key
//! encryption, under [`pke`](crate::pke); when the post-quantum
//! encapsulation schemes land they will sit beside these in a
//! module of their own.
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

pub mod x25519;
