//! Digital signatures.
//!
//! A signature proves a message came from the holder of a secret
//! key, and anyone with the public key can check it: unlike a MAC,
//! checking needs no secret. [`ed25519`] is the scheme of RFC 8032,
//! and the one to pick unless a protocol names another.
//!
//! ```
//! use scytale::random::{Random, Rng, System};
//! use scytale::signature::ed25519;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // The signer keeps 32 secret bytes and publishes the public key.
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let mut secret = [0u8; ed25519::KEY_SIZE];
//! rng.fill(&mut secret)?;
//! let public = ed25519::public_key(&secret)?;
//!
//! // Anyone holding the public key can check a signature.
//! let signature = ed25519::sign(&secret, b"release v1.2")?;
//! ed25519::verify(&public, b"release v1.2", &signature)?;
//! assert!(ed25519::verify(&public, b"release v1.3", &signature).is_err());
//! # Ok(())
//! # }
//! ```

pub mod ed25519;
