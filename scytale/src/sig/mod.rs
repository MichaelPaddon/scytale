//! Signatures: made with a secret key, checked with a public one.
//!
//! A signature binds a message to the holder of a key. [`ed25519`]
//! is the scheme to pick unless a protocol names another; [`rsa`]
//! covers the protocols and certificates that ask for it by name,
//! with PSS and PKCS#1 v1.5 padding.
//!
//! ```
//! use scytale::random::{Random, Rng, System};
//! use scytale::sig::ed25519;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let mut secret = [0u8; ed25519::KEY_SIZE];
//! rng.fill(&mut secret)?;
//!
//! // Made with the secret, checked with the public.
//! let public = ed25519::public_key(&secret)?;
//! let signature = ed25519::sign(&secret, b"release v1.2")?;
//! ed25519::verify(&public, b"release v1.2", &signature)?;
//! assert!(ed25519::verify(&public, b"release v1.3", &signature).is_err());
//! # Ok(())
//! # }
//! ```

pub mod ed25519;
pub mod rsa;
