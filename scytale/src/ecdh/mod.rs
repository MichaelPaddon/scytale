//! Elliptic curve Diffie-Hellman key agreement.
//!
//! Two parties each publish one value and keep one secret, and both
//! can then compute a value nobody else can. That shared secret is
//! not a key: it is a point on a curve, with structure a key must
//! not have. Run it through [`hkdf`](crate::kdf::hkdf) and use the
//! output.
//!
//! [`x25519`] is the curve of RFC 7748, and the one to pick unless a
//! protocol names another.
//!
//! ```
//! use scytale::ecdh::x25519;
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::hkdf;
//! use scytale::random::{Random, Rng, System};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // Each party makes a secret and publishes its public key.
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let mut alice = [0u8; x25519::KEY_SIZE];
//! let mut bob = [0u8; x25519::KEY_SIZE];
//! rng.fill(&mut alice)?;
//! rng.fill(&mut bob)?;
//! let alice_public = x25519::public_key(&alice);
//! let bob_public = x25519::public_key(&bob);
//!
//! // Each combines its secret with the other's public key.
//! let shared = x25519::shared_secret(&alice, &bob_public)?;
//! assert_eq!(shared, x25519::shared_secret(&bob, &alice_public)?);
//!
//! // The point becomes keys through a KDF, never directly.
//! let mut key = [0u8; 32];
//! hkdf::derive::<Sha256>(b"", &shared, b"session v1", &mut key)?;
//! # Ok(())
//! # }
//! ```

pub mod x25519;
