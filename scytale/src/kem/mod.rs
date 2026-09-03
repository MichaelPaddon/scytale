//! Key encapsulation: the sender makes a shared secret and a
//! ciphertext from the recipient's public key, and the recipient
//! recovers the secret from the ciphertext.
//!
//! Encapsulation is what key agreement becomes when one side has
//! only a public key to work with and no chance to contribute a
//! fresh one; it is the interface the post-quantum schemes present.
//! The one scheme here is [`ml_kem`] (FIPS 203), in its three
//! parameter sets. Where both parties are present to contribute a
//! key pair, [`kex`](crate::kex) is the classical alternative; the
//! two are commonly run together and their secrets combined, so that
//! a break in either leaves the other standing.
//!
//! A shared secret from ML-KEM is already uniform, and may be used
//! as a key directly; running it through
//! [`hkdf`](crate::kdf::hkdf) is still the way to bind it to a
//! context or combine it with another.
//!
//! ```
//! use scytale::kem::ml_kem::ml_kem_768::PrivateKey;
//! use scytale::random::{Rng, System};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let recipient = PrivateKey::generate(&mut rng)?;
//!
//! // The sender needs only the public key.
//! let (ciphertext, secret) = recipient.public_key().encapsulate(&mut rng)?;
//! assert_eq!(recipient.decapsulate(&ciphertext), secret);
//! # Ok(())
//! # }
//! ```

pub mod ml_kem;
