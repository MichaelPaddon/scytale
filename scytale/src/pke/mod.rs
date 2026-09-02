//! Public-key encryption: anyone can encrypt to a public key, and
//! only the holder of the private key can read the result.
//!
//! The one scheme here is [`rsa`], with OAEP padding. It is for
//! moving keys, not data: a message must fit inside one modulus, so
//! encrypt a symmetric key and let a cipher carry the rest. When both
//! parties are present to contribute a key pair, key agreement under
//! [`kex`](crate::kex) is the better default; public-key encryption
//! is for the recipient who is not online, or the format that asks
//! for it by name.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::pke::rsa::Rsa2048PrivateKey;
//! use scytale::random::{Rng, System};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let key = Rsa2048PrivateKey::generate(&mut rng)?;
//!
//! // The sender encrypts a session key to the public half.
//! let session_key = [0x42u8; 32];
//! let sealed = key
//!     .public_key()
//!     .encrypt_oaep::<Sha256, _>(&mut rng, b"", &session_key)?;
//!
//! // The key holder recovers it.
//! let mut out = [0u8; 256];
//! let n = key.decrypt_oaep::<Sha256>(b"", &sealed, &mut out)?;
//! assert_eq!(&out[..n], &session_key);
//! # Ok(())
//! # }
//! ```

pub mod rsa;
