//! PBKDF2 (RFC 8018), over the HMACs in [`hmac`].

use core::num::NonZeroU32;

use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{Sha256, Sha384, Sha512};
use scytale::kdf::pbkdf2::pbkdf2;

use crate::digest::Id;
use crate::{error, hmac};

/// Which HMAC PBKDF2 runs over.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Algorithm(hmac::Algorithm);

/// PBKDF2 with HMAC-SHA-1.
pub static PBKDF2_HMAC_SHA1: Algorithm =
    Algorithm(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY);

/// PBKDF2 with HMAC-SHA-256.
pub static PBKDF2_HMAC_SHA256: Algorithm = Algorithm(hmac::HMAC_SHA256);

/// PBKDF2 with HMAC-SHA-384.
pub static PBKDF2_HMAC_SHA384: Algorithm = Algorithm(hmac::HMAC_SHA384);

/// PBKDF2 with HMAC-SHA-512.
pub static PBKDF2_HMAC_SHA512: Algorithm = Algorithm(hmac::HMAC_SHA512);

/// Fills `out` with the key derived from `secret` and `salt` by
/// `iterations` rounds.
pub fn derive(
    algorithm: Algorithm,
    iterations: NonZeroU32,
    salt: &[u8],
    secret: &[u8],
    out: &mut [u8],
) {
    let n = iterations.get();
    let derived = match algorithm.0.digest_algorithm().id {
        Id::SHA1 => pbkdf2::<Sha1>(secret, salt, n, out),
        Id::SHA256 => pbkdf2::<Sha256>(secret, salt, n, out),
        Id::SHA384 => pbkdf2::<Sha384>(secret, salt, n, out),
        Id::SHA512 => pbkdf2::<Sha512>(secret, salt, n, out),
        Id::SHA512_256 => unreachable!("PBKDF2 over SHA-512/256"),
    };
    // The count is nonzero by type, which is the one thing the
    // derivation refuses.
    derived.unwrap_or_else(|_| unreachable!("a nonzero count was refused"));
}

/// Whether `previously_derived` is the key [`derive()`] would produce,
/// compared in constant time, block by block, without a buffer for
/// the whole of it. An empty key is refused.
pub fn verify(
    algorithm: Algorithm,
    iterations: NonZeroU32,
    salt: &[u8],
    secret: &[u8],
    previously_derived: &[u8],
) -> Result<(), error::Unspecified> {
    use scytale::kdf::pbkdf2::verify;
    let n = iterations.get();
    let key = previously_derived;
    match algorithm.0.digest_algorithm().id {
        Id::SHA1 => verify::<Sha1>(secret, salt, n, key),
        Id::SHA256 => verify::<Sha256>(secret, salt, n, key),
        Id::SHA384 => verify::<Sha384>(secret, salt, n, key),
        Id::SHA512 => verify::<Sha512>(secret, salt, n, key),
        Id::SHA512_256 => unreachable!("PBKDF2 over SHA-512/256"),
    }
    .map_err(error::erase)
}
