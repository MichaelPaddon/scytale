//! PBKDF2 (RFC 8018, SP 800-132): a key from a password.
//!
//! Each block of output is HMAC of the salt and block number,
//! rehashed `iterations` times with the results xored together. The
//! iteration count is the whole defence: a password is guessable,
//! and every guess costs the attacker as many hashes as it costs you.
//! Choose it by how long you can afford, not by a table. Salt must
//! be unique per password, so that a guess cannot be checked against
//! every password at once.
//!
//! PBKDF2 is what the standards name, and it is not the best
//! password hash: it needs no memory, so purpose-built hardware runs
//! it far faster than yours. Where the choice is yours, prefer a
//! memory-hard function.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::pbkdf2::pbkdf2;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // The salt is stored beside the derived key, and differs for
//! // every password.
//! let salt = [0x1f; 16];
//! let mut key = [0u8; 32];
//! let password = b"correct horse battery staple";
//! pbkdf2::<Sha256>(password, &salt, 600_000, &mut key)?;
//! # Ok(())
//! # }
//! ```
//!
//! # How many iterations
//!
//! Hundreds of thousands, with SHA-256, as of 2026: OWASP's guidance
//! is 600,000, and SP 800-132, which specifies the construction, says
//! to pick as many as the application can bear. Each iteration is two
//! compressions of the hash, so 600,000 of them is a few hundred
//! milliseconds on a laptop core, which a login can afford and an
//! attacker guessing billions of passwords cannot. Raise the number
//! as processors get faster; it is stored beside the salt, so old
//! keys keep working.

use crate::cipher::Block;
use crate::hash::Hash;
use crate::mac::hmac::Hmac;
use crate::mac::Mac;
use crate::Error;

/// Fills `key` from `password` and `salt` with `iterations` rounds.
///
/// Returns [`Error::InvalidIterations`] for zero iterations, and
/// [`Error::InvalidLength`] if `key` is longer than the construction
/// can number, which no real key is.
pub fn pbkdf2<H: Hash>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key: &mut [u8],
) -> Result<(), Error> {
    if iterations == 0 {
        return Err(Error::InvalidIterations);
    }
    if key.len().div_ceil(H::Output::SIZE) > u32::MAX as usize {
        return Err(Error::InvalidLength(key.len()));
    }
    // The password is the HMAC key, processed once here rather than
    // once per iteration.
    let mut mac = Hmac::<H>::try_new(password)?;
    for (i, chunk) in key.chunks_mut(H::Output::SIZE).enumerate() {
        // U_1 = PRF(P, S || INT(i)), then U_j = PRF(P, U_{j-1}).
        mac.reset();
        mac.update(salt);
        mac.update(&(i as u32 + 1).to_be_bytes());
        let mut u = mac.clone().finalize();
        let mut t = u;
        for _ in 1..iterations {
            mac.reset();
            mac.update(u.as_ref());
            u = mac.clone().finalize();
            for (t, u) in t.as_mut().iter_mut().zip(u.as_ref()) {
                *t ^= u;
            }
        }
        chunk.copy_from_slice(&t.as_ref()[..chunk.len()]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::{Sha256, Sha512};

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(s.len(), 2 * N);
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    // The RFC 6070 inputs with HMAC-SHA-256, as published in the
    // PBKDF2-HMAC-SHA256 test vectors of Stephen Josefsson's
    // draft-josefsson-pbkdf2-test-vectors.

    #[test]
    fn sha256_one_iteration() {
        let mut key = [0u8; 32];
        pbkdf2::<Sha256>(b"password", b"salt", 1, &mut key).unwrap();
        assert_eq!(
            key,
            hex::<32>(
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70\
                 be17b"
            )
        );
    }

    #[test]
    fn sha256_two_iterations() {
        let mut key = [0u8; 32];
        pbkdf2::<Sha256>(b"password", b"salt", 2, &mut key).unwrap();
        assert_eq!(
            key,
            hex::<32>(
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95\
                 474c43"
            )
        );
    }

    #[test]
    fn sha256_4096_iterations() {
        let mut key = [0u8; 32];
        pbkdf2::<Sha256>(b"password", b"salt", 4096, &mut key).unwrap();
        assert_eq!(
            key,
            hex::<32>(
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa\
                 98134a"
            )
        );
    }

    /// Two blocks of output, the second cut short.
    #[test]
    fn sha256_long_output() {
        let mut key = [0u8; 40];
        pbkdf2::<Sha256>(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            &mut key,
        )
        .unwrap();
        assert_eq!(
            key,
            hex::<40>(
                "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8\
                 dd53e1c635518c7dac47e9"
            )
        );
    }

    #[test]
    fn sha512_one_iteration() {
        let mut key = [0u8; 64];
        pbkdf2::<Sha512>(b"password", b"salt", 1, &mut key).unwrap();
        assert_eq!(
            key,
            hex::<64>(
                "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c\
                 8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63\
                 f73b60a57fce"
            )
        );
    }

    #[test]
    fn zero_iterations_is_refused() {
        let mut key = [0u8; 16];
        assert_eq!(
            pbkdf2::<Sha256>(b"p", b"s", 0, &mut key),
            Err(Error::InvalidIterations)
        );
    }

    #[test]
    fn a_prefix_is_a_prefix() {
        let mut long = [0u8; 40];
        let mut short = [0u8; 35];
        pbkdf2::<Sha256>(b"p", b"s", 3, &mut long).unwrap();
        pbkdf2::<Sha256>(b"p", b"s", 3, &mut short).unwrap();
        assert_eq!(long[..35], short);
    }
}
