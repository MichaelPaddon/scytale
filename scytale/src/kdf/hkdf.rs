//! HKDF (RFC 5869): extract-then-expand with HMAC.
//!
//! [`extract`] takes keying material of any shape and a salt and
//! makes a pseudorandom key of one digest; [`expand`] stretches that
//! key, with a context string, to any length up to 255 digests. Most
//! uses want both, which is [`derive()`]. The salt is optional but
//! valuable: without one, `extract` is HMAC under a key of zeros.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::hkdf;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let shared_secret = [0x0b; 32];
//! let salt = [0x42; 16];
//!
//! // Both steps at once: the usual case.
//! let mut key = [0u8; 32];
//! hkdf::derive::<Sha256>(&salt, &shared_secret, b"encryption", &mut key)?;
//!
//! // Expand only, from a key that is already uniformly random, such
//! // as one a generator drew. Extracting again would not hurt, but
//! // there is nothing for it to do.
//! let prk = [0x7e; 32];
//! let mut client = [0u8; 32];
//! let mut server = [0u8; 32];
//! hkdf::expand::<Sha256>(&prk, b"client write", &mut client)?;
//! hkdf::expand::<Sha256>(&prk, b"server write", &mut server)?;
//! assert_ne!(client, server);
//! # Ok(())
//! # }
//! ```
//!
//! # Salt and info
//!
//! The salt should be random and may be public: a protocol nonce,
//! sent in the clear, is ideal. It does not need to be secret, and it
//! is not what makes the output unpredictable; it makes the extract
//! step behave as a random function even when the keying material is
//! structured. `info` is what separates keys: the same secret and
//! salt with different `info` give unrelated keys, so a protocol
//! derives one key per purpose by naming the purpose there, and never
//! reuses a key for two. One expansion is limited to 255 digests, 8
//! kilobytes for SHA-256; a protocol wanting more than that has
//! something else wrong.

use crate::hash::Hash;
use crate::mac::hmac::Hmac;
use crate::mac::Mac;
use crate::{BlockType, Error};

/// Extracts a pseudorandom key from `ikm` under `salt`, which may be
/// empty.
pub fn extract<H: Hash + Clone + BlockType>(
    salt: &[u8],
    ikm: &[u8],
) -> Result<H::Output, Error> {
    let mut mac = Hmac::<H>::try_new(salt)?;
    mac.update(ikm);
    Ok(mac.finalize())
}

/// Fills `okm` with keying material expanded from `prk` and `info`.
///
/// Returns [`Error::InvalidLength`] if `okm` is longer than 255
/// digests, the most the construction defines.
pub fn expand<H: Hash + Clone + BlockType>(
    prk: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), Error> {
    if okm.len() > 255 * size_of::<H::Output>() {
        return Err(Error::InvalidLength(okm.len()));
    }
    let mut mac = Hmac::<H>::try_new(prk)?;
    // T(0) is empty; T(i) = HMAC(PRK, T(i-1) || info || i). Each
    // `finalize` leaves the MAC keyed and ready for the next.
    let mut previous: Option<H::Output> = None;
    for (i, chunk) in okm.chunks_mut(size_of::<H::Output>()).enumerate() {
        if let Some(previous) = &previous {
            mac.update(previous.as_ref());
        }
        mac.update(info);
        mac.update(&[(i + 1) as u8]);
        let t = mac.finalize();
        chunk.copy_from_slice(&t.as_ref()[..chunk.len()]);
        previous = Some(t);
    }
    Ok(())
}

/// Extracts from `ikm` under `salt`, then expands with `info` to fill
/// `okm`.
pub fn derive<H: Hash + Clone + BlockType>(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), Error> {
    let prk = extract::<H>(salt, ikm)?;
    expand::<H>(prk.as_ref(), info, okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::Sha256;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(s.len(), 2 * N);
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    // RFC 5869 appendix A; cases 4 to 7 use SHA-1.

    #[test]
    fn rfc5869_case_1() {
        let ikm = [0x0b; 22];
        let salt = hex::<13>("000102030405060708090a0b0c");
        let info = hex::<10>("f0f1f2f3f4f5f6f7f8f9");
        let prk = extract::<Sha256>(&salt, &ikm).unwrap();
        assert_eq!(
            prk,
            hex::<32>(
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c\
                 2b3e5"
            )
        );
        let mut okm = [0u8; 42];
        expand::<Sha256>(&prk, &info, &mut okm).unwrap();
        assert_eq!(
            okm,
            hex::<42>(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc\
                 4c5bf34007208d5b887185865"
            )
        );
        let mut again = [0u8; 42];
        derive::<Sha256>(&salt, &ikm, &info, &mut again).unwrap();
        assert_eq!(again, okm);
    }

    #[test]
    fn rfc5869_case_2() {
        let ikm: [u8; 80] = core::array::from_fn(|i| i as u8);
        let salt: [u8; 80] = core::array::from_fn(|i| 0x60 + i as u8);
        let info: [u8; 80] = core::array::from_fn(|i| 0xb0 + i as u8);
        let mut okm = [0u8; 82];
        derive::<Sha256>(&salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            okm,
            hex::<82>(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19a\
                 fa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b836779\
                 3a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
            )
        );
    }

    #[test]
    fn rfc5869_case_3() {
        let ikm = [0x0b; 22];
        let mut okm = [0u8; 42];
        derive::<Sha256>(&[], &ikm, &[], &mut okm).unwrap();
        assert_eq!(
            okm,
            hex::<42>(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c7\
                 38d2d9d201395faa4b61a96c8"
            )
        );
    }

    #[test]
    fn rfc5869_case_4() {
        use crate::hash::sha1::Sha1;
        let ikm = [0x0b; 11];
        let salt = hex::<13>("000102030405060708090a0b0c");
        let info = hex::<10>("f0f1f2f3f4f5f6f7f8f9");
        let prk = extract::<Sha1>(&salt, &ikm).unwrap();
        assert_eq!(prk, hex::<20>("9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"));
        let mut okm = [0u8; 42];
        expand::<Sha1>(&prk, &info, &mut okm).unwrap();
        assert_eq!(
            okm,
            hex::<42>(
                "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f15\
                 5fda2c22e422478d305f3f896"
            )
        );
    }

    #[test]
    fn rfc5869_case_5() {
        use crate::hash::sha1::Sha1;
        let ikm: [u8; 80] = core::array::from_fn(|i| i as u8);
        let salt: [u8; 80] = core::array::from_fn(|i| 0x60 + i as u8);
        let info: [u8; 80] = core::array::from_fn(|i| 0xb0 + i as u8);
        let mut okm = [0u8; 82];
        derive::<Sha1>(&salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            okm,
            hex::<82>(
                "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673b\
                 a2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f\
                 9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4"
            )
        );
    }

    #[test]
    fn rfc5869_case_6() {
        use crate::hash::sha1::Sha1;
        let ikm = [0x0b; 22];
        let mut okm = [0u8; 42];
        derive::<Sha1>(&[], &ikm, &[], &mut okm).unwrap();
        assert_eq!(
            okm,
            hex::<42>(
                "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8d\
                 f21d0ea00033de03984d34918"
            )
        );
    }

    /// Case 7: no salt at all, which the RFC defines as a salt of
    /// zeros the hash's length, the same as an empty one here.
    #[test]
    fn rfc5869_case_7() {
        use crate::hash::sha1::Sha1;
        let ikm = [0x0c; 22];
        let mut okm = [0u8; 42];
        derive::<Sha1>(&[], &ikm, &[], &mut okm).unwrap();
        assert_eq!(
            okm,
            hex::<42>(
                "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba\
                 6f5e5673a081d70cce7acfc48"
            )
        );
    }

    #[test]
    fn expand_refuses_more_than_255_blocks() {
        let prk = [0u8; 32];
        let mut okm = [0u8; 255 * 32 + 1];
        assert_eq!(
            expand::<Sha256>(&prk, &[], &mut okm),
            Err(Error::InvalidLength(255 * 32 + 1))
        );
        assert_eq!(expand::<Sha256>(&prk, &[], &mut okm[..255 * 32]), Ok(()));
    }

    #[test]
    fn expand_to_nothing_is_fine() {
        assert_eq!(expand::<Sha256>(&[0u8; 32], b"x", &mut []), Ok(()));
    }
}
