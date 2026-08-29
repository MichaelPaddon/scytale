//! HKDF (RFC 5869): extract-then-expand with HMAC.
//!
//! [`extract`] takes keying material of any shape and a salt and
//! makes a pseudorandom key of one digest; [`expand`] stretches that
//! key, with a context string, to any length up to 255 digests. Most
//! uses want both, which is [`derive()`]. The salt is optional but
//! valuable: without one, `extract` is HMAC under a key of zeros.

use crate::hash::Hash;
use crate::mac::hmac::Hmac;
use crate::mac::Mac;
use crate::symmetric::Block;
use crate::Error;

/// Extracts a pseudorandom key from `ikm` under `salt`, which may be
/// empty.
pub fn extract<H: Hash>(salt: &[u8], ikm: &[u8]) -> Result<H::Output, Error> {
    let mut mac = Hmac::<H>::try_new(salt)?;
    mac.update(ikm);
    Ok(mac.finalize())
}

/// Fills `okm` with keying material expanded from `prk` and `info`.
///
/// Returns [`Error::InvalidLength`] if `okm` is longer than 255
/// digests, the most the construction defines.
pub fn expand<H: Hash>(
    prk: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), Error> {
    if okm.len() > 255 * H::Output::SIZE {
        return Err(Error::InvalidLength(okm.len()));
    }
    let mut mac = Hmac::<H>::try_new(prk)?;
    // T(0) is empty; T(i) = HMAC(PRK, T(i-1) || info || i).
    let mut previous = H::Output::ZERO;
    let mut have_previous = false;
    for (i, chunk) in okm.chunks_mut(H::Output::SIZE).enumerate() {
        mac.reset();
        if have_previous {
            mac.update(previous.as_ref());
        }
        mac.update(info);
        mac.update(&[(i + 1) as u8]);
        previous = mac.clone().finalize();
        have_previous = true;
        chunk.copy_from_slice(&previous.as_ref()[..chunk.len()]);
    }
    Ok(())
}

/// Extracts from `ikm` under `salt`, then expands with `info` to fill
/// `okm`.
pub fn derive<H: Hash>(
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

    // RFC 5869 appendix A. Cases 4 to 6 use SHA-1, which the crate
    // does not have yet.

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
