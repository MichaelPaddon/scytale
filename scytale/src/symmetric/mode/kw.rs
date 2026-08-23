//! Key wrapping (NIST SP 800-38F), the unpadded form.
//!
//! Wrapping protects one key with another, for storing it or sending
//! it somewhere. It is authenticated, so unwrapping tells you whether
//! what came back is what went in, and it takes no nonce, which is
//! what makes it different from every other mode here.
//!
//! Taking no nonce means it is deterministic: the same key wrapped
//! twice gives the same result both times. For a key that is
//! deliberate and harmless, because a key is already unguessable. For
//! anything an attacker might guess it is not, and this is the wrong
//! tool: see the warnings below.
//!
//! The wrapped result is eight bytes longer than the input, which is
//! where the check value lives.
//!
//! # Which cipher direction
//!
//! The standard allows the wrapping to be built on either the
//! cipher's forward direction or its inverse. [`Kw::new`] takes the
//! forward one, which is what RFC 3394 describes and what everyone
//! means by AES key wrap; [`Kw::new_inverse`] takes the other, which
//! the standard permits and a few implementations use. They are not
//! interchangeable: what one wraps, only the same one unwraps.
//!
//! # Using it safely
//!
//! - **Wrap keys, not messages.** Because there is no nonce, equal
//!   inputs give equal outputs, so an attacker who can guess what was
//!   wrapped can confirm the guess by wrapping it themselves. A key
//!   cannot be guessed, which is why this is safe for keys and only
//!   for keys. For anything else use an authenticated mode with a
//!   nonce, such as [`Gcm`](super::Gcm).
//! - The input must be a whole number of eight-byte units, and at
//!   least sixteen bytes. [`Kwp`](super::Kwp) removes both of those
//!   restrictions, at the cost of padding.
//! - This is one shot only. There is no incremental form, because
//!   the check value depends on every byte and the whole thing is
//!   passed over six times.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Kw;
//! use scytale::symmetric::BlockCipher;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let kw = Kw::new(Aes::try_new(&[0u8; 16])?);
//!
//! let key = [7u8; 32];
//! let mut wrapped = [0u8; 40];
//! kw.wrap(&key, &mut wrapped)?;
//!
//! let mut back = [0u8; 32];
//! let n = kw.unwrap(&wrapped, &mut back)?;
//! assert_eq!(&back[..n], &key);
//! # Ok(())
//! # }
//! ```

use crate::symmetric::{BlockCipher, Error};

/// The cipher block this is defined for.
const BLOCK: usize = 16;

/// Half a block, the unit everything here is counted in.
pub(super) const SEMIBLOCK: usize = 8;

/// The check value for the unpadded form, from SP 800-38F.
const ICV1: [u8; SEMIBLOCK] = [0xa6; SEMIBLOCK];

/// Key wrapping over a block cipher.
#[derive(Clone, Debug)]
pub struct Kw<C> {
    cipher: C,
    /// Whether wrapping uses the cipher's forward direction.
    forward: bool,
}

impl<C: BlockCipher> Kw<C> {
    /// Wraps with the cipher's forward direction, as RFC 3394
    /// describes.
    ///
    /// # Panics
    /// If the cipher's block is not 128 bits.
    pub fn new(cipher: C) -> Self {
        Kw::with_direction(cipher, true)
    }

    /// Wraps with the cipher's inverse direction, the other choice
    /// the standard allows.
    ///
    /// # Panics
    /// If the cipher's block is not 128 bits.
    pub fn new_inverse(cipher: C) -> Self {
        Kw::with_direction(cipher, false)
    }

    pub(super) fn with_direction(cipher: C, forward: bool) -> Self {
        assert_eq!(
            C::BLOCK_SIZE,
            BLOCK,
            "key wrapping is defined only for a 128-bit block cipher"
        );
        Kw { cipher, forward }
    }

    /// Wraps `plain` into `out`, and says how much of `out` was used.
    ///
    /// `plain` must be a whole number of eight-byte units and at
    /// least two of them. `out` must have room for eight bytes more
    /// than `plain`.
    pub fn wrap(&self, plain: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if plain.len() < 2 * SEMIBLOCK || !plain.len().is_multiple_of(SEMIBLOCK)
        {
            return Err(Error::InvalidLength(plain.len()));
        }
        let total = plain.len() + SEMIBLOCK;
        let out = out.get_mut(..total).ok_or(Error::InvalidLength(total))?;
        out[SEMIBLOCK..].copy_from_slice(plain);
        let (check, body) = out.split_at_mut(SEMIBLOCK);
        let mut a = ICV1;
        wrap_body(&self.cipher, self.forward, &mut a, body)?;
        check.copy_from_slice(&a);
        Ok(total)
    }

    /// Unwraps `wrapped` into `out`, and says how much of `out` was
    /// used.
    ///
    /// Returns [`Error::AuthenticationFailed`] if the check value is
    /// wrong, having first wiped `out`, so nothing that failed the
    /// check is left where it might be used.
    pub fn unwrap(
        &self,
        wrapped: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if wrapped.len() < 3 * SEMIBLOCK
            || !wrapped.len().is_multiple_of(SEMIBLOCK)
        {
            return Err(Error::InvalidLength(wrapped.len()));
        }
        let total = wrapped.len() - SEMIBLOCK;
        let out = out.get_mut(..total).ok_or(Error::InvalidLength(total))?;
        out.copy_from_slice(&wrapped[SEMIBLOCK..]);
        let mut a = [0u8; SEMIBLOCK];
        a.copy_from_slice(&wrapped[..SEMIBLOCK]);
        unwrap_body(&self.cipher, self.forward, &mut a, out)?;
        if !crate::util::equal(&a, &ICV1) {
            out.fill(0);
            return Err(Error::AuthenticationFailed);
        }
        Ok(total)
    }
}

/// The wrapping function of SP 800-38F, over the semiblocks in
/// `body`, carrying the check value in `a`.
///
/// Six passes over the whole message, each step mixing the running
/// check value into one semiblock and taking a new one back out. The
/// counter that is mixed in differs at every one of the `6n` steps,
/// which is what stops the semiblocks being reordered.
pub(super) fn wrap_body<C: BlockCipher>(
    cipher: &C,
    forward: bool,
    a: &mut [u8; SEMIBLOCK],
    body: &mut [u8],
) -> Result<(), Error> {
    let n = body.len() / SEMIBLOCK;
    let mut block = [0u8; BLOCK];
    for round in 0..6u64 {
        for (i, semi) in body.chunks_exact_mut(SEMIBLOCK).enumerate() {
            block[..SEMIBLOCK].copy_from_slice(a);
            block[SEMIBLOCK..].copy_from_slice(semi);
            apply(cipher, forward, &mut block)?;
            let step = n as u64 * round + i as u64 + 1;
            a.copy_from_slice(&block[..SEMIBLOCK]);
            for (byte, count) in a.iter_mut().zip(step.to_be_bytes()) {
                *byte ^= count;
            }
            semi.copy_from_slice(&block[SEMIBLOCK..]);
        }
    }
    Ok(())
}

/// The inverse of [`wrap_body`]: the same passes, backwards.
pub(super) fn unwrap_body<C: BlockCipher>(
    cipher: &C,
    forward: bool,
    a: &mut [u8; SEMIBLOCK],
    body: &mut [u8],
) -> Result<(), Error> {
    let n = body.len() / SEMIBLOCK;
    let mut block = [0u8; BLOCK];
    for round in (0..6u64).rev() {
        for (i, semi) in body.chunks_exact_mut(SEMIBLOCK).enumerate().rev() {
            let step = n as u64 * round + i as u64 + 1;
            block[..SEMIBLOCK].copy_from_slice(a);
            for (byte, count) in
                block[..SEMIBLOCK].iter_mut().zip(step.to_be_bytes())
            {
                *byte ^= count;
            }
            block[SEMIBLOCK..].copy_from_slice(semi);
            apply(cipher, !forward, &mut block)?;
            a.copy_from_slice(&block[..SEMIBLOCK]);
            semi.copy_from_slice(&block[SEMIBLOCK..]);
        }
    }
    Ok(())
}

/// One block through the cipher, in whichever direction this
/// wrapping was built on.
pub(super) fn apply<C: BlockCipher>(
    cipher: &C,
    forward: bool,
    block: &mut [u8; BLOCK],
) -> Result<(), Error> {
    if forward {
        cipher.encrypt_block(block)
    } else {
        cipher.decrypt_block(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::Aes;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            out[i] =
                u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16)
                    .unwrap();
        }
        out
    }

    /// RFC 3394 sections 4.1 to 4.6, the vectors everyone checks
    /// against, covering all three key sizes.
    #[test]
    fn rfc3394_vectors() {
        fn check<const K: usize, const P: usize, const C: usize>(
            key: &str,
            plain: &str,
            cipher: &str,
        ) {
            let kw = Kw::new(Aes::try_new(&unhex::<K>(key)).unwrap());
            let plain: [u8; P] = unhex(plain);
            let want: [u8; C] = unhex(cipher);

            let mut wrapped = [0u8; C];
            assert_eq!(kw.wrap(&plain, &mut wrapped).unwrap(), C);
            assert_eq!(wrapped, want, "wrap");

            let mut back = [0u8; P];
            assert_eq!(kw.unwrap(&want, &mut back).unwrap(), P);
            assert_eq!(back, plain, "unwrap");
        }

        check::<16, 16, 24>(
            "000102030405060708090A0B0C0D0E0F",
            "00112233445566778899AABBCCDDEEFF",
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        );
        check::<24, 16, 24>(
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "00112233445566778899AABBCCDDEEFF",
            "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
        );
        check::<32, 24, 32>(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
        );
    }

    /// Whatever goes in comes back, at every length the unpadded form
    /// accepts within a reasonable span.
    #[test]
    fn round_trips_at_many_lengths() {
        let kw = Kw::new(Aes::try_new(&[3u8; 16]).unwrap());
        let plain: [u8; 128] = core::array::from_fn(|i| (i * 5) as u8);
        let mut wrapped = [0u8; 136];
        let mut back = [0u8; 128];
        for len in (16..=128).step_by(8) {
            let n = kw.wrap(&plain[..len], &mut wrapped).unwrap();
            assert_eq!(n, len + 8);
            let got = kw.unwrap(&wrapped[..n], &mut back).unwrap();
            assert_eq!(got, len);
            assert_eq!(&back[..len], &plain[..len], "{len} bytes");
        }
    }

    /// Any alteration must be refused, and the buffer left empty
    /// rather than holding something that failed its check.
    #[test]
    fn rejects_and_wipes() {
        let kw = Kw::new(Aes::try_new(&[3u8; 16]).unwrap());
        let plain = [9u8; 32];
        let mut wrapped = [0u8; 40];
        kw.wrap(&plain, &mut wrapped).unwrap();

        for spoil in [0, 7, 8, 20, 39] {
            let mut altered = wrapped;
            altered[spoil] ^= 1;
            let mut back = [0xffu8; 32];
            assert_eq!(
                kw.unwrap(&altered, &mut back).unwrap_err(),
                Error::AuthenticationFailed,
                "byte {spoil}"
            );
            assert_eq!(back, [0u8; 32], "byte {spoil}: not wiped");
        }
    }

    /// The two cipher directions are different wrappings, and neither
    /// will accept the other's work.
    #[test]
    fn the_directions_are_not_interchangeable() {
        let key = [5u8; 16];
        let forward = Kw::new(Aes::try_new(&key).unwrap());
        let inverse = Kw::new_inverse(Aes::try_new(&key).unwrap());
        let plain = [1u8; 16];

        let mut one = [0u8; 24];
        let mut other = [0u8; 24];
        forward.wrap(&plain, &mut one).unwrap();
        inverse.wrap(&plain, &mut other).unwrap();
        assert_ne!(one, other);

        let mut back = [0u8; 16];
        assert_eq!(
            inverse.unwrap(&one, &mut back).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(inverse.unwrap(&other, &mut back).unwrap(), 16);
        assert_eq!(back, plain);
    }

    /// Lengths the unpadded form cannot take, and output that will
    /// not fit, are refused rather than truncated.
    #[test]
    fn rejects_bad_lengths() {
        let kw = Kw::new(Aes::try_new(&[3u8; 16]).unwrap());
        let mut out = [0u8; 64];
        // Not a whole number of units, and too short.
        for len in [0usize, 4, 8, 12, 20] {
            let plain = [0u8; 20];
            assert!(
                matches!(
                    kw.wrap(&plain[..len], &mut out),
                    Err(Error::InvalidLength(_))
                ),
                "wrapping {len}"
            );
        }
        // Output too small by one byte.
        let plain = [0u8; 16];
        assert!(matches!(
            kw.wrap(&plain, &mut out[..23]),
            Err(Error::InvalidLength(_))
        ));
        // A wrapped form must hold at least three units.
        for len in [0usize, 8, 16, 20] {
            let wrapped = [0u8; 20];
            assert!(
                matches!(
                    kw.unwrap(&wrapped[..len], &mut out),
                    Err(Error::InvalidLength(_))
                ),
                "unwrapping {len}"
            );
        }
    }
}
