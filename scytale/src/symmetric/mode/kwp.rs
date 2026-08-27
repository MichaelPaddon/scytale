//! Key wrapping with padding (NIST SP 800-38F), the padded form.
//!
//! The same construction as [`Kw`](super::Kw), with a length recorded
//! in the check value and zero padding to fill out the last unit. That
//! lifts the two restrictions of the unpadded form: any length from a
//! single byte upwards will wrap, and it need not be a multiple of
//! eight.
//!
//! The result is the input rounded up to a multiple of eight, plus
//! eight more for the check value. An input of eight bytes or fewer
//! wraps to a single block, which the standard handles as a special
//! case and this does too.
//!
//! Everything said about [`Kw`](super::Kw) applies here: it is
//! authenticated, it takes no nonce and so is deterministic, and it
//! is for wrapping keys rather than messages. Read those warnings.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Kwp;
//! use scytale::symmetric::BlockCipher;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let kwp = Kwp::new(Aes::try_new(&[0u8; 16])?);
//!
//! // Any length, unlike the unpadded form.
//! let secret = *b"seven..";
//! let mut wrapped = [0u8; 16];
//! let n = kwp.wrap(&secret, &mut wrapped)?;
//!
//! let mut back = [0u8; 16];
//! let got = kwp.unwrap(&wrapped[..n], &mut back)?;
//! assert_eq!(&back[..got], &secret);
//! # Ok(())
//! # }
//! ```

use super::kw::{apply, unwrap_body, wrap_body, SEMIBLOCK};
use crate::symmetric::{BlockCipher, Error};
use crate::util;

/// The cipher block this is defined for.
const BLOCK: usize = 16;

/// The check value for the padded form, from SP 800-38F. The length
/// of the message follows it, filling out the semiblock.
const ICV2: [u8; 4] = [0xa6, 0x59, 0x59, 0xa6];

/// Key wrapping with padding, over a block cipher.
#[derive(Clone, Debug)]
pub struct Kwp<C> {
    cipher: C,
    /// Whether wrapping uses the cipher's forward direction.
    forward: bool,
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Kwp<C> {
    /// Wraps with the cipher's forward direction, as RFC 5649
    /// describes.
    pub fn new(cipher: C) -> Self {
        Kwp::with_direction(cipher, true)
    }

    /// Wraps with the cipher's inverse direction, the other choice
    /// the standard allows.
    pub fn new_inverse(cipher: C) -> Self {
        Kwp::with_direction(cipher, false)
    }

    fn with_direction(cipher: C, forward: bool) -> Self {
        Kwp { cipher, forward }
    }

    /// Wraps `plain` into `out`, and says how much of `out` was used.
    ///
    /// `plain` may be any length from one byte up. `out` needs room
    /// for `plain` rounded up to a multiple of eight, and eight more.
    pub fn wrap(&self, plain: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        // The length has to fit the four bytes that record it.
        if plain.is_empty() || u32::try_from(plain.len()).is_err() {
            return Err(Error::InvalidLength(plain.len()));
        }
        let padded = plain.len().next_multiple_of(SEMIBLOCK);
        let total = padded + SEMIBLOCK;
        let out = out.get_mut(..total).ok_or(Error::InvalidLength(total))?;

        let mut a = [0u8; SEMIBLOCK];
        a[..4].copy_from_slice(&ICV2);
        a[4..].copy_from_slice(&(plain.len() as u32).to_be_bytes());

        out[SEMIBLOCK..SEMIBLOCK + plain.len()].copy_from_slice(plain);
        out[SEMIBLOCK + plain.len()..].fill(0);

        if padded == SEMIBLOCK {
            // One semiblock of message and one of check value make a
            // single block, which goes through the cipher once
            // rather than through the wrapping function.
            let mut block = [0u8; BLOCK];
            block[..SEMIBLOCK].copy_from_slice(&a);
            block[SEMIBLOCK..].copy_from_slice(&out[SEMIBLOCK..]);
            apply(&self.cipher, self.forward, &mut block);
            out.copy_from_slice(&block);
            return Ok(total);
        }

        let (check, body) = out.split_at_mut(SEMIBLOCK);
        wrap_body(&self.cipher, self.forward, &mut a, body)?;
        check.copy_from_slice(&a);
        Ok(total)
    }

    /// Unwraps `wrapped` into `out`, and says how much of `out` was
    /// used, which is the original length rather than the padded one.
    ///
    /// Returns [`Error::AuthenticationFailed`] if the check value,
    /// the recorded length or the padding is wrong, having first
    /// wiped `out`. It does not say which of them it was: that would
    /// tell an attacker how close a forgery came.
    pub fn unwrap(
        &self,
        wrapped: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if wrapped.len() < 2 * SEMIBLOCK
            || !wrapped.len().is_multiple_of(SEMIBLOCK)
        {
            return Err(Error::InvalidLength(wrapped.len()));
        }
        let padded = wrapped.len() - SEMIBLOCK;
        let out = out.get_mut(..padded).ok_or(Error::InvalidLength(padded))?;
        let mut a = [0u8; SEMIBLOCK];

        if wrapped.len() == BLOCK {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(wrapped);
            apply(&self.cipher, !self.forward, &mut block);
            a.copy_from_slice(&block[..SEMIBLOCK]);
            out.copy_from_slice(&block[SEMIBLOCK..]);
        } else {
            a.copy_from_slice(&wrapped[..SEMIBLOCK]);
            out.copy_from_slice(&wrapped[SEMIBLOCK..]);
            unwrap_body(&self.cipher, self.forward, &mut a, out)?;
        }

        // Every check is folded into one answer before anything is
        // decided on it, so that a forgery learns nothing from how
        // long the refusal took.
        let mut bad = !util::equal(&a[..4], &ICV2);
        let mut length = [0u8; 4];
        length.copy_from_slice(&a[4..]);
        let claimed = u32::from_be_bytes(length) as usize;
        // The padding it implies has to be less than a whole unit,
        // or the wrapped form would have been shorter.
        bad |= claimed > padded || padded - claimed >= SEMIBLOCK;
        if !bad {
            for &byte in &out[claimed..] {
                bad |= byte != 0;
            }
        }
        if bad {
            out.fill(0);
            return Err(Error::AuthenticationFailed);
        }
        Ok(claimed)
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

    /// RFC 5649 section 6, which is where the padded form comes from.
    /// The second case is the single-block one: seven bytes of
    /// message wrap into sixteen.
    #[test]
    fn rfc5649_vectors() {
        const KEK: &str = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";

        fn check<const P: usize, const C: usize>(plain: &str, cipher: &str) {
            let kwp = Kwp::new(Aes::try_new(&unhex::<24>(KEK)).unwrap());
            let plain: [u8; P] = unhex(plain);
            let want: [u8; C] = unhex(cipher);

            let mut wrapped = [0u8; C];
            assert_eq!(kwp.wrap(&plain, &mut wrapped).unwrap(), C);
            assert_eq!(wrapped, want, "wrap");

            let mut back = [0u8; C];
            assert_eq!(kwp.unwrap(&want, &mut back).unwrap(), P);
            assert_eq!(&back[..P], &plain, "unwrap");
        }

        check::<20, 32>(
            "c37b7e6492584340bed12207808941155068f738",
            "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
        );
        check::<7, 16>("466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f");
    }

    /// Every length from one byte up, so both the single-block case
    /// and the general one are covered, and every amount of padding
    /// with them.
    #[test]
    fn round_trips_at_many_lengths() {
        let kwp = Kwp::new(Aes::try_new(&[3u8; 16]).unwrap());
        let plain: [u8; 64] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let mut wrapped = [0u8; 72];
        let mut back = [0u8; 72];
        for len in 1..=64 {
            let n = kwp.wrap(&plain[..len], &mut wrapped).unwrap();
            assert_eq!(n, len.next_multiple_of(8) + 8, "{len} wrapped size");
            let got = kwp.unwrap(&wrapped[..n], &mut back).unwrap();
            assert_eq!(got, len, "{len} unwrapped size");
            assert_eq!(&back[..len], &plain[..len], "{len} bytes");
        }
    }

    /// Alteration must be refused and the buffer wiped, in the
    /// single-block case as well as the general one.
    #[test]
    fn rejects_and_wipes() {
        let kwp = Kwp::new(Aes::try_new(&[3u8; 16]).unwrap());
        for len in [5usize, 40] {
            let plain = [9u8; 40];
            let mut wrapped = [0u8; 48];
            let n = kwp.wrap(&plain[..len], &mut wrapped).unwrap();
            for spoil in [0, 5, 7, n - 1] {
                let mut altered = wrapped;
                altered[spoil] ^= 1;
                let mut back = [0xffu8; 48];
                assert_eq!(
                    kwp.unwrap(&altered[..n], &mut back).unwrap_err(),
                    Error::AuthenticationFailed,
                    "{len} bytes, spoiled {spoil}"
                );
                assert!(
                    back[..n - 8].iter().all(|&b| b == 0),
                    "{len} bytes, spoiled {spoil}: not wiped"
                );
            }
        }
    }

    /// Padding that is not zero must be refused. Accepting it would
    /// let a forgery vary bytes the check value does not cover.
    #[test]
    fn padding_must_be_zero() {
        let key = [3u8; 16];
        let kwp = Kwp::new(Aes::try_new(&key).unwrap());
        // Wrap five bytes, then rebuild the wrapped form by hand with
        // the padding set to something other than zero.
        let mut a = [0u8; SEMIBLOCK];
        a[..4].copy_from_slice(&ICV2);
        a[4..].copy_from_slice(&5u32.to_be_bytes());
        let mut body = [0u8; SEMIBLOCK];
        body[..5].copy_from_slice(b"hello");
        body[5] = 1; // padding that should have been zero

        let cipher = Aes::try_new(&key).unwrap();
        let mut block = [0u8; BLOCK];
        block[..SEMIBLOCK].copy_from_slice(&a);
        block[SEMIBLOCK..].copy_from_slice(&body);
        apply(&cipher, true, &mut block);

        let mut back = [0u8; 8];
        assert_eq!(
            kwp.unwrap(&block, &mut back).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    /// The two cipher directions are different wrappings.
    #[test]
    fn the_directions_are_not_interchangeable() {
        let key = [5u8; 16];
        let forward = Kwp::new(Aes::try_new(&key).unwrap());
        let inverse = Kwp::new_inverse(Aes::try_new(&key).unwrap());
        let plain = [1u8; 20];

        let mut one = [0u8; 32];
        let mut other = [0u8; 32];
        forward.wrap(&plain, &mut one).unwrap();
        inverse.wrap(&plain, &mut other).unwrap();
        assert_ne!(one, other);

        let mut back = [0u8; 32];
        assert_eq!(
            inverse.unwrap(&one, &mut back).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(inverse.unwrap(&other, &mut back).unwrap(), 20);
    }

    /// An empty message, and output that will not fit, are refused.
    #[test]
    fn rejects_bad_lengths() {
        let kwp = Kwp::new(Aes::try_new(&[3u8; 16]).unwrap());
        let mut out = [0u8; 64];
        assert!(matches!(
            kwp.wrap(&[], &mut out),
            Err(Error::InvalidLength(0))
        ));
        // Sixteen bytes of output are needed for one byte of message.
        assert!(matches!(
            kwp.wrap(&[1], &mut out[..15]),
            Err(Error::InvalidLength(_))
        ));
        // A wrapped form is at least two units, and a whole number
        // of them.
        for len in [0usize, 8, 12, 20] {
            let wrapped = [0u8; 20];
            assert!(
                matches!(
                    kwp.unwrap(&wrapped[..len], &mut out),
                    Err(Error::InvalidLength(_))
                ),
                "unwrapping {len}"
            );
        }
    }
}
