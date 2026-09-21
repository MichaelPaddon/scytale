//! cSHAKE (NIST SP 800-185): SHAKE with a function name and a
//! customization string.
//!
//! Two SHAKE computations over the same message give the same output,
//! whatever they were for. cSHAKE absorbs a function name and a
//! customization string ahead of the message, padded out to a whole
//! block, so outputs computed for different purposes are unrelated
//! even when the messages agree. The function name is for functions
//! NIST defines on top, such as KMAC; the customization string is the
//! caller's own label.
//!
//! ```
//! use scytale::hash::sha3::CShake128;
//! use scytale::hash::{Xof, XofReader};
//!
//! let mut xof = CShake128::new(b"", b"Email Signature");
//! xof.update(&[0, 1, 2, 3]);
//! let mut out = [0u8; 32];
//! xof.finalize_xof().squeeze(&mut out);
//! assert_eq!(out[..4], [0xc1, 0xc3, 0x69, 0x25]);
//! ```
//!
//! With both strings empty, SP 800-185 defines cSHAKE to be SHAKE
//! itself, and so it is here: `CShake128::new(b"", b"")` gives what
//! [`Shake128`](super::Shake128) gives.
//!
//! The strings are absorbed once, when the function is made; every
//! message after that, through [`Xof::reset`] or
//! [`Xof::finalize_xof`], starts from the state they left.

use core::fmt;

use super::{Auto, AutoReader, SuffixXof, variant};
use crate::hash::{BitXof, Xof, XofReader};
use crate::{BlockType, Error};

/// cSHAKE's domain bits and the first padding one.
const CSHAKE_SUFFIX: u8 = 0x04;

/// SHAKE's, which cSHAKE with nothing to customize is.
const SHAKE_SUFFIX: u8 = 0x1f;

/// `x` as SP 800-185's `left_encode`: the byte count, then the bytes
/// of `x`, most significant first and at least one. Returns the
/// buffer and how much of it is used.
pub(crate) fn left_encode(x: u128) -> ([u8; 17], usize) {
    let n = byte_count(x);
    let mut out = [0u8; 17];
    out[0] = n as u8;
    out[1..=n].copy_from_slice(&x.to_be_bytes()[16 - n..]);
    (out, n + 1)
}

/// `x` as SP 800-185's `right_encode`: the bytes of `x`, then their
/// count.
pub(crate) fn right_encode(x: u128) -> ([u8; 17], usize) {
    let n = byte_count(x);
    let mut out = [0u8; 17];
    out[..n].copy_from_slice(&x.to_be_bytes()[16 - n..]);
    out[n] = n as u8;
    (out, n + 1)
}

/// The bytes needed for `x`, at least one.
fn byte_count(x: u128) -> usize {
    (16 - x.leading_zeros() as usize / 8).max(1)
}

/// Absorbs `bytepad(encode_string(s1) || encode_string(s2) ..., rate)`
/// through `update`.
///
/// Each string is its bytes and its length in bits, and holds exactly
/// the bytes that length needs. A length that is not whole bytes
/// keeps its bits at the top of the last byte, which is absorbed as it
/// stands with the bits below cleared: that is how KMAC's key reaches
/// the sponge. The strings cSHAKE itself takes are whole bytes.
pub(crate) fn absorb_bytepad(
    update: &mut impl FnMut(&[u8]),
    rate: usize,
    strings: &[(&[u8], u128)],
) {
    let (encoded, n) = left_encode(rate as u128);
    update(&encoded[..n]);
    let mut total = n;
    for &(bytes, bits) in strings {
        debug_assert_eq!(bytes.len() as u128, bits.div_ceil(8));
        let (encoded, n) = left_encode(bits);
        update(&encoded[..n]);
        let extra = (bits % 8) as u32;
        match bytes.split_last() {
            Some((&last, whole)) if extra != 0 => {
                update(whole);
                update(&[last & high_bits(extra)]);
            }
            _ => update(bytes),
        }
        total += n + bytes.len();
    }
    const ZEROS: [u8; 168] = [0; 168];
    let mut pad = (rate - total % rate) % rate;
    while pad > 0 {
        let n = pad.min(ZEROS.len());
        update(&ZEROS[..n]);
        pad -= n;
    }
}

/// A mask of the low `bits` bits of a byte, `bits` from 1 to 7: the
/// first bits, as FIPS 202 numbers them.
pub(crate) fn low_bits(bits: u32) -> u8 {
    (1u8 << bits) - 1
}

/// A mask of the high `bits` bits of a byte, `bits` from 1 to 7.
pub(crate) fn high_bits(bits: u32) -> u8 {
    !low_bits(8 - bits)
}

/// cSHAKE over any sponge that takes its suffix at the end: the
/// dispatching one for the public types, or one implementation for
/// the vector suites.
#[derive(Clone)]
pub(crate) struct Core<X: SuffixXof> {
    /// The state after the name and customization.
    template: X,
    xof: X,
    /// Whether there was anything to absorb, which is what separates
    /// cSHAKE from SHAKE.
    custom: bool,
}

impl<X: SuffixXof> Core<X> {
    /// Absorbs the strings into `xof`, a sponge at its start.
    pub(crate) fn with(
        mut xof: X,
        function_name: &[u8],
        customization: &[u8],
    ) -> Self {
        let custom = !function_name.is_empty() || !customization.is_empty();
        if custom {
            let rate = X::zero_block().as_ref().len();
            absorb_bytepad(
                &mut |data| xof.update(data),
                rate,
                &[
                    (function_name, bits_of(function_name)),
                    (customization, bits_of(customization)),
                ],
            );
        }
        Core {
            template: xof.clone(),
            xof,
            custom,
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.xof.update(data);
    }

    pub(crate) fn reset(&mut self) {
        self.xof = self.template.clone();
    }

    /// Makes what has been absorbed so far the state that `reset`
    /// returns to, for a function such as KMAC whose own prefix
    /// follows cSHAKE's.
    pub(crate) fn rebase(&mut self) {
        self.template = self.xof.clone();
    }

    /// Ends the message and returns to the state after the strings.
    pub(crate) fn finalize_xof(&mut self) -> X::Reader {
        let reader = self.xof.finalize_suffix_xof(self.suffix());
        self.reset();
        reader
    }

    /// Ends the message with the first `bits` bits of `last`, zero
    /// to seven, and returns to the state after the strings. Zero is
    /// [`finalize_xof`](Self::finalize_xof); nothing is finalized if
    /// `bits` is out of range.
    pub(crate) fn finalize_bits_xof(
        &mut self,
        last: u8,
        bits: u32,
    ) -> Result<X::Reader, Error> {
        if bits == 0 {
            return Ok(self.finalize_xof());
        }
        let suffix = self.suffix();
        let reader = self.xof.finalize_bits_suffix_xof(suffix, last, bits)?;
        self.reset();
        Ok(reader)
    }

    fn suffix(&self) -> u8 {
        if self.custom {
            CSHAKE_SUFFIX
        } else {
            SHAKE_SUFFIX
        }
    }
}

/// The length of `bytes` in bits, as the encodings take it.
pub(crate) fn bits_of(bytes: &[u8]) -> u128 {
    bytes.len() as u128 * 8
}

/// Defines one of the two public cSHAKE functions and its reader.
macro_rules! cshake {
    ($(#[$doc:meta])* $name:ident, $reader:ident, $variant:ident,
     $rate:literal) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name(Core<Auto<variant::$variant>>);

        #[doc = concat!("The output stream of [`", stringify!($name), "`].")]
        #[derive(Clone, Debug)]
        pub struct $reader(AutoReader<variant::$variant>);

        impl $name {
            /// Starts a function under `function_name` and
            /// `customization`, with the best implementation the
            /// processor supports.
            ///
            /// Any strings are allowed. The function name is for
            /// functions NIST defines over cSHAKE; leave it empty
            /// and put a label of your own in `customization`.
            pub fn new(function_name: &[u8], customization: &[u8]) -> Self {
                $name(Core::with(Auto::new(), function_name, customization))
            }
        }

        impl fmt::Debug for $name {
            /// Deliberately omits the state, which is a function of
            /// the message.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl BlockType for $name {
            type Block = [u8; $rate];

            fn zero_block() -> Self::Block {
                [0; $rate]
            }
        }

        impl XofReader for $reader {
            fn squeeze(&mut self, out: &mut [u8]) {
                self.0.squeeze(out)
            }
        }

        impl Default for $name {
            /// Both strings empty, which is SHAKE.
            fn default() -> Self {
                Self::new(b"", b"")
            }
        }

        impl Xof for $name {
            type Reader = $reader;

            /// Returns to the state after the strings.
            fn reset(&mut self) {
                self.0.reset()
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.0.update(data)
            }

            fn finalize_xof(&mut self) -> Self::Reader {
                $reader(self.0.finalize_xof())
            }
        }

        impl BitXof for $name {
            fn finalize_bits_xof(
                &mut self,
                last: u8,
                bits: u32,
            ) -> Result<Self::Reader, Error> {
                // The trait's range; zero bits is `finalize_xof`.
                if !(1..=7).contains(&bits) {
                    return Err(Error::InvalidBitCount(bits));
                }
                Ok($reader(self.0.finalize_bits_xof(last, bits)?))
            }
        }
    };
}

cshake!(
    /// cSHAKE128: SHAKE128 with a function name and customization.
    CShake128,
    CShake128Reader,
    CShake128,
    168
);
cshake!(
    /// cSHAKE256: SHAKE256 with a function name and customization.
    CShake256,
    CShake256Reader,
    CShake256,
    136
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha3::engine::Sponge;
    use crate::hash::sha3::portable::Keccak;
    use crate::hash::sha3::{Shake128, Shake256};
    use std::vec::Vec;

    fn unhex(text: &str) -> Vec<u8> {
        let text: Vec<u8> =
            text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        text.chunks(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).expect("ascii");
                u8::from_str_radix(pair, 16).expect("hex")
            })
            .collect()
    }

    fn squeeze<X: Xof>(xof: &mut X, message: &[u8], n: usize) -> Vec<u8> {
        xof.update(message);
        let mut out = std::vec![0u8; n];
        xof.finalize_xof().squeeze(&mut out);
        out
    }

    #[test]
    fn encodings() {
        let left = |x| {
            let (bytes, n) = left_encode(x);
            bytes[..n].to_vec()
        };
        let right = |x| {
            let (bytes, n) = right_encode(x);
            bytes[..n].to_vec()
        };
        assert_eq!(left(0), [1, 0]);
        assert_eq!(right(0), [0, 1]);
        assert_eq!(left(255), [1, 255]);
        assert_eq!(left(256), [2, 1, 0]);
        assert_eq!(right(256), [1, 0, 2]);
        assert_eq!(left(u64::MAX as u128)[..2], [8, 255]);
        assert_eq!(left(u128::MAX).len(), 17);
    }

    /// The NIST cSHAKE samples: an empty function name and "Email
    /// Signature", over four bytes and over 200.
    #[test]
    fn nist_samples() {
        let short = [0u8, 1, 2, 3];
        let long: Vec<u8> = (0..200).collect();
        let s = b"Email Signature";
        assert_eq!(
            squeeze(&mut CShake128::new(b"", s), &short, 32),
            unhex(
                "C1C36925B6409A04F1B504FCBCA9D82B
                 4017277CB5ED2B2065FC1D3814D5AAF5"
            )
        );
        assert_eq!(
            squeeze(&mut CShake128::new(b"", s), &long, 32),
            unhex(
                "C5221D50E4F822D96A2E8881A961420F
                 294B7B24FE3D2094BAED2C6524CC166B"
            )
        );
        assert_eq!(
            squeeze(&mut CShake256::new(b"", s), &short, 64),
            unhex(
                "D008828E2B80AC9D2218FFEE1D070C48
                 B8E4C87BFF32C9699D5B6896EEE0EDD1
                 64020E2BE0560858D9C00C037E34A969
                 37C561A74C412BB4C746469527281C8C"
            )
        );
        assert_eq!(
            squeeze(&mut CShake256::new(b"", s), &long, 64),
            unhex(
                "07DC27B11E51FBAC75BC7B3C1D983E8B
                 4B85FB1DEFAF218912AC864302730917
                 27F42B17ED1DF63E8EC118F04B23633C
                 1DFB1574C8FB55CB45DA8E25AFB092BB"
            )
        );
    }

    /// With nothing to customize, cSHAKE is SHAKE.
    #[test]
    fn empty_strings_are_shake() {
        let message = b"abc";
        assert_eq!(
            squeeze(&mut CShake128::new(b"", b""), message, 40),
            squeeze(&mut Shake128::new(), message, 40)
        );
        assert_eq!(
            squeeze(&mut CShake256::new(b"", b""), message, 40),
            squeeze(&mut Shake256::new(), message, 40)
        );
        // A name alone is customization enough.
        assert_ne!(
            squeeze(&mut CShake128::new(b"N", b""), message, 40),
            squeeze(&mut Shake128::new(), message, 40)
        );
    }

    /// Splitting a message, resetting, finalizing and cloning all
    /// start again from the state after the strings.
    #[test]
    fn pieces_reset_and_clone() {
        let data: Vec<u8> = (0..500u32).map(|i| (i * 7) as u8).collect();
        let mut whole = CShake128::new(b"fn", b"label");
        let expected = squeeze(&mut whole, &data, 64);
        for split in [0, 1, 167, 168, 169, 336, 499] {
            let mut xof = CShake128::new(b"fn", b"label");
            xof.update(b"garbage");
            xof.reset();
            xof.update(&data[..split]);
            let copy = xof.clone();
            xof.update(&data[split..]);
            let mut out = [0u8; 64];
            xof.finalize_xof().squeeze(&mut out);
            assert_eq!(out[..], expected[..], "split {split}");
            let mut copy = copy;
            copy.update(&data[split..]);
            copy.finalize_xof().squeeze(&mut out);
            assert_eq!(out[..], expected[..], "clone at {split}");
        }
        // `finalize_xof` left `whole` ready for the next message.
        assert_eq!(squeeze(&mut whole, &data, 64), expected);
    }

    /// The dispatching type agrees with the portable permutation
    /// under a name and customization long enough to need two blocks.
    #[test]
    fn matches_portable() {
        let name = [0x61u8; 100];
        let custom = [0x62u8; 200];
        for len in [0usize, 1, 135, 136, 137, 400] {
            let message: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut auto = CShake256::new(&name, &custom);
            let sponge = Sponge::<Keccak, variant::CShake256>::with(Keccak);
            let mut portable = Core::with(sponge, &name, &custom);
            portable.update(&message);
            let mut want = [0u8; 50];
            portable.finalize_xof().squeeze(&mut want);
            assert_eq!(squeeze(&mut auto, &message, 50), want, "len {len}");
        }
    }

    /// The trait's bit range is one to seven, as for SHAKE, and a
    /// refused call leaves the message as it was.
    #[test]
    fn bit_counts() {
        let mut xof = CShake128::new(b"", b"S");
        xof.update(b"ab");
        assert_eq!(
            xof.finalize_bits_xof(0, 0).err(),
            Some(Error::InvalidBitCount(0))
        );
        assert_eq!(
            xof.finalize_bits_xof(0, 8).err(),
            Some(Error::InvalidBitCount(8))
        );
        let mut out = [0u8; 16];
        xof.finalize_bits_xof(0b101, 3)
            .expect("bits")
            .squeeze(&mut out);

        let mut fresh = CShake128::new(b"", b"S");
        fresh.update(b"ab");
        let mut again = [0u8; 16];
        fresh
            .finalize_bits_xof(0b11111101, 3)
            .expect("bits")
            .squeeze(&mut again);
        assert_eq!(out, again, "high bits of `last` are ignored");
    }
}
