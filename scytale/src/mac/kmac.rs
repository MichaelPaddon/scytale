//! KMAC (NIST SP 800-185): the MAC of the SHA-3 family.
//!
//! `KMAC(K, X, L, S)` is cSHAKE, under the function name `"KMAC"`
//! and the customization `S`, over the key padded to a block, the
//! message `X`, and the output length `L`. Keccak cannot be length
//! extended, so keying the sponge is enough to make a MAC; the padded
//! key is absorbed once, when the MAC is made, and every message
//! starts from the state it left.
//!
//! ```
//! use scytale::mac::kmac::Kmac128;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let key = [0x40u8; 32];
//! let mut mac = Kmac128::new(&key, b"My Tagged Application");
//! mac.update(b"message");
//! let mut tag = [0u8; 32];
//! mac.finalize_to(&mut tag);
//!
//! mac.update(b"message");
//! mac.verify_tag(&tag)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Output length
//!
//! The length asked for is absorbed before the output is squeezed,
//! so a 16-byte tag is not the first half of a 32-byte one: it is a
//! different MAC altogether. [`finalize_to`](Kmac128::finalize_to)
//! and [`verify_tag`](Kmac128::verify_tag) take the length from the
//! buffer. KMACXOF, [`finalize_xof`](Kmac128::finalize_xof), is the
//! variant that fixes no length and gives a stream instead.
//!
//! Through [`Mac`], KMAC128 gives 32 bytes and KMAC256 64, under an
//! empty customization and a 32-byte key.
//!
//! # Bit strings
//!
//! SP 800-185 is defined over bit strings, and the lengths it absorbs
//! are counts of bits, so a key, message or output that does not fill
//! its last byte gives a different MAC from any byte string. The
//! `_bits` calls take those, laid out as the NIST validation vectors
//! lay them out:
//!
//! - A message is little-endian, as [`BitXof`](crate::hash::BitXof)
//!   takes it: its last bits are the low bits of `last`, first bit
//!   least significant.
//! - A key or a tag is a buffer with a length in bits, and a last
//!   byte it does not fill keeps its bits at the top. The bits below
//!   are ignored in a key or a tag being checked, and zero in a tag
//!   produced.

use core::fmt;

use zeroize::ZeroizeOnDrop;

use super::Mac;
use crate::constant_time;
use crate::hash::XofReader;
use crate::hash::sha3::cshake::{
    Core, absorb_bytepad, bits_of, high_bits, low_bits, right_encode,
};
use crate::hash::sha3::{Auto, AutoReader, variant};
use crate::{BlockType, Error, Key, KeyType};

/// The function name KMAC gives cSHAKE.
const NAME: &[u8] = b"KMAC";

/// Checks that `bytes` is exactly the length `bits` needs.
fn check_length(bytes: &[u8], bits: usize) -> Result<(), Error> {
    if bytes.len() == bits.div_ceil(8) {
        Ok(())
    } else {
        Err(Error::InvalidLength(bytes.len()))
    }
}

/// Lays out the last byte of an output `bits` long as a tag carries
/// it: the sponge gives its bits at the bottom, first bit least
/// significant, and they move to the top with zeros below.
fn to_top(out: &mut [u8], bits: usize) {
    let extra = (bits % 8) as u32;
    if let (Some(last), true) = (out.last_mut(), extra != 0) {
        *last = (*last & low_bits(extra)) << (8 - extra);
    }
}

/// Clears the bits below the top `bits % 8` of a tag's last byte,
/// which are not part of it.
fn clear_below(tag: &mut [u8], bits: usize) {
    let extra = (bits % 8) as u32;
    if let (Some(last), true) = (tag.last_mut(), extra != 0) {
        *last &= high_bits(extra);
    }
}

/// Squeezes `tag.len()` bytes and compares them with `tag`, both cut
/// to `bits`, reading every byte whatever the outcome.
fn matches(reader: &mut impl XofReader, tag: &[u8], bits: usize) -> bool {
    let mut ok = true;
    let mut got = [0u8; 64];
    let mut want = [0u8; 64];
    let chunks = tag.len().div_ceil(got.len());
    for (i, piece) in tag.chunks(got.len()).enumerate() {
        let got = &mut got[..piece.len()];
        let want = &mut want[..piece.len()];
        reader.squeeze(got);
        want.copy_from_slice(piece);
        if i + 1 == chunks {
            let bits = bits - 8 * (tag.len() - piece.len());
            to_top(got, bits);
            clear_below(want, bits);
        }
        ok &= constant_time::equal(got, want);
    }
    ok
}

/// Defines KMAC at one width, with its XOF reader.
macro_rules! kmac {
    ($(#[$doc:meta])* $name:ident, $reader:ident, $variant:ident,
     $tag:literal) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name {
            /// cSHAKE after the padded key.
            core: Core<Auto<variant::$variant>>,
        }

        #[doc = concat!("The output stream of [`", stringify!($name),
            "::finalize_xof`], KMACXOF.")]
        #[derive(Clone, Debug)]
        pub struct $reader(AutoReader<variant::$variant>);

        impl XofReader for $reader {
            fn squeeze(&mut self, out: &mut [u8]) {
                self.0.squeeze(out)
            }
        }

        impl $name {
            /// Starts a MAC under `key` and `customization`.
            ///
            /// Any key and any customization are allowed. A key
            /// shorter than the security level, 16 bytes for KMAC128
            /// and 32 for KMAC256, is weaker than the function.
            pub fn new(key: &[u8], customization: &[u8]) -> Self {
                Self::keyed(key, bits_of(key), customization)
            }

            /// Starts a MAC under a key `key_bits` long.
            ///
            /// `key` holds the bytes those bits need, and a last byte
            /// it does not fill has the key's bits at the top; the
            /// bits below them are ignored. Returns
            /// [`Error::InvalidLength`] if `key` is any other length.
            pub fn try_new_bits(
                key: &[u8],
                key_bits: usize,
                customization: &[u8],
            ) -> Result<Self, Error> {
                check_length(key, key_bits)?;
                Ok(Self::keyed(key, key_bits as u128, customization))
            }

            fn keyed(key: &[u8], key_bits: u128, customization: &[u8]) -> Self {
                let mut core =
                    Core::with(Auto::new(), NAME, customization);
                let rate = <Auto<variant::$variant>>::zero_block()
                    .as_ref()
                    .len();
                absorb_bytepad(
                    &mut |data| core.update(data),
                    rate,
                    &[(key, key_bits)],
                );
                core.rebase();
                $name { core }
            }

            /// Appends `data` to the message.
            #[inline]
            pub fn update(&mut self, data: &[u8]) {
                self.core.update(data)
            }

            /// Ends the message and fills `out` with its tag, the
            /// output length being `out`'s. The MAC is then back at
            /// the start of a message.
            pub fn finalize_to(&mut self, out: &mut [u8]) {
                let (length, n) = right_encode(bits_of(out));
                self.core.update(&length[..n]);
                self.core.finalize_xof().squeeze(out);
            }

            /// Ends the message and checks `tag` against it, the
            /// output length being `tag`'s, in time that depends on
            /// that length alone.
            ///
            /// Returns [`Error::AuthenticationFailed`] if it is not
            /// the tag. The MAC is then back at the start of a
            /// message either way.
            pub fn verify_tag(&mut self, tag: &[u8]) -> Result<(), Error> {
                let (length, n) = right_encode(bits_of(tag));
                self.core.update(&length[..n]);
                let mut reader = self.core.finalize_xof();
                if matches(&mut reader, tag, 8 * tag.len()) {
                    Ok(())
                } else {
                    Err(Error::AuthenticationFailed)
                }
            }

            /// Ends the message and returns KMACXOF's output stream,
            /// which commits to no length. The MAC is then back at
            /// the start of a message.
            pub fn finalize_xof(&mut self) -> $reader {
                let (length, n) = right_encode(0);
                self.core.update(&length[..n]);
                $reader(self.core.finalize_xof())
            }

            /// Ends the message with the first `bits` bits of `last`,
            /// zero to seven, and fills `out` with a tag `out_bits`
            /// long.
            ///
            /// `out` holds the bytes those bits need, and a last byte
            /// it does not fill has the tag's bits at the top and
            /// zeros below. Returns
            /// [`Error::InvalidBitCount`] or [`Error::InvalidLength`]
            /// before touching the message if either is out of
            /// range; otherwise the MAC is back at the start of a
            /// message.
            pub fn finalize_bits_to(
                &mut self,
                last: u8,
                bits: u32,
                out: &mut [u8],
                out_bits: usize,
            ) -> Result<(), Error> {
                check_length(out, out_bits)?;
                let mut reader = self.end(last, bits, out_bits as u128)?;
                reader.squeeze(out);
                to_top(out, out_bits);
                Ok(())
            }

            /// As [`finalize_bits_to`](Self::finalize_bits_to), then
            /// checks the result against `tag`, `tag_bits` long, in
            /// constant time; the bits below a partial last byte's
            /// top ones are ignored.
            pub fn verify_bits(
                &mut self,
                last: u8,
                bits: u32,
                tag: &[u8],
                tag_bits: usize,
            ) -> Result<(), Error> {
                check_length(tag, tag_bits)?;
                let mut reader = self.end(last, bits, tag_bits as u128)?;
                if matches(&mut reader, tag, tag_bits) {
                    Ok(())
                } else {
                    Err(Error::AuthenticationFailed)
                }
            }

            /// Ends the message with the first `bits` bits of `last`,
            /// zero to seven, and returns KMACXOF's output stream.
            pub fn finalize_bits_xof(
                &mut self,
                last: u8,
                bits: u32,
            ) -> Result<$reader, Error> {
                Ok($reader(self.end(last, bits, 0)?))
            }

            /// Ends a message whose last `bits` bits are in `last`,
            /// absorbing `right_encode(length)` behind them.
            ///
            /// The encoded length is whole bytes, but it follows the
            /// message's bits directly, so each of its bytes is split
            /// across two: shifted up past those bits, with what
            /// spills over carried into the next. What is left over
            /// at the end is as many bits as the message had, and
            /// ends the sponge's input.
            fn end(
                &mut self,
                last: u8,
                bits: u32,
                length: u128,
            ) -> Result<AutoReader<variant::$variant>, Error> {
                if bits > 7 {
                    return Err(Error::InvalidBitCount(bits));
                }
                let (encoded, n) = right_encode(length);
                if bits == 0 {
                    self.core.update(&encoded[..n]);
                    return Ok(self.core.finalize_xof());
                }
                let mut carry = last & low_bits(bits);
                let mut shifted = [0u8; 17];
                for (out, &byte) in shifted.iter_mut().zip(&encoded[..n]) {
                    *out = carry | (byte << bits);
                    carry = byte >> (8 - bits);
                }
                self.core.update(&shifted[..n]);
                self.core.finalize_bits_xof(carry, bits)
            }
        }

        impl fmt::Debug for $name {
            /// Deliberately omits everything: it is all derived from
            /// the key.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        /// A 32-byte key, for generic code; [`new`](Self::new)
        /// takes any.
        impl KeyType for $name {
            type Key = Key<[u8; 32]>;

            fn zero_key() -> Self::Key {
                Key::from([0u8; 32])
            }
        }

        /// Under an empty customization, with the output length of
        /// the tag type.
        impl Mac for $name {
            type Tag = [u8; $tag];

            fn try_new(key: &Self::Key) -> Result<Self, Error> {
                Ok(Self::new(key.as_ref(), b""))
            }

            fn reset(&mut self) {
                self.core.reset()
            }

            fn update(&mut self, data: &[u8]) {
                self.core.update(data)
            }

            fn finalize(&mut self) -> Self::Tag {
                let mut tag = [0u8; $tag];
                self.finalize_to(&mut tag);
                tag
            }
        }

        // The sponge states wipe themselves; this only says so.
        impl ZeroizeOnDrop for $name {}
    };
}

kmac!(
    /// KMAC128, over cSHAKE128.
    Kmac128,
    Kmac128Reader,
    CShake128,
    32
);
kmac!(
    /// KMAC256, over cSHAKE256.
    Kmac256,
    Kmac256Reader,
    CShake256,
    64
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
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

    const KEY: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
        0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    ];
    const TAGGED: &[u8] = b"My Tagged Application";

    fn short() -> Vec<u8> {
        vec![0, 1, 2, 3]
    }

    fn long() -> Vec<u8> {
        (0..200).collect()
    }

    /// The NIST KMAC samples, 1 to 6.
    #[test]
    fn nist_kmac_samples() {
        let kmac128 = |data: &[u8], s: &[u8]| {
            let mut mac = Kmac128::new(&KEY, s);
            mac.update(data);
            let mut out = vec![0u8; 32];
            mac.finalize_to(&mut out);
            out
        };
        let kmac256 = |data: &[u8], s: &[u8]| {
            let mut mac = Kmac256::new(&KEY, s);
            mac.update(data);
            let mut out = vec![0u8; 64];
            mac.finalize_to(&mut out);
            out
        };
        assert_eq!(
            kmac128(&short(), b""),
            unhex(
                "E5780B0D3EA6F7D3A429C5706AA43A00
                 FADBD7D49628839E3187243F456EE14E"
            )
        );
        assert_eq!(
            kmac128(&short(), TAGGED),
            unhex(
                "3B1FBA963CD8B0B59E8C1A6D71888B71
                 43651AF8BA0A7070C0979E2811324AA5"
            )
        );
        assert_eq!(
            kmac128(&long(), TAGGED),
            unhex(
                "1F5B4E6CCA02209E0DCB5CA635B89A15
                 E271ECC760071DFD805FAA38F9729230"
            )
        );
        assert_eq!(
            kmac256(&short(), TAGGED),
            unhex(
                "20C570C31346F703C9AC36C61C03CB64
                 C3970D0CFC787E9B79599D273A68D2F7
                 F69D4CC3DE9D104A351689F27CF6F595
                 1F0103F33F4F24871024D9C27773A8DD"
            )
        );
        assert_eq!(
            kmac256(&long(), b""),
            unhex(
                "75358CF39E41494E949707927CEE0AF2
                 0A3FF553904C86B08F21CC414BCFD691
                 589D27CF5E15369CBBFF8B9A4C2EB178
                 00855D0235FF635DA82533EC6B759B69"
            )
        );
        assert_eq!(
            kmac256(&long(), TAGGED),
            unhex(
                "B58618F71F92E1D56C1B8C55DDD7CD18
                 8B97B4CA4D99831EB2699A837DA2E4D9
                 70FBACFDE50033AEA585F1A2708510C3
                 2D07880801BD182898FE476876FC8965"
            )
        );
    }

    /// The NIST KMACXOF samples, 1 to 6.
    #[test]
    fn nist_kmacxof_samples() {
        let xof128 = |data: &[u8], s: &[u8]| {
            let mut mac = Kmac128::new(&KEY, s);
            mac.update(data);
            let mut out = vec![0u8; 32];
            mac.finalize_xof().squeeze(&mut out);
            out
        };
        let xof256 = |data: &[u8], s: &[u8]| {
            let mut mac = Kmac256::new(&KEY, s);
            mac.update(data);
            let mut out = vec![0u8; 64];
            mac.finalize_xof().squeeze(&mut out);
            out
        };
        assert_eq!(
            xof128(&short(), b""),
            unhex(
                "CD83740BBD92CCC8CF032B1481A0F446
                 0E7CA9DD12B08A0C4031178BACD6EC35"
            )
        );
        assert_eq!(
            xof128(&short(), TAGGED),
            unhex(
                "31A44527B4ED9F5C6101D11DE6D26F06
                 20AA5C341DEF41299657FE9DF1A3B16C"
            )
        );
        assert_eq!(
            xof128(&long(), TAGGED),
            unhex(
                "47026C7CD793084AA0283C253EF65849
                 0C0DB61438B8326FE9BDDF281B83AE0F"
            )
        );
        assert_eq!(
            xof256(&short(), TAGGED),
            unhex(
                "1755133F1534752AAD0748F2C706FB5C
                 784512CAB835CD15676B16C0C6647FA9
                 6FAA7AF634A0BF8FF6DF39374FA00FAD
                 9A39E322A7C92065A64EB1FB0801EB2B"
            )
        );
        assert_eq!(
            xof256(&long(), b""),
            unhex(
                "FF7B171F1E8A2B24683EED37830EE797
                 538BA8DC563F6DA1E667391A75EDC02C
                 A633079F81CE12A25F45615EC8997203
                 1D18337331D24CEB8F8CA8E6A19FD98B"
            )
        );
        assert_eq!(
            xof256(&long(), TAGGED),
            unhex(
                "D5BE731C954ED7732846BB59DBE3A8E3
                 0F83E77A4BFF4459F2F1C2B4ECEBB8CE
                 67BA01C62E8AB8578D2D499BD1BB2767
                 68781190020A306A97DE281DCC30305D"
            )
        );
    }

    fn tag(mac: &mut Kmac128, data: &[u8], n: usize) -> Vec<u8> {
        mac.update(data);
        let mut out = vec![0u8; n];
        mac.finalize_to(&mut out);
        out
    }

    /// Splitting, resetting and finalizing all start again from the
    /// keyed state.
    #[test]
    fn pieces_and_reset() {
        let data = long();
        let mut mac = Kmac128::new(&KEY, TAGGED);
        let expected = tag(&mut mac, &data, 32);
        for split in [0, 1, 100, 167, 168, 199] {
            mac.update(b"garbage");
            Mac::reset(&mut mac);
            mac.update(&data[..split]);
            assert_eq!(tag(&mut mac, &data[split..], 32), expected);
        }
        let _ = tag(&mut mac, b"garbage", 32);
        assert_eq!(tag(&mut mac, &data, 32), expected);
    }

    /// The length and the customization are part of the tag, not
    /// ways of cutting one.
    #[test]
    fn length_and_customization_change_everything() {
        let mut mac = Kmac128::new(&KEY, b"");
        let full = tag(&mut mac, b"m", 32);
        let half = tag(&mut mac, b"m", 16);
        assert_ne!(full[..16], half[..]);
        let mut other = Kmac128::new(&KEY, b"x");
        assert_ne!(tag(&mut other, b"m", 32), full);
        let mut xof = [0u8; 32];
        mac.update(b"m");
        mac.finalize_xof().squeeze(&mut xof);
        assert_ne!(xof[..], full[..]);
    }

    /// Both verifying calls take the right tag and refuse any other,
    /// and leave the MAC ready for the next message either way.
    #[test]
    fn verify() {
        let mut mac = Kmac256::new(&KEY, TAGGED);
        mac.update(b"message");
        let mut good = [0u8; 100];
        mac.finalize_to(&mut good);

        mac.update(b"message");
        mac.verify_tag(&good).expect("verify");
        let mut bad = good;
        bad[99] ^= 1;
        mac.update(b"message");
        assert_eq!(mac.verify_tag(&bad), Err(Error::AuthenticationFailed));
        mac.update(b"message");
        assert_eq!(
            mac.verify_tag(&good[..99]),
            Err(Error::AuthenticationFailed)
        );
        mac.update(b"message");
        mac.verify_bits(0, 0, &good, 800).expect("verify bits");
        mac.update(b"message");
        assert_eq!(
            mac.verify_bits(0, 0, &bad, 800),
            Err(Error::AuthenticationFailed)
        );
    }

    /// The bit calls with whole-byte lengths are the byte calls.
    #[test]
    fn whole_bytes_through_the_bit_calls() {
        let key: Vec<u8> = (0..45).collect();
        let mut bytes = Kmac128::new(&key, TAGGED);
        let mut bits =
            Kmac128::try_new_bits(&key, 360, TAGGED).expect("key bits");
        let mut a = [0u8; 40];
        let mut b = [0u8; 40];
        bytes.update(b"hello");
        bytes.finalize_to(&mut a);
        bits.update(b"hello");
        bits.finalize_bits_to(0, 0, &mut b, 320).expect("bits");
        assert_eq!(a, b);

        bytes.update(b"hello");
        bytes.finalize_xof().squeeze(&mut a);
        bits.update(b"hello");
        bits.finalize_bits_xof(0, 0).expect("bits").squeeze(&mut b);
        assert_eq!(a, b);
    }

    /// Every count of extra message bits gives its own tag, and the
    /// bits of `last` beyond the count are ignored.
    #[test]
    fn message_bits() {
        let mut mac = Kmac128::new(&KEY, b"");
        let mut out = [0u8; 32];
        let mut tags = Vec::new();
        for bits in 0..8u32 {
            let last = 0b1010_0101 & (0xffu16 >> (8 - bits)) as u8;
            mac.update(b"ab");
            mac.finalize_bits_to(last, bits, &mut out, 256)
                .expect("bits");
            tags.push(out);
            let noisy = last | !(0xffu16 >> (8 - bits)) as u8;
            mac.update(b"ab");
            mac.finalize_bits_to(noisy, bits, &mut out, 256)
                .expect("bits");
            assert_eq!(out, tags[bits as usize], "bits {bits}");
        }
        for i in 0..tags.len() {
            for j in i + 1..tags.len() {
                assert_ne!(tags[i], tags[j], "{i} and {j}");
            }
        }
    }

    /// An output that does not fill its last byte has its bits at the
    /// top of that byte and zeros below, is a different MAC from the
    /// byte one, and verifies whatever the bits below are.
    #[test]
    fn output_bits() {
        let mut mac = Kmac128::new(&KEY, b"");
        let mut whole = [0u8; 32];
        mac.update(b"m");
        mac.finalize_to(&mut whole);
        for out_bits in 249..256 {
            let mut out = [0xffu8; 32];
            mac.update(b"m");
            mac.finalize_bits_to(0, 0, &mut out, out_bits)
                .expect("bits");
            let below = low_bits(8 - (out_bits % 8) as u32);
            assert_eq!(out[31] & below, 0);
            assert_ne!(out[..31], whole[..31], "{out_bits}");
            mac.update(b"m");
            let mut tag = out;
            tag[31] |= below;
            mac.verify_bits(0, 0, &tag, out_bits).expect("unused bits");
        }
    }

    /// A key that ends mid-byte, its bits at the top of the last byte,
    /// keys a different MAC from the whole bytes, and the bits below
    /// do not matter.
    #[test]
    fn key_bits() {
        let whole = [0x5au8; 20];
        let mut noisy = whole;
        noisy[19] = 0xff;
        let mut clean = whole;
        clean[19] = 0xe0;
        let mut from_clean =
            Kmac128::try_new_bits(&clean, 155, b"").expect("key");
        let mut from_noisy =
            Kmac128::try_new_bits(&noisy, 155, b"").expect("key");
        let mut from_whole = Kmac128::new(&whole, b"");
        let expected = tag(&mut from_clean, b"m", 32);
        assert_eq!(tag(&mut from_noisy, b"m", 32), expected);
        assert_ne!(tag(&mut from_whole, b"m", 32), expected);
    }

    /// Bad counts and lengths are refused before the message is
    /// touched.
    #[test]
    fn refuses_bad_lengths() {
        assert_eq!(
            Kmac128::try_new_bits(&[0u8; 3], 25, b"").err(),
            Some(Error::InvalidLength(3))
        );
        assert_eq!(
            Kmac128::try_new_bits(&[0u8; 3], 16, b"").err(),
            Some(Error::InvalidLength(3))
        );
        let mut mac = Kmac128::new(&KEY, b"");
        let mut expected = [0u8; 32];
        mac.update(b"kept");
        let mut probe = mac.clone();
        probe.finalize_to(&mut expected);

        let mut out = [0u8; 32];
        assert_eq!(
            mac.finalize_bits_to(0, 8, &mut out, 256),
            Err(Error::InvalidBitCount(8))
        );
        assert_eq!(
            mac.finalize_bits_to(0, 0, &mut out, 255 + 16),
            Err(Error::InvalidLength(32))
        );
        assert_eq!(
            mac.verify_bits(0, 0, &out, 8),
            Err(Error::InvalidLength(32))
        );
        assert!(mac.finalize_bits_xof(0, 9).is_err());
        mac.finalize_to(&mut out);
        assert_eq!(out, expected, "the message survived");
    }

    #[test]
    fn debug_omits_the_key() {
        let mac = Kmac128::new(&KEY, b"");
        let text = std::format!("{mac:?}");
        assert_eq!(text, "Kmac128 { .. }");
    }
}
