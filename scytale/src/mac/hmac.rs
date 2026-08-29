//! HMAC (RFC 2104, FIPS 198-1): a MAC from any hash.
//!
//! `HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))`, where `K'`
//! is the key padded with zeros to the hash's block, or hashed first
//! if it is longer than that. The two keyed blocks are hashed once,
//! when the key is set, and every message starts from those states,
//! so a message costs its own length plus one block and the key is
//! never reprocessed.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Mac;
use crate::hash::sha2;
use crate::hash::Hash;
use crate::symmetric::Block;
use crate::Error;

/// HMAC-SHA-224.
pub type HmacSha224 = Hmac<sha2::Sha224>;
/// HMAC-SHA-256.
pub type HmacSha256 = Hmac<sha2::Sha256>;
/// HMAC-SHA-384.
pub type HmacSha384 = Hmac<sha2::Sha384>;
/// HMAC-SHA-512.
pub type HmacSha512 = Hmac<sha2::Sha512>;
/// HMAC-SHA-512/224.
pub type HmacSha512_224 = Hmac<sha2::Sha512_224>;
/// HMAC-SHA-512/256.
pub type HmacSha512_256 = Hmac<sha2::Sha512_256>;

/// The largest block any hash here has, which sizes the buffer the
/// padded key is built in. SHA-2 needs 128; SHA-3's rates need up to
/// 168.
const MAX_BLOCK_SIZE: usize = 256;

/// HMAC over the hash `H`.
///
/// Any key length is accepted. Keys shorter than the block are the
/// usual case and are padded; longer ones are hashed down first, as
/// the standard says, so two keys longer than the block can collide
/// on the hash. Keys of at least the digest length are what the
/// security proof assumes.
pub struct Hmac<H: Hash> {
    /// The hash after the inner keyed block.
    inner: H,
    /// The hash after the outer keyed block.
    outer: H,
    /// `inner` with the message so far.
    working: H,
}

impl<H: Hash> Hmac<H> {
    /// Starts a MAC under `key`, of any length.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        const { assert!(H::BLOCK_SIZE <= MAX_BLOCK_SIZE) };
        let mut padded = [0u8; MAX_BLOCK_SIZE];
        let block = &mut padded[..H::BLOCK_SIZE];
        if key.len() > H::BLOCK_SIZE {
            let digest = H::digest(key)?;
            block[..H::Output::SIZE].copy_from_slice(digest.as_ref());
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        let mut inner = H::try_new()?;
        let mut outer = H::try_new()?;
        for b in block.iter_mut() {
            *b ^= 0x36;
        }
        inner.update(block);
        for b in block.iter_mut() {
            *b ^= 0x36 ^ 0x5c;
        }
        outer.update(block);
        padded.zeroize();

        Ok(Hmac {
            working: inner.clone(),
            inner,
            outer,
        })
    }
}

impl<H: Hash> Mac for Hmac<H> {
    type Tag = H::Output;

    fn try_new(key: &[u8]) -> Result<Self, Error> {
        Hmac::try_new(key)
    }

    fn reset(&mut self) {
        self.working = self.inner.clone();
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.working.update(data);
    }

    fn finalize(mut self) -> Self::Tag {
        let mut outer = self.outer.clone();
        let inner = core::mem::replace(&mut self.working, self.inner.clone());
        outer.update(inner.finalize().as_ref());
        outer.finalize()
    }
}

impl<H: Hash> Clone for Hmac<H> {
    fn clone(&self) -> Self {
        Hmac {
            inner: self.inner.clone(),
            outer: self.outer.clone(),
            working: self.working.clone(),
        }
    }
}

// The hash states are functions of the key; they wipe themselves,
// so there is nothing more to do here beyond saying so.
impl<H: Hash + ZeroizeOnDrop> ZeroizeOnDrop for Hmac<H> {}

impl<H: Hash> fmt::Debug for Hmac<H> {
    /// Deliberately omits everything: it is all derived from the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hmac").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes hex into a fixed buffer, returning the used prefix.
    fn hex(s: &str) -> ([u8; 64], usize) {
        let mut out = [0u8; 64];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        (out, s.len() / 2)
    }

    /// One RFC 4231 case: key, data, and the four tags. Case 5 gives
    /// only the first 128 bits.
    struct Case {
        key: &'static [u8],
        data: &'static [u8],
        sha224: &'static str,
        sha256: &'static str,
        sha384: &'static str,
        sha512: &'static str,
    }

    const CASES: [Case; 7] = [
        Case {
            key: &[0x0b; 20],
            data: b"Hi There",
            sha224: "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
            sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c\
                2e32cff7",
            sha384: "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c\
                7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            sha512: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b305\
                45e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f170\
                2e696c203a126854",
        },
        Case {
            key: b"Jefe",
            data: b"what do ya want for nothing?",
            sha224: "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
            sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b9\
                64ec3843",
            sha384: "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec373\
                6322445e8e2240ca5e69e2c78b3239ecfab21649",
            sha512: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7\
                ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b\
                636e070a38bce737",
        },
        Case {
            key: &[0xaa; 20],
            data: &[0xdd; 50],
            sha224: "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
            sha256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514\
                ced565fe",
            sha384: "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e5\
                5966144b2a5ab39dc13814b94e3ab6e101a34f27",
            sha512: "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33\
                b2279d39bf3e848279a722c806b485a47e67c807b946a337bee89426\
                74278859e13292fb",
        },
        Case {
            key: &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x19,
            ],
            data: &[0xcd; 50],
            sha224: "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
            sha256: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff4\
                6729665b",
            sha384: "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e\
                1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
            sha512: "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050\
                361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2d\
                e2adebeb10a298dd",
        },
        Case {
            key: &[0x0c; 20],
            data: b"Test With Truncation",
            sha224: "0e2aea68a90c8d37c988bcdb9fca6fa8",
            sha256: "a3b6167473100ee06e0c796c2955552b",
            sha384: "3abf34c3503b2a23a46efc619baef897",
            sha512: "415fad6271580a531d4179bc891d87a6",
        },
        Case {
            key: &[0xaa; 131],
            data: b"Test Using Larger Than Block-Size Key - Hash Key First",
            sha224: "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
            sha256: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f\
                0ee37f54",
            sha384: "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05\
                033ac4c60c2ef6ab4030fe8296248df163f44952",
            sha512: "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b0137\
                83f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec\
                8b915a985d786598",
        },
        Case {
            key: &[0xaa; 131],
            data: b"This is a test using a larger than block-size key and \
                a larger than block-size data. The key needs to be hashed \
                before being used by the HMAC algorithm.",
            sha224: "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
            sha256: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f5153\
                5c3a35e2",
            sha384: "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82\
                461e99c5a678cc31e799176d3860e6110c46523e",
            sha512: "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d\
                20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de04460\
                65c97440fa8c6a58",
        },
    ];

    fn check<H: Hash>(case: &Case, expected: &str) {
        let (tag, len) = hex(expected);
        let mut mac = Hmac::<H>::try_new(case.key).unwrap();
        mac.update(case.data);
        assert_eq!(mac.clone().finalize().as_ref()[..len], tag[..len]);
        // The truncated case cannot verify against a full tag, which
        // is the point of `verify` taking a slice: it must match all
        // of it.
        if len == H::Output::SIZE {
            assert_eq!(mac.verify(&tag[..len]), Ok(()));
        }
    }

    #[test]
    fn rfc4231() {
        for case in &CASES {
            check::<sha2::Sha224>(case, case.sha224);
            check::<sha2::Sha256>(case, case.sha256);
            check::<sha2::Sha384>(case, case.sha384);
            check::<sha2::Sha512>(case, case.sha512);
        }
    }

    #[test]
    fn empty_key_and_message() {
        // HMAC-SHA-256 with an empty key and message, a widely quoted
        // value.
        let (tag, _) = hex(
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292\
             c5ad",
        );
        assert_eq!(HmacSha256::try_new(b"").unwrap().finalize(), tag[..32]);
    }

    #[test]
    fn verify_rejects_wrong_and_short_tags() {
        let mut mac = HmacSha256::try_new(b"key").unwrap();
        mac.update(b"message");
        let tag = mac.clone().finalize();
        assert_eq!(mac.clone().verify(&tag), Ok(()));
        let mut wrong = tag;
        wrong[31] ^= 1;
        assert_eq!(
            mac.clone().verify(&wrong),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(
            mac.clone().verify(&tag[..16]),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(mac.verify(&[]), Err(Error::AuthenticationFailed));
    }

    #[test]
    fn reset_reuses_the_key() {
        let mut mac = HmacSha512::try_new(b"key").unwrap();
        mac.update(b"not this");
        mac.reset();
        mac.update(b"message");
        let mut fresh = HmacSha512::try_new(b"key").unwrap();
        fresh.update(b"message");
        assert_eq!(mac.finalize(), fresh.finalize());
    }

    #[test]
    fn splitting_does_not_matter() {
        let mut one = HmacSha384::try_new(b"key").unwrap();
        one.update(b"mess");
        one.update(b"age");
        let mut whole = HmacSha384::try_new(b"key").unwrap();
        whole.update(b"message");
        assert_eq!(one.finalize(), whole.finalize());
    }

    #[test]
    fn every_implementation_zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Hmac<sha2::portable::Sha256>>();
        wipes::<Hmac<sha2::portable::Sha512>>();
    }
}
