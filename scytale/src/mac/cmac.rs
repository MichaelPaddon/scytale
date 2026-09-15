//! CMAC (NIST SP 800-38B, RFC 4493): a MAC from a block cipher.
//!
//! A CBC-MAC with the last block masked by one of two subkeys, which
//! is what makes it safe over messages of any length: a plain
//! CBC-MAC lets a tag for one message be extended into a tag for
//! another. The subkeys are derived from the key once, so a message
//! costs one cipher call per block and nothing more.
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::aes::Aes128;
//! use scytale::mac::Mac;
//! use scytale::mac::cmac::Cmac;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let key = Key::from([0x2b; 16]);
//!
//! // In one call.
//! let tag = Cmac::<Aes128>::mac(&key, b"message");
//!
//! // In pieces, then checked in constant time.
//! let mut mac = Cmac::<Aes128>::new(&key);
//! mac.update(b"mess");
//! mac.update(b"age");
//! mac.verify(&tag)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Speed
//!
//! The chain is serial: each block waits for the one before it, so
//! the cipher runs one block at a time however many the processor
//! could take at once. Runs of whole blocks go to the loop CBC
//! encryption has written out for the processor, which keeps the
//! chain in a register and pays for no call per block.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Mac;
use crate::cipher::mode::cbc::MacEngine;
use crate::cipher::mode::xor;
use crate::cipher::{BlockCipher, OneBlock};
use crate::{Error, KeyType};

/// The block, and tag, length in bytes.
const BLOCK: usize = 16;

/// What doubling in the field of 2^128 elements XORs in when the top
/// bit falls off: the low terms of x^128 + x^7 + x^2 + x + 1.
const R: u8 = 0x87;

/// CMAC over a block cipher.
///
/// One state serves many messages: [`Mac::reset`] returns to the
/// keyed state without deriving the subkeys again, and so does
/// [`Mac::finalize`].
#[derive(Clone)]
pub struct Cmac<C: BlockCipher<Block = [u8; BLOCK]>> {
    cipher: C,
    /// The chaining loop for runs of whole blocks.
    engine: MacEngine<C>,
    /// Masks a last block that is whole.
    k1: [u8; BLOCK],
    /// Masks a last block that had to be padded.
    k2: [u8; BLOCK],
    /// The CBC chain over every block folded in so far.
    chain: [u8; BLOCK],
    /// The block not yet folded in. It is held back even when full,
    /// because until more arrives it may be the last, and the last
    /// is masked before it is encrypted.
    block: [u8; BLOCK],
    used: usize,
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Cmac<C> {
    /// Starts a MAC under `key`.
    pub fn new(key: &C::Key) -> Self {
        Self::with_engine(key, MacEngine::new())
    }

    /// The MAC over the chaining loop `implementation` names, or
    /// `None` where this processor or cipher has no such thing.
    #[cfg(test)]
    pub(crate) fn with_implementation(
        key: &C::Key,
        implementation: crate::implementation::Implementation,
    ) -> Option<Self> {
        Some(Self::with_engine(key, MacEngine::with(implementation)?))
    }

    fn with_engine(key: &C::Key, engine: MacEngine<C>) -> Self {
        let cipher = C::new(key);
        let mut l = [0u8; BLOCK];
        cipher.encrypt_one(&mut l);
        let k1 = double(&l);
        let k2 = double(&k1);
        l.zeroize();
        Cmac {
            cipher,
            engine,
            k1,
            k2,
            chain: [0u8; BLOCK],
            block: [0u8; BLOCK],
            used: 0,
        }
    }

    /// The tag of `data` under `key`, in one call.
    pub fn mac(key: &C::Key, data: &[u8]) -> [u8; BLOCK] {
        let mut mac = Self::new(key);
        mac.update(data);
        mac.finalize()
    }

    /// Folds one block that is known not to be the last into the
    /// chain.
    fn fold(&mut self, block: &[u8; BLOCK]) {
        xor(&mut self.chain, block);
        self.cipher.encrypt_one(&mut self.chain);
    }
}

/// Multiplies `block` by x in the field, as a 128-bit big-endian
/// number shifted left. Which constant goes in depends on the top
/// bit, a bit of the key's encryption, so it is chosen by a mask
/// rather than a branch.
fn double(block: &[u8; BLOCK]) -> [u8; BLOCK] {
    let n = u128::from_be_bytes(*block);
    let carry = (n >> 127) as u8;
    let mut out = (n << 1).to_be_bytes();
    out[BLOCK - 1] ^= carry.wrapping_neg() & R;
    out
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> KeyType for Cmac<C> {
    type Key = C::Key;

    fn zero_key() -> Self::Key {
        C::zero_key()
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Mac for Cmac<C> {
    type Tag = [u8; BLOCK];

    /// Never fails: every key the cipher takes is a CMAC key.
    fn try_new(key: &Self::Key) -> Result<Self, Error> {
        Ok(Self::new(key))
    }

    fn reset(&mut self) {
        self.chain.zeroize();
        self.block.zeroize();
        self.used = 0;
    }

    fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // Top up the held block. Once it is full and more data
        // follows, it is not the last, so it can go in.
        if self.used > 0 {
            let n = data.len().min(BLOCK - self.used);
            self.block[self.used..self.used + n].copy_from_slice(&data[..n]);
            self.used += n;
            data = &data[n..];
            if data.is_empty() {
                return;
            }
            let block = self.block;
            self.fold(&block);
            self.used = 0;
        }
        // Whole blocks straight from the input, keeping back the
        // final one, which may yet be the last of the message.
        let keep = match data.len() % BLOCK {
            0 => BLOCK,
            partial => partial,
        };
        let (blocks, last) = data.split_at(data.len() - keep);
        self.engine.fold(&self.cipher, &mut self.chain, blocks);
        self.block[..keep].copy_from_slice(last);
        self.used = keep;
    }

    fn finalize(&mut self) -> Self::Tag {
        let mut last = self.block;
        if self.used == BLOCK {
            xor(&mut last, &self.k1);
        } else {
            last[self.used] = 0x80;
            last[self.used + 1..].fill(0);
            xor(&mut last, &self.k2);
        }
        xor(&mut self.chain, &last);
        self.cipher.encrypt_one(&mut self.chain);
        let tag = self.chain;
        last.zeroize();
        self.reset();
        tag
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Drop for Cmac<C> {
    fn drop(&mut self) {
        self.k1.zeroize();
        self.k2.zeroize();
        self.chain.zeroize();
        self.block.zeroize();
    }
}

// The subkeys and the running state are wiped above; the cipher's
// key schedule wipes itself where the cipher says it does.
impl<C: BlockCipher<Block = [u8; BLOCK]> + ZeroizeOnDrop> ZeroizeOnDrop
    for Cmac<C>
{
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> fmt::Debug for Cmac<C> {
    /// Deliberately omits everything: it is all derived from the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cmac").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key;
    use crate::cipher::aes::{Aes128, Aes192, Aes256};

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        let text: std::vec::Vec<u8> =
            text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        let mut out = [0u8; N];
        assert_eq!(text.len(), 2 * N);
        for (o, pair) in out.iter_mut().zip(text.chunks(2)) {
            let pair = core::str::from_utf8(pair).expect("ascii");
            *o = u8::from_str_radix(pair, 16).expect("hex");
        }
        out
    }

    /// The message every published example takes a prefix of.
    fn message() -> [u8; 64] {
        unhex(
            "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
             30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710",
        )
    }

    /// Checks each `(length, tag)` pair under `key`, in one call and
    /// through the trait.
    fn check<C: BlockCipher<Block = [u8; BLOCK]>>(
        key: &C::Key,
        cases: &[(usize, &str)],
    ) {
        let m = message();
        for &(len, tag) in cases {
            let expected: [u8; 16] = unhex(tag);
            assert_eq!(Cmac::<C>::mac(key, &m[..len]), expected, "{len}");
            let mut mac = Cmac::<C>::try_new(key).expect("key");
            mac.update(&m[..len]);
            mac.verify(&expected).expect("verify");
        }
    }

    /// RFC 4493 section 4: the subkeys.
    #[test]
    fn rfc4493_subkeys() {
        let key = Key::from(unhex("2b7e151628aed2a6abf7158809cf4f3c"));
        let mac = Cmac::<Aes128>::new(&key);
        assert_eq!(mac.k1, unhex::<16>("fbeed618357133667c85e08f7236a8de"));
        assert_eq!(mac.k2, unhex::<16>("f7ddac306ae266ccf90bc11ee46d513b"));
    }

    /// RFC 4493 section 4, examples 1 to 4: empty, one whole block,
    /// a partial last block, and four whole blocks.
    #[test]
    fn rfc4493_examples() {
        let key = Key::from(unhex("2b7e151628aed2a6abf7158809cf4f3c"));
        check::<Aes128>(
            &key,
            &[
                (0, "bb1d6929e95937287fa37d129b756746"),
                (16, "070a16b46b4d4144f79bdd9dd04a287c"),
                (40, "dfa66747de9ae63030ca32611497c827"),
                (64, "51f0bebf7e3b9d92fc49741779363cfe"),
            ],
        );
    }

    /// The NIST AES-CMAC examples for 192- and 256-bit keys.
    #[test]
    fn nist_examples_192_and_256() {
        let key = Key::from(unhex::<24>(
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        ));
        check::<Aes192>(
            &key,
            &[
                (0, "d17ddf46adaacde531cac483de7a9367"),
                (16, "9e99a7bf31e710900662f65e617c5184"),
                (20, "3d75c194ed96070444a9fa7ec740ecf8"),
                (64, "a1d5df0eed790f794d77589659f39a11"),
            ],
        );
        let key = Key::from(unhex::<32>(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ));
        check::<Aes256>(
            &key,
            &[
                (0, "028962f61b7bf89efc6b551f4667d983"),
                (16, "28a7023f452e8f82bd4bf28d8c37c35c"),
                (20, "156727dc0878944a023c1fe03bad6d93"),
                (64, "e1992190549f6ed5696a2c056c315410"),
            ],
        );
    }

    /// Where a message is split makes no difference, including splits
    /// that land on block boundaries and empty pieces.
    #[test]
    fn splitting_does_not_matter() {
        let key = Key::from([0x5au8; 16]);
        let m = message();
        for len in [0, 1, 15, 16, 17, 31, 32, 33, 48, 64] {
            let whole = Cmac::<Aes128>::mac(&key, &m[..len]);
            for split in 0..=len {
                for second in split..=len {
                    let mut mac = Cmac::<Aes128>::new(&key);
                    mac.update(&m[..split]);
                    mac.update(&[]);
                    mac.update(&m[split..second]);
                    mac.update(&m[second..len]);
                    assert_eq!(mac.finalize(), whole, "{len} {split}");
                }
            }
        }
    }

    /// Every chaining loop this processor has gives the tag the
    /// portable one does, at every key width, at lengths from nothing
    /// to many blocks, in one piece and in two.
    #[test]
    fn the_engines_agree() {
        use crate::cipher::mode::cbc::CHOICES;
        use crate::implementation::Implementation;
        let data: std::vec::Vec<u8> =
            (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        fn each<C: BlockCipher<Block = [u8; BLOCK]>>(
            key: &C::Key,
            data: &[u8],
        ) {
            let mut engines = 0;
            for &implementation in CHOICES {
                let Some(mut mac) =
                    Cmac::<C>::with_implementation(key, implementation)
                else {
                    continue;
                };
                engines += 1;
                for len in [0, 1, 16, 17, 32, 48, 64, 200, 1000] {
                    let mut reference = Cmac::<C>::with_implementation(
                        key,
                        Implementation::Portable,
                    )
                    .expect("portable");
                    reference.update(&data[..len]);
                    let expected = reference.finalize();
                    mac.update(&data[..len]);
                    assert_eq!(mac.finalize(), expected, "{len}");
                    let half = len / 2;
                    mac.update(&data[..half]);
                    mac.update(&data[half..len]);
                    assert_eq!(
                        mac.finalize(),
                        expected,
                        "{len} in two, {implementation:?}"
                    );
                }
            }
            assert!(engines >= 1);
        }
        each::<Aes128>(&Key::from([3u8; 16]), &data);
        each::<Aes192>(&Key::from([4u8; 24]), &data);
        each::<Aes256>(&Key::from([5u8; 32]), &data);
    }

    /// A wrong tag and a short one are both refused.
    #[test]
    fn verify_rejects_wrong_and_short_tags() {
        let key = Key::from([1u8; 16]);
        let tag = Cmac::<Aes128>::mac(&key, b"message");
        let mut mac = Cmac::<Aes128>::new(&key);

        let mut wrong = tag;
        wrong[15] ^= 1;
        mac.update(b"message");
        assert_eq!(mac.verify(&wrong), Err(Error::AuthenticationFailed));
        mac.update(b"message");
        assert_eq!(mac.verify(&tag[..8]), Err(Error::AuthenticationFailed));
        mac.update(b"message");
        mac.verify(&tag).expect("verify");
    }

    /// Doubling carries the top bit round as 0x87, and only then.
    #[test]
    fn doubling() {
        let mut top = [0u8; 16];
        top[0] = 0x80;
        let mut expected = [0u8; 16];
        expected[15] = R;
        assert_eq!(double(&top), expected);
        let mut low = [0u8; 16];
        low[15] = 0x41;
        expected[15] = 0x82;
        assert_eq!(double(&low), expected);
    }

    /// Compiles only if CMAC wipes itself over a cipher that does.
    #[test]
    fn wipes_when_the_cipher_does() {
        use crate::cipher::aes::portable::{bitsliced, ttable};
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Cmac<bitsliced::Aes<16>>>();
        wipes::<Cmac<ttable::Aes<32>>>();
    }
}
