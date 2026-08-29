//! Galois/Counter Mode (NIST SP 800-38D).
//!
//! The first authenticated mode here: it encrypts with counter mode
//! and authenticates with GHASH, a hash built on multiplication in a
//! finite field, so a receiver learns not just what the message says
//! but that nobody altered it. Data sent alongside in the clear, such
//! as a header that must be readable but must not be tampered with,
//! can be authenticated too.
//!
//! # Speed
//!
//! GHASH, not the cipher, is what makes GCM slower than counter mode
//! alone. Where the processor has a carry-less multiply instruction
//! the hash uses it, and hashes whole groups of blocks at once where
//! it can, which together bring GCM to within a fifth of the speed of
//! the counter mode underneath it. Without such an instruction the
//! hash walks 128 bits per block, which leaks nothing but is slow
//! enough to dominate everything else here.
//!
//! # Using it safely
//!
//! - **Never reuse a nonce with the same key.** For GCM this is worse
//!   than for the unauthenticated stream modes: as well as revealing
//!   the relationship between the two messages, it lets an attacker
//!   recover the hash key and then forge tags for any message at all.
//!   If nonces cannot be guaranteed unique, use a mode built to
//!   survive repeats.
//! - **Counting beats drawing.** [`Nonces`](super::Nonces) makes a
//!   repeat impossible. A nonce drawn at random is allowed, but then
//!   the standard caps one key at 2^32 messages, and counting those
//!   messages is the caller's job.
//! - A 96-bit nonce is the usual choice and the one the standard
//!   treats specially. Any other length is allowed and supported, but
//!   is hashed down to a counter block first, which costs a little
//!   and gains nothing.
//! - Do not use a decrypted message before the tag has been checked.
//!   The one-shot [`decrypt`](Gcm::decrypt) checks first and wipes the
//!   buffer on failure. The incremental form cannot: see
//!   [`Decryptor`].
//! - A shorter tag is a weaker one. Every method here takes the full
//!   sixteen bytes; a protocol that has decided to carry fewer keeps a
//!   prefix and checks it with [`Decryptor::verify_truncated`], so
//!   that the decision is visible where it is made.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Gcm;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let gcm = Gcm::try_new(Aes::try_new(&[0u8; 16])?)?;
//! let nonce = [0u8; 12];
//! let header = b"to: alice";
//!
//! let mut message = *b"hello";
//! let mut tag = [0u8; 16];
//! gcm.encrypt(&nonce, header, &mut message, &mut tag)?;
//!
//! gcm.decrypt(&nonce, header, &mut message, &tag)?;
//! assert_eq!(&message, b"hello");
//! # Ok(())
//! # }
//! ```

use core::fmt;

use super::ghash::{Ghash, BLOCK};
use super::{xor, LANES};
use crate::symmetric::{Block, BlockCipher};
use crate::util;
use crate::Error;

/// The most message bytes GCM may protect under one key and nonce:
/// 2^39 - 256 bits, the limit at which counter mode would repeat.
const MAX_MESSAGE: u64 = (1 << 36) - 32;

/// The shortest tag SP 800-38D allows, in bytes. Four and eight are
/// for applications the standard names, and are weaker than the rest.
const MIN_TAG: usize = 4;

/// The nonce length the standard singles out, in bytes.
pub(crate) const SHORT_NONCE: usize = 12;

/// The tag length, in bytes.
pub(crate) const TAG: usize = BLOCK;

/// GCM over a block cipher.
#[derive(Clone)]
pub struct Gcm<C> {
    cipher: C,
    /// The hash subkey, the cipher applied to a block of zeros.
    h: [u8; BLOCK],
}

impl<C> fmt::Debug for Gcm<C> {
    /// Deliberately omits the hash subkey, which is enough to forge
    /// tags, and the cipher.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gcm").finish_non_exhaustive()
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Gcm<C> {
    /// Wraps `cipher`.
    pub fn try_new(cipher: C) -> Result<Self, Error> {
        let mut h = [0u8; BLOCK];
        cipher.encrypt_block(&mut h);
        Ok(Gcm { cipher, h })
    }

    /// Encrypts `data` in place and writes its tag.
    ///
    /// `aad` is authenticated but not encrypted.
    pub fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8; TAG],
    ) -> Result<(), Error> {
        let mut state = self.encryptor(nonce)?;
        state.aad(aad)?;
        state.update(data)?;
        *tag = state.finalize()?;
        Ok(())
    }

    /// Checks `tag` and, if it is right, decrypts `data` in place.
    ///
    /// On failure the buffer is wiped and
    /// [`Error::AuthenticationFailed`] returned, so a caller cannot
    /// use plaintext that was never authenticated.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG],
    ) -> Result<(), Error> {
        let mut state = self.decryptor(nonce)?;
        state.aad(aad)?;
        state.update(data)?;
        match state.verify(tag) {
            Ok(()) => Ok(()),
            Err(e) => {
                data.fill(0);
                Err(e)
            }
        }
    }

    /// Starts encrypting a message that arrives in pieces.
    pub fn encryptor(&self, nonce: &[u8]) -> Result<Encryptor<'_, C>, Error> {
        Ok(Encryptor {
            core: Core::new(&self.cipher, &self.h, nonce)?,
        })
    }

    /// Starts decrypting a message that arrives in pieces.
    pub fn decryptor(&self, nonce: &[u8]) -> Result<Decryptor<'_, C>, Error> {
        Ok(Decryptor {
            core: Core::new(&self.cipher, &self.h, nonce)?,
        })
    }
}

/// The first counter block, from which everything else follows.
///
/// A 96-bit nonce becomes the counter directly, with a one in the
/// counter field. Any other length is hashed down to a block, which
/// is why that case costs more. An empty nonce is refused: the
/// standard allows it, and it makes every message share a counter.
fn counter_start(h: &[u8; BLOCK], nonce: &[u8]) -> Result<[u8; BLOCK], Error> {
    if nonce.is_empty() {
        return Err(Error::InvalidNonceLength(0));
    }
    if nonce.len() == SHORT_NONCE {
        let mut start = [0u8; BLOCK];
        start[..SHORT_NONCE].copy_from_slice(nonce);
        start[BLOCK - 1] = 1;
        return Ok(start);
    }
    let mut hash = Ghash::new(h);
    hash.update(nonce);
    hash.pad();
    let bits = (nonce.len() as u64)
        .checked_mul(8)
        .ok_or(Error::MessageTooLong)?;
    let mut lengths = [0u8; BLOCK];
    lengths[8..].copy_from_slice(&bits.to_be_bytes());
    hash.update(&lengths);
    Ok(hash.finish())
}

/// Fills `blocks` with successive counter values and leaves `counter`
/// on the one after the last.
///
/// The counter stays in registers for the whole group. Storing it and
/// reading it back for the next block puts a sixteen-byte load across
/// two narrower stores still in the store buffer, which cannot be
/// forwarded and costs about a dozen cycles a block.
///
/// Read big-endian, the field the standard increments is the low
/// thirty-two bits of the whole block, so masking it off leaves the
/// rest untouched and the addition wraps where it should.
#[inline]
fn counters(counter: &mut [u8; BLOCK], blocks: &mut [[u8; BLOCK]]) {
    let base = u128::from_be_bytes(*counter);
    let rest = base & !(u32::MAX as u128);
    let mut n = base as u32;
    for block in blocks.iter_mut() {
        *block = (rest | u128::from(n)).to_be_bytes();
        n = n.wrapping_add(1);
    }
    *counter = (rest | u128::from(n)).to_be_bytes();
}

/// Adds one to the last four bytes of the counter, wrapping within
/// them. GCM increments only that field, not the whole block.
fn increment32(counter: &mut [u8; BLOCK]) {
    for byte in counter[BLOCK - 4..].iter_mut().rev() {
        let (sum, carried) = byte.overflowing_add(1);
        *byte = sum;
        if !carried {
            break;
        }
    }
}

/// What both directions share: the counter, the hash, and the lengths
/// that go into the tag.
struct Core<'a, C> {
    cipher: &'a C,
    hash: Ghash,
    counter: [u8; BLOCK],
    /// The keystream block a previous piece ended inside.
    keystream: [u8; BLOCK],
    used: usize,
    /// The cipher applied to the first counter block, which the tag
    /// is combined with at the end.
    mask: [u8; BLOCK],
    aad_bits: u64,
    message_bytes: u64,
    /// Whether the additional data is finished. It must all arrive
    /// before any of the message.
    started: bool,
}

impl<C> Core<'_, C> {
    /// Debug for whichever direction owns this core: the counts, and
    /// nothing derived from the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
        f.debug_struct(name)
            .field("aad_bits", &self.aad_bits)
            .field("message_bytes", &self.message_bytes)
            .finish_non_exhaustive()
    }
}

impl<'a, C: BlockCipher<Block = [u8; BLOCK]>> Core<'a, C> {
    fn new(
        cipher: &'a C,
        h: &[u8; BLOCK],
        nonce: &[u8],
    ) -> Result<Self, Error> {
        let start = counter_start(h, nonce)?;
        let mut mask = start;
        cipher.encrypt_block(&mut mask);
        let mut counter = start;
        increment32(&mut counter);
        Ok(Core {
            cipher,
            hash: Ghash::new(h),
            counter,
            keystream: [0; BLOCK],
            used: BLOCK,
            mask,
            aad_bits: 0,
            message_bytes: 0,
            started: false,
        })
    }

    fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        // All additional data must come before any of the message.
        if self.started {
            return Err(Error::OutOfOrder);
        }
        let bits = (data.len() as u64)
            .checked_mul(8)
            .and_then(|b| self.aad_bits.checked_add(b))
            .ok_or(Error::MessageTooLong)?;
        self.aad_bits = bits;
        self.hash.update(data);
        Ok(())
    }

    /// Ends the additional data and counts the message.
    fn begin(&mut self, len: usize) -> Result<(), Error> {
        if !self.started {
            self.hash.pad();
            self.started = true;
        }
        let total = (len as u64)
            .checked_add(self.message_bytes)
            .ok_or(Error::MessageTooLong)?;
        if total > MAX_MESSAGE {
            return Err(Error::MessageTooLong);
        }
        self.message_bytes = total;
        Ok(())
    }

    /// Applies the counter-mode keystream to `data`.
    fn apply(&mut self, mut data: &mut [u8]) -> Result<(), Error> {
        // Finish the block a previous piece stopped inside.
        if self.used < BLOCK {
            let take = data.len().min(BLOCK - self.used);
            let (now, rest) = data.split_at_mut(take);
            xor(now, &self.keystream[self.used..self.used + take]);
            self.used += take;
            data = rest;
        }

        // Whole blocks, in groups: the counters are known in advance.
        let (whole, tail) = <[u8; BLOCK]>::split_mut(data);
        let mut keystream = [[0u8; BLOCK]; LANES];
        for group in whole.chunks_mut(LANES) {
            let keystream = &mut keystream[..group.len()];
            counters(&mut self.counter, keystream);
            self.cipher.encrypt_blocks(keystream);
            for (block, key) in group.iter_mut().zip(&*keystream) {
                xor(block, key);
            }
        }

        if !tail.is_empty() {
            self.keystream = self.counter;
            increment32(&mut self.counter);
            self.cipher.encrypt_block(&mut self.keystream);
            xor(tail, &self.keystream);
            self.used = tail.len();
        }
        Ok(())
    }

    /// The full-length tag.
    fn tag(&mut self) -> Result<[u8; BLOCK], Error> {
        if !self.started {
            self.hash.pad();
            self.started = true;
        }
        self.hash.pad();

        let mut lengths = [0u8; BLOCK];
        lengths[..8].copy_from_slice(&self.aad_bits.to_be_bytes());
        let message_bits = self
            .message_bytes
            .checked_mul(8)
            .ok_or(Error::MessageTooLong)?;
        lengths[8..].copy_from_slice(&message_bits.to_be_bytes());
        self.hash.update(&lengths);

        let mut tag = self.hash.finish();
        xor(&mut tag, &self.mask);
        Ok(tag)
    }
}

/// Encrypts one message, a piece at a time.
///
/// All additional data must be given before any of the message.
pub struct Encryptor<'a, C> {
    core: Core<'a, C>,
}

impl<C> fmt::Debug for Encryptor<'_, C> {
    /// Says how far along it is and nothing else.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.core.fmt(f, "Encryptor")
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Encryptor<'_, C> {
    /// Adds data that is authenticated but not encrypted.
    ///
    /// Returns [`Error::OutOfOrder`] if called after
    /// [`update`](Self::update): all of it must come first.
    pub fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        self.core.aad(data)
    }

    /// Encrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.core.begin(data.len())?;
        self.core.apply(data)?;
        self.core.hash.update(data);
        Ok(())
    }

    /// Finishes, returning the tag. A protocol that carries a shorter
    /// tag keeps the first bytes of this one; the receiver then checks
    /// it with [`Decryptor::verify_truncated`].
    pub fn finalize(mut self) -> Result<[u8; TAG], Error> {
        self.core.tag()
    }
}

/// Decrypts one message, a piece at a time.
///
/// **The pieces this hands back are not yet authenticated.** Nothing
/// can vouch for any of the message until [`verify`](Self::verify)
/// has checked the tag, so a caller must not act on the plaintext, or
/// let anyone else see it, before that succeeds. Where the whole
/// message fits in memory, use [`Gcm::decrypt`], which checks first.
pub struct Decryptor<'a, C> {
    core: Core<'a, C>,
}

impl<C> fmt::Debug for Decryptor<'_, C> {
    /// Says how far along it is and nothing else.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.core.fmt(f, "Decryptor")
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Decryptor<'_, C> {
    /// Adds data that is authenticated but not encrypted.
    ///
    /// Returns [`Error::OutOfOrder`] if called after
    /// [`update`](Self::update): all of it must come first.
    pub fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        self.core.aad(data)
    }

    /// Decrypts the next piece of the message in place, yielding
    /// plaintext that is not yet authenticated.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.core.begin(data.len())?;
        // Hash the ciphertext before it is overwritten.
        self.core.hash.update(data);
        self.core.apply(data)
    }

    /// Checks `tag`, in time that depends on nothing secret.
    ///
    /// Returns [`Error::AuthenticationFailed`] if it is not the tag
    /// of what was given, and never says more than that.
    pub fn verify(self, tag: &[u8; TAG]) -> Result<(), Error> {
        self.verify_truncated(tag)
    }

    /// Checks a tag that a protocol has cut to between four and
    /// sixteen bytes, the range SP 800-38D allows.
    ///
    /// A shorter tag is a weaker one: an attacker's chance of forging
    /// a message is one in 2^(8n), and the standard limits how many
    /// messages a key may protect under the short ones. That is a
    /// decision for a protocol to make, which is why this method is
    /// named for it rather than reached by handing
    /// [`verify`](Decryptor::verify) a shorter slice. Returns
    /// [`Error::InvalidTagLength`]
    /// outside the range and [`Error::AuthenticationFailed`] for a
    /// wrong tag.
    pub fn verify_truncated(mut self, tag: &[u8]) -> Result<(), Error> {
        if !(MIN_TAG..=TAG).contains(&tag.len()) {
            return Err(Error::InvalidTagLength(tag.len()));
        }
        let full = self.core.tag()?;
        if util::equal(&full[..tag.len()], tag) {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::Aes;

    /// Buffers big enough for every case below.
    const MAX: usize = 64;

    fn unhex<'a>(text: &str, buffer: &'a mut [u8]) -> &'a [u8] {
        let n = text.len() / 2;
        for i in 0..n {
            buffer[i] =
                u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        &buffer[..n]
    }

    /// The published GCM test cases: key, nonce, additional data,
    /// plaintext, ciphertext, tag.
    const CASES: [[&str; 6]; 7] = [
        // A nonce that is not 96 bits, so it is hashed first.
        [
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbad",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a\
             721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c74\
             2373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
            "3612d2e79e3b0785561be14aaca2fccb",
        ],
        // Empty message and no additional data.
        [
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        ],
        // One block, still nothing to authenticate alongside.
        [
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        ],
        // Four whole blocks.
        [
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a\
             721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aaf\
             d255",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca1\
             2e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f\
             5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        ],
        // Additional data, and a message that is not whole blocks.
        [
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a\
             721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca1\
             2e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47",
        ],
        // AES-192.
        [
            "feffe9928665731c6d6a8f9467308308feffe9928665731c",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a\
             721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e1\
             9c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
            "2519498e80f1478f37ba55bd6d27618c",
        ],
        // AES-256.
        [
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f94673083\
             08",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a\
             721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1\
             aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        ],
    ];

    #[test]
    fn published_test_cases() {
        for (i, case) in CASES.iter().enumerate() {
            let (mut kb, mut nb) = ([0u8; 32], [0u8; 32]);
            let (mut ab, mut pb) = ([0u8; MAX], [0u8; MAX]);
            let (mut cb, mut tb) = ([0u8; MAX], [0u8; 16]);
            let key = unhex(case[0], &mut kb);
            let nonce = unhex(case[1], &mut nb);
            let aad = unhex(case[2], &mut ab);
            let plain = unhex(case[3], &mut pb);
            let cipher = unhex(case[4], &mut cb);
            unhex(case[5], &mut tb);
            let tag = &tb;

            let gcm = Gcm::try_new(Aes::try_new(key).unwrap()).unwrap();
            let mut data = [0u8; MAX];
            let data = &mut data[..plain.len()];
            data.copy_from_slice(plain);
            let mut got = [0u8; 16];

            gcm.encrypt(nonce, aad, data, &mut got).unwrap();
            assert_eq!(data, cipher, "case {i} ciphertext");
            assert_eq!(&got, tag, "case {i} tag");

            gcm.decrypt(nonce, aad, data, tag).unwrap();
            assert_eq!(data, plain, "case {i} plaintext");
        }
    }

    fn gcm() -> Gcm<Aes> {
        Gcm::try_new(Aes::try_new(&[0x42; 16]).unwrap()).unwrap()
    }

    /// Anything altered must be rejected, and the buffer wiped rather
    /// than left holding plaintext that was never authenticated.
    #[test]
    fn rejects_an_empty_nonce() {
        let gcm = gcm();
        assert_eq!(
            gcm.encryptor(&[]).err(),
            Some(Error::InvalidNonceLength(0))
        );
    }

    #[test]
    fn rejects_and_wipes() {
        let gcm = gcm();
        let nonce = [7u8; 12];
        let aad = [1u8, 2, 3];
        let plain = [9u8; 20];

        let mut sealed = plain;
        let mut tag = [0u8; 16];
        gcm.encrypt(&nonce, &aad, &mut sealed, &mut tag).unwrap();

        // A wrong tag.
        let mut wrong = tag;
        wrong[0] ^= 1;
        let mut data = sealed;
        assert_eq!(
            gcm.decrypt(&nonce, &aad, &mut data, &wrong).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(data, [0u8; 20], "buffer wiped");

        // Altered ciphertext.
        let mut data = sealed;
        data[0] ^= 1;
        assert_eq!(
            gcm.decrypt(&nonce, &aad, &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );

        // Altered additional data.
        let mut data = sealed;
        assert_eq!(
            gcm.decrypt(&nonce, &[1, 2, 4], &mut data, &tag)
                .unwrap_err(),
            Error::AuthenticationFailed
        );

        // A different nonce.
        let mut data = sealed;
        assert_eq!(
            gcm.decrypt(&[8u8; 12], &aad, &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    /// A truncated tag is a prefix of the full one, and only the
    /// lengths the standard allows are accepted.
    #[test]
    fn truncated_tags() {
        let gcm = gcm();
        let nonce = [3u8; 12];
        let mut full = [0u8; 16];
        gcm.encrypt(&nonce, b"", &mut [], &mut full).unwrap();

        for n in [4, 8, 12, 13, 14, 15, 16] {
            let d = gcm.decryptor(&nonce).unwrap();
            d.verify_truncated(&full[..n]).unwrap();
            let mut wrong = full;
            wrong[n - 1] ^= 1;
            let d = gcm.decryptor(&nonce).unwrap();
            assert_eq!(
                d.verify_truncated(&wrong[..n]).unwrap_err(),
                Error::AuthenticationFailed,
                "{n}-byte tag"
            );
        }
        let long = [0u8; 32];
        for n in [0, 1, 2, 3, 17, 32] {
            let d = gcm.decryptor(&nonce).unwrap();
            assert_eq!(
                d.verify_truncated(&long[..n]).unwrap_err(),
                Error::InvalidTagLength(n)
            );
        }
    }

    #[test]
    fn debug_shows_no_secrets() {
        struct Buffer([u8; 128], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let gcm = gcm();
        let mut buffer = Buffer([0; 128], 0);
        core::fmt::write(&mut buffer, format_args!("{gcm:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert_eq!(text, "Gcm { .. }");
        let e = gcm.encryptor(&[0; 12]).unwrap();
        let mut buffer = Buffer([0; 128], 0);
        core::fmt::write(&mut buffer, format_args!("{e:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(text.starts_with("Encryptor {"));
        assert!(!text.contains("42"), "{text}");
    }

    /// Pieces must match one call, including additional data given in
    /// several parts and a message split inside a block.
    #[test]
    fn pieces_match_one_call() {
        let gcm = gcm();
        let nonce = [5u8; 12];
        let aad = [1u8; 25];
        let mut plain = [0u8; 50];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }

        let mut whole = plain;
        let mut tag = [0u8; 16];
        gcm.encrypt(&nonce, &aad, &mut whole, &mut tag).unwrap();

        for split in [1, 7, 16, 17, 32, 49] {
            let mut pieces = plain;
            let mut e = gcm.encryptor(&nonce).unwrap();
            e.aad(&aad[..10]).unwrap();
            e.aad(&aad[10..]).unwrap();
            let (a, b) = pieces.split_at_mut(split);
            e.update(a).unwrap();
            e.update(b).unwrap();
            assert_eq!(
                e.finalize().unwrap(),
                tag,
                "encrypt tag, split {split}"
            );
            assert_eq!(pieces, whole, "encrypt, split {split}");

            let mut d = gcm.decryptor(&nonce).unwrap();
            d.aad(&aad).unwrap();
            let (a, b) = pieces.split_at_mut(split);
            d.update(a).unwrap();
            d.update(b).unwrap();
            d.verify(&tag).unwrap();
            assert_eq!(pieces, plain, "decrypt, split {split}");
        }

        // A byte at a time, which leaves both the keystream and the
        // hash part way through a block at every step.
        let mut pieces = plain;
        let mut e = gcm.encryptor(&nonce).unwrap();
        for byte in aad.iter() {
            e.aad(core::slice::from_ref(byte)).unwrap();
        }
        for byte in pieces.iter_mut() {
            e.update(core::slice::from_mut(byte)).unwrap();
        }
        assert_eq!(e.finalize().unwrap(), tag, "encrypt tag, byte at a time");
        assert_eq!(pieces, whole, "encrypt, byte at a time");
    }

    #[test]
    fn additional_data_after_the_message_is_refused() {
        let gcm = gcm();
        let mut e = gcm.encryptor(&[0; 12]).unwrap();
        e.update(&mut [0; 4]).unwrap();
        assert_eq!(e.aad(b"too late").unwrap_err(), Error::OutOfOrder);
        let mut d = gcm.decryptor(&[0; 12]).unwrap();
        d.update(&mut [0; 4]).unwrap();
        assert_eq!(d.aad(b"too late").unwrap_err(), Error::OutOfOrder);
    }
}
