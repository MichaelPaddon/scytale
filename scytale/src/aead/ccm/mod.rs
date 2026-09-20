//! Counter with CBC-MAC (NIST SP 800-38C, RFC 3610).
//!
//! Counter mode for secrecy and a CBC-MAC over the plaintext for the
//! tag, both under one key. It is what Bluetooth LE, IEEE 802.15.4,
//! WPA2's CCMP and the CCM suites of IPsec and TLS speak.
//!
//! # Parameters
//!
//! CCM is a family. The nonce is 7 to 13 bytes and the tag an even
//! 4 to 16, and both lengths are written into the first block the MAC
//! sees, so a message sealed with one choice does not open under
//! another. The lengths of the slices given to
//! [`encrypt`](Ccm::encrypt) and [`decrypt`](Ccm::decrypt) are those
//! parameters. A shorter nonce leaves more room for the length of the
//! message: 15 bytes less the nonce hold it, so a 13-byte nonce limits
//! a message to 65,535 bytes.
//!
//! Through [`Aead`], the nonce is 12 bytes and the tag 16, as TLS
//! uses it.
//!
//! # One-shot only
//!
//! The first block the MAC sees carries the length of the message,
//! and the MAC covers the plaintext, so nothing can be sealed until
//! the whole message is known. Decryption is kept one-shot to match,
//! and so that no plaintext is released before its tag is checked.
//!
//! # Speed
//!
//! A CBC-MAC chains, so the tag is one block cipher call after
//! another, however fast the processor is. On x86-64 and on AArch64
//! with the AES instructions the MAC and the keystream run as one
//! loop, a keystream block beside each MAC block, so the processor
//! overlaps them; elsewhere runs of whole blocks go to the chaining
//! loop CBC encryption has written out, and the keystream runs in
//! bulk as [`Ctr`] does. [`Gcm`](super::Gcm) is the faster of the two
//! wherever there is a choice.
//!
//! # Using it safely
//!
//! - **Never reuse a nonce with the same key.** The keystream repeats
//!   and the two messages leak into each other.
//!   [`Nonces`](crate::cipher::Nonces) makes that impossible.
//! - A shorter tag is a weaker one. Protocols that choose eight
//!   bytes or fewer do so for the sake of overhead.
//!
//! # Example
//!
//! ```
//! use scytale::Key;
//! use scytale::aead::Ccm;
//! use scytale::cipher::aes::Aes128;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let ccm = Ccm::<Aes128>::new(&Key::from([0u8; 16]));
//! // A 13-byte nonce and an 8-byte tag, as RFC 3610's examples use.
//! let nonce = [0u8; 13];
//!
//! let mut message = *b"hello";
//! let mut tag = [0u8; 8];
//! ccm.encrypt(&nonce, b"header", &mut message, &mut tag)?;
//!
//! ccm.decrypt(&nonce, b"header", &mut message, &tag)?;
//! assert_eq!(&message, b"hello");
//! # Ok(())
//! # }
//! ```
//!
//! [`Ctr`]: crate::cipher::mode::Ctr

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use core::fmt;

use super::Aead;
use crate::cipher::mode::cbc::MacEngine;
use crate::cipher::mode::{Ctr, xor};
use crate::cipher::{BlockCipher, OneBlock};
use crate::constant_time;
#[cfg(test)]
use crate::implementation::Implementation;
use crate::{Error, KeyType};

/// The block width CCM is defined over.
const BLOCK: usize = 16;

/// The nonce lengths the standard allows, in bytes.
const MIN_NONCE: usize = 7;
const MAX_NONCE: usize = 13;

/// The tag lengths the standard allows, in bytes; even ones only.
const MIN_TAG: usize = 4;
const MAX_TAG: usize = BLOCK;

/// The nonce and tag through [`Aead`]: TLS's choice.
const NONCE: usize = 12;
const TAG: usize = BLOCK;

/// Every implementation, best first.
///
/// These are counter mode's; the MAC takes the chaining loop of the
/// same name where CBC has one, and the portable chain where not.
#[cfg(test)]
pub(crate) const CHOICES: &[Implementation] = crate::cipher::mode::ctr::CHOICES;

/// CCM over a block cipher.
#[derive(Clone)]
pub struct Ccm<C: BlockCipher<Block = [u8; BLOCK]>> {
    /// The keystream, and the cipher the MAC borrows from it.
    ctr: Ctr<C>,
    /// The MAC's chaining loop, which needs no key of its own.
    chain: MacEngine<C>,
    /// Both halves as one loop, where the processor has one written.
    #[cfg(target_arch = "aarch64")]
    native: Option<aarch64::Engine<C>>,
    #[cfg(target_arch = "x86_64")]
    native: Option<x86_64::Engine<C>>,
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> fmt::Debug for Ccm<C> {
    /// Deliberately omits everything: it is all derived from the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ccm").finish_non_exhaustive()
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> KeyType for Ccm<C> {
    type Key = C::Key;

    fn zero_key() -> Self::Key {
        C::zero_key()
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Aead for Ccm<C> {
    type Nonce = [u8; NONCE];
    type Tag = [u8; TAG];

    fn new(key: &Self::Key) -> Self {
        // The inherent constructor, which takes precedence here.
        Ccm::new(key)
    }

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    ) -> Result<(), Error> {
        Ccm::encrypt(self, nonce, aad, data, tag)
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), Error> {
        Ccm::decrypt(self, nonce, aad, data, tag)
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Ccm<C> {
    /// Takes the key the cipher runs under.
    pub fn new(key: &C::Key) -> Self {
        Ccm {
            ctr: Ctr::new(key),
            chain: MacEngine::new(),
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            native: best_native(),
        }
    }

    /// The mode over the implementation `implementation` names, or
    /// `None` where this processor or this cipher has no such thing.
    ///
    /// For the tests, the vector suites and the benchmark. The
    /// implementation is counter mode's; the MAC runs the chaining
    /// loop of that name, or the portable one where CBC has none.
    #[cfg(test)]
    pub(crate) fn with_implementation(
        key: &C::Key,
        implementation: Implementation,
    ) -> Option<Self> {
        Some(Ccm {
            ctr: Ctr::with_implementation(key, implementation)?,
            chain: MacEngine::with(implementation)
                .or_else(|| MacEngine::with(Implementation::Portable))?,
            #[cfg(target_arch = "aarch64")]
            native: aarch64::Engine::of(implementation),
            #[cfg(target_arch = "x86_64")]
            native: x86_64::Engine::of(implementation),
        })
    }

    /// Encrypts `data` in place and writes its tag.
    ///
    /// The nonce is 7 to 13 bytes and the tag 4 to 16, even; their
    /// lengths are part of what is authenticated. `aad` is
    /// authenticated but not encrypted.
    pub fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), Error> {
        check(nonce, data.len(), tag.len())?;
        let (mac, s0) = self.crypt(nonce, aad, data, tag.len(), true)?;
        for (t, (m, s)) in tag.iter_mut().zip(mac.iter().zip(&s0)) {
            *t = m ^ s;
        }
        Ok(())
    }

    /// Checks `tag` and, if it is right, decrypts `data` in place.
    ///
    /// The nonce and tag lengths must be those the message was sealed
    /// with. On failure the buffer is wiped and
    /// [`Error::AuthenticationFailed`] returned.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        check(nonce, data.len(), tag.len())?;
        // The MAC covers the plaintext, so the message is decrypted
        // as the tag is taken and checked over the result.
        let (mut expected, s0) =
            self.crypt(nonce, aad, data, tag.len(), false)?;
        xor(&mut expected, &s0);
        if constant_time::equal(&expected[..tag.len()], tag) {
            Ok(())
        } else {
            data.fill(0);
            Err(Error::AuthenticationFailed)
        }
    }

    /// Runs the keystream over `data` from counter one and the MAC
    /// over its plaintext, which is `data` before the keystream when
    /// `encrypt` and after it otherwise. Returns the MAC, unmasked,
    /// and counter zero encrypted, which masks it.
    fn crypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag_len: usize,
        encrypt: bool,
    ) -> Result<([u8; BLOCK], [u8; BLOCK]), Error> {
        let mut counter = [0u8; BLOCK];
        counter[0] = (14 - nonce.len()) as u8;
        counter[1..=nonce.len()].copy_from_slice(nonce);
        let mut s0 = counter;
        self.ctr.cipher().encrypt_one(&mut s0);
        // `check` has bounded the message to the counter field, so
        // counting across the whole block never reaches the nonce.
        counter[BLOCK - 1] = 1;

        let mut mac = self.header(nonce, aad, data.len(), tag_len);
        let (whole, tail) = data.split_at_mut(data.len() / BLOCK * BLOCK);
        if !self.interleaved(&mut mac.chain, &mut counter, whole, encrypt) {
            if encrypt {
                mac.update(whole);
                self.ctr.apply_blocks(&mut counter, whole);
            } else {
                self.ctr.apply_blocks(&mut counter, whole);
                mac.update(whole);
            }
        }
        if encrypt {
            mac.update(tail);
            self.ctr.encrypt(&counter, tail)?;
        } else {
            self.ctr.encrypt(&counter, tail)?;
            mac.update(tail);
        }
        mac.pad();
        Ok((mac.chain, s0))
    }

    /// Both halves over whole blocks in one loop, where there is one;
    /// returns whether it ran.
    fn interleaved(
        &self,
        chain: &mut [u8; BLOCK],
        counter: &mut [u8; BLOCK],
        whole: &mut [u8],
        encrypt: bool,
    ) -> bool {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if let Some(native) = &self.native {
            return native.run(
                self.ctr.cipher(),
                chain,
                counter,
                whole,
                encrypt,
            );
        }
        let _ = (chain, counter, whole, encrypt);
        false
    }

    /// The CBC-MAC over the lengths, the nonce and `aad`, ready for
    /// the plaintext.
    fn header(
        &self,
        nonce: &[u8],
        aad: &[u8],
        length: usize,
        tag_len: usize,
    ) -> Mac<'_, C> {
        let q = 15 - nonce.len();
        let mut b0 = [0u8; BLOCK];
        let adata = if aad.is_empty() { 0 } else { 0x40 };
        b0[0] = adata | (((tag_len - 2) / 2) as u8) << 3 | (q - 1) as u8;
        b0[1..=nonce.len()].copy_from_slice(nonce);
        // The length is at most q bytes wide, which `check` enforced;
        // the leading bytes of a u64 that do not fit are zero.
        let length = (length as u64).to_be_bytes();
        b0[BLOCK - q..].copy_from_slice(&length[8 - q.min(8)..]);

        let mut mac = Mac::new(self.ctr.cipher(), &self.chain);
        mac.update(&b0);
        if !aad.is_empty() {
            let (prefix, n) = aad_length(aad.len() as u64);
            mac.update(&prefix[..n]);
            mac.update(aad);
            mac.pad();
        }
        mac
    }
}

/// The interleaved loop this processor has, best first.
#[cfg(target_arch = "aarch64")]
fn best_native<C: BlockCipher>() -> Option<aarch64::Engine<C>> {
    crate::cipher::mode::ctr::CHOICES
        .iter()
        .find_map(|&implementation| aarch64::Engine::of(implementation))
}

/// The interleaved loop this processor has, best first.
#[cfg(target_arch = "x86_64")]
fn best_native<C: BlockCipher>() -> Option<x86_64::Engine<C>> {
    crate::cipher::mode::ctr::CHOICES
        .iter()
        .find_map(|&implementation| x86_64::Engine::of(implementation))
}

/// Refuses nonce and tag lengths the standard does not define, and a
/// message too long for the counter field the nonce leaves.
fn check(nonce: &[u8], message: usize, tag: usize) -> Result<(), Error> {
    if !(MIN_NONCE..=MAX_NONCE).contains(&nonce.len()) {
        return Err(Error::InvalidNonceLength(nonce.len()));
    }
    if !(MIN_TAG..=MAX_TAG).contains(&tag) || !tag.is_multiple_of(2) {
        return Err(Error::InvalidTagLength(tag));
    }
    let q = 15 - nonce.len();
    if q < 8 && (message as u64) >> (8 * q) != 0 {
        return Err(Error::MessageTooLong);
    }
    Ok(())
}

/// How the length of the additional data is written before it: two
/// bytes where it fits below 2^16 - 2^8, and a marker followed by
/// four or eight bytes above. Returns the bytes and how many to use.
fn aad_length(len: u64) -> ([u8; 10], usize) {
    let mut out = [0u8; 10];
    if len < (1 << 16) - (1 << 8) {
        out[..2].copy_from_slice(&(len as u16).to_be_bytes());
        (out, 2)
    } else if len < 1 << 32 {
        out[..2].copy_from_slice(&[0xff, 0xfe]);
        out[2..6].copy_from_slice(&(len as u32).to_be_bytes());
        (out, 6)
    } else {
        out[..2].copy_from_slice(&[0xff, 0xff]);
        out[2..].copy_from_slice(&len.to_be_bytes());
        (out, 10)
    }
}

/// A CBC-MAC with a zero IV, taking its input in pieces.
///
/// The chain is the running state and the pending block at once:
/// bytes are XORed straight into it, and it is encrypted each time a
/// block's worth has arrived.
struct Mac<'a, C: BlockCipher<Block = [u8; BLOCK]>> {
    cipher: &'a C,
    engine: &'a MacEngine<C>,
    chain: [u8; BLOCK],
    /// Bytes of the current block already XORed in.
    used: usize,
}

impl<'a, C: BlockCipher<Block = [u8; BLOCK]>> Mac<'a, C> {
    fn new(cipher: &'a C, engine: &'a MacEngine<C>) -> Self {
        Mac {
            cipher,
            engine,
            chain: [0u8; BLOCK],
            used: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.used > 0 {
            let n = data.len().min(BLOCK - self.used);
            xor(&mut self.chain[self.used..], &data[..n]);
            self.used += n;
            data = &data[n..];
            if self.used < BLOCK {
                return;
            }
            self.cipher.encrypt_one(&mut self.chain);
            self.used = 0;
        }
        let (blocks, rest) = data.split_at(data.len() / BLOCK * BLOCK);
        self.engine.fold(self.cipher, &mut self.chain, blocks);
        xor(&mut self.chain, rest);
        self.used = rest.len();
    }

    /// Ends the current field, padding it with zeros to a block.
    fn pad(&mut self) {
        if self.used > 0 {
            self.cipher.encrypt_one(&mut self.chain);
            self.used = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key;
    use crate::cipher::aes::{Aes128, Aes256};

    #[allow(unused_imports)]
    use std::{vec, vec::Vec};

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

    /// Every implementation this processor has, under `key`.
    fn every(key: &[u8; 16]) -> Vec<Ccm<Aes128>> {
        CHOICES
            .iter()
            .filter_map(|&i| Ccm::with_implementation(&Key::from(*key), i))
            .collect()
    }

    /// Seals `pt`, checks the ciphertext and tag against `expected`
    /// (ciphertext followed by tag), and opens it again.
    fn known(
        key: &[u8; 16],
        nonce: &str,
        aad: &[u8],
        pt: &[u8],
        expected: &str,
        tag_len: usize,
    ) {
        let nonce = unhex(nonce);
        let expected = unhex(expected);
        let (ct, tag) = expected.split_at(expected.len() - tag_len);
        let modes = every(key);
        assert!(!modes.is_empty());
        for ccm in modes {
            let mut data = pt.to_vec();
            let mut got = vec![0u8; tag_len];
            ccm.encrypt(&nonce, aad, &mut data, &mut got)
                .expect("encrypt");
            assert_eq!(data, ct);
            assert_eq!(got, tag);
            ccm.decrypt(&nonce, aad, &mut data, &got).expect("decrypt");
            assert_eq!(data, pt);
        }
    }

    const SP800_38C_KEY: [u8; 16] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
        0x4c, 0x4d, 0x4e, 0x4f,
    ];

    /// `n` bytes counting up from `start`, wrapping, the pattern the
    /// published examples are built from.
    fn counting(start: u8, n: usize) -> Vec<u8> {
        (0..n).map(|i| start.wrapping_add(i as u8)).collect()
    }

    /// SP 800-38C appendix C, example 1: the shortest nonce and tag.
    #[test]
    fn sp800_38c_example_1() {
        known(
            &SP800_38C_KEY,
            "10111213141516",
            &counting(0, 8),
            &counting(0x20, 4),
            "7162015b 4dac255d",
            4,
        );
    }

    /// Example 2: an 8-byte nonce and 6-byte tag.
    #[test]
    fn sp800_38c_example_2() {
        known(
            &SP800_38C_KEY,
            "1011121314151617",
            &counting(0, 16),
            &counting(0x20, 16),
            "d2a1f0e051ea5f62081a7792073d593d 1fc64fbfaccd",
            6,
        );
    }

    /// Example 3: a 12-byte nonce and 8-byte tag.
    #[test]
    fn sp800_38c_example_3() {
        known(
            &SP800_38C_KEY,
            "101112131415161718191a1b",
            &counting(0, 20),
            &counting(0x20, 24),
            "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5
             484392fbc1b09951",
            8,
        );
    }

    /// Example 4: 65,536 bytes of additional data, past the two-byte
    /// length, so the `ff fe` form is what is exercised.
    #[test]
    fn sp800_38c_example_4() {
        known(
            &SP800_38C_KEY,
            "101112131415161718191a1b1c",
            &counting(0, 65536),
            &counting(0x20, 32),
            "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72
             b4ac6bec93e8598e7f0dadbcea5b",
            14,
        );
    }

    const RFC3610_KEY: [u8; 16] = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
        0xcc, 0xcd, 0xce, 0xcf,
    ];

    /// RFC 3610 packet vectors 1 to 3: an 8-byte header, a 13-byte
    /// nonce and an 8-byte tag, over payloads either side of a block.
    #[test]
    fn rfc3610_packets_1_to_3() {
        known(
            &RFC3610_KEY,
            "00000003020100a0a1a2a3a4a5",
            &counting(0, 8),
            &counting(8, 23),
            "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384
             17e8d12cfdf926e0",
            8,
        );
        known(
            &RFC3610_KEY,
            "00000004030201a0a1a2a3a4a5",
            &counting(0, 8),
            &counting(8, 24),
            "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3b
             a091d56e10400916",
            8,
        );
        known(
            &RFC3610_KEY,
            "00000005040302a0a1a2a3a4a5",
            &counting(0, 8),
            &counting(8, 25),
            "51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da859657
             4adaa76fbd9fb0c5",
            8,
        );
    }

    /// The length prefix switches form exactly where the standard
    /// says.
    #[test]
    fn aad_length_forms() {
        assert_eq!(
            aad_length(0xfeff),
            ([0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 0], 2)
        );
        let (bytes, n) = aad_length(0xff00);
        assert_eq!(&bytes[..n], &[0xff, 0xfe, 0, 0, 0xff, 0]);
        let (bytes, n) = aad_length(1 << 32);
        assert_eq!(&bytes[..n], &[0xff, 0xff, 0, 0, 0, 1, 0, 0, 0, 0]);
    }

    /// Nonce and tag lengths outside the standard are refused, before
    /// anything is written.
    #[test]
    fn refuses_bad_lengths() {
        let ccm = Ccm::<Aes128>::new(&Key::from([0u8; 16]));
        let mut data = *b"data";
        for n in [0, 6, 14, 16] {
            let nonce = vec![0u8; n];
            assert_eq!(
                ccm.encrypt(&nonce, &[], &mut data, &mut [0u8; 8]),
                Err(Error::InvalidNonceLength(n))
            );
        }
        for t in [0, 2, 5, 15, 18] {
            let mut tag = vec![0u8; t];
            assert_eq!(
                ccm.encrypt(&[0u8; 12], &[], &mut data, &mut tag),
                Err(Error::InvalidTagLength(t))
            );
            assert_eq!(
                ccm.decrypt(&[0u8; 12], &[], &mut data, &tag),
                Err(Error::InvalidTagLength(t))
            );
        }
        assert_eq!(&data, b"data");
    }

    /// A 13-byte nonce leaves two bytes for the length, so 65,535
    /// bytes is the longest message and one more is refused.
    #[test]
    fn message_limit_follows_the_nonce() {
        let ccm = Ccm::<Aes128>::new(&Key::from([0u8; 16]));
        let mut tag = [0u8; 8];
        let mut data = vec![0u8; 1 << 16];
        assert_eq!(
            ccm.encrypt(&[0u8; 13], &[], &mut data, &mut tag),
            Err(Error::MessageTooLong)
        );
        ccm.encrypt(&[0u8; 13], &[], &mut data[1..], &mut tag)
            .expect("encrypt");
        ccm.encrypt(&[0u8; 12], &[], &mut data, &mut tag)
            .expect("encrypt");
    }

    /// Any change to the tag, the additional data or the ciphertext is
    /// refused, and the buffer wiped rather than left holding
    /// unauthenticated plaintext.
    #[test]
    fn rejects_tampering() {
        let ccm = Ccm::<Aes256>::new(&Key::from([7u8; 32]));
        let nonce = [9u8; 13];
        let mut sealed = *b"a message longer than a block";
        let mut tag = [0u8; 12];
        ccm.encrypt(&nonce, b"head", &mut sealed, &mut tag)
            .expect("encrypt");

        let fails = |aad: &[u8], data: &mut [u8], tag: &[u8]| {
            assert_eq!(
                ccm.decrypt(&nonce, aad, data, tag),
                Err(Error::AuthenticationFailed)
            );
            assert!(data.iter().all(|&b| b == 0));
        };
        let mut bad_tag = tag;
        bad_tag[11] ^= 1;
        fails(b"head", &mut sealed.clone(), &bad_tag);
        fails(b"heae", &mut sealed.clone(), &tag);
        fails(b"", &mut sealed.clone(), &tag);
        let mut bad_data = sealed;
        bad_data[20] ^= 0x80;
        fails(b"head", &mut bad_data, &tag);
        // The same tag bytes under a shorter tag length are a
        // different MAC, not a truncation of this one.
        fails(b"head", &mut sealed.clone(), &tag[..8]);

        ccm.decrypt(&nonce, b"head", &mut sealed, &tag)
            .expect("decrypt");
        assert_eq!(&sealed, b"a message longer than a block");
    }

    /// Every implementation agrees with the one `new` picks, across
    /// lengths that land either side of block and group boundaries.
    #[test]
    fn implementations_agree() {
        let key = [0x33u8; 16];
        let reference = Ccm::<Aes128>::new(&Key::from(key));
        let aad = counting(1, 37);
        for len in [0, 1, 15, 16, 17, 255, 256, 257, 1000] {
            let pt = counting(5, len);
            let mut want = pt.clone();
            let mut want_tag = [0u8; 16];
            reference
                .encrypt(&[1u8; 11], &aad, &mut want, &mut want_tag)
                .expect("encrypt");
            for ccm in every(&key) {
                let mut got = pt.clone();
                let mut tag = [0u8; 16];
                ccm.encrypt(&[1u8; 11], &aad, &mut got, &mut tag)
                    .expect("encrypt");
                assert_eq!((got, tag), (want.clone(), want_tag));
            }
        }
    }
}
