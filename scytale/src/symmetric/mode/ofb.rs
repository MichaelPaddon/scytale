//! Output feedback (NIST SP 800-38A).
//!
//! The cipher encrypts a register to make a keystream block, and that
//! block becomes the register for the next one. The keystream depends
//! only on the key and the IV, never on the message, which has two
//! consequences: encryption and decryption are the same operation,
//! and a message may be any length, since the final keystream block
//! can simply be cut short.
//!
//! # Using it safely
//!
//! - **Never use the same key and IV twice.** The keystream is then
//!   identical, and combining two ciphertexts cancels it out and
//!   leaves the two plaintexts combined with each other. This is the
//!   single easiest way to destroy the security of any stream mode.
//! - OFB provides no authentication, and because the ciphertext is
//!   the plaintext combined with a keystream, flipping a ciphertext
//!   bit flips exactly that plaintext bit. An attacker who knows the
//!   plaintext can therefore make it say anything. Prefer an
//!   authenticated mode.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Ofb;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let ofb = Ofb::new(Aes::try_new(&[0u8; 16])?);
//! let iv = [0u8; 16];
//!
//! // Any length, not just whole blocks.
//! let mut data = [0u8; 21];
//! ofb.encrypt(&iv, &mut data)?;
//! ofb.decrypt(&iv, &mut data)?;
//! assert_eq!(data, [0u8; 21]);
//! # Ok(())
//! # }
//! ```

use core::fmt;

use super::xor;
use crate::symmetric::{Block, BlockCipher};
use crate::Error;

/// OFB over a block cipher.
#[derive(Clone)]
pub struct Ofb<C> {
    cipher: C,
}

impl<C: BlockCipher> Ofb<C> {
    /// Wraps `cipher`.
    pub fn new(cipher: C) -> Self {
        Ofb { cipher }
    }

    /// Encrypts `data` in place under `iv`. Any length of message is
    /// allowed.
    pub fn encrypt(&self, iv: &C::Block, data: &mut [u8]) -> Result<(), Error> {
        self.stream(iv).update(data)
    }

    /// Decrypts `data` in place under `iv`.
    ///
    /// This is the same operation as [`encrypt`](Self::encrypt): the
    /// keystream does not depend on the message. Both names exist so
    /// that calling code reads the way it means.
    pub fn decrypt(&self, iv: &C::Block, data: &mut [u8]) -> Result<(), Error> {
        self.stream(iv).update(data)
    }

    /// Starts a message that arrives in pieces.
    ///
    /// One state serves both directions, again because the keystream
    /// does not depend on the message.
    pub fn stream(&self, iv: &C::Block) -> Stream<'_, C> {
        Stream {
            cipher: &self.cipher,
            register: *iv,
            used: C::Block::SIZE,
        }
    }
}

/// Applies the keystream to one message, a piece at a time.
///
/// Pieces may be any length, and a piece may end part way through a
/// keystream block: the rest of that block is kept for the next one.
/// There is nothing to finish.
pub struct Stream<'a, C: BlockCipher> {
    cipher: &'a C,
    /// Holds the current keystream block, which is also the input for
    /// the next one, since in OFB they are the same value.
    register: C::Block,
    /// Bytes of the current keystream block already used. Starts full
    /// so that the first byte generates a block.
    used: usize,
}

impl<C: BlockCipher> Stream<'_, C> {
    /// Applies the keystream to the next piece of the message.
    ///
    /// Each keystream block is the encryption of the one before it,
    /// so this cannot use the cipher's bulk path.
    pub fn update(&mut self, mut data: &mut [u8]) -> Result<(), Error> {
        let size = C::Block::SIZE;
        while !data.is_empty() {
            if self.used == size {
                self.cipher.encrypt_block(&mut self.register);
                self.used = 0;
            }
            let take = data.len().min(size - self.used);
            let (now, rest) = data.split_at_mut(take);
            xor(now, &self.register.as_ref()[self.used..self.used + take]);
            self.used += take;
            data = rest;
        }
        Ok(())
    }
}

// Debug output omits the state: it is all derived from the key.
impl<C> fmt::Debug for Ofb<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ofb").finish_non_exhaustive()
    }
}

impl<C: BlockCipher> fmt::Debug for Stream<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::Aes;

    const MAX: usize = 40;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            out[i] =
                u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16)
                    .unwrap();
        }
        out
    }

    fn ofb(key: &[u8]) -> Ofb<Aes> {
        Ofb::new(Aes::try_new(key).unwrap())
    }

    /// NIST SP 800-38A F.4.1 and F.4.2, AES-128.
    #[test]
    fn sp800_38a_aes128() {
        let key: [u8; 16] = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
        let plain: [u8; 64] = unhex(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let cipher: [u8; 64] = unhex(
            "3b3fd92eb72dad20333449f8e83cfb4a\
             7789508d16918f03f53c52dac54ed825\
             9740051e9c5fecf64344f7a82260edcc\
             304c6528f659c77866a510d9c1d6ae5e",
        );
        let ofb = ofb(&key);

        let mut data = plain;
        ofb.encrypt(&iv, &mut data).unwrap();
        assert_eq!(data, cipher, "encrypt");
        ofb.decrypt(&iv, &mut data).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    /// The two directions are one operation, so encrypting twice must
    /// give the message back.
    #[test]
    fn encrypting_twice_undoes_it() {
        let ofb = ofb(&[0x11; 16]);
        let iv = [0x22u8; 16];
        let mut data = [0x33u8; 21];
        ofb.encrypt(&iv, &mut data).unwrap();
        assert_ne!(data, [0x33u8; 21]);
        ofb.encrypt(&iv, &mut data).unwrap();
        assert_eq!(data, [0x33u8; 21]);
    }

    #[test]
    fn round_trips_at_many_lengths() {
        let ofb = ofb(&[0x5a; 32]);
        let iv = [0x77u8; 16];
        let mut plain = [0u8; MAX];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        // Any length, including partial final blocks.
        for n in [0, 1, 2, 15, 16, 17, 31, 33, 40] {
            let mut data = [0u8; MAX];
            data[..n].copy_from_slice(&plain[..n]);
            ofb.encrypt(&iv, &mut data[..n]).unwrap();
            if n > 0 {
                assert_ne!(data[..n], plain[..n], "{n} bytes");
            }
            ofb.decrypt(&iv, &mut data[..n]).unwrap();
            assert_eq!(data[..n], plain[..n], "{n} bytes");
        }
    }

    /// Pieces that end part way through a keystream block must carry
    /// the rest of it over, which is the only subtle part of the
    /// incremental state.
    #[test]
    fn pieces_match_one_call() {
        let ofb = ofb(&[0x33; 24]);
        let iv = [1u8; 16];
        let mut plain = [0u8; MAX];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }
        let mut whole = plain;
        ofb.encrypt(&iv, &mut whole).unwrap();

        for split in [1, 5, 15, 16, 17, 31] {
            let mut pieces = plain;
            let mut s = ofb.stream(&iv);
            let (a, b) = pieces.split_at_mut(split);
            s.update(a).unwrap();
            s.update(b).unwrap();
            assert_eq!(pieces, whole, "split at {split}");
        }

        // Also one byte at a time, which crosses every boundary.
        let mut pieces = plain;
        let mut s = ofb.stream(&iv);
        for byte in pieces.iter_mut() {
            s.update(core::slice::from_mut(byte)).unwrap();
        }
        assert_eq!(pieces, whole, "one byte at a time");
    }

    /// The state derives from the key, so its debug output must not
    /// show it.
    #[test]
    fn debug_omits_the_state() {
        struct Buffer([u8; 256], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let mode = ofb(&[0x5a; 16]);
        let iv = [0x5a; 16];
        let state = mode.stream(&iv);
        let mut buffer = Buffer([0; 256], 0);
        core::fmt::write(&mut buffer, format_args!("{mode:?} {state:?}"))
            .unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        // 0x5a prints as 90 in decimal.
        assert!(!text.contains("90"), "{text}");
    }
}
