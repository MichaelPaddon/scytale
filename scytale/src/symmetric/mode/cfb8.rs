//! Cipher feedback with 8-bit segments (NIST SP 800-38A).
//!
//! One byte of message per block cipher call: the cipher encrypts a
//! shift register, the top byte of the result is combined with one
//! plaintext byte, and the ciphertext byte is shifted into the
//! register. That costs a full block encryption for every byte, so
//! it is roughly sixteen times the work of [`Cfb128`](super::Cfb128)
//! for the same message. It exists for protocols that must encrypt a
//! byte at a time without buffering.
//!
//! # Using it safely
//!
//! - The IV must be unpredictable, so draw it with
//!   [`random`](crate::random). A key and IV pair must never
//!   be reused across messages.
//! - CFB provides no authentication. Prefer an authenticated mode.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Cfb8;
//!
//! # fn main() -> Result<(), scytale::symmetric::Error> {
//! let cfb = Cfb8::new(Aes::try_new(&[0u8; 16])?);
//! let iv = [0u8; 16];
//!
//! // Any length, down to a single byte.
//! let mut data = [0u8; 5];
//! cfb.encrypt(&iv, &mut data)?;
//! cfb.decrypt(&iv, &mut data)?;
//! assert_eq!(data, [0u8; 5]);
//! # Ok(())
//! # }
//! ```

use super::{register_from, shift_in_byte, MAX_BLOCK_SIZE};
use crate::symmetric::{BlockCipher, Error};

/// CFB with 8-bit segments over a block cipher.
#[derive(Clone, Debug)]
pub struct Cfb8<C> {
    cipher: C,
}

impl<C: BlockCipher> Cfb8<C> {
    /// Wraps `cipher`.
    ///
    /// # Panics
    /// If the cipher's block is larger than the modes support.
    pub fn new(cipher: C) -> Self {
        assert!(
            C::BLOCK_SIZE > 0 && C::BLOCK_SIZE <= MAX_BLOCK_SIZE,
            "block size is outside the range the modes support"
        );
        Cfb8 { cipher }
    }

    /// Encrypts `data` in place under `iv`, which must be one block.
    /// Any length of message is allowed.
    pub fn encrypt(&self, iv: &[u8], data: &mut [u8]) -> Result<(), Error> {
        self.encryptor(iv)?.update(data)
    }

    /// Decrypts `data` in place under `iv`, which must be one block.
    pub fn decrypt(&self, iv: &[u8], data: &mut [u8]) -> Result<(), Error> {
        self.decryptor(iv)?.update(data)
    }

    /// Starts encrypting a message that arrives in pieces.
    pub fn encryptor(&self, iv: &[u8]) -> Result<Encryptor<'_, C>, Error> {
        Ok(Encryptor {
            cipher: &self.cipher,
            register: register_from(iv, C::BLOCK_SIZE)?,
        })
    }

    /// Starts decrypting a message that arrives in pieces.
    pub fn decryptor(&self, iv: &[u8]) -> Result<Decryptor<'_, C>, Error> {
        Ok(Decryptor {
            cipher: &self.cipher,
            register: register_from(iv, C::BLOCK_SIZE)?,
        })
    }
}

/// Encrypts one message, a piece at a time. Pieces may be any
/// length; there is nothing to finish.
#[derive(Debug)]
pub struct Encryptor<'a, C> {
    cipher: &'a C,
    register: [u8; MAX_BLOCK_SIZE],
}

impl<C: BlockCipher> Encryptor<'_, C> {
    /// Encrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let size = C::BLOCK_SIZE;
        let mut keystream = [0u8; MAX_BLOCK_SIZE];
        for byte in data.iter_mut() {
            keystream[..size].copy_from_slice(&self.register[..size]);
            self.cipher.encrypt_block(&mut keystream[..size])?;
            *byte ^= keystream[0];
            shift_in_byte(&mut self.register[..size], *byte);
        }
        Ok(())
    }
}

/// Decrypts one message, a piece at a time. Pieces may be any
/// length; there is nothing to finish.
#[derive(Debug)]
pub struct Decryptor<'a, C> {
    cipher: &'a C,
    register: [u8; MAX_BLOCK_SIZE],
}

impl<C: BlockCipher> Decryptor<'_, C> {
    /// Decrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let size = C::BLOCK_SIZE;
        let mut keystream = [0u8; MAX_BLOCK_SIZE];
        for byte in data.iter_mut() {
            keystream[..size].copy_from_slice(&self.register[..size]);
            self.cipher.encrypt_block(&mut keystream[..size])?;
            // The register takes the ciphertext, so save it before
            // the byte becomes plaintext.
            let ciphertext = *byte;
            *byte ^= keystream[0];
            shift_in_byte(&mut self.register[..size], ciphertext);
        }
        Ok(())
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

    fn cfb(key: &[u8]) -> Cfb8<Aes> {
        Cfb8::new(Aes::try_new(key).unwrap())
    }

    /// NIST SP 800-38A F.3.7 and F.3.8, AES-128.
    #[test]
    fn sp800_38a_aes128() {
        let key: [u8; 16] = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
        let plain: [u8; 18] = unhex("6bc1bee22e409f96e93d7e117393172aae2d");
        let cipher: [u8; 18] = unhex("3b79424c9c0dd436bace9e0ed4586a4f32b9");
        let cfb = cfb(&key);

        let mut data = plain;
        cfb.encrypt(&iv, &mut data).unwrap();
        assert_eq!(data, cipher, "encrypt");
        cfb.decrypt(&iv, &mut data).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    #[test]
    fn round_trips_at_many_lengths() {
        let cfb = cfb(&[0x5a; 24]);
        let iv = [0x77u8; 16];
        let mut plain = [0u8; 40];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        // Any length is allowed, including none and less than a block.
        for n in [0, 1, 2, 15, 16, 17, 33, 40] {
            let mut data = [0u8; 40];
            data[..n].copy_from_slice(&plain[..n]);
            cfb.encrypt(&iv, &mut data[..n]).unwrap();
            if n > 0 {
                assert_ne!(data[..n], plain[..n], "{n} bytes");
            }
            cfb.decrypt(&iv, &mut data[..n]).unwrap();
            assert_eq!(data[..n], plain[..n], "{n} bytes");
        }
    }

    #[test]
    fn pieces_match_one_call() {
        let cfb = cfb(&[0x33; 16]);
        let iv = [1u8; 16];
        let mut plain = [0u8; 40];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }
        // Splits that fall inside a block, unlike the block modes.
        for split in [1, 5, 16, 23] {
            let mut whole = plain;
            cfb.encrypt(&iv, &mut whole).unwrap();

            let mut pieces = plain;
            let mut e = cfb.encryptor(&iv).unwrap();
            let (a, b) = pieces.split_at_mut(split);
            e.update(a).unwrap();
            e.update(b).unwrap();
            assert_eq!(pieces, whole, "encrypt split at {split}");

            let mut d = cfb.decryptor(&iv).unwrap();
            let (a, b) = pieces.split_at_mut(split);
            d.update(a).unwrap();
            d.update(b).unwrap();
            assert_eq!(pieces, plain, "decrypt split at {split}");
        }
    }

    #[test]
    fn rejects_wrong_iv_length() {
        let cfb = cfb(&[0; 16]);
        let source = [0u8; 32];
        for n in [0, 1, 15, 17, 32] {
            assert_eq!(
                cfb.encrypt(&source[..n], &mut [0; 4]).unwrap_err(),
                Error::InvalidNonceLength(n)
            );
        }
    }
}
