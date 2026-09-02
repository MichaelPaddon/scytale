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
//! use scytale::cipher::aes::Aes;
//! use scytale::cipher::mode::Cfb8;
//!
//! # fn main() -> Result<(), scytale::Error> {
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

use core::fmt;

use super::shift_in_byte;
use crate::cipher::BlockCipher;
use crate::Error;

/// CFB with 8-bit segments over a block cipher.
#[derive(Clone)]
pub struct Cfb8<C> {
    cipher: C,
}

impl<C: BlockCipher> Cfb8<C> {
    /// Wraps `cipher`.
    pub fn new(cipher: C) -> Self {
        Cfb8 { cipher }
    }

    /// Encrypts `data` in place under `iv`. Any length of message is
    /// allowed.
    pub fn encrypt(&self, iv: &C::Block, data: &mut [u8]) -> Result<(), Error> {
        self.encryptor(iv).update(data)
    }

    /// Decrypts `data` in place under `iv`, which must be one block.
    pub fn decrypt(&self, iv: &C::Block, data: &mut [u8]) -> Result<(), Error> {
        self.decryptor(iv).update(data)
    }

    /// Starts encrypting a message that arrives in pieces.
    pub fn encryptor(&self, iv: &C::Block) -> Encryptor<'_, C> {
        Encryptor {
            cipher: &self.cipher,
            register: *iv,
        }
    }

    /// Starts decrypting a message that arrives in pieces.
    pub fn decryptor(&self, iv: &C::Block) -> Decryptor<'_, C> {
        Decryptor {
            cipher: &self.cipher,
            register: *iv,
        }
    }
}

/// Encrypts one message, a piece at a time. Pieces may be any
/// length; there is nothing to finish.
pub struct Encryptor<'a, C: BlockCipher> {
    cipher: &'a C,
    register: C::Block,
}

impl<C: BlockCipher> Encryptor<'_, C> {
    /// Encrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        for byte in data.iter_mut() {
            let mut keystream = self.register;
            self.cipher.encrypt_block(&mut keystream);
            *byte ^= keystream.as_ref()[0];
            shift_in_byte(self.register.as_mut(), *byte);
        }
        Ok(())
    }
}

/// Decrypts one message, a piece at a time. Pieces may be any
/// length; there is nothing to finish.
pub struct Decryptor<'a, C: BlockCipher> {
    cipher: &'a C,
    register: C::Block,
}

impl<C: BlockCipher> Decryptor<'_, C> {
    /// Decrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        for byte in data.iter_mut() {
            let mut keystream = self.register;
            self.cipher.encrypt_block(&mut keystream);
            // The register takes the ciphertext, so save it before
            // the byte becomes plaintext.
            let ciphertext = *byte;
            *byte ^= keystream.as_ref()[0];
            shift_in_byte(self.register.as_mut(), ciphertext);
        }
        Ok(())
    }
}

// Debug output omits the state: it is all derived from the key.
impl<C> fmt::Debug for Cfb8<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cfb8").finish_non_exhaustive()
    }
}

impl<C: BlockCipher> fmt::Debug for Encryptor<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor").finish_non_exhaustive()
    }
}

impl<C: BlockCipher> fmt::Debug for Decryptor<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryptor").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::Aes;

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
            let mut e = cfb.encryptor(&iv);
            let (a, b) = pieces.split_at_mut(split);
            e.update(a).unwrap();
            e.update(b).unwrap();
            assert_eq!(pieces, whole, "encrypt split at {split}");

            let mut d = cfb.decryptor(&iv);
            let (a, b) = pieces.split_at_mut(split);
            d.update(a).unwrap();
            d.update(b).unwrap();
            assert_eq!(pieces, plain, "decrypt split at {split}");
        }
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
        let mode = cfb(&[0x5a; 16]);
        let iv = [0x5a; 16];
        let state = mode.encryptor(&iv);
        let mut buffer = Buffer([0; 256], 0);
        core::fmt::write(&mut buffer, format_args!("{mode:?} {state:?}"))
            .unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        // 0x5a prints as 90 in decimal.
        assert!(!text.contains("90"), "{text}");
    }
}
