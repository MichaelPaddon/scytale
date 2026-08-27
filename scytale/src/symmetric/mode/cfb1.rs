//! Cipher feedback with 1-bit segments (NIST SP 800-38A).
//!
//! One *bit* of message per block cipher call: the cipher encrypts a
//! shift register, the top bit of the result is combined with one
//! plaintext bit, and the ciphertext bit is shifted into the
//! register. That is one full block encryption per bit, so it costs
//! about 128 times what [`Cfb128`](super::Cfb128) does for the same
//! message. It exists for protocols that must encrypt a bit at a
//! time; do not reach for it otherwise.
//!
//! Bits are numbered from the most significant bit of the first byte,
//! as the standard numbers them, so bit 0 is `0x80` of `data[0]`.
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
//! use scytale::symmetric::mode::Cfb1;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let cfb = Cfb1::new(Aes::try_new(&[0u8; 16])?);
//! let iv = [0u8; 16];
//!
//! // Five bits, held in the top of one byte.
//! let mut data = [0b1011_0000u8];
//! cfb.encrypt(&iv, &mut data, 5)?;
//! cfb.decrypt(&iv, &mut data, 5)?;
//! assert_eq!(data, [0b1011_0000]);
//! # Ok(())
//! # }
//! ```

use super::{bit, register_from, set_bit, shift_in_bit};
use crate::symmetric::BlockCipher;
use crate::Error;

/// CFB with 1-bit segments over a block cipher.
#[derive(Clone, Debug)]
pub struct Cfb1<C> {
    cipher: C,
}

impl<C: BlockCipher> Cfb1<C> {
    /// Wraps `cipher`.
    pub fn new(cipher: C) -> Self {
        Cfb1 { cipher }
    }

    /// Encrypts the first `bits` bits of `data` in place under `iv`.
    ///
    /// `iv` must be one block, and `data` must hold at least `bits`
    /// bits. Any bits beyond that are left alone.
    pub fn encrypt(
        &self,
        iv: &[u8],
        data: &mut [u8],
        bits: usize,
    ) -> Result<(), Error> {
        self.encryptor(iv)?.update(data, bits)
    }

    /// Decrypts the first `bits` bits of `data` in place under `iv`.
    pub fn decrypt(
        &self,
        iv: &[u8],
        data: &mut [u8],
        bits: usize,
    ) -> Result<(), Error> {
        self.decryptor(iv)?.update(data, bits)
    }

    /// Starts encrypting a message that arrives in pieces.
    pub fn encryptor(&self, iv: &[u8]) -> Result<Encryptor<'_, C>, Error> {
        Ok(Encryptor {
            cipher: &self.cipher,
            register: register_from(iv)?,
        })
    }

    /// Starts decrypting a message that arrives in pieces.
    pub fn decryptor(&self, iv: &[u8]) -> Result<Decryptor<'_, C>, Error> {
        Ok(Decryptor {
            cipher: &self.cipher,
            register: register_from(iv)?,
        })
    }
}

/// Checks that `data` holds `bits` bits.
fn check(data: &[u8], bits: usize) -> Result<(), Error> {
    if bits > 8 * data.len() {
        return Err(Error::InvalidLength(bits));
    }
    Ok(())
}

/// Encrypts one message, a piece at a time.
///
/// Each piece is counted in bits and starts at the first bit of the
/// slice given, so a piece need not be a whole number of bytes.
/// There is nothing to finish.
#[derive(Debug)]
pub struct Encryptor<'a, C: BlockCipher> {
    cipher: &'a C,
    register: C::Block,
}

impl<C: BlockCipher> Encryptor<'_, C> {
    /// Encrypts the first `bits` bits of `data` in place.
    pub fn update(
        &mut self,
        data: &mut [u8],
        bits: usize,
    ) -> Result<(), Error> {
        check(data, bits)?;
        for i in 0..bits {
            let mut keystream = self.register;
            self.cipher.encrypt_block(&mut keystream);
            let out = bit(data, i) ^ (keystream.as_ref()[0] >> 7);
            set_bit(data, i, out);
            shift_in_bit(self.register.as_mut(), out);
        }
        Ok(())
    }
}

/// Decrypts one message, a piece at a time. See [`Encryptor`].
#[derive(Debug)]
pub struct Decryptor<'a, C: BlockCipher> {
    cipher: &'a C,
    register: C::Block,
}

impl<C: BlockCipher> Decryptor<'_, C> {
    /// Decrypts the first `bits` bits of `data` in place.
    pub fn update(
        &mut self,
        data: &mut [u8],
        bits: usize,
    ) -> Result<(), Error> {
        check(data, bits)?;
        for i in 0..bits {
            let mut keystream = self.register;
            self.cipher.encrypt_block(&mut keystream);
            // The register takes the ciphertext bit, so read it
            // before the bit becomes plaintext.
            let ciphertext = bit(data, i);
            set_bit(data, i, ciphertext ^ (keystream.as_ref()[0] >> 7));
            shift_in_bit(self.register.as_mut(), ciphertext);
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

    fn cfb(key: &[u8]) -> Cfb1<Aes> {
        Cfb1::new(Aes::try_new(key).unwrap())
    }

    /// NIST SP 800-38A F.3.1 and F.3.2, AES-128: the first sixteen
    /// bits of the standard plaintext.
    #[test]
    fn sp800_38a_aes128() {
        let key: [u8; 16] = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
        let plain: [u8; 2] = unhex("6bc1");
        let cipher: [u8; 2] = unhex("68b3");
        let cfb = cfb(&key);

        let mut data = plain;
        cfb.encrypt(&iv, &mut data, 16).unwrap();
        assert_eq!(data, cipher, "encrypt");
        cfb.decrypt(&iv, &mut data, 16).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    #[test]
    fn round_trips_at_many_bit_counts() {
        let cfb = cfb(&[0x5a; 32]);
        let iv = [0x77u8; 16];
        let mut plain = [0u8; 5];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 37 + 1) as u8;
        }
        for bits in [0, 1, 2, 7, 8, 9, 15, 16, 33, 40] {
            let mut data = plain;
            cfb.encrypt(&iv, &mut data, bits).unwrap();
            cfb.decrypt(&iv, &mut data, bits).unwrap();
            assert_eq!(data, plain, "{bits} bits");
        }
    }

    /// Bits past the count must be left alone.
    #[test]
    fn leaves_later_bits_alone() {
        let cfb = cfb(&[0; 16]);
        let mut data = [0xffu8; 2];
        cfb.encrypt(&[0; 16], &mut data, 4).unwrap();
        assert_eq!(data[0] & 0x0f, 0x0f, "low bits of the first byte");
        assert_eq!(data[1], 0xff, "the second byte");
    }

    #[test]
    fn pieces_match_one_call() {
        let cfb = cfb(&[0x33; 16]);
        let iv = [1u8; 16];
        let plain = [0b1011_0110u8, 0b0100_1101];

        let mut whole = plain;
        cfb.encrypt(&iv, &mut whole, 16).unwrap();

        // A piece may end inside a byte, since each starts at the
        // first bit of the slice it is given.
        let mut first = [plain[0]];
        let mut second = [plain[1]];
        let mut e = cfb.encryptor(&iv).unwrap();
        e.update(&mut first, 8).unwrap();
        e.update(&mut second, 8).unwrap();
        assert_eq!([first[0], second[0]], whole);
    }

    #[test]
    fn rejects_bad_lengths() {
        let cfb = cfb(&[0; 16]);
        let source = [0u8; 32];
        for n in [0, 1, 15, 17, 32] {
            assert_eq!(
                cfb.encrypt(&source[..n], &mut [0; 2], 1).unwrap_err(),
                Error::InvalidNonceLength(n)
            );
        }
        for bits in [9, 17, 100] {
            assert_eq!(
                cfb.encrypt(&[0; 16], &mut [0; 1], bits).unwrap_err(),
                Error::InvalidLength(bits)
            );
        }
    }
}
