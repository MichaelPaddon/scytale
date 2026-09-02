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
//! use scytale::cipher::aes::Aes;
//! use scytale::cipher::mode::Cfb1;
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

use core::fmt;

use super::{bit, set_bit, shift_in_bit};
use crate::cipher::BlockCipher;
use crate::Error;

/// CFB with 1-bit segments over a block cipher.
#[derive(Clone)]
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
    /// `data` must hold at least `bits` bits. Any bits beyond that are
    /// left alone.
    pub fn encrypt(
        &self,
        iv: &C::Block,
        data: &mut [u8],
        bits: usize,
    ) -> Result<(), Error> {
        self.encryptor(iv).update(data, bits)
    }

    /// Decrypts the first `bits` bits of `data` in place under `iv`.
    pub fn decrypt(
        &self,
        iv: &C::Block,
        data: &mut [u8],
        bits: usize,
    ) -> Result<(), Error> {
        self.decryptor(iv).update(data, bits)
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

// Debug output omits the state: it is all derived from the key.
impl<C> fmt::Debug for Cfb1<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cfb1").finish_non_exhaustive()
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
        let mut e = cfb.encryptor(&iv);
        e.update(&mut first, 8).unwrap();
        e.update(&mut second, 8).unwrap();
        assert_eq!([first[0], second[0]], whole);
    }

    #[test]
    fn rejects_bad_lengths() {
        let cfb = cfb(&[0; 16]);
        for bits in [9, 17, 100] {
            assert_eq!(
                cfb.encrypt(&[0; 16], &mut [0; 1], bits).unwrap_err(),
                Error::InvalidLength(bits)
            );
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
