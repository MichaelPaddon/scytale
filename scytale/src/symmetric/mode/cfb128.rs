//! Cipher feedback with full-block segments (NIST SP 800-38A).
//!
//! The cipher encrypts a shift register to make a keystream block,
//! which is combined with the plaintext; the ciphertext then becomes
//! the register for the next block. Both directions run the cipher
//! forwards, so a decrypt-only cipher is never needed.
//!
//! # Using it safely
//!
//! - The IV must be unpredictable to an attacker who can influence
//!   the plaintext, so draw it with [`random`](crate::random) for
//!   each message.
//! - Never use the same key and IV for two messages. The keystream
//!   repeats, and an attacker who knows one plaintext learns another.
//! - CFB provides no authentication; it does not detect a modified
//!   message. Prefer an authenticated mode.
//! - The message must be a whole number of blocks. For byte or bit
//!   granularity use [`Cfb8`](super::Cfb8) or [`Cfb1`](super::Cfb1).
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Cfb128;
//!
//! # fn main() -> Result<(), scytale::symmetric::Error> {
//! let cfb = Cfb128::new(Aes::try_new(&[0u8; 16])?);
//! let iv = [0u8; 16];
//!
//! let mut data = [0u8; 32];
//! cfb.encrypt(&iv, &mut data)?;
//! cfb.decrypt(&iv, &mut data)?;
//! assert_eq!(data, [0u8; 32]);
//! # Ok(())
//! # }
//! ```

use super::{register_from, xor, LANES, MAX_BLOCK_SIZE};
use crate::symmetric::{BlockCipher, Error};

/// CFB with 128-bit segments over a block cipher.
#[derive(Clone, Debug)]
pub struct Cfb128<C> {
    cipher: C,
}

impl<C: BlockCipher> Cfb128<C> {
    /// Wraps `cipher`.
    ///
    /// # Panics
    /// If the cipher's block is larger than the modes support.
    pub fn new(cipher: C) -> Self {
        assert!(
            C::BLOCK_SIZE > 0 && C::BLOCK_SIZE <= MAX_BLOCK_SIZE,
            "block size is outside the range the modes support"
        );
        Cfb128 { cipher }
    }

    /// Encrypts `data` in place under `iv`.
    ///
    /// `iv` must be one block and `data` a whole number of blocks.
    pub fn encrypt(&self, iv: &[u8], data: &mut [u8]) -> Result<(), Error> {
        self.encryptor(iv)?.update(data)
    }

    /// Decrypts `data` in place under `iv`.
    ///
    /// `iv` must be one block and `data` a whole number of blocks.
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

/// Encrypts one message, a piece at a time.
///
/// Every piece must be a whole number of blocks. There is nothing to
/// finish: drop the state when the message ends.
#[derive(Debug)]
pub struct Encryptor<'a, C> {
    cipher: &'a C,
    register: [u8; MAX_BLOCK_SIZE],
}

impl<C: BlockCipher> Encryptor<'_, C> {
    /// Encrypts the next piece of the message in place.
    ///
    /// The register takes the ciphertext just produced, so this runs
    /// one block at a time and cannot use the cipher's bulk path.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let size = C::BLOCK_SIZE;
        if !data.len().is_multiple_of(size) {
            return Err(Error::NotBlockAligned(data.len()));
        }
        let mut keystream = [0u8; MAX_BLOCK_SIZE];
        for block in data.chunks_exact_mut(size) {
            keystream[..size].copy_from_slice(&self.register[..size]);
            self.cipher.encrypt_block(&mut keystream[..size])?;
            xor(block, &keystream[..size]);
            self.register[..size].copy_from_slice(block);
        }
        Ok(())
    }
}

/// Decrypts one message, a piece at a time.
///
/// Every piece must be a whole number of blocks. There is nothing to
/// finish.
#[derive(Debug)]
pub struct Decryptor<'a, C> {
    cipher: &'a C,
    register: [u8; MAX_BLOCK_SIZE],
}

impl<C: BlockCipher> Decryptor<'_, C> {
    /// Decrypts the next piece of the message in place.
    ///
    /// Every register value is known in advance here: the IV, then
    /// each ciphertext block. So the keystream for a whole group is
    /// built first and encrypted in one bulk call, unlike encryption,
    /// which has to wait for its own output.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let size = C::BLOCK_SIZE;
        if !data.len().is_multiple_of(size) {
            return Err(Error::NotBlockAligned(data.len()));
        }
        let mut seen = [0u8; LANES * MAX_BLOCK_SIZE];
        let mut keystream = [0u8; LANES * MAX_BLOCK_SIZE];
        for group in data.chunks_mut(LANES * size) {
            let n = group.len();
            let seen = &mut seen[..n];
            seen.copy_from_slice(group);

            let keystream = &mut keystream[..n];
            keystream[..size].copy_from_slice(&self.register[..size]);
            keystream[size..].copy_from_slice(&seen[..n - size]);
            self.cipher.encrypt_blocks(keystream)?;

            xor(group, keystream);
            self.register[..size].copy_from_slice(&seen[n - size..]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::Aes;

    const MAX: usize = 24 * 16;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            out[i] =
                u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16)
                    .unwrap();
        }
        out
    }

    fn cfb(key: &[u8]) -> Cfb128<Aes> {
        Cfb128::new(Aes::try_new(key).unwrap())
    }

    /// NIST SP 800-38A F.3.13 and F.3.14, AES-128.
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
             c8a64537a0b3a93fcde3cdad9f1ce58b\
             26751f67a3cbb140b1808cf187a4f4df\
             c04b05357c5d1c0eeac4c66f9ff7f2e6",
        );
        let cfb = cfb(&key);

        let mut data = plain;
        cfb.encrypt(&iv, &mut data).unwrap();
        assert_eq!(data, cipher, "encrypt");
        cfb.decrypt(&iv, &mut data).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    #[test]
    fn round_trips_at_many_lengths() {
        let cfb = cfb(&[0x5a; 32]);
        let iv = [0x77u8; 16];
        let mut plain = [0u8; MAX];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        // Enough blocks to cross the group the decryption path uses.
        for blocks in [0, 1, 2, 7, 8, 9, 16, 17, 24] {
            let n = blocks * 16;
            let mut data = [0u8; MAX];
            data[..n].copy_from_slice(&plain[..n]);
            cfb.encrypt(&iv, &mut data[..n]).unwrap();
            if blocks > 0 {
                assert_ne!(data[..n], plain[..n], "{blocks} blocks");
            }
            cfb.decrypt(&iv, &mut data[..n]).unwrap();
            assert_eq!(data[..n], plain[..n], "{blocks} blocks");
        }
    }

    #[test]
    fn pieces_match_one_call() {
        let cfb = cfb(&[0x33; 24]);
        let iv = [1u8; 16];
        let mut plain = [0u8; MAX];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }
        for split in [1, 7, 8, 15] {
            let mut whole = plain;
            cfb.encrypt(&iv, &mut whole).unwrap();

            let mut pieces = plain;
            let mut e = cfb.encryptor(&iv).unwrap();
            let (a, b) = pieces.split_at_mut(split * 16);
            e.update(a).unwrap();
            e.update(b).unwrap();
            assert_eq!(pieces, whole, "encrypt split at {split}");

            let mut d = cfb.decryptor(&iv).unwrap();
            let (a, b) = pieces.split_at_mut(split * 16);
            d.update(a).unwrap();
            d.update(b).unwrap();
            assert_eq!(pieces, plain, "decrypt split at {split}");
        }
    }

    #[test]
    fn rejects_bad_lengths() {
        let cfb = cfb(&[0; 16]);
        let source = [0u8; 32];
        for n in [0, 1, 15, 17, 32] {
            assert_eq!(
                cfb.encrypt(&source[..n], &mut [0; 16]).unwrap_err(),
                Error::InvalidNonceLength(n)
            );
        }
        for n in [1, 15, 17, 31] {
            let mut data = [0x44u8; 31];
            let data = &mut data[..n];
            assert_eq!(
                cfb.encrypt(&[0; 16], data).unwrap_err(),
                Error::NotBlockAligned(n)
            );
            assert!(data.iter().all(|&b| b == 0x44), "data untouched");
        }
    }
}
