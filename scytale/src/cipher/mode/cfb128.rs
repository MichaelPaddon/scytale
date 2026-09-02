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
//! use scytale::cipher::aes::Aes;
//! use scytale::cipher::mode::Cfb128;
//!
//! # fn main() -> Result<(), scytale::Error> {
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

use core::fmt;

use super::{xor, LANES};
use crate::cipher::{Block, BlockCipher};
use crate::Error;

/// CFB with 128-bit segments over a block cipher.
#[derive(Clone)]
pub struct Cfb128<C> {
    cipher: C,
}

impl<C: BlockCipher> Cfb128<C> {
    /// Wraps `cipher`.
    pub fn new(cipher: C) -> Self {
        Cfb128 { cipher }
    }

    /// Encrypts `data` in place under `iv`.
    ///
    /// `data` must be a whole number of blocks.
    pub fn encrypt(&self, iv: &C::Block, data: &mut [u8]) -> Result<(), Error> {
        self.encryptor(iv).update(data)
    }

    /// Decrypts `data` in place under `iv`.
    ///
    /// `data` must be a whole number of blocks.
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

/// Encrypts one message, a piece at a time.
///
/// Every piece must be a whole number of blocks. There is nothing to
/// finish: drop the state when the message ends.
pub struct Encryptor<'a, C: BlockCipher> {
    cipher: &'a C,
    register: C::Block,
}

impl<C: BlockCipher> Encryptor<'_, C> {
    /// Encrypts the next piece of the message in place.
    ///
    /// The register takes the ciphertext just produced, so this runs
    /// one block at a time and cannot use the cipher's bulk path.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let (blocks, rest) = C::Block::split_mut(data);
        if !rest.is_empty() {
            return Err(Error::NotBlockAligned(data.len()));
        }
        for block in blocks {
            let mut keystream = self.register;
            self.cipher.encrypt_block(&mut keystream);
            xor(block.as_mut(), keystream.as_ref());
            self.register = *block;
        }
        Ok(())
    }
}

/// Decrypts one message, a piece at a time.
///
/// Every piece must be a whole number of blocks. There is nothing to
/// finish.
pub struct Decryptor<'a, C: BlockCipher> {
    cipher: &'a C,
    register: C::Block,
}

impl<C: BlockCipher> Decryptor<'_, C> {
    /// Decrypts the next piece of the message in place.
    ///
    /// Every register value is known in advance here: the IV, then
    /// each ciphertext block. So the keystream for a whole group is
    /// built first and encrypted in one bulk call, unlike encryption,
    /// which has to wait for its own output.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let (blocks, rest) = C::Block::split_mut(data);
        if !rest.is_empty() {
            return Err(Error::NotBlockAligned(data.len()));
        }
        let mut seen = [C::Block::ZERO; LANES];
        let mut keystream = [C::Block::ZERO; LANES];
        for group in blocks.chunks_mut(LANES) {
            let n = group.len();
            let seen = &mut seen[..n];
            seen.copy_from_slice(group);

            let keystream = &mut keystream[..n];
            keystream[0] = self.register;
            keystream[1..].copy_from_slice(&seen[..n - 1]);
            self.cipher.encrypt_blocks(keystream);

            for (block, key) in group.iter_mut().zip(&*keystream) {
                xor(block.as_mut(), key.as_ref());
            }
            self.register = seen[n - 1];
        }
        Ok(())
    }
}

// Debug output omits the state: it is all derived from the key.
impl<C> fmt::Debug for Cfb128<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cfb128").finish_non_exhaustive()
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
            let mut e = cfb.encryptor(&iv);
            let (a, b) = pieces.split_at_mut(split * 16);
            e.update(a).unwrap();
            e.update(b).unwrap();
            assert_eq!(pieces, whole, "encrypt split at {split}");

            let mut d = cfb.decryptor(&iv);
            let (a, b) = pieces.split_at_mut(split * 16);
            d.update(a).unwrap();
            d.update(b).unwrap();
            assert_eq!(pieces, plain, "decrypt split at {split}");
        }
    }

    #[test]
    fn rejects_bad_lengths() {
        let cfb = cfb(&[0; 16]);
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
