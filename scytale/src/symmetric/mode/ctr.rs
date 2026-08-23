//! Counter mode (NIST SP 800-38A).
//!
//! The cipher encrypts a counter block to make a keystream block, and
//! the counter is increased by one for the next. Nothing feeds back,
//! so every block of keystream can be computed independently: counter
//! mode is the only mode here that runs the cipher's bulk path in
//! both directions, which makes it by far the fastest.
//!
//! As with output feedback, the keystream depends only on the key and
//! the counter, so encryption and decryption are one operation and a
//! message may be any length.
//!
//! # The counter
//!
//! The initial counter block is one full block, and each step adds
//! one to it as a big-endian integer over the whole block. Callers
//! whose protocol fixes a narrower counter field, such as the 32-bit
//! field of RFC 3686, simply supply the right initial block; the
//! difference only shows once that field would wrap, which those
//! protocols forbid anyway.
//!
//! # Using it safely
//!
//! - **Never reuse a counter value with the same key.** The keystream
//!   repeats, and combining the two ciphertexts leaves the two
//!   plaintexts combined with each other. This includes overlapping
//!   ranges: a long message consumes many counter values, and the
//!   next message must start beyond them.
//! - Counter mode provides no authentication, and flipping a
//!   ciphertext bit flips exactly that plaintext bit. Prefer an
//!   authenticated mode; GCM is counter mode with authentication
//!   added.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Ctr;
//!
//! # fn main() -> Result<(), scytale::symmetric::Error> {
//! let ctr = Ctr::new(Aes::try_new(&[0u8; 16])?);
//! let counter = [0u8; 16];
//!
//! let mut data = [0u8; 21];
//! ctr.encrypt(&counter, &mut data)?;
//! ctr.decrypt(&counter, &mut data)?;
//! assert_eq!(data, [0u8; 21]);
//! # Ok(())
//! # }
//! ```

use super::{register_from, xor, LANES, MAX_BLOCK_SIZE};
use crate::symmetric::{BlockCipher, Error};

/// Counter mode over a block cipher.
#[derive(Clone, Debug)]
pub struct Ctr<C> {
    cipher: C,
}

impl<C: BlockCipher> Ctr<C> {
    /// Wraps `cipher`.
    ///
    /// # Panics
    /// If the cipher's block is larger than the modes support.
    pub fn new(cipher: C) -> Self {
        assert!(
            C::BLOCK_SIZE > 0 && C::BLOCK_SIZE <= MAX_BLOCK_SIZE,
            "block size is outside the range the modes support"
        );
        Ctr { cipher }
    }

    /// Encrypts `data` in place, starting from `counter`, which must
    /// be one block. Any length of message is allowed.
    pub fn encrypt(
        &self,
        counter: &[u8],
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.stream(counter)?.update(data)
    }

    /// Decrypts `data` in place, starting from `counter`.
    ///
    /// This is the same operation as [`encrypt`](Self::encrypt): the
    /// keystream does not depend on the message. Both names exist so
    /// that calling code reads the way it means.
    pub fn decrypt(
        &self,
        counter: &[u8],
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.stream(counter)?.update(data)
    }

    /// Starts a message that arrives in pieces.
    pub fn stream(&self, counter: &[u8]) -> Result<Stream<'_, C>, Error> {
        Ok(Stream {
            cipher: &self.cipher,
            counter: register_from(counter, C::BLOCK_SIZE)?,
            keystream: [0u8; MAX_BLOCK_SIZE],
            used: C::BLOCK_SIZE,
        })
    }
}

/// Adds one to a big-endian counter, wrapping round at the top.
#[inline]
pub(crate) fn increment(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        let (sum, carried) = byte.overflowing_add(1);
        *byte = sum;
        if !carried {
            break;
        }
    }
}

/// Applies the keystream to one message, a piece at a time.
///
/// Pieces may be any length, and a piece may end part way through a
/// keystream block: the rest of that block is kept for the next one.
/// There is nothing to finish.
#[derive(Debug)]
pub struct Stream<'a, C> {
    cipher: &'a C,
    counter: [u8; MAX_BLOCK_SIZE],
    /// The keystream block a previous piece ended inside.
    keystream: [u8; MAX_BLOCK_SIZE],
    /// Bytes of that block already used. Starts full, so the first
    /// byte generates a block.
    used: usize,
}

impl<C: BlockCipher> Stream<'_, C> {
    /// Applies the keystream to the next piece of the message.
    pub fn update(&mut self, mut data: &mut [u8]) -> Result<(), Error> {
        let size = C::BLOCK_SIZE;

        // Finish the block a previous piece stopped inside.
        if self.used < size {
            let take = data.len().min(size - self.used);
            let (now, rest) = data.split_at_mut(take);
            xor(now, &self.keystream[self.used..self.used + take]);
            self.used += take;
            data = rest;
        }

        // Whole blocks, in groups: their counters are known in
        // advance, so the cipher sees them all at once.
        let mut blocks = [0u8; LANES * MAX_BLOCK_SIZE];
        while data.len() >= size {
            let count = (data.len() / size).min(LANES);
            let n = count * size;
            for block in blocks[..n].chunks_exact_mut(size) {
                block.copy_from_slice(&self.counter[..size]);
                increment(&mut self.counter[..size]);
            }
            self.cipher.encrypt_blocks(&mut blocks[..n])?;
            let (now, rest) = data.split_at_mut(n);
            xor(now, &blocks[..n]);
            data = rest;
        }

        // A final piece of a block, whose remainder is kept.
        if !data.is_empty() {
            self.keystream[..size].copy_from_slice(&self.counter[..size]);
            increment(&mut self.counter[..size]);
            self.cipher.encrypt_block(&mut self.keystream[..size])?;
            xor(data, &self.keystream[..size]);
            self.used = data.len();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::Aes;

    /// Enough to cover several bulk groups and a partial tail.
    const MAX: usize = 20 * 16 + 5;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            out[i] =
                u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16)
                    .unwrap();
        }
        out
    }

    fn ctr(key: &[u8]) -> Ctr<Aes> {
        Ctr::new(Aes::try_new(key).unwrap())
    }

    /// NIST SP 800-38A F.5.1 and F.5.2, AES-128.
    #[test]
    fn sp800_38a_aes128() {
        let key: [u8; 16] = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let counter: [u8; 16] = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plain: [u8; 64] = unhex(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let cipher: [u8; 64] = unhex(
            "874d6191b620e3261bef6864990db6ce\
             9806f66b7970fdff8617187bb9fffdff\
             5ae4df3edbd5d35e5b4f09020db03eab\
             1e031dda2fbe03d1792170a0f3009cee",
        );
        let ctr = ctr(&key);

        let mut data = plain;
        ctr.encrypt(&counter, &mut data).unwrap();
        assert_eq!(data, cipher, "encrypt");
        ctr.decrypt(&counter, &mut data).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    #[test]
    fn counter_increments_and_carries() {
        let mut counter = [0u8; 4];
        increment(&mut counter);
        assert_eq!(counter, [0, 0, 0, 1]);

        // A carry out of the last byte.
        let mut counter = [0x00, 0x00, 0x00, 0xff];
        increment(&mut counter);
        assert_eq!(counter, [0, 0, 1, 0]);

        // A carry the whole way along.
        let mut counter = [0x01, 0xff, 0xff, 0xff];
        increment(&mut counter);
        assert_eq!(counter, [2, 0, 0, 0]);

        // And round the top, which the standard allows.
        let mut counter = [0xff; 4];
        increment(&mut counter);
        assert_eq!(counter, [0; 4]);
    }

    /// The counter must carry between blocks of a single message, not
    /// just between messages.
    #[test]
    fn carries_across_blocks_of_one_message() {
        let ctr = ctr(&[0x11; 16]);
        // Two blocks in, this counter carries into its third byte.
        let start: [u8; 16] = unhex("000000000000000000000000ffffffff");
        let mut together = [0u8; 48];
        ctr.encrypt(&start, &mut together).unwrap();

        // The same three blocks, each with the counter written out.
        let mut apart = [0u8; 48];
        for (i, block) in apart.chunks_exact_mut(16).enumerate() {
            let mut counter = start;
            for _ in 0..i {
                increment(&mut counter);
            }
            ctr.encrypt(&counter, block).unwrap();
        }
        assert_eq!(together, apart);
    }

    #[test]
    fn round_trips_at_many_lengths() {
        let ctr = ctr(&[0x5a; 32]);
        let counter = [0x77u8; 16];
        let mut plain = [0u8; MAX];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        // Around the bulk group boundary, and partial final blocks.
        for n in [0, 1, 15, 16, 17, 127, 128, 129, 255, MAX] {
            let mut data = [0u8; MAX];
            data[..n].copy_from_slice(&plain[..n]);
            ctr.encrypt(&counter, &mut data[..n]).unwrap();
            if n > 0 {
                assert_ne!(data[..n], plain[..n], "{n} bytes");
            }
            ctr.decrypt(&counter, &mut data[..n]).unwrap();
            assert_eq!(data[..n], plain[..n], "{n} bytes");
        }
    }

    /// The bulk path handles whole groups of blocks while the tail
    /// goes through one at a time, so the two must agree.
    #[test]
    fn pieces_match_one_call() {
        let ctr = ctr(&[0x33; 24]);
        let counter = [1u8; 16];
        let mut plain = [0u8; MAX];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }
        let mut whole = plain;
        ctr.encrypt(&counter, &mut whole).unwrap();

        for split in [1, 15, 16, 17, 128, 129] {
            let mut pieces = plain;
            let mut s = ctr.stream(&counter).unwrap();
            let (a, b) = pieces.split_at_mut(split);
            s.update(a).unwrap();
            s.update(b).unwrap();
            assert_eq!(pieces, whole, "split at {split}");
        }

        // One byte at a time crosses every block boundary.
        let mut pieces = plain;
        let mut s = ctr.stream(&counter).unwrap();
        for byte in pieces.iter_mut() {
            s.update(core::slice::from_mut(byte)).unwrap();
        }
        assert_eq!(pieces, whole, "one byte at a time");
    }

    #[test]
    fn rejects_wrong_counter_length() {
        let ctr = ctr(&[0; 16]);
        let source = [0u8; 32];
        for n in [0, 1, 15, 17, 32] {
            assert_eq!(
                ctr.encrypt(&source[..n], &mut [0; 4]).unwrap_err(),
                Error::InvalidNonceLength(n)
            );
        }
    }
}
