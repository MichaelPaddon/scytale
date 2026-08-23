//! XTS-AES (IEEE 1619, NIST SP 800-38E), the mode used for storage.
//!
//! A disk has no room for a nonce or a tag: a sector holds exactly as
//! much ciphertext as it held plaintext, and the same sector is
//! written over and over. XTS is built for that. Each data unit is
//! encrypted under a tweak, normally the sector number, so identical
//! sectors elsewhere on the disk look different, and each block
//! within the unit gets its own derived tweak.
//!
//! # What it does not do
//!
//! - **No authentication.** Nothing detects a modified sector. An
//!   attacker who can write to the disk can flip bits, and the change
//!   is confined to one block, which is often exactly what they want.
//!   XTS protects a disk against being read, not against being
//!   altered.
//! - **No freshness.** Writing the same plaintext to the same sector
//!   twice gives the same ciphertext twice, so an observer watching
//!   the disk over time learns which sectors changed and when they
//!   returned to an earlier value.
//!
//! Use it for storage at rest, where those limits are understood, and
//! an authenticated mode everywhere else.
//!
//! # Shape of the data
//!
//! A data unit is whole bytes, at least one block of them, and is
//! encrypted in one call: the last two blocks are entwined by
//! ciphertext stealing, so there is nothing useful to stream.
//!
//! The key is the two keys joined: the first half encrypts the data,
//! the second the tweak. They must differ. A tweak is one block; for
//! a sector number, write it as a little-endian integer.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Xts;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // Two 128-bit keys, joined.
//! let mut key = [0u8; 32];
//! key[16..].copy_from_slice(&[1u8; 16]);
//! let xts: Xts<Aes> = Xts::try_new(&key)?;
//!
//! // Sector 7, as a little-endian integer.
//! let mut tweak = [0u8; 16];
//! tweak[..8].copy_from_slice(&7u64.to_le_bytes());
//!
//! let mut sector = [0u8; 512];
//! xts.encrypt(&tweak, &mut sector)?;
//! xts.decrypt(&tweak, &mut sector)?;
//! assert_eq!(sector, [0u8; 512]);
//! # Ok(())
//! # }
//! ```

use super::ghash::BLOCK;
use super::{xor, LANES};
use crate::symmetric::BlockCipher;
use crate::util;
use crate::Error;

/// XTS over a block cipher.
#[derive(Clone, Debug)]
pub struct Xts<C> {
    data: C,
    tweak: C,
}

impl<C: BlockCipher> Xts<C> {
    /// Takes the two keys joined together, the first half for the
    /// data and the second for the tweak.
    ///
    /// The halves must differ: XTS with one key repeated is a weaker
    /// construction, and the standard forbids it.
    ///
    /// # Panics
    /// If the cipher's block is not 128 bits.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        assert_eq!(
            C::BLOCK_SIZE,
            BLOCK,
            "XTS is defined only for a 128-bit block cipher"
        );
        if !key.len().is_multiple_of(2) {
            return Err(Error::InvalidKeyLength(key.len()));
        }
        let (data, tweak) = key.split_at(key.len() / 2);
        if util::equal(data, tweak) {
            return Err(Error::InvalidKeyLength(key.len()));
        }
        Ok(Xts {
            data: C::try_new(data)?,
            tweak: C::try_new(tweak)?,
        })
    }

    /// Encrypts one data unit in place under `tweak`.
    ///
    /// `tweak` is one block and `data` at least one block, of any
    /// length from there.
    pub fn encrypt(&self, tweak: &[u8], data: &mut [u8]) -> Result<(), Error> {
        let mut t = self.start(tweak, data.len())?;
        let (whole, stolen) = self.split(data);
        self.bulk(whole, &mut t, true)?;
        if let Some((last, short)) = stolen {
            // The last whole block is encrypted first, then its head
            // becomes the short ciphertext and its tail completes the
            // short plaintext into a block, which is encrypted in the
            // last block's place.
            xor(last, &t);
            self.data.encrypt_block(last)?;
            xor(last, &t);
            multiply_by_alpha(&mut t);

            let mut carried = [0u8; BLOCK];
            let n = short.len();
            carried[..n].copy_from_slice(short);
            carried[n..].copy_from_slice(&last[n..]);
            short.copy_from_slice(&last[..n]);

            xor(&mut carried, &t);
            self.data.encrypt_block(&mut carried)?;
            xor(&mut carried, &t);
            last.copy_from_slice(&carried);
        }
        Ok(())
    }

    /// Decrypts one data unit in place under `tweak`.
    pub fn decrypt(&self, tweak: &[u8], data: &mut [u8]) -> Result<(), Error> {
        let mut t = self.start(tweak, data.len())?;
        let (whole, stolen) = self.split(data);
        self.bulk(whole, &mut t, false)?;
        if let Some((last, short)) = stolen {
            // The mirror of encryption: the last whole block is
            // decrypted under the *later* tweak, because that is the
            // one it was encrypted with.
            let mut later = t;
            multiply_by_alpha(&mut later);

            xor(last, &later);
            self.data.decrypt_block(last)?;
            xor(last, &later);

            let mut carried = [0u8; BLOCK];
            let n = short.len();
            carried[..n].copy_from_slice(short);
            carried[n..].copy_from_slice(&last[n..]);
            short.copy_from_slice(&last[..n]);

            xor(&mut carried, &t);
            self.data.decrypt_block(&mut carried)?;
            xor(&mut carried, &t);
            last.copy_from_slice(&carried);
        }
        Ok(())
    }

    /// The first tweak: the tweak value encrypted under the second
    /// key. Also checks the lengths.
    fn start(&self, tweak: &[u8], len: usize) -> Result<[u8; BLOCK], Error> {
        if tweak.len() != BLOCK {
            return Err(Error::InvalidNonceLength(tweak.len()));
        }
        if len < BLOCK {
            return Err(Error::InvalidLength(len));
        }
        let mut start = [0u8; BLOCK];
        start.copy_from_slice(tweak);
        self.tweak.encrypt_block(&mut start)?;
        Ok(start)
    }

    /// Splits a data unit into the blocks handled normally and, if
    /// the unit does not divide evenly, the last whole block and the
    /// short one that steals from it.
    #[allow(clippy::type_complexity)]
    fn split<'d>(
        &self,
        data: &'d mut [u8],
    ) -> (&'d mut [u8], Option<(&'d mut [u8], &'d mut [u8])>) {
        let short = data.len() % BLOCK;
        if short == 0 {
            return (data, None);
        }
        let boundary = data.len() - short - BLOCK;
        let (whole, rest) = data.split_at_mut(boundary);
        let (last, short) = rest.split_at_mut(BLOCK);
        (whole, Some((last, short)))
    }

    /// Runs the blocks that need no stealing, in groups, advancing
    /// the tweak as it goes.
    fn bulk(
        &self,
        data: &mut [u8],
        t: &mut [u8; BLOCK],
        encrypt: bool,
    ) -> Result<(), Error> {
        let mut tweaks = [0u8; LANES * BLOCK];
        for group in data.chunks_mut(LANES * BLOCK) {
            let n = group.len();
            for tweak in tweaks[..n].chunks_exact_mut(BLOCK) {
                tweak.copy_from_slice(t);
                multiply_by_alpha(t);
            }
            xor(group, &tweaks[..n]);
            if encrypt {
                self.data.encrypt_blocks(group)?;
            } else {
                self.data.decrypt_blocks(group)?;
            }
            xor(group, &tweaks[..n]);
        }
        Ok(())
    }
}

/// Advances the tweak: multiplication by the field element the
/// standard calls alpha, which here is a shift with one feedback
/// term. Done without a branch, since the tweaks after the first
/// depend on the key.
fn multiply_by_alpha(tweak: &mut [u8; BLOCK]) {
    let mut carry = 0u8;
    for byte in tweak.iter_mut() {
        let next = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
    tweak[0] ^= 0x87 & 0u8.wrapping_sub(carry);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::Aes;

    const MAX: usize = 80;

    fn unhex<'a>(text: &str, buffer: &'a mut [u8]) -> &'a [u8] {
        let n = text.len() / 2;
        for i in 0..n {
            buffer[i] =
                u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        &buffer[..n]
    }

    fn xts() -> Xts<Aes> {
        let mut key = [0u8; 32];
        let mut buffer = [0u8; 32];
        key.copy_from_slice(unhex(
            "271828182845904523536028747135266249775724709369995957496696\
             7627",
            &mut buffer,
        ));
        Xts::try_new(&key).unwrap()
    }

    /// A whole number of blocks: no stealing involved.
    #[test]
    fn whole_blocks() {
        let (mut tb, mut pb, mut cb) = ([0u8; 16], [0u8; MAX], [0u8; MAX]);
        let tweak = unhex("ff000000000000000000000000000000", &mut tb);
        let plain = unhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e\
             1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d\
             3e3f",
            &mut pb,
        );
        let cipher = unhex(
            "da5738a3e120351ce754721fabd9bb2d4b2492f72a2932c53b33afcfa135ae\
             f65f15e627b19be0530ea12a5fad7e25efa88f68455426886a3eed2a313d96\
             bfe6",
            &mut cb,
        );

        let xts = xts();
        let mut data = [0u8; MAX];
        let data = &mut data[..plain.len()];
        data.copy_from_slice(plain);
        xts.encrypt(tweak, data).unwrap();
        assert_eq!(data, cipher, "encrypt");
        xts.decrypt(tweak, data).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    /// A length that is not a whole number of blocks, so the last two
    /// blocks steal from each other.
    #[test]
    fn ciphertext_stealing() {
        let (mut tb, mut pb, mut cb) = ([0u8; 16], [0u8; MAX], [0u8; MAX]);
        let tweak = unhex("ff000000000000000000000000000000", &mut tb);
        let plain = unhex("000102030405060708090a0b0c0d0e0f10111213", &mut pb);
        let cipher = unhex("d561cea5180aebe696267bf5894868ebda5738a3", &mut cb);

        let xts = xts();
        let mut data = [0u8; MAX];
        let data = &mut data[..plain.len()];
        data.copy_from_slice(plain);
        xts.encrypt(tweak, data).unwrap();
        assert_eq!(data, cipher, "encrypt");
        xts.decrypt(tweak, data).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    #[test]
    fn round_trips_at_many_lengths() {
        let xts = xts();
        let tweak = [3u8; 16];
        let mut plain = [0u8; MAX];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        // A block, partial blocks either side of the group boundary,
        // and whole groups.
        for n in [16, 17, 31, 32, 33, 63, 64, 65, 79, MAX] {
            let mut data = [0u8; MAX];
            data[..n].copy_from_slice(&plain[..n]);
            xts.encrypt(&tweak, &mut data[..n]).unwrap();
            assert_ne!(data[..n], plain[..n], "{n} bytes");
            xts.decrypt(&tweak, &mut data[..n]).unwrap();
            assert_eq!(data[..n], plain[..n], "{n} bytes");
        }
    }

    /// The tweak is what makes one sector's ciphertext differ from
    /// another's holding the same bytes.
    #[test]
    fn the_tweak_separates_sectors() {
        let xts = xts();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&7u64.to_le_bytes());
        xts.encrypt(&tweak, &mut first).unwrap();
        tweak[..8].copy_from_slice(&8u64.to_le_bytes());
        xts.encrypt(&tweak, &mut second).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn rejects_bad_lengths() {
        // The halves must differ.
        assert_eq!(
            Xts::<Aes>::try_new(&[0x11; 32]).unwrap_err(),
            Error::InvalidKeyLength(32)
        );
        // And the key must split evenly into two the cipher accepts.
        for n in [0, 15, 17, 31, 33] {
            let source = [0u8; 64];
            assert!(Xts::<Aes>::try_new(&source[..n]).is_err(), "{n} bytes");
        }

        let xts = xts();
        let source = [0u8; 32];
        for n in [0, 8, 15, 17, 32] {
            assert_eq!(
                xts.encrypt(&source[..n], &mut [0; 16]).unwrap_err(),
                Error::InvalidNonceLength(n)
            );
        }
        // A data unit must be at least one block.
        for n in [0, 1, 15] {
            let mut data = [0u8; 15];
            assert_eq!(
                xts.encrypt(&[0; 16], &mut data[..n]).unwrap_err(),
                Error::InvalidLength(n)
            );
        }
    }
}
