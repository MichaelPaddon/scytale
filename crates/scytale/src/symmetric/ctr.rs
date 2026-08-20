//! Counter (CTR) mode, as specified in NIST SP 800-38A.
//!
//! CTR turns a block cipher into a stream cipher: successive counter
//! values are encrypted to produce a keystream, which is XORed with the
//! data. Encryption and decryption are therefore the same operation, and
//! only an encryption key schedule is ever needed.
//!
//! # The counter
//!
//! The counter is the whole block read as a single big-endian integer,
//! incremented by one per block, wrapping at `2^(8 * BLOCK_SIZE)`. It
//! carries the full width of the block rather than a fixed low field,
//! which is the standard's counter and what the ACVP vectors expect.
//! Modes that count in a narrower field, such as the 32-bit counter GCM
//! uses, are a different construction and not what this is.
//!
//! [`Ctr`] wraps any [`BlockEncrypt`] implementation and takes its width
//! from whatever it wraps, so the counter is 128 bits over AES and 64
//! over a cipher with an eight byte block. Nothing here assumes AES. It
//! generates the keystream through the cipher's bulk interface a full
//! parallel width at a time, so a pipelined or vectorized cipher runs at
//! full speed even though the mode itself is generic.
//!
//! # Nonce reuse
//!
//! A (key, counter) pair must never be used for two different messages.
//! Reusing one XORs the two plaintexts together for anyone who can see
//! both ciphertexts. Choosing unique initial counter values is the
//! caller's responsibility; the mode cannot detect reuse.

use zeroize::Zeroize;

use crate::symmetric::block_cipher::{BlockEncrypt, InvalidKeyLength};

use core::fmt;

/// An IV was rejected because its length is not the block size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidIvLength {
    /// The length that was supplied, in bytes.
    pub got: usize,
}

impl fmt::Display for InvalidIvLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IV length: {} bytes", self.got)
    }
}

impl core::error::Error for InvalidIvLength {}

/// Why a CTR construction was rejected.
///
/// Constructors that take both a key and an IV can fail on either; this
/// says which one was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrInitError {
    /// The key length is not one the cipher accepts.
    Key(InvalidKeyLength),
    /// The IV length is not the cipher's block size.
    Iv(InvalidIvLength),
}

impl fmt::Display for CtrInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(e) => e.fmt(f),
            Self::Iv(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for CtrInitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Key(e) => Some(e),
            Self::Iv(e) => Some(e),
        }
    }
}

impl From<InvalidKeyLength> for CtrInitError {
    fn from(e: InvalidKeyLength) -> Self {
        Self::Key(e)
    }
}

impl From<InvalidIvLength> for CtrInitError {
    fn from(e: InvalidIvLength) -> Self {
        Self::Iv(e)
    }
}

/// Advance a big-endian counter by one, wrapping at its full width.
///
/// The early exit leaks how far the carry propagated, but the counter is
/// not secret: CTR's security does not rest on hiding it.
fn increment(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            return;
        }
    }
}

/// XOR `keystream` into `data`. The lengths must match.
fn xor_into(data: &mut [u8], keystream: &[u8]) {
    for (d, k) in data.iter_mut().zip(keystream) {
        *d ^= *k;
    }
}

/// CTR mode over any block cipher.
///
/// The counter is one block wide, big endian, and wraps at the width of
/// the cipher being wrapped rather than at any fixed size.
///
/// The stream is resumable: [`Self::apply_keystream`] accepts arbitrary
/// lengths, and feeding a message in pieces produces the same bytes as
/// feeding it whole. A partial trailing block's unused keystream is kept
/// for the next call.
pub struct Ctr<C: BlockEncrypt> {
    cipher: C,
    /// The next block's counter value, big endian, one block wide.
    counter: Vec<u8>,
    /// Keystream staging, sized to the cipher's full parallel width so
    /// the bulk call underneath can keep every lane busy.
    scratch: Vec<u8>,
    /// The most recent keystream block; `used` bytes of it are consumed.
    /// `used == BLOCK_SIZE` means nothing is buffered.
    keystream: Vec<u8>,
    used: usize,
}

impl<C: BlockEncrypt> Ctr<C> {
    /// Wrap `cipher`, starting the counter at `iv`.
    ///
    /// `iv` is the initial counter value and must be exactly one block
    /// of `cipher`, which is 16 bytes for AES. It is read as a
    /// big-endian integer and counts up from there.
    ///
    /// The buffers live on the heap because the cipher's block size and
    /// width are trait constants, which stable Rust does not accept as
    /// array lengths in generic code; the allocation happens once, off
    /// the hot path.
    pub fn try_new(cipher: C, iv: &[u8]) -> Result<Self, InvalidIvLength> {
        if iv.len() != C::BLOCK_SIZE {
            return Err(InvalidIvLength { got: iv.len() });
        }
        // A width of zero would make no forward progress below, so a
        // misreporting cipher is clamped rather than looped on forever.
        let width = C::PARALLEL_BLOCKS.max(1);
        Ok(Self {
            cipher,
            counter: iv.to_vec(),
            scratch: vec![0u8; width * C::BLOCK_SIZE],
            keystream: vec![0u8; C::BLOCK_SIZE],
            used: C::BLOCK_SIZE,
        })
    }

    /// XOR the keystream into `data`, advancing the stream.
    ///
    /// Encrypting and decrypting are the same operation. Any length is
    /// accepted, and successive calls continue where the last left off.
    pub fn apply_keystream(&mut self, mut data: &mut [u8]) {
        let block = C::BLOCK_SIZE;

        // Drain keystream buffered by a previous partial block first.
        if self.used < block {
            let take = (block - self.used).min(data.len());
            xor_into(
                &mut data[..take],
                &self.keystream[self.used..self.used + take],
            );
            self.used += take;
            data = &mut core::mem::take(&mut data)[take..];
        }

        // Whole blocks, a scratch buffer's worth at a time: write the
        // counter values out, encrypt them in place through the bulk
        // call, and XOR the result in.
        while data.len() >= block {
            let want = data.len() / block * block;
            let n = want.min(self.scratch.len());
            for chunk in self.scratch[..n].chunks_exact_mut(block) {
                chunk.copy_from_slice(&self.counter);
                increment(&mut self.counter);
            }
            let consumed = self.cipher.encrypt(&mut self.scratch[..n]);
            // On any shortfall the scratch tail would still hold raw
            // counter values, and XORing those in would emit plaintext.
            assert_eq!(consumed, n, "cipher did not consume whole blocks");
            xor_into(&mut data[..n], &self.scratch[..n]);
            data = &mut core::mem::take(&mut data)[n..];
        }

        // A trailing partial block takes what it needs from one fresh
        // keystream block and leaves the rest buffered.
        if !data.is_empty() {
            self.keystream.copy_from_slice(&self.counter);
            increment(&mut self.counter);
            let consumed = self.cipher.encrypt(&mut self.keystream);
            assert_eq!(consumed, block, "cipher did not consume a block");
            let take = data.len();
            xor_into(data, &self.keystream[..take]);
            self.used = take;
        }
    }
}

impl<C: BlockEncrypt> Drop for Ctr<C> {
    fn drop(&mut self) {
        // The scratch and keystream buffers hold keystream, which is as
        // sensitive as the key while the counter position is knowable.
        // The cipher wipes its own schedule.
        self.counter.zeroize();
        self.scratch.zeroize();
        self.keystream.zeroize();
    }
}

impl<C: BlockEncrypt> fmt::Debug for Ctr<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never format the counter or buffered keystream.
        f.write_str("Ctr { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::arch::portable::ttable::Aes128Enc;

    /// A stand-in block cipher whose block is not AES's, to hold the
    /// mode to its promise of following whatever it wraps.
    ///
    /// It is not a cipher and claims no security. The mode's job is to
    /// count, chunk and combine at the width of the thing underneath
    /// it, and that is all this is here to exercise. The width is odd
    /// on purpose: three blocks in flight divides neither the counter
    /// sequence nor any message length used below.
    struct Stand {
        key: [u8; STAND_BLOCK],
    }

    const STAND_BLOCK: usize = 8;

    impl Stand {
        /// The permutation applied to one block, spelled out so a test
        /// can predict the keystream without going through the mode.
        fn block(
            mut b: [u8; STAND_BLOCK],
            key: &[u8; STAND_BLOCK],
        ) -> [u8; STAND_BLOCK] {
            for (x, k) in b.iter_mut().zip(key) {
                *x ^= *k;
            }
            b.rotate_left(1);
            b
        }
    }

    impl BlockEncrypt for Stand {
        const BLOCK_SIZE: usize = STAND_BLOCK;
        const PARALLEL_BLOCKS: usize = 3;

        fn encrypt(&self, data: &mut [u8]) -> usize {
            let (blocks, _tail) = data.as_chunks_mut::<STAND_BLOCK>();
            for b in blocks.iter_mut() {
                *b = Stand::block(*b, &self.key);
            }
            blocks.len() * STAND_BLOCK
        }
    }

    fn stand() -> Stand {
        Stand { key: [0x5a, 0x17, 0x03, 0xc4, 0x9e, 0x2b, 0x88, 0x61] }
    }

    /// The IV is a block of whatever is wrapped, not sixteen bytes.
    #[test]
    fn iv_must_match_the_wrapped_block_size() {
        assert!(Ctr::try_new(stand(), &[0u8; STAND_BLOCK]).is_ok());
        assert_eq!(
            Ctr::try_new(stand(), &[0u8; 16]).unwrap_err(),
            InvalidIvLength { got: 16 },
            "an AES sized IV is wrong for an eight byte block"
        );
    }

    /// The keystream must be the wrapped cipher applied to successive
    /// counters of the wrapped width, across a partial trailing block.
    #[test]
    fn keystream_follows_the_wrapped_block_size() {
        let iv = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        let mut stream = [0u8; STAND_BLOCK * 3 + 5];
        Ctr::try_new(stand(), &iv)
            .expect("block-size IV")
            .apply_keystream(&mut stream);

        let key = stand().key;
        let mut counter = u64::from_be_bytes(iv);
        let mut expected = Vec::new();
        while expected.len() < stream.len() {
            expected.extend_from_slice(&Stand::block(
                counter.to_be_bytes(),
                &key,
            ));
            counter = counter.wrapping_add(1);
        }
        assert_eq!(stream[..], expected[..stream.len()]);
    }

    /// The counter wraps at the wrapped width, not at 2^128.
    #[test]
    fn counter_wraps_at_the_wrapped_block_width() {
        let iv = [0xffu8; STAND_BLOCK];

        let mut stream = [0u8; STAND_BLOCK * 2];
        Ctr::try_new(stand(), &iv)
            .expect("block-size IV")
            .apply_keystream(&mut stream);

        let key = stand().key;
        assert_eq!(stream[..STAND_BLOCK], Stand::block(iv, &key));
        assert_eq!(
            stream[STAND_BLOCK..],
            Stand::block([0u8; STAND_BLOCK], &key),
            "the block after ff..ff is the cipher applied to zero"
        );
    }

    /// Chunking must not care about the wrapped width either, including
    /// chunks that straddle the three block staging buffer.
    #[test]
    fn chunked_equals_one_shot_at_another_block_size() {
        let iv = [0x9au8; STAND_BLOCK];
        let message: Vec<u8> = (0..101u32).map(|i| i as u8).collect();

        let mut whole = message.clone();
        Ctr::try_new(stand(), &iv)
            .expect("block-size IV")
            .apply_keystream(&mut whole);

        for size in [1, 3, 7, 8, 9, 24, 25] {
            let mut pieces = message.clone();
            let mut ctr =
                Ctr::try_new(stand(), &iv).expect("block-size IV");
            for chunk in pieces.chunks_mut(size) {
                ctr.apply_keystream(chunk);
            }
            assert_eq!(pieces, whole, "chunk size {size}");
        }
    }

    #[test]
    fn increment_carries() {
        let mut c = [0u8; 4];
        increment(&mut c);
        assert_eq!(c, [0, 0, 0, 1]);

        let mut c = [0, 0, 0, 0xff];
        increment(&mut c);
        assert_eq!(c, [0, 0, 1, 0]);

        let mut c = [0, 0xff, 0xff, 0xff];
        increment(&mut c);
        assert_eq!(c, [1, 0, 0, 0]);

        let mut c = [0xffu8; 4];
        increment(&mut c);
        assert_eq!(c, [0, 0, 0, 0], "wraps at full width");
    }

    #[test]
    fn iv_must_be_one_block() {
        let short = Ctr::try_new(Aes128Enc::new(&[0u8; 16]), &[0u8; 15]);
        assert_eq!(short.unwrap_err(), InvalidIvLength { got: 15 });
        let long = Ctr::try_new(Aes128Enc::new(&[0u8; 16]), &[0u8; 17]);
        assert_eq!(long.unwrap_err(), InvalidIvLength { got: 17 });
        assert!(Ctr::try_new(Aes128Enc::new(&[0u8; 16]), &[0u8; 16]).is_ok());
    }

    /// The keystream must be E(iv), E(iv + 1), ... per SP 800-38A.
    #[test]
    fn keystream_is_the_encrypted_counter_sequence() {
        let key = [0x2bu8; 16];
        let iv = [0x01u8; 16];

        let mut ctr = Ctr::try_new(Aes128Enc::new(&key), &iv)
            .expect("block-size IV");
        let mut stream = [0u8; 48];
        ctr.apply_keystream(&mut stream);

        let aes = Aes128Enc::new(&key);
        let mut counter = u128::from_be_bytes(iv);
        for block in stream.as_chunks::<16>().0 {
            let mut expected = counter.to_be_bytes();
            aes.encrypt_block(&mut expected);
            assert_eq!(*block, expected);
            counter = counter.wrapping_add(1);
        }
    }

    /// An all-ones IV exercises the wrap to zero mid-stream.
    #[test]
    fn counter_wraps_at_full_width() {
        let key = [0x5au8; 16];
        let iv = [0xffu8; 16];

        let mut ctr = Ctr::try_new(Aes128Enc::new(&key), &iv)
            .expect("block-size IV");
        let mut stream = [0u8; 32];
        ctr.apply_keystream(&mut stream);

        let aes = Aes128Enc::new(&key);
        let mut first = [0xffu8; 16];
        aes.encrypt_block(&mut first);
        let mut second = [0u8; 16];
        aes.encrypt_block(&mut second);
        assert_eq!(stream[..16], first);
        assert_eq!(stream[16..], second, "block after ff..ff is E(0)");
    }

    /// Chunked feeding must equal one-shot, whatever the chunking.
    #[test]
    fn chunked_equals_one_shot() {
        let key = [0xa5u8; 16];
        let iv = [0x10u8; 16];
        let message: Vec<u8> = (0..251u32).map(|i| i as u8).collect();

        let mut whole = message.clone();
        Ctr::try_new(Aes128Enc::new(&key), &iv)
            .expect("block-size IV")
            .apply_keystream(&mut whole);

        for size in [1, 3, 5, 16, 17, 37, 250] {
            let mut pieces = message.clone();
            let mut ctr = Ctr::try_new(Aes128Enc::new(&key), &iv)
                .expect("block-size IV");
            for chunk in pieces.chunks_mut(size) {
                ctr.apply_keystream(chunk);
            }
            assert_eq!(pieces, whole, "chunk size {size}");
        }
    }

    #[test]
    fn applying_twice_round_trips() {
        let key = [0x77u8; 16];
        let iv = [0x42u8; 16];
        let message = [0xabu8; 100];

        let mut data = message;
        Ctr::try_new(Aes128Enc::new(&key), &iv)
            .expect("block-size IV")
            .apply_keystream(&mut data);
        assert_ne!(data, message);
        Ctr::try_new(Aes128Enc::new(&key), &iv)
            .expect("block-size IV")
            .apply_keystream(&mut data);
        assert_eq!(data, message);
    }

    #[test]
    fn empty_input_is_a_no_op() {
        let mut ctr =
            Ctr::try_new(Aes128Enc::new(&[0u8; 16]), &[0u8; 16])
                .expect("block-size IV");
        ctr.apply_keystream(&mut []);
        let mut a = [0u8; 16];
        ctr.apply_keystream(&mut a);

        let mut b = [0u8; 16];
        Ctr::try_new(Aes128Enc::new(&[0u8; 16]), &[0u8; 16])
            .expect("block-size IV")
            .apply_keystream(&mut b);
        assert_eq!(a, b, "an empty call must not advance the stream");
    }

    #[test]
    fn debug_does_not_leak_state() {
        let ctr = Ctr::try_new(Aes128Enc::new(&[0xab; 16]), &[0xcd; 16])
            .expect("block-size IV");
        assert_eq!(format!("{ctr:?}"), "Ctr { .. }");
    }
}
