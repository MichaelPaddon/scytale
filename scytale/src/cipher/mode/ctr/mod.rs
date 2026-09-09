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
//!   next message must start beyond them. This is a counter, not
//!   something to draw with [`random`](crate::random): the sequence
//!   is the caller's to keep, because only the caller knows how many
//!   blocks the last message spent.
//! - Counter mode provides no authentication, and flipping a
//!   ciphertext bit flips exactly that plaintext bit. Prefer an
//!   authenticated mode; GCM is counter mode with authentication
//!   added.
//!
//! # Example
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::mode::Ctr;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let ctr = Ctr::<Aes128>::new(&Key::from([0u8; 16]));
//! let counter = [0u8; 16];
//!
//! let mut data = [0u8; 21];
//! ctr.encrypt(&counter, &mut data)?;
//! ctr.decrypt(&counter, &mut data)?;
//! assert_eq!(data, [0u8; 21]);
//! # Ok(())
//! # }
//! ```

#[cfg(target_arch = "x86_64")]
mod x86_64;

use core::fmt;

use super::xor;
use crate::cipher::{BlockCipher, ByteOrder, CounterFn, OneBlock, counter_fn};
use crate::{ByteArray, Error};

/// What does the work, settled when the mode is built, because it is
/// the processor that decides and the processor does not change.
///
/// Where this cipher runs on the AES instructions, [`x86_64::Engine`]
/// is counter mode written out for them, start to finish. Anywhere
/// else it is the construction over the cipher's own bulk encrypt,
/// which is as fast as that processor allows.
enum Engine<C: BlockCipher> {
    #[cfg(target_arch = "x86_64")]
    Native(x86_64::Engine<C>),
    Generic(CounterFn<C>),
}

/// By hand rather than derived: an engine holds no cipher, only a
/// pointer to the loop written for one, so it clones whatever `C` is.
impl<C: BlockCipher> Clone for Engine<C> {
    fn clone(&self) -> Self {
        match self {
            #[cfg(target_arch = "x86_64")]
            Engine::Native(engine) => Engine::Native(engine.clone()),
            Engine::Generic(blocks) => Engine::Generic(*blocks),
        }
    }
}

impl<C: BlockCipher> Engine<C> {
    /// The best engine for this cipher on this processor.
    fn new() -> Self {
        #[cfg(target_arch = "x86_64")]
        if let Some(native) = x86_64::Engine::new() {
            return Engine::Native(native);
        }
        Engine::Generic(counter_fn::<C>())
    }

    /// Encrypts the counter blocks made from `counter` and XORs them
    /// over `data`, which is a whole number of blocks, leaving
    /// `counter` on the block after the last.
    fn blocks(&self, cipher: &C, counter: &mut C::Block, data: &mut [u8]) {
        match self {
            #[cfg(target_arch = "x86_64")]
            Engine::Native(engine) => {
                // The engine exists only for a cipher whose block is
                // this width, so the conversion cannot fail; the
                // compiler does not carry that across the pointer it
                // was chosen through.
                match <&mut [u8; 16]>::try_from(counter.as_mut()) {
                    Ok(counter) => {
                        engine.xor_counter_blocks(cipher, counter, data)
                    }
                    Err(_) => debug_assert!(false, "block is not a block"),
                }
            }
            Engine::Generic(blocks) => {
                blocks(cipher, counter, ByteOrder::Big, data)
            }
        }
    }
}

/// Counter mode over a block cipher.
#[derive(Clone)]
pub struct Ctr<C: BlockCipher> {
    cipher: C,
    /// What does the work, settled when the mode is built.
    engine: Engine<C>,
}

impl<C: BlockCipher> Ctr<C>
where
    C::Block: ByteArray,
{
    /// Takes the key the cipher runs under.
    pub fn new(key: &C::Key) -> Self {
        Ctr {
            cipher: C::new(key),
            engine: Engine::new(),
        }
    }

    /// Encrypts `data` in place, starting from `counter`. Any length
    /// of message is allowed.
    pub fn encrypt(
        &self,
        counter: &C::Block,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.stream(counter).update(data)
    }

    /// Decrypts `data` in place, starting from `counter`.
    ///
    /// This is the same operation as [`encrypt`](Self::encrypt): the
    /// keystream does not depend on the message. Both names exist so
    /// that calling code reads the way it means.
    pub fn decrypt(
        &self,
        counter: &C::Block,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.stream(counter).update(data)
    }

    /// Starts a message that arrives in pieces.
    pub fn stream(&self, counter: &C::Block) -> Stream<'_, C> {
        Stream {
            cipher: &self.cipher,
            engine: self.engine.clone(),
            counter: *counter,
            keystream: C::zero_block(),
            used: size_of::<C::Block>(),
        }
    }
}

/// Adds one to a big-endian counter, wrapping round at the top.
///
/// A sixteen-byte counter is one 128-bit addition. The byte loop
/// below is correct for any width, but the compiler cannot see the
/// width through a slice and unrolls the carry into a branch for
/// every byte, so the common case says its size out loud.
#[inline]
pub(crate) fn increment<B: ByteArray>(counter: &mut B) {
    if let Ok(block) = <&mut [u8; 16]>::try_from(counter.as_mut()) {
        *block = u128::from_be_bytes(*block).wrapping_add(1).to_be_bytes();
        return;
    }
    for byte in counter.as_mut().iter_mut().rev() {
        let (sum, carried) = byte.overflowing_add(1);
        *byte = sum;
        if !carried {
            break;
        }
    }
}

/// The last four bytes of a block, as one big-endian number.
#[inline]
fn low32(block: &[u8]) -> u32 {
    let n = block.len();
    u32::from_be_bytes([block[n - 4], block[n - 3], block[n - 2], block[n - 1]])
}

/// Adds one to everything above the last four bytes.
///
/// The cipher's counter run wraps inside those four bytes and drops
/// the carry, because that is what GCM wants; counting in the whole
/// block, this puts it back.
#[inline]
fn carry_out_of_low32<B: ByteArray>(counter: &mut B) {
    let bytes = counter.as_mut();
    let high = bytes.len() - 4;
    for byte in bytes[..high].iter_mut().rev() {
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
pub struct Stream<'a, C: BlockCipher> {
    cipher: &'a C,
    /// What does the work, chosen when the mode was built.
    engine: Engine<C>,
    counter: C::Block,
    /// The keystream block a previous piece ended inside.
    keystream: C::Block,
    /// Bytes of that block already used. Starts full, so the first
    /// byte generates a block.
    used: usize,
}

impl<C: BlockCipher> Stream<'_, C>
where
    C::Block: ByteArray,
{
    /// Applies the keystream to the next piece of the message.
    pub fn update(&mut self, mut data: &mut [u8]) -> Result<(), Error> {
        let size = size_of::<C::Block>();

        // Finish the block a previous piece stopped inside.
        if self.used < size {
            let take = data.len().min(size - self.used);
            let (now, rest) = data.split_at_mut(take);
            xor(now, &self.keystream.as_ref()[self.used..self.used + take]);
            self.used += take;
            data = rest;
        }

        // Whole blocks, handed to the cipher in one run so that it
        // can keep the counters in registers. It counts in the last
        // four bytes only, so a run stops where they would carry
        // into the rest of the block; that is once every 2^32
        // blocks, or 64 gigabytes.
        let (whole, tail) = <C::Block as ByteArray>::split_mut(data);
        let mut done = 0;
        while done < whole.len() {
            let room = (u32::MAX - low32(self.counter.as_ref())) as usize + 1;
            let take = (whole.len() - done).min(room);
            let run = &mut whole[done..done + take];
            self.engine.blocks(
                self.cipher,
                &mut self.counter,
                <C::Block as ByteArray>::flatten_mut(run),
            );
            if take == room {
                carry_out_of_low32(&mut self.counter);
            }
            done += take;
        }

        // A final piece of a block, whose remainder is kept.
        if !tail.is_empty() {
            self.keystream = self.counter;
            increment(&mut self.counter);
            self.cipher.encrypt_one(&mut self.keystream);
            xor(tail, self.keystream.as_ref());
            self.used = tail.len();
        }
        Ok(())
    }
}

// Debug output omits the state: it is all derived from the key.
impl<C: BlockCipher> fmt::Debug for Ctr<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ctr").finish_non_exhaustive()
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
    use crate::Key;
    use crate::cipher::aes::Aes;

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

    fn ctr<const K: usize>(key: &[u8; K]) -> Ctr<Aes<K>> {
        Ctr::new(&Key::from(*key))
    }

    /// Every length across the bulk group, the tail widths under it
    /// and the odd block at the end.
    ///
    /// Round-tripping would not catch a wrong keystream, since the
    /// same wrong keystream undoes itself, so this checks against one
    /// built a block at a time.
    #[test]
    fn keystream_matches_a_block_at_a_time() {
        // Two bulk groups, an odd number of pairs, and a part block.
        const N: usize = 2 * 16 * 16 + 5 * 16 + 7;
        let key = [0x5au8; 16];
        let start = [0x77u8; 16];
        let aes = Aes::<16>::new(&key);

        let mut want = [0u8; N];
        let mut counter = start;
        for chunk in want.chunks_mut(16) {
            let mut block = counter;
            aes.encrypt_one(&mut block);
            chunk.copy_from_slice(&block[..chunk.len()]);
            increment(&mut counter);
        }

        for n in 0..=N {
            let mut got = [0u8; N];
            ctr(&key).encrypt(&start, &mut got[..n]).unwrap();
            assert_eq!(got[..n], want[..n], "{n} bytes");
        }
    }

    /// The cipher counts in the last four bytes and drops the carry
    /// there, so a run crossing that boundary is split in two and the
    /// The loops add to the last byte of the block without carrying
    /// out of it, so a message long enough for that byte to overflow
    /// must be cut where it would, and the carry done in full.
    ///
    /// Every starting byte is tried, since where the cut falls
    /// depends on it, and the message is long enough to pass the
    /// boundary more than once.
    #[test]
    fn crosses_the_low_byte_boundary() {
        // Three times round the 256 blocks that byte counts.
        const N: usize = 3 * 256 * 16 + 32;
        let key = [0x11u8; 16];
        let aes = Aes::<16>::new(&key);

        for last in [0u8, 1, 15, 16, 127, 239, 240, 241, 254, 255] {
            let mut start = [0x42u8; 16];
            start[15] = last;

            let mut want = [0u8; N];
            let mut counter = start;
            for chunk in want.chunks_mut(16) {
                let mut block = counter;
                aes.encrypt_one(&mut block);
                chunk.copy_from_slice(&block[..chunk.len()]);
                increment(&mut counter);
            }

            let mut got = [0u8; N];
            ctr(&key).encrypt(&start, &mut got).unwrap();
            assert_eq!(got, want, "counter ending {last}");

            // And in pieces, so a run starts at every offset within
            // the byte as well as at the boundary itself.
            for piece in [16, 4080, 4096, 4112] {
                let mut got = [0u8; N];
                let mode = ctr(&key);
                let mut stream = mode.stream(&start);
                for part in got.chunks_mut(piece) {
                    stream.update(part).unwrap();
                }
                assert_eq!(
                    got, want,
                    "counter ending {last}, {piece} at a time"
                );
            }
        }
    }

    /// carry put back by hand. Starting two blocks short of the wrap
    /// exercises both sides of the split, and the run after it is
    /// long enough to reach the bulk path and leave a tail.
    #[test]
    fn crosses_the_four_byte_counter_boundary() {
        const N: usize = 40;
        let key = [0x2bu8; 16];
        let mut start = [0xa5u8; 16];
        start[12..].copy_from_slice(&0xffff_fffeu32.to_be_bytes());

        // The keystream as counter mode defines it: a block at a
        // time, counting in the whole block.
        let aes = Aes::<16>::new(&key);
        let mut want = [0u8; N * 16];
        let mut counter = start;
        for chunk in want.chunks_mut(16) {
            let mut block = counter;
            aes.encrypt_one(&mut block);
            chunk.copy_from_slice(&block);
            increment(&mut counter);
        }

        let mut got = [0u8; N * 16];
        ctr(&key).encrypt(&start, &mut got).unwrap();
        assert_eq!(got, want);
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
            let mut s = ctr.stream(&counter);
            let (a, b) = pieces.split_at_mut(split);
            s.update(a).unwrap();
            s.update(b).unwrap();
            assert_eq!(pieces, whole, "split at {split}");
        }

        // One byte at a time crosses every block boundary.
        let mut pieces = plain;
        let mut s = ctr.stream(&counter);
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
        let mode = ctr(&[0x5a; 16]);
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
