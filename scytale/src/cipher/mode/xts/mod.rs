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
//! # Bit lengths
//!
//! The standard defines a data unit in bits, and the length only
//! matters where the last two blocks steal from each other, so
//! [`encrypt_bits`](Xts::encrypt_bits) and
//! [`decrypt_bits`](Xts::decrypt_bits) take a unit that is not a
//! whole number of bytes while the byte methods run as before.
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::mode::Xts;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // Two 128-bit keys: one for the data, one for the tweak.
//! let data = Key::from([0u8; 16]);
//! let tweak_key = Key::from([1u8; 16]);
//! let xts: Xts<Aes128> = Xts::try_new(&data, &tweak_key)?;
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

use core::fmt;

use crate::cipher::BLOCK;
#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

// The loops written out for this processor, whichever it is. Each
// architecture's module offers the same entry points, so the code
// below needs no conditionals beyond whether there is one at all.
#[cfg(target_arch = "aarch64")]
use self::aarch64 as native;
#[cfg(target_arch = "x86_64")]
use self::x86_64 as native;

use super::{LANES, xor};
use crate::Error;
use crate::cipher::{BlockCipher, OneBlock};
use crate::util;

/// XTS over a block cipher.
///
/// Takes two keys, one for the data and one for the tweak, expanded
/// separately.
#[derive(Clone)]
pub struct Xts<C: BlockCipher<Block = [u8; BLOCK]>> {
    data: C,
    tweak: C,
    /// What does the bulk work, settled when the mode is built. Read
    /// only where there is a loop written out to reach.
    #[cfg_attr(
        not(any(target_arch = "aarch64", target_arch = "x86_64")),
        allow(dead_code)
    )]
    engine: Engine<C>,
}

/// Which implementation to use.
///
/// A caller never names one: the mode takes the best the processor
/// has. The tests and the vector suites do name them, so that every
/// implementation is validated and not only the one this machine
/// would pick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Choice {
    /// XTS written out, two blocks to a register.
    Wide,
    /// The same, one block to a register.
    Narrow,
    /// The construction over the cipher's own bulk calls.
    Generic,
}

/// Every implementation, best first.
pub(crate) const CHOICES: [Choice; 3] =
    [Choice::Wide, Choice::Narrow, Choice::Generic];

/// What does the bulk work, settled when the mode is built.
enum Engine<C: BlockCipher<Block = [u8; BLOCK]>> {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    Native(native::Engine<C>),
    /// What the other arm is written for. On an architecture with no
    /// such arm nothing here names `C`, and the parameter would
    /// otherwise go unused.
    Generic(core::marker::PhantomData<C>),
}

/// By hand rather than derived: an engine holds no cipher, only a
/// pointer to the loop written for one, so it clones whatever `C` is.
impl<C: BlockCipher<Block = [u8; BLOCK]>> Clone for Engine<C> {
    fn clone(&self) -> Self {
        match self {
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            Engine::Native(engine) => Engine::Native(engine.clone()),
            Engine::Generic(_) => Engine::Generic(core::marker::PhantomData),
        }
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Engine<C> {
    /// The best engine for this cipher on this processor.
    fn new() -> Self {
        for choice in CHOICES {
            if let Some(engine) = Self::with(choice) {
                return engine;
            }
        }
        Engine::Generic(core::marker::PhantomData)
    }

    /// The engine `choice` names, or `None` where this processor or
    /// this cipher has no such thing.
    fn with(choice: Choice) -> Option<Self> {
        match choice {
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            Choice::Wide => native::Engine::at_width(true).map(Engine::Native),
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            Choice::Narrow => {
                native::Engine::at_width(false).map(Engine::Native)
            }
            Choice::Generic => Some(Engine::Generic(core::marker::PhantomData)),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> fmt::Debug for Xts<C> {
    /// Deliberately omits the ciphers, which hold the keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Xts").finish_non_exhaustive()
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Xts<C> {
    /// Takes the two keys: one for the data and one for the tweak.
    ///
    /// They must differ: XTS with one key repeated is a weaker
    /// construction, and the standard forbids it. That is reported
    /// as [`Error::InvalidKeyLength`] with the length of the pair.
    pub fn try_new(data: &C::Key, tweak: &C::Key) -> Result<Self, Error> {
        if util::equal(data.as_ref(), tweak.as_ref()) {
            return Err(Error::InvalidKeyLength(2 * data.as_ref().len()));
        }
        Ok(Xts {
            data: C::new(data),
            tweak: C::new(tweak),
            engine: Engine::new(),
        })
    }

    /// The mode over the implementation `choice` names, or `None`
    /// where this processor or this cipher has no such thing.
    ///
    /// For the tests and the vector suites, which run every
    /// implementation rather than only the one [`try_new`](Self::try_new)
    /// would take.
    #[cfg(test)]
    pub(crate) fn with_choice(
        data: &C::Key,
        tweak: &C::Key,
        choice: Choice,
    ) -> Option<Self> {
        Some(Xts {
            data: C::new(data),
            tweak: C::new(tweak),
            engine: Engine::with(choice)?,
        })
    }

    /// Encrypts one data unit in place under `tweak`.
    ///
    /// `data` is at least one block, of any length from there.
    pub fn encrypt(
        &self,
        tweak: &C::Block,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.run(tweak, data, data.len() * 8, true)
    }

    /// Decrypts one data unit in place under `tweak`.
    pub fn decrypt(
        &self,
        tweak: &C::Block,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.run(tweak, data, data.len() * 8, false)
    }

    /// Encrypts a data unit of `bits` bits in place under `tweak`.
    ///
    /// `data` holds the unit in `bits.div_ceil(8)` bytes, the last
    /// byte's bits at its top; its low bits are ignored on input and
    /// zero on output. Returns [`Error::InvalidLength`] if the unit
    /// is shorter than one block or `data` is not that many bytes.
    pub fn encrypt_bits(
        &self,
        tweak: &C::Block,
        data: &mut [u8],
        bits: usize,
    ) -> Result<(), Error> {
        Self::check_bits(data, bits)?;
        self.run(tweak, data, bits, true)
    }

    /// Decrypts a data unit of `bits` bits in place under `tweak`;
    /// see [`encrypt_bits`](Self::encrypt_bits) for the layout.
    pub fn decrypt_bits(
        &self,
        tweak: &C::Block,
        data: &mut [u8],
        bits: usize,
    ) -> Result<(), Error> {
        Self::check_bits(data, bits)?;
        self.run(tweak, data, bits, false)
    }

    fn check_bits(data: &[u8], bits: usize) -> Result<(), Error> {
        if bits < BLOCK * 8 || data.len() != bits.div_ceil(8) {
            return Err(Error::InvalidLength(bits));
        }
        Ok(())
    }

    /// Both directions: the bulk, then the last two blocks, which
    /// steal from each other when the unit is not whole blocks.
    ///
    /// Only the steal knows the unit's length in bits, and only
    /// through the mask on the byte the partial block ends in. For a
    /// whole number of bytes that mask is all ones.
    fn run(
        &self,
        tweak: &C::Block,
        data: &mut [u8],
        bits: usize,
        encrypt: bool,
    ) -> Result<(), Error> {
        let mut t = self.start(tweak, data.len())?;
        // Bytes of the partial block, if there is one.
        let short = (bits % (BLOCK * 8)).div_ceil(8);
        let (whole, stolen) = Self::split(data, short);
        self.bulk(whole, &mut t, encrypt);
        if let Some((last, short)) = stolen {
            let mask = match bits % 8 {
                0 => 0xff,
                b => 0xffu8 << (8 - b),
            };
            self.steal(last, short, mask, &mut t, encrypt);
        }
        Ok(())
    }

    /// Ciphertext stealing over the last whole block and the short
    /// one after it. `mask` selects the bits of the short block's
    /// last byte that belong to it.
    ///
    /// Encrypting, the last whole block goes first, then its head
    /// becomes the short ciphertext and its tail completes the short
    /// plaintext into a block, which is encrypted in the last
    /// block's place under the next tweak. Decrypting is the mirror:
    /// the last whole block is decrypted under the *later* tweak,
    /// because that is the one it was encrypted with.
    fn steal(
        &self,
        last: &mut [u8],
        short: &mut [u8],
        mask: u8,
        t: &mut [u8; BLOCK],
        encrypt: bool,
    ) {
        let last: &mut [u8; BLOCK] = last.try_into().expect("one whole block");
        let mut first = *t;
        let mut second = *t;
        if encrypt {
            multiply_by_alpha(&mut second);
        } else {
            multiply_by_alpha(&mut first);
        }

        xor(last, &first);
        if encrypt {
            self.data.encrypt_one(last);
        } else {
            self.data.decrypt_one(last);
        }
        xor(last, &first);

        let mut carried = [0u8; BLOCK];
        let n = short.len();
        carried[..n].copy_from_slice(short);
        // The split byte: the short block's own bits, and the stolen
        // block's below them.
        carried[n - 1] = (short[n - 1] & mask) | (last[n - 1] & !mask);
        carried[n..].copy_from_slice(&last[n..]);
        short.copy_from_slice(&last[..n]);
        short[n - 1] &= mask;

        xor(&mut carried, &second);
        if encrypt {
            self.data.encrypt_one(&mut carried);
        } else {
            self.data.decrypt_one(&mut carried);
        }
        xor(&mut carried, &second);
        last.copy_from_slice(&carried);
        *t = second;
    }

    /// The first tweak: the tweak value encrypted under the second
    /// key. Also checks the length.
    fn start(
        &self,
        tweak: &C::Block,
        len: usize,
    ) -> Result<[u8; BLOCK], Error> {
        if len < BLOCK {
            return Err(Error::InvalidLength(len));
        }
        let mut start = *tweak;
        self.tweak.encrypt_one(&mut start);
        Ok(start)
    }

    /// Splits a data unit into the blocks handled normally and, if
    /// the unit does not divide evenly, the last whole block and the
    /// `short` bytes that steal from it.
    #[allow(clippy::type_complexity)]
    fn split(
        data: &mut [u8],
        short: usize,
    ) -> (&mut [u8], Option<(&mut [u8], &mut [u8])>) {
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
    fn bulk(&self, data: &mut [u8], t: &mut [u8; BLOCK], encrypt: bool) {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if let Engine::Native(engine) = &self.engine {
            engine.bulk(&self.data, t, data, encrypt);
            return;
        }
        let (whole, _) = data.as_chunks_mut::<BLOCK>();
        let mut tweaks = [[0u8; BLOCK]; LANES];
        for group in whole.chunks_mut(LANES) {
            let tweaks = &mut tweaks[..group.len()];
            // The tweak stays in registers across the group. Stored
            // and read back for the next block, the sixteen-byte read
            // would cross narrower stores still in the store buffer,
            // which the processor cannot forward and must wait out.
            let mut value = u128::from_le_bytes(*t);
            for tweak in tweaks.iter_mut() {
                *tweak = value.to_le_bytes();
                value = alpha(value);
            }
            *t = value.to_le_bytes();
            for (block, tweak) in group.iter_mut().zip(&*tweaks) {
                xor(block, tweak);
            }
            if encrypt {
                self.data.encrypt(group);
            } else {
                self.data.decrypt(group);
            }
            for (block, tweak) in group.iter_mut().zip(&*tweaks) {
                xor(block, tweak);
            }
        }
    }
}

/// Advances the tweak, for a caller holding it as a block.
fn multiply_by_alpha(tweak: &mut [u8; BLOCK]) {
    *tweak = alpha(u128::from_le_bytes(*tweak)).to_le_bytes();
}

/// Multiplication by the field element the standard calls alpha, on
/// the block read as the little-endian integer it is: a shift by one
/// with the bit shifted out fed back through the field polynomial.
/// Done without a branch, since the tweaks after the first depend on
/// the key.
#[inline]
pub(crate) fn alpha(tweak: u128) -> u128 {
    let carry = tweak >> 127;
    (tweak << 1) ^ (0u128.wrapping_sub(carry) & 0x87)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::Key;
    use crate::cipher::aes::Aes128;
    use std::vec::Vec;

    const MAX: usize = 80;

    fn unhex<'a>(text: &str, buffer: &'a mut [u8]) -> &'a [u8] {
        let n = text.len() / 2;
        for i in 0..n {
            buffer[i] =
                u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        &buffer[..n]
    }

    fn xts() -> Xts<Aes128> {
        let mut key = [0u8; 32];
        let mut buffer = [0u8; 32];
        key.copy_from_slice(unhex(
            "271828182845904523536028747135266249775724709369995957496696\
             7627",
            &mut buffer,
        ));
        let (data, tweak) = key.split_at(16);
        Xts::try_new(
            &Key::try_from(data).unwrap(),
            &Key::try_from(tweak).unwrap(),
        )
        .unwrap()
    }

    /// A whole number of blocks: no stealing involved.
    #[test]
    fn whole_blocks() {
        let (mut tb, mut pb, mut cb) = ([0u8; 16], [0u8; MAX], [0u8; MAX]);
        unhex("ff000000000000000000000000000000", &mut tb);
        let tweak = &tb;
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
        unhex("ff000000000000000000000000000000", &mut tb);
        let tweak = &tb;
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

    /// Every implementation this processor has must agree, at every
    /// length around the group boundaries of both widths, with and
    /// without a block to steal from.
    #[test]
    fn the_engines_agree() {
        const MAX: usize = 5 * 16 * BLOCK + 7;
        let data = Key::from([0x44u8; 16]);
        let tweak = Key::from([0x55u8; 16]);
        let t = [0x66u8; BLOCK];
        let mut message = [0u8; MAX];
        for (i, b) in message.iter_mut().enumerate() {
            *b = (i * 11 + 5) as u8;
        }

        let all: Vec<Xts<Aes128>> = CHOICES
            .iter()
            .filter_map(|&c| Xts::<Aes128>::with_choice(&data, &tweak, c))
            .collect();
        assert!(!all.is_empty(), "no implementation to test");
        // The generic one is always to be had.
        assert!(
            Xts::<Aes128>::with_choice(&data, &tweak, Choice::Generic)
                .is_some()
        );

        for len in BLOCK..MAX {
            let mut want = [0u8; MAX];
            want[..len].copy_from_slice(&message[..len]);
            all[all.len() - 1].encrypt(&t, &mut want[..len]).unwrap();

            for (i, xts) in all.iter().enumerate() {
                let mut got = [0u8; MAX];
                got[..len].copy_from_slice(&message[..len]);
                xts.encrypt(&t, &mut got[..len]).unwrap();
                assert_eq!(got[..len], want[..len], "encrypt {len}, {i}");
                xts.decrypt(&t, &mut got[..len]).unwrap();
                assert_eq!(got[..len], message[..len], "decrypt {len}, {i}");
            }
        }
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
        // The two keys must differ.
        assert_eq!(
            Xts::<Aes128>::try_new(
                &Key::from([0x11; 16]),
                &Key::from([0x11; 16])
            )
            .unwrap_err(),
            Error::InvalidKeyLength(32)
        );

        let xts = xts();
        // A data unit must be at least one block.
        for n in [0, 1, 15] {
            let mut data = [0u8; 15];
            assert_eq!(
                xts.encrypt(&[0; 16], &mut data[..n]).unwrap_err(),
                Error::InvalidLength(n)
            );
        }
    }

    /// Formatting the state must not print the key.
    /// A whole number of bytes through the bit methods is the byte
    /// methods; and units of odd bit lengths round trip, differ from
    /// their byte-length neighbours, and leave the spare bits zero.
    #[test]
    fn bit_lengths() {
        let xts = xts();
        let tweak = [0x11u8; 16];
        let data: [u8; 40] = core::array::from_fn(|i| (i * 37 + 5) as u8);

        let mut bytes = data;
        let mut bits = data;
        xts.encrypt(&tweak, &mut bytes[..33]).unwrap();
        xts.encrypt_bits(&tweak, &mut bits[..33], 264).unwrap();
        assert_eq!(bytes, bits);

        for n in [129usize, 135, 200, 255, 257, 319] {
            let len = n.div_ceil(8);
            let mut unit = data;
            xts.encrypt_bits(&tweak, &mut unit[..len], n).unwrap();
            assert_ne!(unit[..len], data[..len], "{n} bits");
            let spare = 8 * len - n;
            assert_eq!(unit[len - 1] & ((1u8 << spare) - 1), 0, "{n} bits");
            xts.decrypt_bits(&tweak, &mut unit[..len], n).unwrap();
            let mask = 0xffu8 << spare;
            assert_eq!(unit[..len - 1], data[..len - 1], "{n} bits");
            assert_eq!(unit[len - 1] & mask, data[len - 1] & mask, "{n}");
        }
    }

    #[test]
    fn rejects_bad_bit_lengths() {
        let xts = xts();
        let tweak = [0u8; 16];
        let mut data = [0u8; 32];
        for (len, bits) in [(16, 127), (15, 120), (18, 129), (31, 250)] {
            assert_eq!(
                xts.encrypt_bits(&tweak, &mut data[..len], bits),
                Err(Error::InvalidLength(bits)),
                "{len} bytes, {bits} bits"
            );
            assert_eq!(
                xts.decrypt_bits(&tweak, &mut data[..len], bits),
                Err(Error::InvalidLength(bits))
            );
        }
    }

    #[test]
    fn debug_omits_the_key() {
        struct Buffer([u8; 256], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let mut buffer = Buffer([0; 256], 0);
        core::fmt::write(&mut buffer, format_args!("{:?}", xts())).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("["), "{text}");
        assert!(text.starts_with("Xts"));
    }
}
