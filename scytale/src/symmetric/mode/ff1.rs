//! FF1, format-preserving encryption (NIST SP 800-38G).
//!
//! Every other mode turns a message into bytes that look nothing like
//! it. FF1 does not: a sixteen-digit card number encrypts to a
//! sixteen-digit card number, so ciphertext can be kept in a field
//! that only accepts card numbers. That is its whole reason for
//! existing, and the reason to be careful with it.
//!
//! A message is a string of symbols, each a number below the radix.
//! What those numbers mean is the caller's business: for digits,
//! zero to nine; for an alphabet, the position of each letter in it.
//!
//! # Using it safely
//!
//! - **The security depends on how many messages are possible.**
//!   Preserving the format means the ciphertext is drawn from the same
//!   small set as the plaintext, so an attacker who can encrypt can
//!   simply try every possibility. The standard demands at least a
//!   million; that is a floor, not a comfortable margin, and known
//!   attacks weaken these modes further as the set shrinks.
//! - The tweak should vary with the record, and acts rather like a
//!   nonce: two equal messages under equal tweaks give equal
//!   ciphertexts.
//! - There is no authentication, and none is possible: the output has
//!   no room for a tag.
//! - Reach for an ordinary authenticated mode unless the format
//!   really must be preserved.
//!
//! # Limits here
//!
//! Messages are at most 512 symbols, which is what the vectors reach
//! and far beyond any real use of format-preserving encryption. The
//! working values live on the stack, a few kilobytes of it per call.
//!
//! Unlike the rest of the library, this mode is **not constant time**
//! with respect to the message: converting between a number and a
//! string of symbols divides by the radix, and division timing
//! depends on its operands on some processors.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Ff1;
//!
//! # fn main() -> Result<(), scytale::symmetric::Error> {
//! // Decimal digits.
//! let ff1 = Ff1::try_new(Aes::try_new(&[0u8; 16])?, 10)?;
//!
//! let mut account = [0u16, 1, 2, 3, 4, 5, 6, 7, 8, 9];
//! ff1.encrypt(b"record 42", &mut account)?;
//! // Still ten decimal digits.
//! assert!(account.iter().all(|&d| d < 10));
//!
//! ff1.decrypt(b"record 42", &mut account)?;
//! assert_eq!(account, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
//! # Ok(())
//! # }
//! ```

use super::ghash::BLOCK;
use crate::math::natural::Natural;
use crate::symmetric::{BlockCipher, Error};

/// Rounds of the Feistel network, fixed by the standard.
const ROUNDS: usize = 10;

/// The smallest number of possible messages the standard allows.
const MIN_DOMAIN: u64 = 1_000_000;

/// The longest message, in symbols.
pub const MAX_SYMBOLS: usize = 512;

/// Half of that, the longest either side of the split can be.
const MAX_HALF: usize = MAX_SYMBOLS.div_ceil(2);

/// The most bytes the numeric form of one half can take, at the
/// largest radix.
const MAX_NUMBER: usize = MAX_HALF * 2;

/// The most bytes drawn from the cipher each round.
const MAX_DRAWN: usize = 4 * MAX_NUMBER.div_ceil(4) + 4 + BLOCK;

/// FF1 over a block cipher, for one radix.
#[derive(Clone, Debug)]
pub struct Ff1<C> {
    cipher: C,
    radix: u32,
}

impl<C: BlockCipher> Ff1<C> {
    /// Wraps `cipher` for messages written in `radix` symbols, which
    /// must be between 2 and 65536.
    ///
    /// # Panics
    /// If the cipher's block is not 128 bits.
    pub fn try_new(cipher: C, radix: u32) -> Result<Self, Error> {
        assert_eq!(
            C::BLOCK_SIZE,
            BLOCK,
            "FF1 is defined only for a 128-bit block cipher"
        );
        if !(2..=65536).contains(&radix) {
            return Err(Error::InvalidRadix(radix));
        }
        Ok(Ff1 { cipher, radix })
    }

    /// Encrypts `message` in place, leaving it the same length and in
    /// the same radix.
    pub fn encrypt(
        &self,
        tweak: &[u8],
        message: &mut [u16],
    ) -> Result<(), Error> {
        self.run(tweak, message, true)
    }

    /// Decrypts `message` in place.
    pub fn decrypt(
        &self,
        tweak: &[u8],
        message: &mut [u16],
    ) -> Result<(), Error> {
        self.run(tweak, message, false)
    }

    /// Checks the message and reports how many bytes the numeric form
    /// of a half takes.
    fn check(&self, message: &[u16]) -> Result<usize, Error> {
        let n = message.len();
        if !(2..=MAX_SYMBOLS).contains(&n) {
            return Err(Error::InvalidLength(n));
        }
        for &symbol in message {
            if u32::from(symbol) >= self.radix {
                return Err(Error::InvalidSymbol(u32::from(symbol)));
            }
        }
        // How many messages are possible, capped so the count itself
        // cannot run away.
        let mut domain: u64 = 1;
        for _ in 0..n {
            domain = domain.saturating_mul(u64::from(self.radix));
            if domain >= MIN_DOMAIN {
                break;
            }
        }
        if domain < MIN_DOMAIN {
            return Err(Error::DomainTooSmall);
        }

        // The standard's b: the bytes needed for the largest value a
        // half can take, which is the radix to that power, less one.
        let v = n - n / 2;
        let mut largest = Natural::zero();
        for _ in 0..v {
            largest.multiply_add(self.radix, self.radix - 1);
        }
        Ok(largest.bit_length().div_ceil(8))
    }

    fn run(
        &self,
        tweak: &[u8],
        message: &mut [u16],
        encrypt: bool,
    ) -> Result<(), Error> {
        let number_bytes = self.check(message)?;
        let drawn = 4 * number_bytes.div_ceil(4) + 4;
        let n = message.len();
        let u = n / 2;

        // The two halves, which trade places every round.
        let mut left = [0u16; MAX_SYMBOLS];
        let mut right = [0u16; MAX_SYMBOLS];
        left[..u].copy_from_slice(&message[..u]);
        right[..n - u].copy_from_slice(&message[u..]);
        let (mut left_len, mut right_len) = (u, n - u);

        let prefix = self.prefix(n, u, tweak.len());

        for round in 0..ROUNDS {
            let i = if encrypt { round } else { ROUNDS - 1 - round };

            // The half that feeds the round function, and the one
            // that is changed, swap between the directions.
            let (source, source_len) = if encrypt {
                (&right, right_len)
            } else {
                (&left, left_len)
            };
            let step = self.round_value(
                &prefix,
                tweak,
                i,
                &source[..source_len],
                number_bytes,
                drawn,
            )?;

            if encrypt {
                // left = left + step, then the halves rotate.
                add_into(&mut left[..left_len], &step, self.radix);
                let mut carried = [0u16; MAX_SYMBOLS];
                carried[..left_len].copy_from_slice(&left[..left_len]);
                let carried_len = left_len;
                left[..right_len].copy_from_slice(&right[..right_len]);
                left_len = right_len;
                right[..carried_len].copy_from_slice(&carried[..carried_len]);
                right_len = carried_len;
            } else {
                subtract_from(&mut right[..right_len], &step, self.radix);
                let mut carried = [0u16; MAX_SYMBOLS];
                carried[..right_len].copy_from_slice(&right[..right_len]);
                let carried_len = right_len;
                right[..left_len].copy_from_slice(&left[..left_len]);
                right_len = left_len;
                left[..carried_len].copy_from_slice(&carried[..carried_len]);
                left_len = carried_len;
            }
        }

        message[..left_len].copy_from_slice(&left[..left_len]);
        message[left_len..].copy_from_slice(&right[..right_len]);
        Ok(())
    }

    /// The fixed block that starts every round's input.
    fn prefix(&self, n: usize, u: usize, tweak: usize) -> [u8; BLOCK] {
        let mut prefix = [0u8; BLOCK];
        prefix[0] = 1;
        prefix[1] = 2;
        prefix[2] = 1;
        prefix[3..6].copy_from_slice(&self.radix.to_be_bytes()[1..]);
        prefix[6] = 10;
        prefix[7] = (u % 256) as u8;
        prefix[8..12].copy_from_slice(&(n as u32).to_be_bytes());
        prefix[12..BLOCK].copy_from_slice(&(tweak as u32).to_be_bytes());
        prefix
    }

    /// One round's output, as symbols: the cipher applied to the
    /// round number and the other half, spread out to enough bytes
    /// and read back as a number.
    fn round_value(
        &self,
        prefix: &[u8; BLOCK],
        tweak: &[u8],
        round: usize,
        source: &[u16],
        number_bytes: usize,
        drawn: usize,
    ) -> Result<[u16; MAX_SYMBOLS], Error> {
        // The other half, as a number in a fixed-width field.
        let mut value = Natural::zero();
        for &symbol in source {
            value.multiply_add(self.radix, u32::from(symbol));
        }
        let mut number = [0u8; MAX_NUMBER];
        value.to_bytes(&mut number[..number_bytes]);

        // A chained authentication over all of it.
        let padding =
            (BLOCK - (tweak.len() + number_bytes + 1) % BLOCK) % BLOCK;
        let mut mac = Chain::new(&self.cipher);
        mac.update(prefix)?;
        mac.update(tweak)?;
        mac.update(&[0u8; BLOCK][..padding])?;
        mac.update(&[round as u8])?;
        mac.update(&number[..number_bytes])?;
        let seed = mac.finish();

        // Stretched to as many bytes as the round needs.
        let mut drawn_bytes = [0u8; MAX_DRAWN];
        drawn_bytes[..BLOCK].copy_from_slice(&seed);
        let mut filled = BLOCK;
        let mut counter: u128 = 1;
        while filled < drawn {
            let mut block = seed;
            for (byte, mask) in block.iter_mut().zip(counter.to_be_bytes()) {
                *byte ^= mask;
            }
            self.cipher.encrypt_block(&mut block)?;
            drawn_bytes[filled..filled + BLOCK].copy_from_slice(&block);
            filled += BLOCK;
            counter += 1;
        }

        // Read back as a number, then written out as symbols. Taking
        // only as many symbols as the half is long is what reduces it
        // to the right range.
        let mut value = Natural::from_bytes(&drawn_bytes[..drawn]);
        let mut step = [0u16; MAX_SYMBOLS];
        for slot in step[..MAX_SYMBOLS].iter_mut().rev() {
            *slot = value.divide(self.radix) as u16;
        }
        Ok(step)
    }
}

/// Adds `step` into `half`, symbol by symbol, discarding anything
/// that carries off the top. `step` is the full-width value, of which
/// only the last symbols matter.
fn add_into(half: &mut [u16], step: &[u16; MAX_SYMBOLS], radix: u32) {
    let offset = MAX_SYMBOLS - half.len();
    let mut carry = 0u32;
    for (k, slot) in half.iter_mut().enumerate().rev() {
        let sum = u32::from(*slot) + u32::from(step[offset + k]) + carry;
        let over = u32::from(sum >= radix);
        *slot = (sum - over * radix) as u16;
        carry = over;
    }
}

/// Takes `step` away from `half`, the reverse of [`add_into`].
fn subtract_from(half: &mut [u16], step: &[u16; MAX_SYMBOLS], radix: u32) {
    let offset = MAX_SYMBOLS - half.len();
    let mut borrow = 0i32;
    for (k, slot) in half.iter_mut().enumerate().rev() {
        let difference =
            i32::from(*slot) - i32::from(step[offset + k]) - borrow;
        let under = (difference >> 31) & 1;
        *slot = (difference + under * radix as i32) as u16;
        borrow = under;
    }
}

/// A chained authentication over a whole number of blocks: each block
/// is combined with the one before it and encrypted, and the last
/// result is the answer.
struct Chain<'a, C> {
    cipher: &'a C,
    state: [u8; BLOCK],
    block: [u8; BLOCK],
    used: usize,
}

impl<'a, C: BlockCipher> Chain<'a, C> {
    fn new(cipher: &'a C) -> Self {
        Chain {
            cipher,
            state: [0; BLOCK],
            block: [0; BLOCK],
            used: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) -> Result<(), Error> {
        while !data.is_empty() {
            let take = data.len().min(BLOCK - self.used);
            self.block[self.used..self.used + take]
                .copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used == BLOCK {
                for (s, b) in self.state.iter_mut().zip(&self.block) {
                    *s ^= b;
                }
                self.cipher.encrypt_block(&mut self.state)?;
                self.used = 0;
            }
        }
        Ok(())
    }

    fn finish(self) -> [u8; BLOCK] {
        debug_assert_eq!(self.used, 0, "input was not whole blocks");
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::Aes;

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            out[i] =
                u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16)
                    .unwrap();
        }
        out
    }

    fn ff1(radix: u32) -> Ff1<Aes> {
        let key: [u8; 16] = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        Ff1::try_new(Aes::try_new(&key).unwrap(), radix).unwrap()
    }

    /// NIST's published sample for FF1 with AES-128, decimal digits
    /// and no tweak.
    #[test]
    fn nist_sample_without_a_tweak() {
        let ff1 = ff1(10);
        let plain = [0u16, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cipher = [2u16, 4, 3, 3, 4, 7, 7, 4, 8, 4];

        let mut data = plain;
        ff1.encrypt(b"", &mut data).unwrap();
        assert_eq!(data, cipher, "encrypt");
        ff1.decrypt(b"", &mut data).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    /// The same message with a tweak, which must change the answer.
    #[test]
    fn nist_sample_with_a_tweak() {
        let ff1 = ff1(10);
        let tweak: [u8; 10] = unhex("39383736353433323130");
        let plain = [0u16, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cipher = [6u16, 1, 2, 4, 2, 0, 0, 7, 7, 3];

        let mut data = plain;
        ff1.encrypt(&tweak, &mut data).unwrap();
        assert_eq!(data, cipher, "encrypt");
        ff1.decrypt(&tweak, &mut data).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    /// The format is preserved: the output is the same length, in the
    /// same radix.
    #[test]
    fn the_format_survives() {
        let ff1 = ff1(10);
        let mut data = [9u16, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2];
        ff1.encrypt(b"customer 7", &mut data).unwrap();
        assert_eq!(data.len(), 12);
        assert!(data.iter().all(|&d| d < 10), "still decimal digits");
    }

    #[test]
    fn round_trips_at_many_lengths_and_radices() {
        for radix in [2u32, 10, 26, 256, 65536] {
            // Long enough that the domain rule is satisfied.
            let ff1 = ff1(radix);
            for n in [20usize, 21, 32, 33] {
                let mut plain = [0u16; 33];
                for (i, s) in plain[..n].iter_mut().enumerate() {
                    *s = ((i * 7 + 1) as u32 % radix) as u16;
                }
                let mut data = plain;
                ff1.encrypt(b"t", &mut data[..n]).unwrap();
                assert_ne!(data[..n], plain[..n], "radix {radix}, {n}");
                ff1.decrypt(b"t", &mut data[..n]).unwrap();
                assert_eq!(data[..n], plain[..n], "radix {radix}, {n}");
            }
        }
    }

    /// The security rests on there being many possible messages, so
    /// too few must be refused rather than quietly encrypted.
    #[test]
    fn refuses_a_domain_that_is_too_small() {
        // Ten decimal digits is plenty; five is not.
        assert!(ff1(10).encrypt(b"", &mut [0; 10]).is_ok());
        assert_eq!(
            ff1(10).encrypt(b"", &mut [0; 5]).unwrap_err(),
            Error::DomainTooSmall
        );
        // Nineteen bits is under a million; twenty is over.
        assert_eq!(
            ff1(2).encrypt(b"", &mut [0; 19]).unwrap_err(),
            Error::DomainTooSmall
        );
        assert!(ff1(2).encrypt(b"", &mut [0; 20]).is_ok());
    }

    #[test]
    fn rejects_bad_input() {
        let key: [u8; 16] = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        for radix in [0u32, 1, 65537, 100_000] {
            assert_eq!(
                Ff1::try_new(Aes::try_new(&key).unwrap(), radix).unwrap_err(),
                Error::InvalidRadix(radix)
            );
        }

        let ff1 = ff1(10);
        // A symbol the radix does not allow.
        let mut bad = [0u16; 10];
        bad[3] = 10;
        assert_eq!(
            ff1.encrypt(b"", &mut bad).unwrap_err(),
            Error::InvalidSymbol(10)
        );
        // Too short to have two halves, and too long for the buffers.
        assert_eq!(
            ff1.encrypt(b"", &mut [0; 1]).unwrap_err(),
            Error::InvalidLength(1)
        );
        let mut huge = [0u16; MAX_SYMBOLS + 1];
        assert_eq!(
            ff1.encrypt(b"", &mut huge).unwrap_err(),
            Error::InvalidLength(MAX_SYMBOLS + 1)
        );
    }
}
