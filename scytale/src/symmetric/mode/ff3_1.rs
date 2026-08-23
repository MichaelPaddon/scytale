//! FF3-1, format-preserving encryption (NIST SP 800-38G revision 1).
//!
//! The same purpose as [`Ff1`](super::Ff1): a string of symbols
//! encrypts to a string of the same symbols and the same length. It
//! is a different construction, with eight rounds instead of ten and
//! a tweak fixed at 56 bits.
//!
//! # History worth knowing
//!
//! The original FF3 was broken: its 64-bit tweak allowed an attack
//! that recovered plaintext far faster than searching. FF3-1 is the
//! repair, narrowing the tweak to 56 bits. Later work has continued
//! to chip away at both format-preserving modes, so treat the margins
//! here as thinner than for an ordinary mode, and prefer
//! [`Ff1`](super::Ff1) where either would do.
//!
//! # Using it safely
//!
//! - **The security depends on how many messages are possible**, for
//!   the reasons given in [`Ff1`](super::Ff1). At least a million is
//!   demanded and enforced here; more is better.
//! - The tweak is exactly seven bytes and should vary with the
//!   record.
//! - There is no authentication, and none is possible.
//!
//! # Limits here
//!
//! The construction caps the message itself: one half must fit in 96
//! bits, so the longest message is 56 decimal digits, or 192 symbols
//! at the smallest radix.
//!
//! As with [`Ff1`](super::Ff1), this mode is **not constant time**
//! with respect to the message.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Ff3_1;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let ff3: Ff3_1<Aes> = Ff3_1::try_new(&[0u8; 16], 10)?;
//! let tweak = [0u8; 7];
//!
//! let mut account = [0u16, 1, 2, 3, 4, 5, 6, 7, 8, 9];
//! ff3.encrypt(&tweak, &mut account)?;
//! assert!(account.iter().all(|&d| d < 10));
//!
//! ff3.decrypt(&tweak, &mut account)?;
//! assert_eq!(account, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
//! # Ok(())
//! # }
//! ```

use super::ghash::BLOCK;
use crate::math::natural::Natural;
use crate::symmetric::BlockCipher;
use crate::Error;

/// Rounds of the Feistel network, fixed by the standard.
const ROUNDS: usize = 8;

/// The smallest number of possible messages the standard allows.
const MIN_DOMAIN: u64 = 1_000_000;

/// The tweak length, fixed by the standard.
const TWEAK: usize = 7;

/// Bits one half of the message must fit in.
const HALF_BITS: u32 = 96;

/// The longest message, in symbols: two halves at the smallest radix.
pub const MAX_SYMBOLS: usize = 2 * HALF_BITS as usize;

/// FF3-1 over a block cipher, for one radix.
#[derive(Clone, Debug)]
pub struct Ff3_1<C> {
    cipher: C,
    radix: u32,
    /// The longest message this radix allows, from the 96-bit cap on
    /// each half.
    max_symbols: usize,
}

impl<C: BlockCipher> Ff3_1<C> {
    /// Takes the key and the radix, which must be between 2 and
    /// 65536.
    ///
    /// The key is held reversed, as the standard specifies.
    ///
    /// # Panics
    /// If the cipher's block is not 128 bits.
    pub fn try_new(key: &[u8], radix: u32) -> Result<Self, Error> {
        assert_eq!(
            C::BLOCK_SIZE,
            BLOCK,
            "FF3-1 is defined only for a 128-bit block cipher"
        );
        if !(2..=65536).contains(&radix) {
            return Err(Error::InvalidRadix(radix));
        }
        // Longest half whose value still fits in 96 bits.
        let mut half = 0usize;
        let mut span: u128 = 1;
        let ceiling = 1u128 << HALF_BITS;
        while let Some(next) = span.checked_mul(u128::from(radix)) {
            if next > ceiling {
                break;
            }
            span = next;
            half += 1;
        }

        let mut reversed = [0u8; 32];
        let reversed = &mut reversed[..key.len().min(32)];
        if reversed.len() != key.len() {
            return Err(Error::InvalidKeyLength(key.len()));
        }
        for (slot, byte) in reversed.iter_mut().zip(key.iter().rev()) {
            *slot = *byte;
        }

        Ok(Ff3_1 {
            cipher: C::try_new(reversed)?,
            radix,
            max_symbols: 2 * half,
        })
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

    fn run(
        &self,
        tweak: &[u8],
        message: &mut [u16],
        encrypt: bool,
    ) -> Result<(), Error> {
        let n = message.len();
        if n < 2 || n > self.max_symbols {
            return Err(Error::InvalidLength(n));
        }
        for &symbol in message.iter() {
            if u32::from(symbol) >= self.radix {
                return Err(Error::InvalidSymbol(u32::from(symbol)));
            }
        }
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
        if tweak.len() != TWEAK {
            return Err(Error::InvalidNonceLength(tweak.len()));
        }

        // The tweak splits into two halves, with its middle nibble
        // shared between them.
        let left_tweak = [tweak[0], tweak[1], tweak[2], tweak[3] & 0xf0];
        let right_tweak =
            [tweak[4], tweak[5], tweak[6], (tweak[3] & 0x0f) << 4];

        let u = n.div_ceil(2);
        let mut left = [0u16; MAX_SYMBOLS];
        let mut right = [0u16; MAX_SYMBOLS];
        left[..u].copy_from_slice(&message[..u]);
        right[..n - u].copy_from_slice(&message[u..]);
        let (mut left_len, mut right_len) = (u, n - u);

        for round in 0..ROUNDS {
            let i = if encrypt { round } else { ROUNDS - 1 - round };
            let half_tweak = if i % 2 == 0 { right_tweak } else { left_tweak };

            let (source, source_len) = if encrypt {
                (&right, right_len)
            } else {
                (&left, left_len)
            };
            let step =
                self.round_value(&half_tweak, i, &source[..source_len])?;

            // Symbols are held least significant first here, which is
            // what the standard's reversals amount to.
            if encrypt {
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

    /// One round's output, as symbols least significant first.
    fn round_value(
        &self,
        half_tweak: &[u8; 4],
        round: usize,
        source: &[u16],
    ) -> Result<[u16; MAX_SYMBOLS], Error> {
        // The other half as a number, in twelve bytes.
        let mut value = Natural::zero();
        for &symbol in source.iter().rev() {
            value.multiply_add(self.radix, u32::from(symbol));
        }
        let mut block = [0u8; BLOCK];
        block[..4].copy_from_slice(half_tweak);
        for (slot, byte) in
            block[..4].iter_mut().zip((round as u32).to_be_bytes())
        {
            *slot ^= byte;
        }
        value.to_bytes(&mut block[4..BLOCK]);

        // The standard runs the cipher over the block reversed, under
        // a reversed key, and reverses the answer.
        block.reverse();
        self.cipher.encrypt_block(&mut block)?;
        block.reverse();

        let mut value = Natural::from_bytes(&block);
        let mut step = [0u16; MAX_SYMBOLS];
        for slot in step.iter_mut() {
            *slot = value.divide(self.radix) as u16;
        }
        Ok(step)
    }
}

/// Adds `step` into `half`, least significant symbol first.
fn add_into(half: &mut [u16], step: &[u16; MAX_SYMBOLS], radix: u32) {
    let mut carry = 0u32;
    for (slot, add) in half.iter_mut().zip(step.iter()) {
        let sum = u32::from(*slot) + u32::from(*add) + carry;
        let over = u32::from(sum >= radix);
        *slot = (sum - over * radix) as u16;
        carry = over;
    }
}

/// Takes `step` away from `half`, the reverse of [`add_into`].
fn subtract_from(half: &mut [u16], step: &[u16; MAX_SYMBOLS], radix: u32) {
    let mut borrow = 0i32;
    for (slot, take) in half.iter_mut().zip(step.iter()) {
        let difference = i32::from(*slot) - i32::from(*take) - borrow;
        let under = (difference >> 31) & 1;
        *slot = (difference + under * radix as i32) as u16;
        borrow = under;
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

    /// Reads a string of decimal digits into symbol values.
    fn digits<const N: usize>(text: &str) -> [u16; N] {
        let mut out = [0u16; N];
        for (slot, c) in out.iter_mut().zip(text.chars()) {
            *slot = c.to_digit(10).unwrap() as u16;
        }
        out
    }

    fn ff3(radix: u32) -> Ff3_1<Aes> {
        let key: [u8; 16] = unhex("44d737102ccc9aec882045c31c08252a");
        Ff3_1::try_new(&key, radix).unwrap()
    }

    #[test]
    fn known_answer() {
        let tweak: [u8; 7] = unhex("7e0a5d29e0462e");
        let plain: [u16; 30] = digits("594305339157537322411756936648");
        let cipher: [u16; 30] = digits("302999799972717161117243949033");

        let ff3 = ff3(10);
        let mut data = plain;
        ff3.encrypt(&tweak, &mut data).unwrap();
        assert_eq!(data, cipher, "encrypt");
        ff3.decrypt(&tweak, &mut data).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    #[test]
    fn the_format_survives() {
        let ff3 = ff3(10);
        let mut data = [9u16, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2];
        ff3.encrypt(&[1u8; 7], &mut data).unwrap();
        assert_eq!(data.len(), 12);
        assert!(data.iter().all(|&d| d < 10), "still decimal digits");
    }

    #[test]
    fn round_trips_at_many_lengths_and_radices() {
        for radix in [2u32, 10, 26, 64] {
            let ff3 = ff3(radix);
            for n in [20usize, 21, 27, 28] {
                let mut plain = [0u16; 28];
                for (i, s) in plain[..n].iter_mut().enumerate() {
                    *s = ((i * 7 + 1) as u32 % radix) as u16;
                }
                let mut data = plain;
                ff3.encrypt(&[2u8; 7], &mut data[..n]).unwrap();
                assert_ne!(data[..n], plain[..n], "radix {radix}, {n}");
                ff3.decrypt(&[2u8; 7], &mut data[..n]).unwrap();
                assert_eq!(data[..n], plain[..n], "radix {radix}, {n}");
            }
        }
    }

    /// The tweak is exactly seven bytes, unlike FF1 which takes any
    /// length. The original FF3 allowed eight, and that was the flaw.
    #[test]
    fn the_tweak_must_be_seven_bytes() {
        let ff3 = ff3(10);
        let source = [0u8; 16];
        for n in [0, 6, 8, 16] {
            assert_eq!(
                ff3.encrypt(&source[..n], &mut [0; 10]).unwrap_err(),
                Error::InvalidNonceLength(n)
            );
        }
        assert!(ff3.encrypt(&source[..7], &mut [0; 10]).is_ok());
    }

    /// Each half must fit in 96 bits, so the longest message depends
    /// on the radix: 56 decimal digits, fewer as the radix grows.
    #[test]
    fn the_radix_caps_the_length() {
        let mut buffer = [0u16; 200];
        for (radix, longest) in [(10u32, 56usize), (26, 40), (64, 32)] {
            let ff3 = ff3(radix);
            assert!(
                ff3.encrypt(&[0; 7], &mut buffer[..longest]).is_ok(),
                "radix {radix} should allow {longest}"
            );
            assert_eq!(
                ff3.encrypt(&[0; 7], &mut buffer[..longest + 1])
                    .unwrap_err(),
                Error::InvalidLength(longest + 1),
                "radix {radix} should refuse {}",
                longest + 1
            );
        }
    }

    #[test]
    fn refuses_a_domain_that_is_too_small() {
        assert_eq!(
            ff3(10).encrypt(&[0; 7], &mut [0; 5]).unwrap_err(),
            Error::DomainTooSmall
        );
        assert!(ff3(10).encrypt(&[0; 7], &mut [0; 6]).is_ok());
    }

    #[test]
    fn rejects_bad_input() {
        let key: [u8; 16] = unhex("44d737102ccc9aec882045c31c08252a");
        for radix in [0u32, 1, 65537] {
            assert_eq!(
                Ff3_1::<Aes>::try_new(&key, radix).unwrap_err(),
                Error::InvalidRadix(radix)
            );
        }
        let mut bad = [0u16; 10];
        bad[3] = 10;
        assert_eq!(
            ff3(10).encrypt(&[0; 7], &mut bad).unwrap_err(),
            Error::InvalidSymbol(10)
        );
    }
}
