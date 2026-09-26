//! Text as symbols, for the format-preserving modes.
//!
//! [`Ff1`](super::Ff1) and [`Ff3_1`](super::Ff3_1) work on strings
//! of numerals below a radix, as SP 800-38G defines them. A caller
//! has text: a card number, a name, a field in a form. An
//! [`Alphabet`] is the correspondence between the two, the string
//! of characters whose position is each symbol's value, so `"0123
//! 456789"` makes the ten digits the numerals 0 to 9 and a card
//! number a string of them.
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::mode::{Alphabet, Ff1};
//! use scytale::cipher::mode::alphabet::DIGITS;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let ff1 = Ff1::<Aes128>::try_new(&Key::from([0u8; 16]), DIGITS.radix())?;
//! let mut symbols = [0u16; 16];
//! let n = DIGITS.encode("4000123456789010", &mut symbols)?;
//! ff1.encrypt(b"", &mut symbols[..n])?;
//! let mut text = [0u8; 16];
//! let m = DIGITS.decode(&symbols[..n], &mut text)?;
//! assert_eq!(m, 16);
//! assert!(text.iter().all(u8::is_ascii_digit));
//! # Ok(())
//! # }
//! ```
//!
//! Like the modes it serves, this is not constant time: which
//! character a symbol is decides how far a search runs. It is the
//! caller's format that is being preserved, and a format is not a
//! secret.

use crate::Error;

/// A radix's numerals, as the characters that stand for them.
///
/// Built once from a string of distinct characters, then used to
/// [`encode`](Self::encode) text into symbols for a mode and
/// [`decode`](Self::decode) the mode's output back into text. The
/// radix is the string's length in characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alphabet<'a> {
    symbols: &'a str,
    radix: u32,
}

/// The decimal digits, the alphabet of a card number.
pub const DIGITS: Alphabet<'static> = Alphabet {
    symbols: "0123456789",
    radix: 10,
};

impl<'a> Alphabet<'a> {
    /// An alphabet whose numeral `i` is the `i`th character of
    /// `symbols`. There must be 2 to 65536 of them, the radixes the
    /// modes take, or the count is [`Error::InvalidRadix`]; and none
    /// may repeat, or the first repeated one is
    /// [`Error::InvalidSymbol`].
    pub fn try_new(symbols: &'a str) -> Result<Self, Error> {
        let radix = symbols.chars().count();
        if !(2..=65536).contains(&radix) {
            let radix = radix.min(u32::MAX as usize) as u32;
            return Err(Error::InvalidRadix(radix));
        }
        for (i, c) in symbols.chars().enumerate() {
            if symbols.chars().take(i).any(|d| d == c) {
                return Err(Error::InvalidSymbol(c as u32));
            }
        }
        Ok(Alphabet {
            symbols,
            radix: radix as u32,
        })
    }

    /// The radix, to build the mode with.
    pub const fn radix(&self) -> u32 {
        self.radix
    }

    /// The characters, in numeral order.
    pub const fn symbols(&self) -> &'a str {
        self.symbols
    }

    /// Writes `text` as symbols into the front of `out`, one per
    /// character, returning how many. A character not in the
    /// alphabet is [`Error::InvalidSymbol`], carrying its code point.
    pub fn encode(&self, text: &str, out: &mut [u16]) -> Result<usize, Error> {
        let needed = text.chars().count();
        let out = out.get_mut(..needed).ok_or(Error::OutputTooSmall(needed))?;
        for (c, slot) in text.chars().zip(out.iter_mut()) {
            let i = self
                .symbols
                .chars()
                .position(|d| d == c)
                .ok_or(Error::InvalidSymbol(c as u32))?;
            *slot = i as u16;
        }
        Ok(needed)
    }

    /// Writes `symbols` as text, UTF-8, into the front of `out`,
    /// returning the length in bytes. A symbol at or above the radix
    /// is [`Error::InvalidSymbol`].
    pub fn decode(
        &self,
        symbols: &[u16],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut needed = 0;
        for &s in symbols {
            needed += self.character(s)?.len_utf8();
        }
        let out = out.get_mut(..needed).ok_or(Error::OutputTooSmall(needed))?;
        let mut n = 0;
        for &s in symbols {
            let c = self.character(s)?;
            n += c.encode_utf8(&mut out[n..]).len();
        }
        Ok(needed)
    }

    fn character(&self, symbol: u16) -> Result<char, Error> {
        self.symbols
            .chars()
            .nth(usize::from(symbol))
            .ok_or(Error::InvalidSymbol(u32::from(symbol)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_round_trip() {
        let mut symbols = [0u16; 4];
        assert_eq!(DIGITS.encode("0918", &mut symbols), Ok(4));
        assert_eq!(symbols, [0, 9, 1, 8]);
        let mut text = [0u8; 4];
        assert_eq!(DIGITS.decode(&symbols, &mut text), Ok(4));
        assert_eq!(&text, b"0918");
        assert_eq!(DIGITS.radix(), 10);
        assert_eq!(DIGITS, Alphabet::try_new("0123456789").unwrap());
    }

    #[test]
    fn any_characters_in_any_order() {
        // Multi-byte characters count as one symbol each, and the
        // numeral is the position, whatever the character.
        let alphabet = Alphabet::try_new("z\u{e9}\u{4e2d}0").unwrap();
        assert_eq!(alphabet.radix(), 4);
        let mut symbols = [0u16; 4];
        let n = alphabet.encode("0\u{4e2d}\u{e9}z", &mut symbols).unwrap();
        assert_eq!(&symbols[..n], &[3, 2, 1, 0]);
        let mut text = [0u8; 16];
        let m = alphabet.decode(&symbols[..n], &mut text).unwrap();
        assert_eq!(&text[..m], "0\u{4e2d}\u{e9}z".as_bytes());
        assert_eq!(alphabet.symbols(), "z\u{e9}\u{4e2d}0");
    }

    #[test]
    fn refuses_bad_alphabets() {
        assert_eq!(Alphabet::try_new(""), Err(Error::InvalidRadix(0)));
        assert_eq!(Alphabet::try_new("a"), Err(Error::InvalidRadix(1)));
        assert_eq!(
            Alphabet::try_new("abca"),
            Err(Error::InvalidSymbol(u32::from('a')))
        );
        assert!(Alphabet::try_new("ab").is_ok());
    }

    #[test]
    fn refuses_what_is_not_in_it() {
        let mut symbols = [0u16; 4];
        assert_eq!(
            DIGITS.encode("12a4", &mut symbols),
            Err(Error::InvalidSymbol(u32::from('a')))
        );
        let mut text = [0u8; 4];
        assert_eq!(
            DIGITS.decode(&[1, 10], &mut text),
            Err(Error::InvalidSymbol(10))
        );
    }

    #[test]
    fn sizes_the_output() {
        let mut symbols = [0u16; 2];
        assert_eq!(
            DIGITS.encode("123", &mut symbols),
            Err(Error::OutputTooSmall(3))
        );
        let alphabet = Alphabet::try_new("a\u{e9}").unwrap();
        let mut text = [0u8; 2];
        assert_eq!(
            alphabet.decode(&[1, 1], &mut text),
            Err(Error::OutputTooSmall(4))
        );
    }
}
