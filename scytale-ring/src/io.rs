//! Reading DER, for callers that pick a structure apart themselves.

use crate::error;

/// A positive integer as DER holds it: big-endian, no leading zero.
#[derive(Copy, Clone)]
pub struct Positive<'a>(&'a [u8]);

impl<'a> Positive<'a> {
    fn from_be_bytes(bytes: &'a [u8]) -> Result<Self, error::Unspecified> {
        match bytes.first() {
            Some(&first) if first != 0 => Ok(Self(bytes)),
            _ => Err(error::Unspecified),
        }
    }

    /// The bytes, most significant first.
    #[inline]
    pub fn big_endian_without_leading_zero(&self) -> &'a [u8] {
        self.0
    }
}

impl Positive<'_> {
    /// The most significant byte, which is never zero.
    pub fn first_byte(&self) -> u8 {
        self.0[0]
    }
}

/// The DER reader ring shows its callers.
#[doc(hidden)]
pub mod der {
    use super::Positive;
    use crate::error;

    /// The bit that marks a constructed tag.
    pub const CONSTRUCTED: u8 = 1 << 5;

    /// The bits that mark a context-specific tag.
    pub const CONTEXT_SPECIFIC: u8 = 2 << 6;

    /// The tags read here.
    #[derive(Clone, Copy, PartialEq)]
    #[repr(u8)]
    #[allow(clippy::upper_case_acronyms, missing_docs)]
    pub enum Tag {
        Boolean = 0x01,
        Integer = 0x02,
        BitString = 0x03,
        OctetString = 0x04,
        Null = 0x05,
        OID = 0x06,
        Sequence = CONSTRUCTED | 0x10,
        UTCTime = 0x17,
        GeneralizedTime = 0x18,
        ContextSpecific1 = CONTEXT_SPECIFIC | 1,
        ContextSpecificConstructed0 = CONTEXT_SPECIFIC | CONSTRUCTED,
        ContextSpecificConstructed1 = CONTEXT_SPECIFIC | CONSTRUCTED | 1,
        ContextSpecificConstructed3 = CONTEXT_SPECIFIC | CONSTRUCTED | 3,
    }

    impl From<Tag> for usize {
        fn from(tag: Tag) -> Self {
            Self::from(Tag::into(tag))
        }
    }

    impl From<Tag> for u8 {
        fn from(tag: Tag) -> Self {
            Tag::into(tag)
        }
    }

    impl Tag {
        /// The tag's byte.
        #[allow(clippy::wrong_self_convention)]
        pub const fn into(self) -> u8 {
            self as u8
        }
    }

    /// The contents of the next element, which must have tag `tag`.
    pub fn expect_tag_and_get_value<'a>(
        input: &mut untrusted::Reader<'a>,
        tag: Tag,
    ) -> Result<untrusted::Input<'a>, error::Unspecified> {
        let (actual_tag, inner) = read_tag_and_get_value(input)?;
        if usize::from(tag) != usize::from(actual_tag) {
            return Err(error::Unspecified);
        }
        Ok(inner)
    }

    /// The next element's tag and contents. Lengths are read in the
    /// short form and the one- and two-byte long forms, each only in
    /// its canonical use.
    pub fn read_tag_and_get_value<'a>(
        input: &mut untrusted::Reader<'a>,
    ) -> Result<(u8, untrusted::Input<'a>), error::Unspecified> {
        let tag = input.read_byte()?;
        if (tag & 0x1f) == 0x1f {
            return Err(error::Unspecified);
        }
        let length = match input.read_byte()? {
            n if (n & 0x80) == 0 => usize::from(n),
            0x81 => {
                let second = input.read_byte()?;
                if second < 128 {
                    return Err(error::Unspecified);
                }
                usize::from(second)
            }
            0x82 => {
                let second = usize::from(input.read_byte()?);
                let third = usize::from(input.read_byte()?);
                let combined = (second << 8) | third;
                if combined < 256 {
                    return Err(error::Unspecified);
                }
                combined
            }
            _ => return Err(error::Unspecified),
        };
        let inner = input.read_bytes(length)?;
        Ok((tag, inner))
    }

    /// The contents of a BIT STRING whose bits fill whole bytes.
    #[inline]
    pub fn bit_string_with_no_unused_bits<'a>(
        input: &mut untrusted::Reader<'a>,
    ) -> Result<untrusted::Input<'a>, error::Unspecified> {
        nested(input, Tag::BitString, error::Unspecified, |value| {
            let unused = value.read_byte().map_err(|_| error::Unspecified)?;
            if unused != 0 {
                return Err(error::Unspecified);
            }
            Ok(value.read_bytes_to_end())
        })
    }

    /// Runs `decoder` over the contents of the next element, which
    /// must have tag `tag` and be read entirely.
    pub fn nested<'a, F, R, E: Copy>(
        input: &mut untrusted::Reader<'a>,
        tag: Tag,
        error: E,
        decoder: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&mut untrusted::Reader<'a>) -> Result<R, E>,
    {
        let inner = expect_tag_and_get_value(input, tag).map_err(|_| error)?;
        inner.read_all(error, decoder)
    }

    fn nonnegative_integer<'a>(
        input: &mut untrusted::Reader<'a>,
    ) -> Result<&'a [u8], error::Unspecified> {
        let value = expect_tag_and_get_value(input, Tag::Integer)?;
        let value = value.as_slice_less_safe();
        match value.split_first().ok_or(error::Unspecified)? {
            (0, rest) => match rest.first() {
                None => Ok(value),
                Some(&second) if second & 0x80 == 0x80 => Ok(rest),
                _ => Err(error::Unspecified),
            },
            (first, _) if first & 0x80 == 0 => Ok(value),
            (_, _) => Err(error::Unspecified),
        }
    }

    /// The next INTEGER, which must fit one byte.
    #[inline]
    pub fn small_nonnegative_integer(
        input: &mut untrusted::Reader,
    ) -> Result<u8, error::Unspecified> {
        match *nonnegative_integer(input)? {
            [b] => Ok(b),
            _ => Err(error::Unspecified),
        }
    }

    /// The next INTEGER, which must be positive.
    pub fn positive_integer<'a>(
        input: &mut untrusted::Reader<'a>,
    ) -> Result<Positive<'a>, error::Unspecified> {
        Positive::from_be_bytes(nonnegative_integer(input)?)
    }
}

#[cfg(test)]
mod tests {
    use super::der::*;
    use crate::error;

    type Read<'a, R> =
        fn(&mut untrusted::Reader<'a>) -> Result<R, error::Unspecified>;

    fn read<'a, R>(
        bytes: &'a [u8],
        f: Read<'a, R>,
    ) -> Result<R, error::Unspecified> {
        untrusted::Input::from(bytes).read_all(error::Unspecified, f)
    }

    #[test]
    fn integers_are_read_in_their_canonical_forms() {
        let small = |b: &[u8]| read(b, small_nonnegative_integer);
        assert_eq!(small(&[0x02, 0x01, 0x00]), Ok(0));
        assert_eq!(small(&[0x02, 0x01, 0x7f]), Ok(0x7f));
        assert_eq!(small(&[0x02, 0x02, 0x00, 0x80]), Ok(0x80));
        assert_eq!(small(&[0x02, 0x01, 0x80]), Err(error::Unspecified));
        assert_eq!(small(&[0x02, 0x02, 0x00, 0x01]), Err(error::Unspecified));
        let positive = |b: &[u8]| {
            read(b, positive_integer)
                .map(|p| p.big_endian_without_leading_zero().to_vec())
        };
        assert_eq!(positive(&[0x02, 0x01, 0x00]), Err(error::Unspecified));
        assert_eq!(positive(&[0x02, 0x02, 0x00, 0xff]), Ok(alloc::vec![0xff]));
    }

    #[test]
    fn lengths_are_read_in_every_canonical_form() {
        let long = [0x04, 0x81, 0x80].iter().chain([7u8; 128].iter());
        let long: alloc::vec::Vec<u8> = long.copied().collect();
        let got =
            read(&long, |r| expect_tag_and_get_value(r, Tag::OctetString))
                .expect("long form");
        assert_eq!(got.len(), 128);
        assert!(
            read(&[0x04, 0x81, 0x01, 0x00], |r| {
                expect_tag_and_get_value(r, Tag::OctetString)
            })
            .is_err()
        );
        assert!(
            read(&[0x04, 0x01, 0x00], |r| {
                expect_tag_and_get_value(r, Tag::Sequence)
            })
            .is_err()
        );
    }
}
