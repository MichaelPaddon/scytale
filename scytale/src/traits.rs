//! The traits every module shares: the vocabulary for saying what
//! block a type works in, what key it takes, where random bytes
//! come from, and how a byte slice is cut into arrays.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

/// A type that works in blocks of one fixed type: `[u8; 16]` for
/// AES, `[u8; 64]` for SHA-256.
///
/// The block is a type rather than a size so that it is checked
/// where it is used, and so that the traits built on it stay usable
/// as objects: `dyn BlockCipher<Block = [u8; 16]>` names it and
/// carries no constant.
pub trait BlockType {
    /// The block.
    ///
    /// [`ByteArray`] rather than a bare bound, because everything
    /// that works in blocks eventually cuts a message into them.
    type Block: ByteArray;

    /// A block of zeros, to encrypt in place or fill.
    ///
    /// Generic code has no other way to make one: the length is the
    /// block type's alone.
    fn zero_block() -> Self::Block
    where
        Self: Sized;
}

/// A type constructed from a key of one fixed type: [`Key<[u8; 16]>`](Key)
/// for AES-128, `Key<[u8; 32]>` for Poly1305.
///
/// The key is a type rather than a length so that the wrong one is
/// a compile error, and so that generic code can make one to fill
/// from a random source.
///
/// A bare array cannot be the key, because it cannot wipe itself:
///
/// ```compile_fail
/// use scytale::KeyType;
///
/// struct MyCipher;
///
/// impl KeyType for MyCipher {
///     // `[u8; 16]` is `Copy`, so it can have no `Drop`.
///     type Key = [u8; 16];
///
///     fn zero_key() -> Self::Key {
///         [0; 16]
///     }
/// }
/// ```
pub trait KeyType {
    /// The key.
    ///
    /// It wipes itself when it is dropped, which is why it is not a
    /// bare array: a `Copy` type may not implement `Drop`, so an
    /// array cannot erase itself and every copy of one is silent.
    /// [`Key`] is the type that satisfies this.
    type Key: ZeroizeOnDrop + Clone + AsRef<[u8]> + AsMut<[u8]>;

    /// A key of zeros, to fill from a random source.
    fn zero_key() -> Self::Key
    where
        Self: Sized;

    /// A key drawn from `rng`.
    ///
    /// The whole of it comes from `rng`, so a source that cannot
    /// fill it yields no key rather than a short one.
    ///
    /// `rng` is an object rather than a type parameter so that this
    /// trait, and the traits built on it, stay usable as objects
    /// themselves. The call happens once per key.
    fn random_key(rng: &mut dyn Random) -> Result<Self::Key, Error>
    where
        Self: Sized,
    {
        let mut key = Self::zero_key();
        rng.fill(key.as_mut())?;
        Ok(key)
    }
}

/// A source of random bytes fit to use.
///
/// [`Rng`](crate::random::Rng) is the one that matters. The trait
/// exists so that work which consumes randomness can be handed a
/// fixed sequence instead and tested for an exact answer, and so
/// that a caller with a generator of their own can bring it.
///
/// This is not where raw entropy goes: see
/// [`Entropy`](crate::random::Entropy), which is kept apart so that
/// unconditioned bits cannot reach a caller by mistake.
pub trait Random {
    /// Fills the whole of `out`, or fails without leaving anything
    /// worth relying on.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;
}

/// A secret, wiped when it is dropped.
///
/// `B` is the byte array the secret is held in, so the width is a
/// type: `Key<[u8; 16]>` is an AES-128 key and nothing else will
/// pass for one. It is generic over the array rather than over a
/// length because HMAC's key is its hash's block, which is a type
/// with no length to name.
///
/// Deliberately not `Copy`, which is what makes the wipe possible
/// and makes a second copy of a key something someone wrote. The
/// bytes come back out through [`AsRef`] and [`AsMut`] only: there
/// is no dereference to the array, so no expression quietly puts
/// the secret back where nothing will erase it.
///
/// Wiping this wipes this. A caller who has the same bytes in an
/// array of their own still holds them; [`Key::take`] is the way to
/// hand those over and have them erased.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key<B: ByteArray>(B);

impl<B: ByteArray> Key<B> {
    /// A key of zeros, to fill in place.
    pub fn zeroed() -> Self {
        Key(B::zeroed())
    }

    /// Takes the key out of `bytes`, wiping `bytes`.
    ///
    /// A key usually arrives in an array somebody else owns: read
    /// from a file, derived into a buffer, handed over by a
    /// protocol. That array is the copy nothing erases, so this
    /// erases it.
    pub fn take(bytes: &mut B) -> Self {
        let key = Key(*bytes);
        bytes.zeroize();
        key
    }

    /// The bytes as the array they are.
    ///
    /// A borrow, not a copy, and crate-internal: an implementation
    /// that expands a key wants the array's width, and a caller
    /// wants no way to lift the secret back out into one.
    pub(crate) fn array(&self) -> &B {
        &self.0
    }

    /// A key drawn from `rng`.
    pub fn random(rng: &mut dyn Random) -> Result<Self, Error> {
        let mut key = Self::zeroed();
        rng.fill(key.as_mut())?;
        Ok(key)
    }
}

impl<B: ByteArray> From<B> for Key<B> {
    /// Takes ownership of the bytes. The caller's own copy, if the
    /// array was one, is theirs to wipe; [`Key::take`] does it.
    fn from(bytes: B) -> Self {
        Key(bytes)
    }
}

impl<B: ByteArray> TryFrom<&[u8]> for Key<B> {
    type Error = Error;

    /// Refuses any length but this key's, as
    /// [`Error::InvalidKeyLength`].
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        let mut key = Self::zeroed();
        if key.as_ref().len() != bytes.len() {
            return Err(Error::InvalidKeyLength(bytes.len()));
        }
        key.as_mut().copy_from_slice(bytes);
        Ok(key)
    }
}

impl<B: ByteArray> AsRef<[u8]> for Key<B> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<B: ByteArray> AsMut<[u8]> for Key<B> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<B: ByteArray> PartialEq for Key<B> {
    /// Constant time, since one of these is a secret.
    fn eq(&self, other: &Self) -> bool {
        crate::util::equal(self.as_ref(), other.as_ref())
    }
}

impl<B: ByteArray> Eq for Key<B> {}

impl<B: ByteArray> fmt::Debug for Key<B> {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("bytes", &self.as_ref().len())
            .finish()
    }
}

/// A fixed-size byte array, and the mechanism for cutting a byte
/// slice into a slice of them and back.
///
/// Implemented for every `[u8; N]`. Code that runs a block cipher
/// over a message bounds the cipher's block with this so that it can
/// hand the cipher whole blocks; nothing else needs it.
pub trait ByteArray: Copy + Zeroize + AsRef<[u8]> + AsMut<[u8]> {
    /// An array of zeros.
    fn zeroed() -> Self;

    /// Splits `data` into whole arrays and the bytes left over.
    fn split(data: &[u8]) -> (&[Self], &[u8]);

    /// Splits `data` into whole arrays and the bytes left over.
    fn split_mut(data: &mut [u8]) -> (&mut [Self], &mut [u8]);

    /// The arrays as the bytes they are.
    fn flatten(arrays: &[Self]) -> &[u8];

    /// The arrays as the bytes they are.
    fn flatten_mut(arrays: &mut [Self]) -> &mut [u8];
}

impl<const N: usize> ByteArray for [u8; N] {
    fn zeroed() -> Self {
        [0; N]
    }

    fn split(data: &[u8]) -> (&[Self], &[u8]) {
        data.as_chunks::<N>()
    }

    fn split_mut(data: &mut [u8]) -> (&mut [Self], &mut [u8]) {
        data.as_chunks_mut::<N>()
    }

    fn flatten(arrays: &[Self]) -> &[u8] {
        arrays.as_flattened()
    }

    fn flatten_mut(arrays: &mut [Self]) -> &mut [u8] {
        arrays.as_flattened_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::Aes128;

    /// The array a key came from is wiped, which is the copy nobody
    /// would have remembered.
    #[test]
    fn take_wipes_its_source() {
        let mut bytes = [0x5au8; 16];
        let key = Key::take(&mut bytes);
        assert_eq!(bytes, [0u8; 16]);
        assert_eq!(key.as_ref(), &[0x5au8; 16]);
    }

    /// A wrong length is refused rather than padded or truncated.
    #[test]
    fn try_from_checks_the_length() {
        assert!(Key::<[u8; 16]>::try_from(&[7u8; 16][..]).is_ok());
        assert_eq!(
            Key::<[u8; 16]>::try_from(&[7u8; 15][..]).unwrap_err(),
            Error::InvalidKeyLength(15)
        );
    }

    /// Debug says how wide the key is and nothing about it.
    #[test]
    fn debug_omits_the_key() {
        struct Writer<'a>(&'a mut [u8], usize);

        impl fmt::Write for Writer<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let end = self.1 + s.len();
                self.0
                    .get_mut(self.1..end)
                    .ok_or(fmt::Error)?
                    .copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }

        let key = Key::from([0xabu8; 16]);
        let mut buf = [0u8; 64];
        let mut w = Writer(&mut buf, 0);
        fmt::write(&mut w, format_args!("{key:?}")).unwrap();
        let len = w.1;
        let text = core::str::from_utf8(&buf[..len]).unwrap();
        assert!(!text.contains("ab"), "{text}");
        assert!(text.contains("16"), "{text}");
    }

    /// Generic code draws a key of the right width without knowing
    /// the cipher, and takes every byte of it from the source.
    #[test]
    fn random_key_comes_from_the_source() {
        struct Counting(u8);
        impl Random for Counting {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
                for byte in out.iter_mut() {
                    self.0 = self.0.wrapping_add(1);
                    *byte = self.0;
                }
                Ok(())
            }
        }
        let key = Aes128::random_key(&mut Counting(0)).unwrap();
        let mut expected = [0u8; 16];
        for (i, byte) in expected.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        assert_eq!(key.as_ref(), &expected[..]);
    }

    #[test]
    fn split_and_flatten_round_trip() {
        let mut data = [0u8; 37];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let (whole, rest) = <[u8; 16]>::split(&data);
        assert_eq!(whole.len(), 2);
        assert_eq!(rest, &data[32..]);
        assert_eq!(<[u8; 16]>::flatten(whole), &data[..32]);

        let (whole, rest) = <[u8; 16]>::split_mut(&mut data);
        whole[1][0] = 0xff;
        rest[0] = 0xee;
        assert_eq!(<[u8; 16]>::flatten_mut(whole)[16], 0xff);
        assert_eq!(data[16], 0xff);
        assert_eq!(data[32], 0xee);
    }
}
