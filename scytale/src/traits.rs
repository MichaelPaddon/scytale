//! The traits every module shares: the vocabulary for saying what
//! block a type works in, what key it takes, and how a byte slice
//! is cut into arrays.

/// A type that works in blocks of one fixed type: `[u8; 16]` for
/// AES, `[u8; 64]` for SHA-256.
///
/// The block is a type rather than a size so that it is checked
/// where it is used, and so that the traits built on it stay usable
/// as objects: `dyn BlockCipher<Block = [u8; 16]>` names it and
/// carries no constant.
pub trait BlockType {
    /// The block.
    type Block: Copy + AsRef<[u8]> + AsMut<[u8]>;

    /// A block of zeros, to encrypt in place or fill.
    ///
    /// Generic code has no other way to make one: the length is the
    /// block type's alone.
    fn zero_block() -> Self::Block
    where
        Self: Sized;
}

/// A type constructed from a key of one fixed type: `[u8; 16]` for
/// AES-128, `[u8; 32]` for Poly1305.
///
/// The key is a type rather than a length so that the wrong one is
/// a compile error, and so that generic code can make one to fill
/// from a random source.
pub trait KeyType {
    /// The key.
    type Key: Copy + AsRef<[u8]> + AsMut<[u8]>;

    /// A key of zeros, to fill from a random source.
    fn zero_key() -> Self::Key
    where
        Self: Sized;
}

/// A fixed-size byte array, and the mechanism for cutting a byte
/// slice into a slice of them and back.
///
/// Implemented for every `[u8; N]`. Code that runs a block cipher
/// over a message bounds the cipher's block with this so that it can
/// hand the cipher whole blocks; nothing else needs it.
pub trait ByteArray: Copy + AsRef<[u8]> + AsMut<[u8]> {
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
