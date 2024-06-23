use hybrid_array::{Array, ArraySize};
use crate::InvalidKeyLengthError;

pub trait BlockCipher {
    type BlockSize: ArraySize;

    fn new(key: impl AsRef<[u8]>)
        -> Result<Self, InvalidKeyLengthError> where Self: Sized;
    fn encrypt(&self, block: &Array<u8, Self::BlockSize>)
        -> Array<u8, Self::BlockSize>;
    fn decrypt(&self, block: &Array<u8, Self::BlockSize>)
        -> Array<u8, Self::BlockSize>;
}

pub mod aes;
