use hybrid_array::{Array, ArraySize};
use crate::error::Error;

pub trait KeySize {
    type KeySize: ArraySize;
}

pub trait BlockSize {
    type BlockSize: ArraySize;
}

pub trait NewFromKey: KeySize {
    fn new(key: &[u8]) -> Result<Self, Error> where Self: Sized;
}

pub trait Rekey: KeySize {
    fn rekey(&mut self, key: &[u8]) -> Result<(), Error>;
}

pub trait EncryptBlocks: BlockSize {
    fn encrypt_blocks(
        &self,
        plaintext: &[Array<u8, Self::BlockSize>],
        ciphertext: &mut [Array<u8, Self::BlockSize>]
    );
}

pub trait DecryptBlocks: BlockSize {
    fn decrypt_blocks(
        &self,
        ciphertext: &[Array<u8, Self::BlockSize>],
        plaintext: &mut [Array<u8, Self::BlockSize>]
    );
}

pub trait EncryptingBlockCipher: NewFromKey + Rekey + EncryptBlocks {}
pub trait DecryptingBlockCipher: NewFromKey + Rekey + DecryptBlocks {}
pub trait BlockCipher: EncryptingBlockCipher + DecryptingBlockCipher {}

pub mod aes;
