use typenum::Unsigned;
use crate::error::Error;

pub trait KeySize {
    type KeySize: Unsigned;
}

pub trait BlockSize {
    type BlockSize: Unsigned;
}

pub trait BlockCipher: KeySize + BlockSize {
    fn new(key: &[u8]) -> Result<Self, Error> where Self: Sized;

    fn new_encrypt_only(key: &[u8]) -> Result<Self, Error> where Self: Sized {
        Self::new(key)
    }

    fn new_decrypt_only(key: &[u8]) -> Result<Self, Error> where Self: Sized {
        Self::new(key)
    }

    fn encrypt(&self, plaintext: &[u8], ciphertext: &mut [u8]);
    fn decrypt(&self, ciphertext: &[u8], plaintext: &mut [u8]);
}

pub mod aes;
