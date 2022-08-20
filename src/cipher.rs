#[allow(dead_code)]
#[derive(PartialEq)]
pub enum KeyUsage {
    EncryptOnly,
    DecryptOnly,
    EncryptAndDecrypt
}

pub trait BlockCipher {
    type Key;
    type Block;

    fn new(key: &Self::Key, usage: KeyUsage) -> Self;
    fn rekey(&mut self, key: &Self::Key, usage: KeyUsage);
    fn encrypt(&self, plaintext: &Self::Block, ciphertext: &mut Self::Block);
    fn decrypt(&self, ciphertext: &Self::Block, plaintext: &mut Self::Block);
}

pub mod aes;
