//! Symmetric primitives: block ciphers and the modes built on them.

pub mod aes;
pub mod block_cipher;

pub use block_cipher::{
    BlockDecrypt, BlockEncrypt, InvalidKeyLength, KeyInit,
};
