use hybrid_array::{Array, ArraySize};
use crate::error::Error;

/// A trait for types that use fixed length keys.
pub trait KeySize {
    /// The key size (conventionally in bytes).
    type KeySize: ArraySize;
}

/// A trait for types that use fixed length blocks.
pub trait BlockSize {
    /// The block size (conventionally in bytes).
    type BlockSize: ArraySize;
}

/// A trait for types that are created using a key.
pub trait NewUsingKey: KeySize {
    /// Returns a new instance.
    fn new(key: &[u8]) -> Result<Self, Error> where Self: Sized;
}

/// A trait for types that can modify their key.  .
pub trait Rekey: KeySize {
    /// Replaces the active key.
    fn rekey(&mut self, key: &[u8]) -> Result<(), Error>;
}

/// A trait for types that encrypt blocks.
pub trait EncryptBlocks: BlockSize {
    fn encrypt_blocks(
        &mut self,
        plaintext: &[Array<u8, Self::BlockSize>],
        ciphertext: &mut [Array<u8, Self::BlockSize>]
    );
}

/// A trait for types that decrypt blocks.
pub trait DecryptBlocks: BlockSize {
    fn decrypt_blocks(
        &mut self,
        ciphertext: &[Array<u8, Self::BlockSize>],
        plaintext: &mut [Array<u8, Self::BlockSize>]
    );
}

/// A marker trait for a block cipher that can perform encryption.
pub trait EncryptingBlockCipher: NewUsingKey + Rekey + EncryptBlocks {}

/// A marker trait for a block cipher that can perform decryption.
pub trait DecryptingBlockCipher: NewUsingKey + Rekey + DecryptBlocks {}

/// A marker trait for a block cipher that can perform
/// encryption and decryption.
pub trait BlockCipher: EncryptingBlockCipher + DecryptingBlockCipher {}

pub trait BlockCipher2{
    type KeySize: ArraySize;
    type BlockSize: ArraySize;

    fn new(key: &[u8]) -> Result<Self, Error> where Self: Sized;

    fn rekey(&mut self, key: &[u8]) -> Result<(), Error>;

    fn encrypt_blocks(
        &mut self,
        plaintext: &[Array<u8, Self::BlockSize>],
        ciphertext: &mut [Array<u8, Self::BlockSize>]
    );

    fn decrypt_blocks(
        &mut self,
        ciphertext: &[Array<u8, Self::BlockSize>],
        plaintext: &mut [Array<u8, Self::BlockSize>]
    );
}

macro_rules! impl_key_size {
    ($name: ident, $key_size: ty) => {
        impl KeySize for $name {
            type KeySize = $key_size;
        }
    }
}

macro_rules! impl_block_size {
    ($name: ident, $block_size: ty) => {
        impl BlockSize for $name {
            type BlockSize = $block_size;
        }
    }
}

macro_rules! impl_new_from_key_for_enum {
    (
        $name: ident,
        $(
            if $expr: expr => $variant: ident ( $type: ty )
        ),*,
        $default: ident ( $default_type: ty )
    ) => {
        impl NewUsingKey for $name {
            fn new(key: &[u8]) -> Result<Self, Error> {
                $(
                    if $expr {
                        return Ok(Self::$variant(<$type>::new(key)?));
                    }
                )*
                Ok(Self::$default(<$default_type>::new(key)?))
            }
        }
    }
}

macro_rules! impl_rekey_for_enum {
    ($name: ident, $( $variant: ident ),+) => {
        impl Rekey for $name {
            fn rekey(&mut self, key: &[u8]) -> Result<(), Error> {
                match self {
                    $(
                        Self::$variant(inner) => inner.rekey(key),
                    )+
                }
            }
        }
    }
}

macro_rules! impl_encrypt_blocks_for_enum {
    ($name: ident, $( $variant: ident ),+) => {
        impl EncryptBlocks for $name {
            fn encrypt_blocks(
                &self,
                plaintext: &[Array<u8, Self::BlockSize>],
                ciphertext: &mut [Array<u8, Self::BlockSize>]
            ) {
                match self {
                    $(
                        Self::$variant(inner) =>
                            inner.encrypt_blocks(plaintext, ciphertext),
                    )+
                }
            }
        }
    }
}

macro_rules! impl_decrypt_blocks_for_enum {
    ($name: ident, $( $variant: ident ),+) => {
        impl DecryptBlocks for $name {
            fn decrypt_blocks(
                &self,
                ciphertext: &[Array<u8, Self::BlockSize>],
                plaintext: &mut [Array<u8, Self::BlockSize>]
            ) {
                match self {
                    $(
                        Self::$variant(inner) =>
                            inner.decrypt_blocks(ciphertext, plaintext),
                    )+
                }
            }
        }
    }
}

macro_rules! define_block_cipher_enum_base {
    (
        $vis: vis,
        $name: ident,
        $(
            if $expr: expr => $variant: ident ( $type: ty )
        ),*,
        $default: ident ( $default_type: ty )
    ) => {
        $vis enum $name {
            $(
                $variant($type),
            )*
            $default($default_type)
        }

        impl_key_size!{$name, <$default_type as KeySize>::KeySize}
        impl_block_size!{$name, <$default_type as BlockSize>::BlockSize}
        impl_new_from_key_for_enum!{
            $name,
            $(if $expr => $variant($type))*,
            $default($default_type)
        }
        impl_rekey_for_enum!{$name, $($variant)*, $default}
    }
}

macro_rules! define_encrypting_block_cipher_enum {
    (
        $vis: vis,
        $name: ident,
        $(
            if $expr: expr => $variant: ident ( $type: ty )
        ),*,
        $default: ident ( $default_type: ty )
    ) => {
        define_block_cipher_enum_base!{
            $vis,
            $name,
            $(if $expr => $variant($type))*,
            $default($default_type)
        }
        impl_encrypt_blocks_for_enum!{$name, $($variant)*, $default}
        impl EncryptingBlockCipher for $name {}
    }
}

/*
macro_rules! define_decrypting_block_cipher_enum {
    (
        $vis: vis,
        $name: ident,
        $(
            if $expr: expr => $variant: ident ( $type: ty )
        ),*,
        $default: ident ( $default_type: ty )
    ) => {
        define_block_cipher_enum_base!{
            $vis,
            $name,
            $(if $expr => $variant($type))*,
            $default($default_type)
        }
        impl_decrypt_blocks_for_enum!{$name, $($variant)*, $default}
        impl DecryptingBlockCipher for $name {}
    }
}
*/

macro_rules! define_block_cipher_enum {
    (
        $vis: vis,
        $name: ident,
        $(
            if $expr: expr => $variant: ident ( $type: ty )
        ),*,
        $default: ident ( $default_type: ty )
    ) => {
        define_block_cipher_enum_base!{
            $vis,
            $name,
            $(if $expr => $variant($type))*,
            $default($default_type)
        }
        impl_encrypt_blocks_for_enum!{$name, $($variant)*, $default}
        impl_decrypt_blocks_for_enum!{$name, $($variant)*, $default}
        impl EncryptingBlockCipher for $name {}
        impl DecryptingBlockCipher for $name {}
        impl BlockCipher for $name {}
    }
}

pub mod aes;
