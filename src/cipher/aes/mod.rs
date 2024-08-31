//! The Advanced Encryption Standard (AES) is a block cipher, defined in
//! [FIPS PUB 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).

use cfg_if::cfg_if;

pub mod fast;
pub mod soft;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;

cfg_if!{
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        pub type Aes128 = x86::Aes128;
        pub type Aes192 = x86::Aes192;
        pub type Aes256 = x86::Aes256;
        pub type Aes128Encrypt = x86::Aes128Encrypt;
        pub type Aes192Encrypt = x86::Aes192Encrypt;
        pub type Aes256Encrypt = x86::Aes256Encrypt;
    } else {
        pub type Aes128 = soft::Aes128;
        pub type Aes192 = soft::Aes192;
        pub type Aes256 = soft::Aes256;
        pub type Aes128Encrypt = soft::Aes128;
        pub type Aes192Encrypt = soft::Aes192;
        pub type Aes256Encrypt = soft::Aes256;
    }
}
