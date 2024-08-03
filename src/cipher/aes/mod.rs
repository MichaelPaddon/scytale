#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[cfg(target_feature = "aes")]
pub mod x86;

//pub use self::soft::Aes128;
//pub use self::soft::Aes192;
//pub use self::soft::Aes256;

//#[cfg(test)]
//mod test;
