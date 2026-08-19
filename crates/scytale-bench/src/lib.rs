//! Benchmark support for comparing scytale against OpenSSL.
//!
//! OpenSSL is cloned and built by this crate's build script, never vendored.
//! While scytale has only software implementations, that build is configured
//! `no-asm` so the comparison is software against software.

pub mod cycles;
pub mod harness;
pub mod openssl;
