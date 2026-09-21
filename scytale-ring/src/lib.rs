//! ring's API, answered by scytale.
//!
//! This crate presents the public interface of
//! [ring](https://crates.io/crates/ring) 0.17, and does the work with
//! [scytale](https://crates.io/crates/scytale). It is not a fork: no
//! line of ring's implementation is here, and there is no C or
//! assembly to build. Code written against ring compiles against it
//! unchanged, because the library is named `ring`.
//!
//! Switch a crate over in its own manifest:
//!
//! ```toml
//! [dependencies]
//! ring = { package = "scytale-ring", version = "0.17" }
//! ```
//!
//! That reaches the crate whose manifest it is. It cannot reach a
//! dependency that names ring itself: cargo's `[patch]` matches a
//! replacement by its real package name, which this is not.
//!
//! # Where it differs from ring
//!
//! ECDSA signatures are deterministic here (RFC 6979), where ring
//! draws a random nonce. Both verify against the other, and the
//! random source ring asks for is accepted and not used, but a test
//! that compares signature bytes with stored ones will not match.
//!
//! The minimum Rust is scytale's, 1.88, where ring's is 1.66.

#![no_std]
#![forbid(unsafe_code)]

mod debug;

pub mod aead;
pub mod agreement;
pub mod digest;
pub mod error;
pub mod hkdf;
pub mod hmac;
pub mod rand;
pub mod rsa;
pub mod signature;

mod sealed {
    pub trait Sealed {}
}
