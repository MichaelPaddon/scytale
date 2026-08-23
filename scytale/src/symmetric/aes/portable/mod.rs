//! Portable AES implementations, in plain Rust for any target.
//!
//! [`bitsliced`] is constant time and is what the automatic choice
//! falls back to. [`Aes`] is the faster table-driven version, which
//! leaks through cache timing; read its documentation before using it.

pub mod bitsliced;
pub(crate) mod ttable;

pub use ttable::Aes;
