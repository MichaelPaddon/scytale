//! Portable AES implementations, in plain Rust for any target.
//!
//! Two peers, neither of them the default: [`bitsliced`] is constant
//! time, and [`ttable`] is roughly twice as fast but indexes lookup
//! tables with bytes derived from the key, so it leaks through cache
//! timing. [`Aes`](crate::cipher::aes::Aes) picks the bitsliced one
//! when the processor has no AES instructions, and never picks the
//! other; read [`ttable`]'s documentation before naming it.

pub mod bitsliced;
pub mod ttable;
