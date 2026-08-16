//! AES, as specified in FIPS-197.
//!
//! Name [`Aes128`], [`Aes192`] or [`Aes256`] to get the best implementation
//! available on the machine the code is actually running on. Reach into
//! [`arch`] only to pin one exact implementation.
//!
//! Each key size has three types. The `Enc` and `Dec` types hold a single
//! key schedule; the bare name holds both and costs about twice as much to
//! construct. Prefer `Aes128Enc` when you never decrypt.

pub mod arch;

// Only the portable backend exists so far, so "best available" is that. When
// a second backend lands these re-exports become the runtime dispatch point;
// the names callers use do not change.
pub use arch::portable::ttable::{
    Aes128, Aes128Dec, Aes128Enc, Aes192, Aes192Dec, Aes192Enc, Aes256,
    Aes256Dec, Aes256Enc, BLOCK_SIZE,
};
