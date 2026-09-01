//! Arithmetic the primitives need beyond what the integer types give.
//!
//! [`natural`] is a bounded non-negative integer, which the
//! format-preserving modes use to move between a string of symbols
//! and the number it stands for. [`fe25519`] is the field under
//! Curve25519, shared by X25519 and Ed25519. Further public-key work
//! will want considerably more, and its shape should be decided by
//! writing that work rather than by guessing at it now.

pub(crate) mod fe25519;
pub(crate) mod natural;
