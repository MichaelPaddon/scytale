//! Arithmetic the primitives need beyond what the integer types give.
//!
//! [`natural`] is a bounded non-negative integer, which the
//! format-preserving modes use to move between a string of symbols
//! and the number it stands for. [`fe25519`] is the field under
//! Curve25519, shared by X25519 and Ed25519. [`uint`] is an unsigned
//! integer of any fixed width, and [`montgomery`] the multiplication
//! and exponentiation modulo an odd number built on it, which is the
//! arithmetic under RSA.

pub(crate) mod fe25519;
pub(crate) mod montgomery;
pub(crate) mod natural;
pub(crate) mod uint;
