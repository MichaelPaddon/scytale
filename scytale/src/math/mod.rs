//! Arithmetic the primitives need beyond what the integer types give.
//!
//! At present this is only [`natural`], a bounded non-negative
//! integer, which the format-preserving modes use to move between a
//! string of symbols and the number it stands for. Public-key work
//! will want considerably more, and its shape should be decided by
//! writing that work rather than by guessing at it now.

pub(crate) mod natural;
