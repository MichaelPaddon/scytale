//! What GHASH uses on an architecture with nothing to accelerate it.
//!
//! Every architecture module offers the same items so that the code
//! using them needs no conditionals. Here the answer to "is there a
//! carry-less multiply" is no, and nothing else is ever reached.

// The signatures have to match the real ones.
#![allow(unsafe_code)]

/// How many blocks the group multiply takes at once. One means there
/// is no group multiply.
pub(super) const GROUP: usize = 1;

/// There is no carry-less multiply here.
pub(super) fn has_carryless_multiply() -> bool {
    false
}

/// Never called, because the subkey is never prepared.
pub(super) fn prepare(h: &[u64; 2]) -> [u64; 2] {
    *h
}

/// Never called, because the subkey is never prepared.
///
/// # Safety
/// Unreachable.
pub(super) unsafe fn multiply(_value: &mut [u64; 2], _h: &[u64; 2]) {
    unreachable!("no carry-less multiply on this architecture")
}

/// Never called: [`GROUP`] is one.
///
/// # Safety
/// Unreachable.
pub(super) unsafe fn multiply_group(
    _value: &mut [u64; 2],
    _powers: &[[u64; 2]; super::MAX_GROUP],
    _blocks: &[u8],
) {
    unreachable!("no group multiply on this architecture")
}
