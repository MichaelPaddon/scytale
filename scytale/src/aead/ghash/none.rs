//! What GHASH uses on an architecture with nothing to accelerate it.
//!
//! Every architecture module offers the same items so that the code
//! using them needs no conditionals. Here the answer to "is there a
//! carry-less multiply" is no, and nothing else is ever reached.

// The signatures have to match the real ones.
#![allow(unsafe_code)]

/// The carry-less multiply this architecture does not have. There
/// is no value of the type, so a hash holding one cannot exist, and
/// the calls below are never made; the type says so rather than a
/// panic.
#[derive(Clone, Copy)]
pub(crate) enum Multiply {}

/// Never anything: there is no multiply to find.
pub(crate) fn probe() -> Option<Multiply> {
    None
}

impl Multiply {
    pub(crate) fn group(self) -> usize {
        match self {}
    }

    pub(super) fn prepare(self, _h: &[u64; 2]) -> [u64; 2] {
        match self {}
    }

    pub(super) fn multiply(self, _value: &mut [u64; 2], _h: &[u64; 2]) {
        match self {}
    }

    pub(crate) fn multiply_group(
        self,
        _value: &mut [u64; 2],
        _powers: &[[u64; 2]; super::MAX_GROUP],
        _blocks: &[u8],
    ) {
        match self {}
    }
}
