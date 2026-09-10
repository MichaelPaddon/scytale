//! Values an aligned vector load can reach.
//!
//! A constant that assembly addresses by symbol has to be aligned to
//! the width of the load that reads it, which Rust expresses as an
//! attribute on a type rather than on the value. So a wrapper, and two
//! of them, because alignment cannot be a const generic parameter: one
//! for the 128-bit loads and one for the 256-bit.
//!
//! The field is read by the assembly rather than by Rust, which in
//! several cases means Rust never reads it at all. That is what the
//! `dead_code` exemption here is for, and having it in one place is
//! most of the reason these are not written out wherever they are
//! wanted. The types themselves are exempt too, since which of the
//! two an architecture wants depends on the width of its registers.

#![allow(dead_code)]

/// A value a 128-bit load can reach.
#[derive(Clone, Copy)]
#[repr(align(16))]
pub(crate) struct At16<T>(pub(crate) T);

/// A value a 256-bit load can reach.
#[derive(Clone, Copy)]
#[repr(align(32))]
pub(crate) struct At32<T>(pub(crate) T);

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point is the address, so that is what is checked.
    #[test]
    fn the_wrappers_align_what_they_hold() {
        static SIXTEEN: At16<[u8; 16]> = At16([0; 16]);
        static THIRTY_TWO: At32<[u8; 32]> = At32([0; 32]);
        assert_eq!(SIXTEEN.0.as_ptr() as usize % 16, 0);
        assert_eq!(THIRTY_TWO.0.as_ptr() as usize % 32, 0);
    }

    /// Alignment is of the wrapper, so it holds whatever the
    /// assembly wants: bytes, words, or an array of pairs.
    #[test]
    fn the_wrappers_hold_anything() {
        static WORDS: At16<[u32; 8]> = At16([1, 2, 3, 4, 5, 6, 7, 8]);
        static PAIRS: At32<[[u64; 2]; 2]> = At32([[1, 2], [3, 4]]);
        assert_eq!(WORDS.0[7], 8);
        assert_eq!(PAIRS.0[1][0], 3);
        assert_eq!(WORDS.0.as_ptr() as usize % 16, 0);
        assert_eq!(PAIRS.0.as_ptr() as usize % 32, 0);
    }
}
