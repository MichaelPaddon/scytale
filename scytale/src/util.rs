//! Small helpers shared across the library.

/// Reports whether two byte strings are equal, without letting the
/// time taken reveal where they first differ.
///
/// Comparing an authentication tag with `==` would stop at the first
/// differing byte, and an attacker who can time that learns how much
/// of a guessed tag was right, one byte at a time. This reads every
/// byte of both, always.
pub(crate) fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    // The compiler is not allowed to look inside this, so it cannot
    // turn the accumulation above into an early exit.
    core::hint::black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_matches_ordinary_comparison() {
        assert!(equal(b"", b""));
        assert!(equal(b"abc", b"abc"));
        assert!(!equal(b"abc", b"abd"));
        assert!(!equal(b"abc", b"Abc"));
        assert!(!equal(b"abc", b"abcd"));
        assert!(!equal(b"abcd", b"abc"));
        assert!(!equal(b"", b"a"));
    }
}
