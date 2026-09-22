//! Comparing secrets without timing them. Deprecated in ring, and
//! kept for the code that still calls it.

use crate::error;

/// Whether `a` and `b` are the same bytes, in time that depends only
/// on their lengths.
#[deprecated(
    note = "To be removed. Internal function not intended for external \
            use with no promises regarding side channels."
)]
pub fn verify_slices_are_equal(
    a: &[u8],
    b: &[u8],
) -> Result<(), error::Unspecified> {
    if scytale::constant_time::equal(a, b) {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}
