//! Windows, through `ProcessPrng`.
//!
//! This is the generator underneath the rest of the system's
//! cryptography. It takes a buffer of any size, fills all of it, and
//! is documented always to succeed, so there is neither a loop nor an
//! error to handle.
//!
//! It is named straight from the library that holds it rather than
//! through an import library, so building for Windows needs nothing
//! installed.

#![allow(unsafe_code)]

use crate::Error;

/// Whether there is a call to make here.
#[cfg(test)]
pub(crate) const AVAILABLE: bool = true;

#[link(name = "bcryptprimitives", kind = "raw-dylib")]
extern "system" {
    /// Fills `data`. Documented to return non-zero always.
    fn ProcessPrng(data: *mut u8, len: usize) -> i32;
}

/// Fills `out` with random bytes from the system.
pub(crate) fn fill(out: &mut [u8]) -> Result<(), Error> {
    // SAFETY: the call writes exactly `len` bytes at `ptr`, and the
    // two describe a slice held exclusively here.
    let ret = unsafe { ProcessPrng(out.as_mut_ptr(), out.len()) };
    // It is documented never to fail, but saying so and checking it
    // costs nothing next to handing back a buffer it did not fill.
    if ret == 0 {
        return Err(Error::EntropyUnavailable(0));
    }
    Ok(())
}
