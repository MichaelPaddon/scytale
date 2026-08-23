//! Apple's systems, the BSDs and the Solaris family, through
//! `getentropy`.
//!
//! One function, the same on all of them: it either fills the buffer
//! completely or fails, with no partial answer to handle. Unlike
//! Linux there is no system call made directly here, because none of
//! these systems promises its numbers will stay put. Apple says so
//! outright, and OpenBSD changes them on purpose.
//!
//! It refuses more than 256 bytes at a time, so larger requests are
//! made in pieces.

#![allow(unsafe_code)]

use crate::Error;

/// Whether there is a call to make here.
#[cfg(test)]
pub(crate) const AVAILABLE: bool = true;

/// The most `getentropy` accepts in one call.
const LIMIT: usize = 256;

extern "C" {
    /// Fills `buf`, waiting if the system's generator is not ready.
    /// Returns zero, or -1 having set `errno`.
    fn getentropy(buf: *mut u8, len: usize) -> i32;
}

/// Fills `out` with random bytes from the system.
pub(crate) fn fill(out: &mut [u8]) -> Result<(), Error> {
    for piece in out.chunks_mut(LIMIT) {
        // SAFETY: the call writes exactly `len` bytes at `ptr`, and
        // the two describe a slice held exclusively here. The length
        // is within what it accepts.
        let ret = unsafe { getentropy(piece.as_mut_ptr(), piece.len()) };
        if ret != 0 {
            // The number it failed with is in `errno`, which cannot
            // be read without naming a symbol that differs on every
            // one of these systems. It is not worth that: the only
            // failure that is not a bug here is the generator itself
            // being broken.
            return Err(Error::EntropyUnavailable(0));
        }
    }
    Ok(())
}
