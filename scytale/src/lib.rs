//! Portable cryptographic primitives.

#![no_std]
// Hardware implementations need intrinsics; they opt in per module.
#![deny(unsafe_code)]
// `chunks_exact(N)` reads better than `as_chunks::<N>()` and the
// compiler removes the length checks either way.
#![allow(clippy::chunks_exact_to_as_chunks)]
#![warn(missing_docs)]

pub mod symmetric;
