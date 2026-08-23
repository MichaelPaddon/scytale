//! Shared test support: vector loading and generic ACVP drivers.
//!
//! Each integration test binary includes this module and runs the
//! drivers against one implementation, so every implementation of a
//! primitive is checked against the same vectors.

// Each test binary uses only part of this module.
#![allow(dead_code)]

pub mod acvp;
pub mod vectors;
