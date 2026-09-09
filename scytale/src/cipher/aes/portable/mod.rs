//! Portable AES implementations, in plain Rust for any target.
//!
//! Two peers, neither of them the default: [`bitsliced`] is constant
//! time, and [`ttable`] is roughly twice as fast but indexes lookup
//! tables with bytes derived from the key, so it leaks through cache
//! timing. The dispatching cipher picks the bitsliced one when the
//! processor has no AES instructions, and never picks the other.

pub(crate) mod bitsliced;

// Nothing selects the table-driven code yet: it leaks through cache
// timing, so it is not the automatic choice, and the mechanism for
// an application to ask for it by name is still to be designed. It
// is compiled and tested meanwhile so that it does not rot.
#[allow(dead_code)]
pub(crate) mod ttable;
