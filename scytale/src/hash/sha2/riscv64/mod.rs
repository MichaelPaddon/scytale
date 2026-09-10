//! SHA-2 implementations for RISC-V (RV64).
//!
//! [`zvknh`] uses the vector cryptography extension, which has an
//! instruction for a pair of rounds and another for four words of the
//! message schedule. [`zknh`] uses the scalar cryptography extension,
//! which has one instruction for each of the sigma functions and
//! leaves the rest of the round to ordinary arithmetic. Both probe
//! for their instructions at run time.

pub mod zknh;
pub mod zvknh;

pub use zknh::Zknh;
pub use zvknh::Zvknh;
