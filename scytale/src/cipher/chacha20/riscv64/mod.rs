//! ChaCha20 implementations for RISC-V (RV64).
//!
//! [`zvkb`] computes as many blocks at once as a vector register has
//! 32-bit lanes, and [`zbb`] one block at a time on the general
//! registers. Both need nothing but a rotate instruction, which is
//! what the cipher spends a third of its work on where there is none;
//! each probes for its own at run time.
//!
//! A processor with a vector unit wants [`zvkb`]. [`zbb`] is for one
//! without, which is most RISC-V hardware shipped so far, and where
//! the alternative is the portable code computing four blocks at a
//! time with no instruction to do it four times over.

pub mod zbb;
pub mod zvkb;

pub use zbb::Zbb;
pub use zvkb::Zvkb;
