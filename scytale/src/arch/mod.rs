//! Asking the processor what it can do.
//!
//! Each architecture has its own way of reporting which optional
//! instructions are present, and more than one primitive wants the
//! answer, so the asking lives here rather than beside any one of
//! them.

#[cfg(target_arch = "riscv64")]
pub(crate) mod riscv64;
