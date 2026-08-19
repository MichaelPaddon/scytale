//! The individual AES implementations, each nameable directly.
//!
//! Use these when you need one specific implementation and are willing to
//! guarantee it is supported. Otherwise prefer the parent module's names,
//! which select at run time.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

pub mod portable;
