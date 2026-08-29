//! Key derivation functions.
//!
//! Two different jobs share the name. [`hkdf`] turns keying material
//! that is already unguessable, such as a shared secret from a key
//! agreement, into as many keys as a protocol needs. [`pbkdf2`]
//! turns a password, which is guessable, into a key, and its
//! iteration count is there to make each guess cost the attacker
//! what it costs you.

pub mod hkdf;
pub mod pbkdf2;
