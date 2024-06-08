//! Message Authentication Code (MAC) algorithms.
//!
//! A MAC algorithm takes a secret key and a message, and
//! generates an authentication tag.
//! Anyone with the secret key can verify this tag.
//! MACs are useful for data origin authentication, which also
//! implies data integrity.

use std::io::Write;
use crate::hash::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use crate::mac::hmac::Hmac;
use crate::hash::UnknownAlgorithmError;

/// A Message Authentication Code algorithm.
pub trait Mac: Write {
    /// Constructs a new MAC instance.
    fn new(key: &[u8]) -> Self where Self: Sized;

    /// Resets the MAC to its initial state.
    fn reset(&mut self);

    /// Rekeys and resets the MAC.
    fn rekey(&mut self, key: &[u8]);

    /// Updates the MAC with some data.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the MAC, generating an authentication code.
    fn finalize<'a>(&'a mut self) -> &'a [u8];

    /// Constructs a new MAC instance and updates it with some data.
    #[inline(always)]
    fn new_with_prefix(key: &[u8], data: &[u8]) -> Self where Self: Sized {
        let mut mac = Self::new(key);
        mac.update(data);
        mac
    }
}

pub mod hmac;

const MACS: [(&str, fn(k: &[u8]) -> Box<dyn Mac>); 6] = [
    ("hmac-sha224", |k| Box::new(Hmac::<Sha224>::new(k))),
    ("hmac-sha256", |k| Box::new(Hmac::<Sha256>::new(k))),
    ("hmac-sha384", |k| Box::new(Hmac::<Sha384>::new(k))),
    ("hmac-sha512", |k| Box::new(Hmac::<Sha512>::new(k))),
    ("hmac-sha512/224", |k| Box::new(Hmac::<Sha512_224>::new(k))),
    ("hmac-sha512/256", |k| Box::new(Hmac::<Sha512_256>::new(k)))
];

/// Returns a iterator over the names of the supported hash algorithms.
pub fn list() -> impl Iterator<Item = &'static str> {
    MACS.iter().map(|x| x.0)
}

/// Constructs a boxed hash from a name.
pub fn from_name(name: &str, key: &[u8])
    -> Result<Box<dyn Mac>, UnknownAlgorithmError>
{
    match MACS.binary_search_by(|x| x.0.cmp(name)) {
        Ok(i) => Ok(MACS[i].1(key)),
        _ => Err(UnknownAlgorithmError::new(name.to_string()))
    }
}
