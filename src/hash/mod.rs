//! Cryptographic hashes.

use std::io::Write;
use derive_more::{Constructor, Display, Error};

#[derive(Clone, Constructor, Debug, Display, Error)]
#[display(fmt = "{}: unknown algorithm", name)]
pub struct UnknownAlgorithmError {
    name: String
}

/// A cryptographic hash algorithm.
pub trait Hash: Write {
    /// Constructs a new hash.
    fn new() -> Self where Self: Sized;

    /// Returns the block size of the hash, in bytes.
    fn block_size() -> usize where Self: Sized;

    /// Resets the hash.
    fn reset(&mut self);

    /// Updates the hash with some data.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash and return the digest.
    fn finalize<'a>(&'a mut self) -> &'a [u8];

    /// Constructs a new hash and updates it with some data.
    #[inline(always)]
    fn new_with_prefix(data: &[u8]) -> Self where Self: Sized{
        let mut hash = Self::new();
        hash.update(data);
        hash
    }
}

pub mod sha2;

const HASHES: [(&str, fn() -> Box<dyn Hash>); 6] = [
    ("sha224", || Box::new(sha2::Sha224::new())),
    ("sha256", || Box::new(sha2::Sha256::new())),
    ("sha384", || Box::new(sha2::Sha384::new())),
    ("sha512", || Box::new(sha2::Sha512::new())),
    ("sha512_224", || Box::new(sha2::Sha512_224::new())),
    ("sha512_256", || Box::new(sha2::Sha512_256::new()))
];

/// Returns a iterator over the names of the supported hash algorithms.
pub fn list() -> impl Iterator<Item = &'static str> {
    HASHES.iter().map(|x| x.0)
}

/// Constructs a boxed hash from a name.
pub fn from_name(name: &str)
    -> Result<Box<dyn Hash>, UnknownAlgorithmError>
{
    match HASHES.binary_search_by(|x| x.0.cmp(name)) {
        Ok(i) => Ok(HASHES[i].1()),
        _ => Err(UnknownAlgorithmError::new(name.to_string()))
    }
}
