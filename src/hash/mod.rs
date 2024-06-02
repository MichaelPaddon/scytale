//! Cryptographic hashes.

/// A cryptographic hash algorithm.
pub trait Hash {
    /// Constructs a new hash algorithm instance.
    fn new() -> Self
    where
        Self: Sized;

    fn block_size() -> usize
    where
        Self: Sized;

    /// Resets the hash.
    fn reset(&mut self);

    /// Updates the hash with some data.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash and return the digest.
    fn finalize<'a>(&'a mut self) -> &'a [u8];

    /// Constructs a new hash instance, and updates it with some initial data.
    #[inline]
    fn new_with_prefix(data: &[u8]) -> Self
    where
        Self: Sized
    {
        let mut hash = Self::new();
        hash.update(data);
        hash
    }

    /// Returns the digest of a message.
    fn hash(message: &[u8]) -> Vec<u8>
    where
        Self: Sized
    {
        let mut hash = Self::new_with_prefix(message);
        hash.finalize().to_vec()
    }
}

macro_rules! impl_hash_newtype {
    ($name: ident, $inner: ty) => {
        impl crate::hash::Hash for $name {
            #[inline]
            fn new() -> Self
            where
                Self: Sized
            {
                Self(<$inner>::new())
            }

            #[inline]
            fn block_size() -> usize
            where
                Self: Sized
            {
                <$inner>::block_size()
            }

            #[inline]
            fn reset(&mut self) {
                self.0.reset()
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.0.update(data)
            }

            #[inline]
            fn finalize<'a>(&'a mut self) -> &'a [u8] {
                self.0.finalize()
            }
        }

        impl std::io::Write for $name {
            #[inline]
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.update(data);
                Ok(data.len())
            }

            #[inline]
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
    }
}

const ALGORITHMS: [(&str, fn() -> Box<dyn Hash>); 6] = [
    ("sha224", || Box::new(sha2::Sha224::new())),
    ("sha256", || Box::new(sha2::Sha256::new())),
    ("sha384", || Box::new(sha2::Sha384::new())),
    ("sha512", || Box::new(sha2::Sha512::new())),
    ("sha512_224", || Box::new(sha2::Sha512_224::new())),
    ("sha512_256", || Box::new(sha2::Sha512_256::new()))
];

pub fn algorithms() -> impl Iterator {
    ALGORITHMS.iter().map(|x| x.0)
}

pub mod sha2;
