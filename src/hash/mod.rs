//! Cryptographic hashes.

use core::convert::AsRef;

/// A cryptographic hash algorithm.
pub trait Hash: {
    /// The digest type.
    type Digest: AsRef<[u8]>;

    /// Constructs a new hash instance.
    fn new() -> Self;

    /// Resets the hash.
    fn reset(&mut self);

    /// Updates the hash state.
    fn update(&mut self, bytes: &[u8]);

    /// Return the digest.
    fn finalize(self) -> Self::Digest;

    /// Reset the hash and return the digest.
    fn finalize_and_reset(&mut self) -> Self::Digest;

    /// Convenience function to hash a slice of bytes.
    fn hash(bytes: &[u8]) -> Self::Digest
    where
        Self: Sized
    {
        let mut hash = Self::new();
        hash.update(bytes);
        hash.finalize()
    }
}

macro_rules! hash_delegate {
    ($hash: ident, $inner: tt, $digest: ty) => {
        impl Hash for $hash {
            type Digest = $digest;

            #[inline(always)]
            fn new() -> Self {
                Self::default()
            }

            #[inline(always)]
            fn reset(&mut self) {
                self.$inner.reset()
            }

            #[inline(always)]
            fn update(&mut self, bytes: &[u8]){
                self.$inner.update(bytes)
            }

            #[inline(always)]
            fn finalize(self) -> Self::Digest {
                self.$inner.finalize()
            }

            #[inline(always)]
            fn finalize_and_reset(&mut self) -> Self::Digest {
                self.$inner.finalize_and_reset()
            }
        }
    }
}

macro_rules! hash_write {
    ($hash: ident) => {
        impl Write for $hash {
            #[inline(always)]
            fn write(&mut self, bytes: &[u8]) -> Result<usize> {
                self.update(bytes);
                Ok(bytes.len())
            }

            #[inline(always)]
            fn flush(&mut self) -> Result<()> {
                Ok(())
            }
        }
    }
}

pub mod sha2;
