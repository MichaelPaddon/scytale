//! Cryptographic hashes.

use core::convert::AsRef;

/// A cryptographic hash algorithm.
pub trait Hash: {
    /// The block type
    type Block: AsMut<[u8]>;

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
    fn hash(message: &[u8]) -> Self::Digest
    where
        Self: Sized
    {
        let mut hash = Self::new();
        hash.update(message);
        hash.finalize()
    }
}

macro_rules! impl_hash_for_newtype {
    ($hash: ident, $block: ty, $digest: ty) => {
        impl Hash for $hash {
            type Block = $block;
            type Digest = $digest;

            #[inline(always)]
            fn new() -> Self {
                Self::default()
            }

            #[inline(always)]
            fn reset(&mut self) {
                self.0.reset()
            }

            #[inline(always)]
            fn update(&mut self, data: &[u8]){
                self.0.update(data)
            }

            #[inline(always)]
            fn finalize(mut self) -> Self::Digest {
                self.0.finalize()
            }

            #[inline(always)]
            fn finalize_and_reset(&mut self) -> Self::Digest {
                let digest = self.0.finalize();
                self.0.reset();
                digest
            }
        }
    }
}

macro_rules! impl_write_for_hash {
    ($hash: ident) => {
        impl std::io::Write for $hash {
            #[inline(always)]
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.update(buf);
                Ok(buf.len())
            }

            #[inline(always)]
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
    }
}

pub mod sha2;
