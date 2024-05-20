//! Cryptographic hashes.

use core::ops::DerefMut;

/// A cryptographic hash algorithm.
pub trait Hash {
    /// The digest type.
    type Digest: AsRef<[u8]> + AsMut<[u8]> + DerefMut<Target = [u8]>;

    /// Construct a new hash instance.
    fn new() -> Self;

    /// Construct a new hash instance, and update it with some initial data.
    fn new_with_prefix(bytes: &[u8]) -> Self
    where
        Self: Sized
    {
        let mut hash = Self::new();
        hash.update(bytes);
        hash
    }

    /// Reset the hash.
    fn reset(&mut self);

    /// Update the hash with some data.
    fn update(&mut self, bytes: &[u8]);

    /// Finalize the hash and return the digest.
    fn finalize(self) -> Self::Digest;

    /// Finalize the hash and return the digest.
    /// The hash is reset and available for reuse.
    fn finalize_and_reset(&mut self) -> Self::Digest;

    /// Return the digest of a message.
    fn hash(message: &[u8]) -> Self::Digest
    where
        Self: Sized
    {
        let mut hash = Self::new();
        hash.update(message);
        hash.finalize()
    }
}

pub(crate) mod internal {
    use core::ops::DerefMut;
    use super::Hash;

    pub trait BlockHash: Hash {
        /// The block type
        type Block: AsRef<[u8]> + AsMut<[u8]> + DerefMut<Target = [u8]>;
    }
}

macro_rules! impl_hash_for_newtype {
    ($hash: ident, $block: ty, $digest: ty) => {
        impl crate::hash::Hash for $hash {
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
                self.0.finalize().into()
            }

            #[inline(always)]
            fn finalize_and_reset(&mut self) -> Self::Digest {
                let digest = self.0.finalize().into();
                self.0.reset();
                digest
            }
        }

        impl crate::hash::internal::BlockHash for $hash {
            type Block = $block;
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
