//! Cryptographic hashes.

use core::ops::Deref;

/// A cryptographic hash algorithm.
pub trait Hash {
    /// The digest type.
    type Digest: AsRef<[u8]> + Clone + Deref<Target = [u8]>;

    /// Constructs a new hash instance.
    fn new() -> Self;

    /// Resets the hash.
    fn reset(&mut self);

    /// Updates the hash with some data.
    fn update<T>(&mut self, data: T)
    where
        T: AsRef<[u8]>;

    /// Finalizes the hash and return the digest.
    fn finalize(self) -> Self::Digest;

    /// Finalizes the hash and return the digest.
    /// The hash is reset and available for reuse.
    fn finalize_and_reset(&mut self) -> Self::Digest;

    /// Constructs a new hash instance, and updates it with some initial data.
    #[inline]
    fn new_with_prefix<T>(data: T) -> Self
    where
        T: AsRef<[u8]>,
        Self: Sized
    {
        let mut hash = Self::new();
        hash.update(data);
        hash
    }

    /// Returns the digest of a message.
    #[inline]
    fn hash<T>(message: T) -> Self::Digest
    where
        T: AsRef<[u8]>,
        Self: Sized
    {
        Self::new_with_prefix(message).finalize()
    }
}

pub(crate) mod internal {
    use core::ops::DerefMut;
    use super::Hash;

    pub trait BlockHash: Hash {
        /// The block type
        type Block: AsMut<[u8]> + AsRef<[u8]> + Clone + DerefMut<Target = [u8]>;
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
            fn update<T>(&mut self, data: T)
            where
                T: AsRef<[u8]>
            {
                self.0.update(data.as_ref())
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
