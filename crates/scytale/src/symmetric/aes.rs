//! AES, as specified in FIPS-197.
//!
//! Name [`Aes128`], [`Aes192`] or [`Aes256`] to get the best implementation
//! available on the machine the code is actually running on. Reach into
//! [`arch`] only to pin one exact implementation.
//!
//! Each key size has three types. The `Enc` and `Dec` types hold a single
//! key schedule; the bare name holds both and costs about twice as much to
//! construct. Prefer `Aes128Enc` when you never decrypt.

pub mod arch;
pub mod ctr;

pub use ctr::{Aes128Ctr, Aes192Ctr, Aes256Ctr};

use arch::portable::ttable;

use crate::symmetric::block_cipher::{
    BlockDecrypt, BlockEncrypt, InvalidKeyLength, KeyInit,
};

/// The AES block size in bytes. Identical for all three key sizes.
pub const BLOCK_SIZE: usize = ttable::BLOCK_SIZE;

/// The accelerated implementations for this target, if it has any.
///
/// Targets with no acceleration name the portable types here and report no
/// support, so the dispatch below needs no target specific spelling: the
/// accelerated arm is simply never taken.
#[cfg(target_arch = "x86_64")]
mod accel {
    pub use super::arch::x86_64::{aesni, vaes};
}

#[cfg(target_arch = "aarch64")]
mod accel {
    pub use super::arch::aarch64::armv8 as aesni;

    /// A stand-in for the tier this target has nothing in. It reports no
    /// support, so that arm is never taken.
    pub mod vaes {
        pub use super::super::arch::portable::ttable::{
            Aes128Dec, Aes128Enc, Aes192Dec, Aes192Enc, Aes256Dec,
            Aes256Enc,
        };

        pub fn supported() -> bool {
            false
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod accel {
    /// Stand-ins so the dispatch below needs no target specific spelling.
    /// Both report no support, so neither arm is ever taken.
    pub mod vaes {
        pub use super::super::arch::portable::ttable::{
            Aes128Dec, Aes128Enc, Aes192Dec, Aes192Enc, Aes256Dec,
            Aes256Enc,
        };

        pub fn supported() -> bool {
            false
        }

        /// The counter kernels are no more available than the rest.
        pub use self::supported as ctr_supported;
    }

    pub use vaes as aesni;
}

/// Which implementation a dispatching type chose.
///
/// The choice is made once, when the key is expanded, and then it is a
/// property of the value. Nothing re-examines the CPU per call.
enum Backend<V, A, P> {
    Vector(V),
    Accelerated(A),
    Portable(P),
}

macro_rules! define_dispatch {
    (
        $name:ident, $vector:ty, $accel:ty, $portable:ty, $key_size:expr,
        $op:ident, $op_block:ident, $tr:ident, $doc:expr
    ) => {
        #[doc = $doc]
        pub struct $name(Backend<$vector, $accel, $portable>);

        impl $name {
            /// The key length in bytes.
            pub const KEY_SIZE: usize = $key_size;
            /// The block length in bytes.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;
            /// The most blocks any implementation here keeps in flight.
            ///
            /// Use [`Self::parallel_blocks`] for the number the selected
            /// one actually uses; this is the figure to size a buffer by.
            pub const PARALLEL_BLOCKS: usize =
                <$vector>::PARALLEL_BLOCKS;

            /// Expand `key`, choosing an implementation for this CPU.
            ///
            /// Widest first: the vector kernels do the most work per
            /// instruction, and fall back to the single block accelerated
            /// ones for anything they cannot fill.
            pub fn new(key: &[u8; $key_size]) -> Self {
                Self(if accel::vaes::supported() {
                    Backend::Vector(<$vector>::new(key))
                } else if accel::aesni::supported() {
                    Backend::Accelerated(<$accel>::new(key))
                } else {
                    Backend::Portable(<$portable>::new(key))
                })
            }

            #[doc = concat!(
                stringify!($op),
                " whole blocks in place, returning bytes consumed."
            )]
            pub fn $op(&self, data: &mut [u8]) -> usize {
                match &self.0 {
                    Backend::Vector(v) => v.$op(data),
                    Backend::Accelerated(a) => a.$op(data),
                    Backend::Portable(p) => p.$op(data),
                }
            }

            #[doc = concat!(stringify!($op), " exactly one block in place.")]
            pub fn $op_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                match &self.0 {
                    Backend::Vector(v) => v.$op_block(block),
                    Backend::Accelerated(a) => a.$op_block(block),
                    Backend::Portable(p) => p.$op_block(block),
                }
            }

            /// How many blocks the chosen implementation keeps in flight.
            pub fn parallel_blocks(&self) -> usize {
                match &self.0 {
                    Backend::Vector(_) => <$vector>::PARALLEL_BLOCKS,
                    Backend::Accelerated(_) => <$accel>::PARALLEL_BLOCKS,
                    Backend::Portable(_) => <$portable>::PARALLEL_BLOCKS,
                }
            }

            /// Whether this value is using an accelerated implementation.
            pub fn is_accelerated(&self) -> bool {
                !matches!(self.0, Backend::Portable(_))
            }

            /// The name of the implementation this value chose.
            pub fn implementation(&self) -> &'static str {
                match &self.0 {
                    Backend::Vector(_) => "vector",
                    Backend::Accelerated(_) => "accelerated",
                    Backend::Portable(_) => "portable",
                }
            }
        }

        impl KeyInit for $name {
            fn try_new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                let key: &[u8; $key_size] = key
                    .try_into()
                    .map_err(|_| InvalidKeyLength { got: key.len() })?;
                Ok(Self::new(key))
            }
        }

        impl $tr for $name {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = <$vector>::PARALLEL_BLOCKS;

            fn $op(&self, data: &mut [u8]) -> usize {
                $name::$op(self, data)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                // Never format round keys.
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

define_dispatch!(
    Aes128Enc, accel::vaes::Aes128Enc, accel::aesni::Aes128Enc,
    ttable::Aes128Enc, 16, encrypt, encrypt_block, BlockEncrypt,
    "AES-128 encryption only."
);
define_dispatch!(
    Aes128Dec, accel::vaes::Aes128Dec, accel::aesni::Aes128Dec,
    ttable::Aes128Dec, 16, decrypt, decrypt_block, BlockDecrypt,
    "AES-128 decryption only."
);
define_dispatch!(
    Aes192Enc, accel::vaes::Aes192Enc, accel::aesni::Aes192Enc,
    ttable::Aes192Enc, 24, encrypt, encrypt_block, BlockEncrypt,
    "AES-192 encryption only."
);
define_dispatch!(
    Aes192Dec, accel::vaes::Aes192Dec, accel::aesni::Aes192Dec,
    ttable::Aes192Dec, 24, decrypt, decrypt_block, BlockDecrypt,
    "AES-192 decryption only."
);
define_dispatch!(
    Aes256Enc, accel::vaes::Aes256Enc, accel::aesni::Aes256Enc,
    ttable::Aes256Enc, 32, encrypt, encrypt_block, BlockEncrypt,
    "AES-256 encryption only."
);
define_dispatch!(
    Aes256Dec, accel::vaes::Aes256Dec, accel::aesni::Aes256Dec,
    ttable::Aes256Dec, 32, decrypt, decrypt_block, BlockDecrypt,
    "AES-256 decryption only."
);

macro_rules! define_both {
    ($name:ident, $enc:ident, $dec:ident, $key_size:expr, $doc:expr) => {
        #[doc = $doc]
        ///
        /// Builds both key schedules, so it costs about twice what a
        /// one-direction type does to construct. Use it when you genuinely
        /// need both.
        pub struct $name {
            enc: $enc,
            dec: $dec,
        }

        impl $name {
            /// The key length in bytes.
            pub const KEY_SIZE: usize = $key_size;
            /// The block length in bytes.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;

            /// Expand `key` into both schedules.
            pub fn new(key: &[u8; $key_size]) -> Self {
                Self { enc: $enc::new(key), dec: $dec::new(key) }
            }

            /// Encrypt whole blocks in place, returning bytes consumed.
            pub fn encrypt(&self, data: &mut [u8]) -> usize {
                self.enc.encrypt(data)
            }

            /// Decrypt whole blocks in place, returning bytes consumed.
            pub fn decrypt(&self, data: &mut [u8]) -> usize {
                self.dec.decrypt(data)
            }

            /// Encrypt exactly one block in place.
            pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                self.enc.encrypt_block(block);
            }

            /// Decrypt exactly one block in place.
            pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                self.dec.decrypt_block(block);
            }

            /// Borrow just the encryption half.
            pub fn encryptor(&self) -> &$enc {
                &self.enc
            }

            /// Borrow just the decryption half.
            pub fn decryptor(&self) -> &$dec {
                &self.dec
            }

            /// Whether this value is using an accelerated implementation.
            pub fn is_accelerated(&self) -> bool {
                self.enc.is_accelerated()
            }
        }

        impl KeyInit for $name {
            fn try_new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                let key: &[u8; $key_size] = key
                    .try_into()
                    .map_err(|_| InvalidKeyLength { got: key.len() })?;
                Ok(Self::new(key))
            }
        }

        impl BlockEncrypt for $name {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = $enc::PARALLEL_BLOCKS;

            fn encrypt(&self, data: &mut [u8]) -> usize {
                self.enc.encrypt(data)
            }
        }

        impl BlockDecrypt for $name {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = $dec::PARALLEL_BLOCKS;

            fn decrypt(&self, data: &mut [u8]) -> usize {
                self.dec.decrypt(data)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

define_both!(Aes128, Aes128Enc, Aes128Dec, 16, "AES-128, both directions.");
define_both!(Aes192, Aes192Enc, Aes192Dec, 24, "AES-192, both directions.");
define_both!(Aes256, Aes256Enc, Aes256Dec, 32, "AES-256, both directions.");

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatching type must agree with both implementations it can
    /// choose between, or which one a machine picks would change results.
    #[test]
    fn dispatch_agrees_with_the_portable_implementation() {
        let key = [0x2bu8; 16];
        let plaintext: Vec<u8> = (0..=255u8).cycle().take(1024).collect();

        let mut dispatched = plaintext.clone();
        let mut portable = plaintext.clone();
        Aes128Enc::new(&key).encrypt(&mut dispatched);
        ttable::Aes128Enc::new(&key).encrypt(&mut portable);
        assert_eq!(dispatched, portable);

        Aes128Dec::new(&key).decrypt(&mut dispatched);
        assert_eq!(dispatched, plaintext);
    }

    /// What this target's accelerated tier is, if it has one.
    fn accelerated_here() -> bool {
        accel::aesni::supported()
    }

    /// What this target's vector tier is, if it has one.
    fn vector_here() -> bool {
        accel::vaes::supported()
    }

    /// A machine with the instructions must actually be using them. Without
    /// this a silent fall back would look exactly like success.
    #[test]
    fn uses_acceleration_when_the_cpu_has_it() {
        let expected = accelerated_here() || vector_here();
        assert_eq!(Aes128Enc::new(&[0u8; 16]).is_accelerated(), expected);
        assert_eq!(Aes192Enc::new(&[0u8; 24]).is_accelerated(), expected);
        assert_eq!(Aes256Dec::new(&[0u8; 32]).is_accelerated(), expected);
        assert_eq!(Aes128::new(&[0u8; 16]).is_accelerated(), expected);
    }

    /// The widest available implementation must be the one chosen, or the
    /// dispatch order is wrong and nobody would notice.
    #[test]
    fn picks_the_widest_implementation_available() {
        let expected = if vector_here() {
            "vector"
        } else if accelerated_here() {
            "accelerated"
        } else {
            "portable"
        };
        assert_eq!(Aes128Enc::new(&[0u8; 16]).implementation(), expected);
        assert_eq!(Aes256Dec::new(&[0u8; 32]).implementation(), expected);
    }

    #[test]
    fn parallel_blocks_reports_the_chosen_implementation() {
        let aes = Aes128Enc::new(&[0u8; 16]);
        let expected = match aes.implementation() {
            "vector" => accel::vaes::Aes128Enc::PARALLEL_BLOCKS,
            "accelerated" => accel::aesni::Aes128Enc::PARALLEL_BLOCKS,
            _ => ttable::Aes128Enc::PARALLEL_BLOCKS,
        };
        assert_eq!(aes.parallel_blocks(), expected);
    }
}
