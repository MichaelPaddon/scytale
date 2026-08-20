//! AES-CTR with fused counter kernels.
//!
//! These types are to [`Ctr`](crate::symmetric::ctr::Ctr) what the
//! parent module's cipher types are to the backends: name [`Aes128Ctr`],
//! [`Aes192Ctr`] or [`Aes256Ctr`] to get the best implementation on the
//! machine the code actually runs on. The accelerated backends generate
//! counters in registers and XOR the keystream into the data in the
//! same pass, so the keystream never touches memory; the generic mode
//! stages it through a buffer instead.
//!
//! The counter is the whole block, big endian, wrapping mod 2^128, as
//! NIST SP 800-38A specifies. Encrypting and decrypting are the same
//! operation. The nonce reuse warning on the generic mode applies here
//! unchanged: never use one (key, counter) pair for two messages.

use zeroize::Zeroize;

use super::arch::portable::ttable;
use super::{BLOCK_SIZE, Backend, accel};
use crate::symmetric::block_cipher::InvalidKeyLength;
use crate::symmetric::ctr::{CtrInitError, InvalidIvLength};

macro_rules! define_ctr {
    (
        $name:ident, $vector:ty, $accel:ty, $portable:ty, $key_size:expr,
        $doc:expr
    ) => {
        #[doc = $doc]
        pub struct $name {
            cipher: Backend<$vector, $accel, $portable>,
            /// The next block's counter value, big endian.
            counter: [u8; BLOCK_SIZE],
            /// The most recent keystream block; `used` bytes of it are
            /// consumed. `used == BLOCK_SIZE` means nothing is buffered.
            keystream: [u8; BLOCK_SIZE],
            used: usize,
        }

        impl $name {
            /// The key length in bytes.
            pub const KEY_SIZE: usize = $key_size;
            /// The block length in bytes.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;

            /// Expand `key` and start the counter at `iv`, choosing an
            /// implementation for this CPU.
            ///
            /// Widest first, exactly as the parent module's cipher
            /// types choose. The accelerated arm additionally needs
            /// the counter kernels' own instructions, which is a
            /// separate check on some targets.
            pub fn new(
                key: &[u8; $key_size],
                iv: &[u8; BLOCK_SIZE],
            ) -> Self {
                let cipher = if accel::vaes::supported() {
                    Backend::Vector(<$vector>::new(key))
                } else if accel::aesni::ctr_supported() {
                    Backend::Accelerated(<$accel>::new(key))
                } else {
                    Backend::Portable(<$portable>::new(key))
                };
                Self {
                    cipher,
                    counter: *iv,
                    keystream: [0u8; BLOCK_SIZE],
                    used: BLOCK_SIZE,
                }
            }

            /// As [`Self::new`], from slices checked at run time.
            pub fn try_new(
                key: &[u8],
                iv: &[u8],
            ) -> Result<Self, CtrInitError> {
                let key: &[u8; $key_size] = key
                    .try_into()
                    .map_err(|_| InvalidKeyLength { got: key.len() })?;
                let iv: &[u8; BLOCK_SIZE] = iv
                    .try_into()
                    .map_err(|_| InvalidIvLength { got: iv.len() })?;
                Ok(Self::new(key, iv))
            }

            /// Whole blocks through the chosen backend's fused entry.
            fn ctr_blocks(
                &self,
                counter: &mut [u8; BLOCK_SIZE],
                data: &mut [u8],
            ) -> usize {
                match &self.cipher {
                    Backend::Vector(v) => v.ctr(counter, data),
                    Backend::Accelerated(a) => a.ctr(counter, data),
                    Backend::Portable(p) => p.ctr(counter, data),
                }
            }

            /// XOR the keystream into `data`, advancing the stream.
            ///
            /// Encrypting and decrypting are the same operation. Any
            /// length is accepted, and successive calls continue where
            /// the last left off.
            pub fn apply_keystream(&mut self, mut data: &mut [u8]) {
                // Drain keystream buffered by a previous partial block.
                if self.used < BLOCK_SIZE {
                    let take =
                        (BLOCK_SIZE - self.used).min(data.len());
                    let tail =
                        &self.keystream[self.used..self.used + take];
                    for (d, k) in data[..take].iter_mut().zip(tail) {
                        *d ^= *k;
                    }
                    self.used += take;
                    data = &mut core::mem::take(&mut data)[take..];
                }

                // Every whole block goes to the backend in one call.
                // The counter moves through a local so the borrow of
                // the cipher and the borrow of the counter stay apart.
                let whole = data.len() / BLOCK_SIZE * BLOCK_SIZE;
                if whole > 0 {
                    let mut counter = self.counter;
                    let consumed =
                        self.ctr_blocks(&mut counter, &mut data[..whole]);
                    self.counter = counter;
                    debug_assert_eq!(consumed, whole);
                    data = &mut core::mem::take(&mut data)[whole..];
                }

                // A trailing partial block takes what it needs from one
                // fresh keystream block, made by running the fused
                // entry over a zero block: E(counter) XOR 0.
                if !data.is_empty() {
                    let mut block = [0u8; BLOCK_SIZE];
                    let mut counter = self.counter;
                    self.ctr_blocks(&mut counter, &mut block);
                    self.counter = counter;
                    let take = data.len();
                    for (d, k) in data.iter_mut().zip(&block[..take]) {
                        *d ^= *k;
                    }
                    self.keystream = block;
                    self.used = take;
                }
            }

            /// How many blocks the chosen implementation keeps in
            /// flight.
            pub fn parallel_blocks(&self) -> usize {
                match &self.cipher {
                    Backend::Vector(_) => <$vector>::PARALLEL_BLOCKS,
                    Backend::Accelerated(_) => <$accel>::PARALLEL_BLOCKS,
                    Backend::Portable(_) => <$portable>::PARALLEL_BLOCKS,
                }
            }

            /// Whether this value is using an accelerated
            /// implementation.
            pub fn is_accelerated(&self) -> bool {
                !matches!(self.cipher, Backend::Portable(_))
            }

            /// The name of the implementation this value chose.
            pub fn implementation(&self) -> &'static str {
                match &self.cipher {
                    Backend::Vector(_) => "vector",
                    Backend::Accelerated(_) => "accelerated",
                    Backend::Portable(_) => "portable",
                }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // Buffered keystream is as sensitive as the key while
                // the counter position is knowable; the cipher wipes
                // its own schedule.
                self.counter.zeroize();
                self.keystream.zeroize();
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                // Never format the counter or buffered keystream.
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

define_ctr!(
    Aes128Ctr, accel::vaes::Aes128Enc, accel::aesni::Aes128Enc,
    ttable::Aes128Enc, 16, "AES-128 in CTR mode."
);
define_ctr!(
    Aes192Ctr, accel::vaes::Aes192Enc, accel::aesni::Aes192Enc,
    ttable::Aes192Enc, 24, "AES-192 in CTR mode."
);
define_ctr!(
    Aes256Ctr, accel::vaes::Aes256Enc, accel::aesni::Aes256Enc,
    ttable::Aes256Enc, 32, "AES-256 in CTR mode."
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::ctr::Ctr;

    /// xorshift64*, so a divergence is reproducible from the seed.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let bytes = self.next().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    /// The dispatching type against the generic mode over the portable
    /// cipher, on random lengths fed in random pieces, so the fused
    /// backends and the partial block state machine are both hit.
    #[test]
    fn agrees_with_the_generic_portable_mode() {
        let mut rng = Rng(0x0f1e_2d3c_4b5a_6978);
        for _ in 0..50 {
            let mut key = [0u8; 16];
            rng.fill(&mut key);
            let mut iv = [0u8; 16];
            rng.fill(&mut iv);
            let len = (rng.next() % 1024) as usize;
            let mut data = vec![0u8; len];
            rng.fill(&mut data);

            let mut ours = data.clone();
            let mut ctr = Aes128Ctr::new(&key, &iv);
            let mut rest = ours.as_mut_slice();
            while !rest.is_empty() {
                let take = ((rng.next() % 96) as usize + 1)
                    .min(rest.len());
                let (head, tail) = rest.split_at_mut(take);
                ctr.apply_keystream(head);
                rest = tail;
            }

            let cipher = ttable::Aes128Enc::new(&key);
            Ctr::try_new(cipher, &iv)
                .expect("block-size IV")
                .apply_keystream(&mut data);

            assert_eq!(ours, data, "length {len}");
        }
    }

    #[test]
    fn uses_acceleration_when_the_cpu_has_it() {
        let ctr = Aes128Ctr::new(&[0u8; 16], &[0u8; 16]);
        assert_eq!(
            ctr.is_accelerated(),
            accel::aesni::ctr_supported() || accel::vaes::supported()
        );
    }

    #[test]
    fn picks_the_widest_implementation_available() {
        let ctr = Aes256Ctr::new(&[0u8; 32], &[0u8; 16]);
        let expected = if accel::vaes::supported() {
            "vector"
        } else if accel::aesni::ctr_supported() {
            "accelerated"
        } else {
            "portable"
        };
        assert_eq!(ctr.implementation(), expected);
    }

    #[test]
    fn resumes_across_a_partial_block() {
        let key = [0x2bu8; 24];
        let iv = [0x42u8; 16];

        let mut whole = [0xa5u8; 61];
        Aes192Ctr::new(&key, &iv).apply_keystream(&mut whole);

        let mut pieces = [0xa5u8; 61];
        let mut ctr = Aes192Ctr::new(&key, &iv);
        // 7 + 9 stops mid-block twice before the next whole block.
        let (a, rest) = pieces.split_at_mut(7);
        ctr.apply_keystream(a);
        let (b, rest) = rest.split_at_mut(9);
        ctr.apply_keystream(b);
        ctr.apply_keystream(rest);
        assert_eq!(pieces, whole);
    }

    #[test]
    fn try_new_rejects_bad_lengths() {
        use crate::symmetric::ctr::CtrInitError;
        assert!(matches!(
            Aes128Ctr::try_new(&[0u8; 15], &[0u8; 16]),
            Err(CtrInitError::Key(_))
        ));
        assert!(matches!(
            Aes128Ctr::try_new(&[0u8; 16], &[0u8; 12]),
            Err(CtrInitError::Iv(_))
        ));
        assert!(Aes128Ctr::try_new(&[0u8; 16], &[0u8; 16]).is_ok());
    }

    /// Drop the value in storage we own, then read that storage back
    /// as raw bytes to confirm the destructor cleared the secrets.
    ///
    /// The whole struct cannot be required to be zero: the backend
    /// discriminant, the `used` length and padding legitimately
    /// survive. Instead the counter is given a recognisable pattern
    /// and a keystream block is buffered, and neither may remain.
    #[test]
    fn state_is_wiped_on_drop() {
        let mut ctr = Aes128Ctr::new(&[0xab; 16], &[0xcd; 16]);
        // Buffer a partial block so `keystream` holds real keystream.
        ctr.apply_keystream(&mut [0u8; 5]);
        let keystream = ctr.keystream;
        assert!(keystream.iter().any(|&b| b != 0));

        let mut slot = core::mem::MaybeUninit::new(ctr);
        let ptr = slot.as_mut_ptr();
        let bytes = ptr.cast::<u8>();
        let len = core::mem::size_of::<Aes128Ctr>();

        let holds = |hay: &[u8], needle: &[u8]| {
            hay.windows(needle.len()).any(|w| w == needle)
        };

        // SAFETY: slot holds an initialized value of exactly this size.
        let live = unsafe { core::slice::from_raw_parts(bytes, len) };
        assert!(holds(live, &keystream), "keystream not where expected");
        // SAFETY: the value is never read as a value again.
        unsafe { core::ptr::drop_in_place(ptr) };
        // SAFETY: the storage is ours and still allocated.
        let dead = unsafe { core::slice::from_raw_parts(bytes, len) };
        assert!(
            !holds(dead, &keystream),
            "buffered keystream survived the drop"
        );
        assert!(
            !holds(dead, &[0xcd; 8]),
            "counter state survived the drop"
        );
    }

    #[test]
    fn debug_does_not_leak_state() {
        let ctr = Aes128Ctr::new(&[0xab; 16], &[0xcd; 16]);
        assert_eq!(format!("{ctr:?}"), "Aes128Ctr { .. }");
    }
}
