//! AES on the 256 bit VAES vector instructions.
//!
//! Each ymm register carries two blocks and the kernels run eight registers
//! wide, so sixteen blocks are in flight per iteration and every round
//! instruction does the work of two AES-NI ones. Round keys are broadcast
//! to both lanes with `vbroadcasti128`.
//!
//! Key expansion and any tail shorter than sixteen blocks are handled by
//! the AES-NI backend, which [`supported`] requires. Sharing the schedule
//! is what makes that free: the two backends read exactly the same bytes.
//!
//! The kernels end with `vzeroupper`, so the SSE code they return to pays
//! no AVX transition penalty.
//!
//! Like AES-NI, and unlike a T-table cipher, this is constant time with
//! respect to the key.

use core::arch::asm;

use super::aesni;
use crate::symmetric::block_cipher::{
    BlockDecrypt, BlockEncrypt, InvalidKeyLength, KeyInit,
};

/// The AES block size in bytes.
pub const BLOCK_SIZE: usize = 16;

/// Blocks in flight: eight registers of two blocks each.
const WIDTH: usize = 16;

/// Whether this CPU can run these kernels.
///
/// AES-NI is required as well: it expands the key and takes the tails.
pub fn supported() -> bool {
    use std::sync::OnceLock;
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        is_x86_feature_detected!("vaes")
            && is_x86_feature_detected!("avx2")
            && aesni::supported()
    })
}

/// A fully unrolled sixteen block kernel, looping over the buffer.
///
/// The round keys are the only repetition, so the round sequence is
/// straight line code; the loop that remains walks whole groups of sixteen
/// blocks and is amortised over 128 round instructions.
macro_rules! kernel {
    (
        $name:ident, $round:literal, $last:literal,
        [$($key:literal),+], $final:literal
    ) => {
        /// # Safety
        ///
        /// The CPU must have VAES and AVX2. `rk` must hold the schedule,
        /// and `data` at least `groups * 16` whole blocks.
        #[inline]
        unsafe fn $name(rk: *const u8, data: *mut u8, groups: usize) {
            // SAFETY: the caller guarantees the instructions and the
            // range. VEX encoded loads have no alignment requirement.
            unsafe {
                asm!(
                    "2:",
                    "vmovdqu ymm0, [{d} + 0]",
                    "vmovdqu ymm1, [{d} + 32]",
                    "vmovdqu ymm2, [{d} + 64]",
                    "vmovdqu ymm3, [{d} + 96]",
                    "vmovdqu ymm4, [{d} + 128]",
                    "vmovdqu ymm5, [{d} + 160]",
                    "vmovdqu ymm6, [{d} + 192]",
                    "vmovdqu ymm7, [{d} + 224]",
                    "vbroadcasti128 ymm8, [{rk}]",
                    "vpxor ymm0, ymm0, ymm8",
                    "vpxor ymm1, ymm1, ymm8",
                    "vpxor ymm2, ymm2, ymm8",
                    "vpxor ymm3, ymm3, ymm8",
                    "vpxor ymm4, ymm4, ymm8",
                    "vpxor ymm5, ymm5, ymm8",
                    "vpxor ymm6, ymm6, ymm8",
                    "vpxor ymm7, ymm7, ymm8",
                    $(
                        concat!("vbroadcasti128 ymm8, [{rk} + ", $key, "]"),
                        concat!($round, " ymm0, ymm0, ymm8"),
                        concat!($round, " ymm1, ymm1, ymm8"),
                        concat!($round, " ymm2, ymm2, ymm8"),
                        concat!($round, " ymm3, ymm3, ymm8"),
                        concat!($round, " ymm4, ymm4, ymm8"),
                        concat!($round, " ymm5, ymm5, ymm8"),
                        concat!($round, " ymm6, ymm6, ymm8"),
                        concat!($round, " ymm7, ymm7, ymm8"),
                    )+
                    concat!("vbroadcasti128 ymm8, [{rk} + ", $final, "]"),
                    concat!($last, " ymm0, ymm0, ymm8"),
                    concat!($last, " ymm1, ymm1, ymm8"),
                    concat!($last, " ymm2, ymm2, ymm8"),
                    concat!($last, " ymm3, ymm3, ymm8"),
                    concat!($last, " ymm4, ymm4, ymm8"),
                    concat!($last, " ymm5, ymm5, ymm8"),
                    concat!($last, " ymm6, ymm6, ymm8"),
                    concat!($last, " ymm7, ymm7, ymm8"),
                    "vmovdqu [{d} + 0], ymm0",
                    "vmovdqu [{d} + 32], ymm1",
                    "vmovdqu [{d} + 64], ymm2",
                    "vmovdqu [{d} + 96], ymm3",
                    "vmovdqu [{d} + 128], ymm4",
                    "vmovdqu [{d} + 160], ymm5",
                    "vmovdqu [{d} + 192], ymm6",
                    "vmovdqu [{d} + 224], ymm7",
                    "add {d}, 256",
                    "dec {g}",
                    "jnz 2b",
                    // Leave the upper halves zeroed so the SSE
                    // code this returns to pays no transition
                    // penalty.
                    "vzeroupper",
                    rk = in(reg) rk,
                    d = inout(reg) data => _,
                    g = inout(reg) groups => _,
                    out("ymm0") _, out("ymm1") _, out("ymm2") _,
                    out("ymm3") _, out("ymm4") _, out("ymm5") _,
                    out("ymm6") _, out("ymm7") _, out("ymm8") _,
                    options(nostack),
                );
            }
        }
    };
}

kernel!(
    e128, "vaesenc", "vaesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90"], "0xa0"
);
kernel!(
    d128, "vaesdec", "vaesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90"], "0xa0"
);
kernel!(
    e192, "vaesenc", "vaesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0"], "0xc0"
);
kernel!(
    d192, "vaesdec", "vaesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0"], "0xc0"
);
kernel!(
    e256, "vaesenc", "vaesenclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0", "0xc0", "0xd0"], "0xe0"
);
kernel!(
    d256, "vaesdec", "vaesdeclast",
    ["0x10", "0x20", "0x30", "0x40", "0x50", "0x60", "0x70", "0x80", "0x90", "0xa0", "0xb0", "0xc0", "0xd0"], "0xe0"
);

macro_rules! define_aes {
    (
        $enc:ident, $dec:ident, $inner_enc:path, $inner_dec:path,
        $key_size:expr, $enc_kernel:ident, $dec_kernel:ident, $bits:expr
    ) => {
        #[doc = concat!("AES-", $bits, " encryption only, on VAES.")]
        pub struct $enc {
            inner: $inner_enc,
        }

        #[doc = concat!("AES-", $bits, " decryption only, on VAES.")]
        pub struct $dec {
            inner: $inner_dec,
        }

        impl $enc {
            /// The key length in bytes.
            pub const KEY_SIZE: usize = $key_size;
            /// The block length in bytes.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;
            /// Blocks kept in flight.
            pub const PARALLEL_BLOCKS: usize = WIDTH;

            /// Expand `key` into an encryption schedule.
            ///
            /// # Panics
            ///
            /// If the CPU cannot run these kernels. Naming this type
            /// asserts that it can; the parent module's type of the same
            /// name checks and falls back instead.
            pub fn new(key: &[u8; $key_size]) -> Self {
                assert!(supported(), "VAES is not available");
                Self { inner: <$inner_enc>::new(key) }
            }

            /// Encrypt whole blocks in place, returning bytes consumed.
            pub fn encrypt(&self, data: &mut [u8]) -> usize {
                let blocks = data.len() / BLOCK_SIZE;
                let groups = blocks / WIDTH;
                if groups > 0 {
                    // SAFETY: support was checked when the key was
                    // expanded, and the buffer holds this many groups.
                    unsafe {
                        $enc_kernel(
                            self.inner.schedule().as_ptr(),
                            data.as_mut_ptr(),
                            groups,
                        );
                    }
                }
                // Anything left is shorter than a group; AES-NI takes it.
                self.inner.encrypt(&mut data[groups * WIDTH * BLOCK_SIZE..]);
                blocks * BLOCK_SIZE
            }

            /// Encrypt exactly one block in place.
            pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                self.inner.encrypt_block(block);
            }
        }

        impl $dec {
            /// The key length in bytes.
            pub const KEY_SIZE: usize = $key_size;
            /// The block length in bytes.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;
            /// Blocks kept in flight.
            pub const PARALLEL_BLOCKS: usize = WIDTH;

            /// Expand `key` into a decryption schedule.
            ///
            /// # Panics
            ///
            /// If the CPU cannot run these kernels.
            pub fn new(key: &[u8; $key_size]) -> Self {
                assert!(supported(), "VAES is not available");
                Self { inner: <$inner_dec>::new(key) }
            }

            /// Decrypt whole blocks in place, returning bytes consumed.
            pub fn decrypt(&self, data: &mut [u8]) -> usize {
                let blocks = data.len() / BLOCK_SIZE;
                let groups = blocks / WIDTH;
                if groups > 0 {
                    // SAFETY: as for the encryption side.
                    unsafe {
                        $dec_kernel(
                            self.inner.schedule().as_ptr(),
                            data.as_mut_ptr(),
                            groups,
                        );
                    }
                }
                self.inner.decrypt(&mut data[groups * WIDTH * BLOCK_SIZE..]);
                blocks * BLOCK_SIZE
            }

            /// Decrypt exactly one block in place.
            pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                self.inner.decrypt_block(block);
            }
        }

        impl KeyInit for $enc {
            fn try_new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                let key: &[u8; $key_size] = key
                    .try_into()
                    .map_err(|_| InvalidKeyLength { got: key.len() })?;
                Ok(Self::new(key))
            }
        }

        impl KeyInit for $dec {
            fn try_new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                let key: &[u8; $key_size] = key
                    .try_into()
                    .map_err(|_| InvalidKeyLength { got: key.len() })?;
                Ok(Self::new(key))
            }
        }

        impl BlockEncrypt for $enc {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = WIDTH;

            fn encrypt(&self, data: &mut [u8]) -> usize {
                $enc::encrypt(self, data)
            }
        }

        impl BlockDecrypt for $dec {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = WIDTH;

            fn decrypt(&self, data: &mut [u8]) -> usize {
                $dec::decrypt(self, data)
            }
        }

        impl core::fmt::Debug for $enc {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                // Never format round keys.
                f.write_str(concat!(stringify!($enc), " { .. }"))
            }
        }

        impl core::fmt::Debug for $dec {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                f.write_str(concat!(stringify!($dec), " { .. }"))
            }
        }
    };
}

define_aes!(
    Aes128Enc, Aes128Dec, aesni::Aes128Enc, aesni::Aes128Dec, 16,
    e128, d128, "128"
);
define_aes!(
    Aes192Enc, Aes192Dec, aesni::Aes192Enc, aesni::Aes192Dec, 24,
    e192, d192, "192"
);
define_aes!(
    Aes256Enc, Aes256Dec, aesni::Aes256Enc, aesni::Aes256Dec, 32,
    e256, d256, "256"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::arch::portable::ttable;

    /// xorshift64*, so a divergence is reproducible from the seed.
    struct Rng(u64);

    impl Rng {
        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                let b = x.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
        }
    }

    macro_rules! check {
        ($enc:ident, $dec:ident, $pe:path, $len:expr, $seed:expr) => {{
            let mut rng = Rng($seed);
            // Lengths either side of a sixteen block group, so the kernel,
            // the AES-NI tail and the boundary between them are all hit.
            for blocks in
                [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 100, 129]
            {
                let mut key = [0u8; $len];
                rng.fill(&mut key);
                let mut plaintext = vec![0u8; blocks * BLOCK_SIZE];
                rng.fill(&mut plaintext);

                let mut ours = plaintext.clone();
                let mut theirs = plaintext.clone();
                assert_eq!(
                    $enc::new(&key).encrypt(&mut ours),
                    blocks * BLOCK_SIZE
                );
                <$pe>::new(&key).encrypt(&mut theirs);
                assert_eq!(
                    ours, theirs,
                    "{} bit encrypt differs at {} blocks",
                    $len * 8, blocks
                );

                $dec::new(&key).decrypt(&mut ours);
                assert_eq!(
                    ours, plaintext,
                    "{} bit decrypt failed at {} blocks",
                    $len * 8, blocks
                );
            }
        }};
    }

    #[test]
    fn agrees_with_the_portable_implementation() {
        if !supported() {
            return;
        }
        check!(Aes128Enc, Aes128Dec, ttable::Aes128Enc, 16, 0x1111_2222);
        check!(Aes192Enc, Aes192Dec, ttable::Aes192Enc, 24, 0x3333_4444);
        check!(Aes256Enc, Aes256Dec, ttable::Aes256Enc, 32, 0x5555_6666);
    }

    /// FIPS-197 Appendix C.1, through the tail path.
    #[test]
    fn fips_197_aes128() {
        if !supported() {
            return;
        }
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd,
            0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];
        let mut block = plaintext;
        Aes128Enc::new(&key).encrypt_block(&mut block);
        assert_eq!(block, expected);
        Aes128Dec::new(&key).decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }

    #[test]
    fn partial_trailing_block_is_left_alone() {
        if !supported() {
            return;
        }
        let aes = Aes128Enc::new(&[0u8; 16]);
        let mut data = [0xccu8; WIDTH * BLOCK_SIZE + BLOCK_SIZE + 5];
        assert_eq!(
            aes.encrypt(&mut data),
            (WIDTH + 1) * BLOCK_SIZE
        );
        assert_eq!(&data[(WIDTH + 1) * BLOCK_SIZE..], &[0xcc; 5]);
    }
}
