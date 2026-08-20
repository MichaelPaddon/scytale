//! AES-128, AES-192 and AES-256 over 32-bit T-tables.
//!
//! This is the portable implementation: pure Rust, no target features, valid
//! on every platform. It is the baseline every other AES backend is measured
//! against.
//!
//! Each key size comes in three types. `Aes128Enc` holds only an encryption
//! schedule, `Aes128Dec` only a decryption one, and `Aes128` holds both for
//! callers that need both directions. Deriving a decryption schedule costs
//! roughly as much again as the encryption one plus an InvMixColumns pass
//! over every round key, so a counter mode that only ever encrypts should
//! name the `Enc` type and not pay for it.
//!
//! # Side channels
//!
//! T-table AES indexes its tables with key-dependent bytes, so which cache
//! lines get touched depends on the key. An attacker able to observe cache
//! state can recover key material from that. This is inherent to the T-table
//! construction, not a defect in this code. Prefer a hardware backend where
//! one exists and the threat model includes a local or co-resident attacker.

mod tables;

use tables::{INV_SBOX, RCON, SBOX, TD, TE};

use zeroize::Zeroize;

use crate::symmetric::block_cipher::{
    BlockDecrypt, BlockEncrypt, InvalidKeyLength, KeyInit,
};

/// The AES block size in bytes. Identical for all three key sizes.
pub const BLOCK_SIZE: usize = 16;

/// Substitute all four bytes of a word through the S-box.
fn sub_word(w: u32) -> u32 {
    ((SBOX[(w >> 24) as usize] as u32) << 24)
        | ((SBOX[((w >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX[((w >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX[(w & 0xff) as usize] as u32)
}

/// Expand `key` into the encryption round keys.
///
/// `W` is the round key length in words, so the round count is implied and
/// the compiler sees a fixed-size array rather than an opaque slice.
fn expand_encrypt_key<const W: usize>(
    key: &[u8],
    nk: usize,
    rk: &mut [u32; W],
) {
    for i in 0..nk {
        rk[i] = u32::from_be_bytes([
            key[4 * i],
            key[4 * i + 1],
            key[4 * i + 2],
            key[4 * i + 3],
        ]);
    }

    for i in nk..W {
        let mut temp = rk[i - 1];
        if i % nk == 0 {
            temp = sub_word(temp.rotate_left(8)) ^ RCON[i / nk];
        } else if nk > 6 && i % nk == 4 {
            // AES-256 substitutes again at the midpoint of each key block.
            temp = sub_word(temp);
        }
        rk[i] = rk[i - nk] ^ temp;
    }

    // The expansion above follows the specification's big endian words. The
    // rounds want little endian columns, so convert once here rather than
    // byte swapping every block.
    for word in rk.iter_mut() {
        *word = word.swap_bytes();
    }
}

/// Turn encryption round keys into decryption ones for the equivalent
/// inverse cipher.
///
/// The round keys are reversed by group of four and then passed through
/// InvMixColumns, which lets decryption use the same table-driven round
/// structure as encryption instead of a separate slower one.
fn derive_decrypt_key<const W: usize>(rk: &mut [u32; W]) {
    let rounds = W / 4 - 1;

    for i in 0..rounds.div_ceil(2) {
        let (lo, hi) = (4 * i, 4 * (rounds - i));
        for j in 0..4 {
            rk.swap(lo + j, hi + j);
        }
    }

    // The first and last round keys are used before and after the table
    // rounds, so they stay untransformed.
    for word in rk[4..W - 4].iter_mut() {
        let w = *word;
        *word = TD[0][SBOX[byte(w, 0)] as usize]
            ^ TD[1][SBOX[byte(w, 1)] as usize]
            ^ TD[2][SBOX[byte(w, 2)] as usize]
            ^ TD[3][SBOX[byte(w, 3)] as usize];
    }
}

/// The state as four columns.
type Columns = [u32; 4];

/// Row `row` of a column.
#[inline(always)]
fn byte(column: u32, row: usize) -> usize {
    (column >> (8 * row)) as u8 as usize
}

#[inline(always)]
fn load(block: &[u8; BLOCK_SIZE]) -> Columns {
    let mut s = [0u32; 4];
    for (column, chunk) in s.iter_mut().zip(block.chunks_exact(4)) {
        *column =
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    s
}

#[inline(always)]
fn store(s: Columns, block: &mut [u8; BLOCK_SIZE]) {
    for (column, chunk) in s.iter().zip(block.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&column.to_le_bytes());
    }
}

#[inline(always)]
fn round_key<const W: usize>(rk: &[u32; W], round: usize) -> Columns {
    let mut out = [0u32; 4];
    for (column, word) in out.iter_mut().zip(&rk[4 * round..4 * round + 4]) {
        *column = *word;
    }
    out
}

// ShiftRows is folded into which column each row's byte is taken from:
// forward rounds read column (c + r) mod 4 for row r, inverse rounds read
// column (c - r) mod 4.

#[inline(always)]
fn encrypt_round(s: Columns, rk: Columns) -> Columns {
    let mut t = [0u32; 4];
    for (c, out) in t.iter_mut().enumerate() {
        *out = TE[0][byte(s[c], 0)]
            ^ TE[1][byte(s[(c + 1) % 4], 1)]
            ^ TE[2][byte(s[(c + 2) % 4], 2)]
            ^ TE[3][byte(s[(c + 3) % 4], 3)]
            ^ rk[c];
    }
    t
}

#[inline(always)]
fn decrypt_round(s: Columns, rk: Columns) -> Columns {
    let mut t = [0u32; 4];
    for (c, out) in t.iter_mut().enumerate() {
        *out = TD[0][byte(s[c], 0)]
            ^ TD[1][byte(s[(c + 3) % 4], 1)]
            ^ TD[2][byte(s[(c + 2) % 4], 2)]
            ^ TD[3][byte(s[(c + 1) % 4], 3)]
            ^ rk[c];
    }
    t
}

// The last round substitutes and shifts but does not mix, so it reads the
// S-box directly instead of the tables.

#[inline(always)]
fn encrypt_last_round(s: Columns, rk: Columns) -> Columns {
    let mut t = [0u32; 4];
    for (c, out) in t.iter_mut().enumerate() {
        *out = u32::from_le_bytes([
            SBOX[byte(s[c], 0)],
            SBOX[byte(s[(c + 1) % 4], 1)],
            SBOX[byte(s[(c + 2) % 4], 2)],
            SBOX[byte(s[(c + 3) % 4], 3)],
        ]) ^ rk[c];
    }
    t
}

#[inline(always)]
fn decrypt_last_round(s: Columns, rk: Columns) -> Columns {
    let mut t = [0u32; 4];
    for (c, out) in t.iter_mut().enumerate() {
        *out = u32::from_le_bytes([
            INV_SBOX[byte(s[c], 0)],
            INV_SBOX[byte(s[(c + 3) % 4], 1)],
            INV_SBOX[byte(s[(c + 2) % 4], 2)],
            INV_SBOX[byte(s[(c + 1) % 4], 3)],
        ]) ^ rk[c];
    }
    t
}

/// One block through the encryption rounds.
///
/// `R` is the round count as a constant, so the loop has a known trip count.
#[inline(always)]
fn encrypt_block_with<const W: usize, const R: usize>(
    rk: &[u32; W],
    block: &mut [u8; BLOCK_SIZE],
) {
    let mut s = load(block);
    for (column, k) in s.iter_mut().zip(round_key(rk, 0).iter()) {
        *column ^= k;
    }
    // Two rounds per iteration, so the loop's increment and test are paid
    // once per two rounds. R - 1 middle rounds is always odd, so the second
    // half is skipped on the final pass.
    let mut round = 1;
    let mut pairs = R / 2;
    loop {
        s = encrypt_round(s, round_key(rk, round));
        round += 1;
        pairs -= 1;
        if pairs == 0 {
            break;
        }
        s = encrypt_round(s, round_key(rk, round));
        round += 1;
    }
    s = encrypt_last_round(s, round_key(rk, R));
    store(s, block);
}

/// One block through the decryption rounds.
#[inline(always)]
fn decrypt_block_with<const W: usize, const R: usize>(
    rk: &[u32; W],
    block: &mut [u8; BLOCK_SIZE],
) {
    let mut s = load(block);
    for (column, k) in s.iter_mut().zip(round_key(rk, 0).iter()) {
        *column ^= k;
    }
    // Two rounds per iteration, so the loop's increment and test are paid
    // once per two rounds. R - 1 middle rounds is always odd, so the second
    // half is skipped on the final pass.
    let mut round = 1;
    let mut pairs = R / 2;
    loop {
        s = decrypt_round(s, round_key(rk, round));
        round += 1;
        pairs -= 1;
        if pairs == 0 {
            break;
        }
        s = decrypt_round(s, round_key(rk, round));
        round += 1;
    }
    s = decrypt_last_round(s, round_key(rk, R));
    store(s, block);
}

macro_rules! define_aes {
    (
        $enc:ident, $dec:ident, $both:ident,
        $key_size:expr, $nk:expr, $words:expr, $rounds:expr,
        $bits:expr
    ) => {
        #[doc = concat!("AES-", $bits, " encryption only.")]
        ///
        /// Holds just the encryption key schedule. Prefer this over the
        /// combined type when you never decrypt, which is the case for every
        /// counter based mode.
        pub struct $enc {
            rk: [u32; $words],
        }

        #[doc = concat!("AES-", $bits, " decryption only.")]
        pub struct $dec {
            rk: [u32; $words],
        }

        #[doc = concat!("AES-", $bits, ", both directions.")]
        ///
        /// Builds both key schedules, so it costs about twice what a
        /// one-direction type does to construct. Use it when you genuinely
        /// need both.
        pub struct $both {
            enc: $enc,
            dec: $dec,
        }

        impl $enc {
            /// The key length in bytes.
            pub const KEY_SIZE: usize = $key_size;
            /// The block length in bytes.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;
            /// Blocks kept in flight. This implementation is scalar.
            pub const PARALLEL_BLOCKS: usize = 1;

            /// Expand `key` into an encryption schedule.
            ///
            /// Taking a fixed-size array means a wrong key length is a
            /// compile error, so there is no failure case to report.
            pub fn new(key: &[u8; $key_size]) -> Self {
                // Expanded in place: a local array moved out afterwards
                // would leave a second copy of the schedule on the stack
                // that no destructor reaches.
                let mut this = Self { rk: [0u32; $words] };
                expand_encrypt_key(key, $nk, &mut this.rk);
                this
            }

            /// Encrypt whole blocks in place, returning bytes consumed.
            ///
            /// Pass as much data as you have: this is what lets an
            /// accelerated implementation pipeline.
            pub fn encrypt(&self, data: &mut [u8]) -> usize {
                let (blocks, _tail) = data.as_chunks_mut::<BLOCK_SIZE>();
                for block in blocks.iter_mut() {
                    encrypt_block_with::<$words, $rounds>(&self.rk, block);
                }
                blocks.len() * BLOCK_SIZE
            }

            /// Encrypt exactly one block in place.
            pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                encrypt_block_with::<$words, $rounds>(&self.rk, block);
            }

            /// Encrypt successive counter values and XOR them into
            /// `data` in place, advancing `counter`.
            ///
            /// The counter is one block, big endian, wrapping at the
            /// full block width, as SP 800-38A specifies. Whole blocks
            /// only, like [`Self::encrypt`]; returns bytes consumed.
            /// This scalar version is the reference the accelerated
            /// counter kernels are tested against.
            pub fn ctr(
                &self,
                counter: &mut [u8; BLOCK_SIZE],
                data: &mut [u8],
            ) -> usize {
                let (blocks, _tail) = data.as_chunks_mut::<BLOCK_SIZE>();
                let mut c = u128::from_be_bytes(*counter);
                let mut keystream = [0u8; BLOCK_SIZE];
                for block in blocks.iter_mut() {
                    keystream = c.to_be_bytes();
                    encrypt_block_with::<$words, $rounds>(
                        &self.rk,
                        &mut keystream,
                    );
                    for (d, k) in block.iter_mut().zip(&keystream) {
                        *d ^= *k;
                    }
                    c = c.wrapping_add(1);
                }
                keystream.zeroize();
                *counter = c.to_be_bytes();
                blocks.len() * BLOCK_SIZE
            }
        }

        impl $dec {
            /// The key length in bytes.
            pub const KEY_SIZE: usize = $key_size;
            /// The block length in bytes.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;
            /// Blocks kept in flight. This implementation is scalar.
            pub const PARALLEL_BLOCKS: usize = 1;

            /// Expand `key` into a decryption schedule.
            pub fn new(key: &[u8; $key_size]) -> Self {
                let mut this = Self { rk: [0u32; $words] };
                expand_encrypt_key(key, $nk, &mut this.rk);
                derive_decrypt_key(&mut this.rk);
                this
            }

            /// Decrypt whole blocks in place, returning bytes consumed.
            pub fn decrypt(&self, data: &mut [u8]) -> usize {
                let (blocks, _tail) = data.as_chunks_mut::<BLOCK_SIZE>();
                for block in blocks.iter_mut() {
                    decrypt_block_with::<$words, $rounds>(&self.rk, block);
                }
                blocks.len() * BLOCK_SIZE
            }

            /// Decrypt exactly one block in place.
            pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                decrypt_block_with::<$words, $rounds>(&self.rk, block);
            }
        }

        impl $both {
            /// The key length in bytes.
            pub const KEY_SIZE: usize = $key_size;
            /// The block length in bytes.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;
            /// Blocks kept in flight. This implementation is scalar.
            pub const PARALLEL_BLOCKS: usize = 1;

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

        impl KeyInit for $both {
            fn try_new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                let key: &[u8; $key_size] = key
                    .try_into()
                    .map_err(|_| InvalidKeyLength { got: key.len() })?;
                Ok(Self::new(key))
            }
        }

        impl BlockEncrypt for $enc {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = 1;

            fn encrypt(&self, data: &mut [u8]) -> usize {
                $enc::encrypt(self, data)
            }
        }

        impl BlockDecrypt for $dec {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = 1;

            fn decrypt(&self, data: &mut [u8]) -> usize {
                $dec::decrypt(self, data)
            }
        }

        impl BlockEncrypt for $both {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = 1;

            fn encrypt(&self, data: &mut [u8]) -> usize {
                self.enc.encrypt(data)
            }
        }

        impl BlockDecrypt for $both {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            const PARALLEL_BLOCKS: usize = 1;

            fn decrypt(&self, data: &mut [u8]) -> usize {
                self.dec.decrypt(data)
            }
        }

        impl Drop for $enc {
            fn drop(&mut self) {
                self.rk.zeroize();
            }
        }

        impl Drop for $dec {
            fn drop(&mut self) {
                self.rk.zeroize();
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

        impl core::fmt::Debug for $both {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                f.write_str(concat!(stringify!($both), " { .. }"))
            }
        }
    };
}

define_aes!(Aes128Enc, Aes128Dec, Aes128, 16, 4, 44, 10, "128");
define_aes!(Aes192Enc, Aes192Dec, Aes192, 24, 6, 52, 12, "192");
define_aes!(Aes256Enc, Aes256Dec, Aes256, 32, 8, 60, 14, "256");

#[cfg(test)]
mod tests {
    use super::*;

    const FIPS_PLAINTEXT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];

    /// FIPS-197 Appendix C.1.
    #[test]
    fn fips_197_aes128() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd,
            0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];

        let mut block = FIPS_PLAINTEXT;
        Aes128Enc::new(&key).encrypt_block(&mut block);
        assert_eq!(block, expected);
        Aes128Dec::new(&key).decrypt_block(&mut block);
        assert_eq!(block, FIPS_PLAINTEXT);
    }

    /// FIPS-197 Appendix C.2.
    #[test]
    fn fips_197_aes192() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
        ];
        let expected = [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf,
            0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
        ];

        let mut block = FIPS_PLAINTEXT;
        Aes192Enc::new(&key).encrypt_block(&mut block);
        assert_eq!(block, expected);
        Aes192Dec::new(&key).decrypt_block(&mut block);
        assert_eq!(block, FIPS_PLAINTEXT);
    }

    /// FIPS-197 Appendix C.3.
    #[test]
    fn fips_197_aes256() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let expected = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc,
            0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];

        let mut block = FIPS_PLAINTEXT;
        Aes256Enc::new(&key).encrypt_block(&mut block);
        assert_eq!(block, expected);
        Aes256Dec::new(&key).decrypt_block(&mut block);
        assert_eq!(block, FIPS_PLAINTEXT);
    }

    /// The split types must agree with the combined one, or callers choosing
    /// the cheaper type would silently get different answers.
    #[test]
    fn split_and_combined_types_agree() {
        let key = [0x2bu8; 16];
        let plaintext: Vec<u8> = (0..16u8 * 5).collect();

        let mut split = plaintext.clone();
        Aes128Enc::new(&key).encrypt(&mut split);

        let mut combined = plaintext.clone();
        Aes128::new(&key).encrypt(&mut combined);
        assert_eq!(split, combined);

        Aes128Dec::new(&key).decrypt(&mut split);
        assert_eq!(split, plaintext);
    }

    #[test]
    fn bulk_matches_block_at_a_time() {
        let aes = Aes128Enc::new(&[0x2bu8; 16]);
        let mut bulk = [0u8; 16 * 7];
        for (i, b) in bulk.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut one_at_a_time = bulk;

        assert_eq!(aes.encrypt(&mut bulk), 16 * 7);
        for block in one_at_a_time.as_chunks_mut::<16>().0 {
            aes.encrypt_block(block);
        }
        assert_eq!(bulk, one_at_a_time);
    }

    #[test]
    fn partial_trailing_block_is_left_alone() {
        let aes = Aes256Enc::new(&[0u8; 32]);
        let mut data = [0xccu8; 16 + 5];

        assert_eq!(aes.encrypt(&mut data), 16, "only whole blocks consumed");
        assert_eq!(&data[16..], &[0xcc; 5], "tail must be untouched");
    }

    #[test]
    fn short_buffer_consumes_nothing() {
        let aes = Aes128Enc::new(&[0u8; 16]);
        let mut data = [0xccu8; 15];
        assert_eq!(aes.encrypt(&mut data), 0);
        assert_eq!(data, [0xcc; 15]);
    }

    #[test]
    fn try_new_rejects_wrong_key_lengths() {
        assert!(Aes128Enc::try_new(&[0u8; 16]).is_ok());
        assert_eq!(
            Aes128Enc::try_new(&[0u8; 24]).unwrap_err(),
            InvalidKeyLength { got: 24 }
        );
        assert!(Aes192Dec::try_new(&[0u8; 24]).is_ok());
        assert!(Aes256::try_new(&[0u8; 32]).is_ok());
        assert_eq!(
            Aes256Enc::try_new(&[]).unwrap_err(),
            InvalidKeyLength { got: 0 }
        );
    }

    /// Drop the value in storage we own, then read that storage back as
    /// raw bytes to confirm the destructor cleared it.
    macro_rules! assert_wiped_on_drop {
        ($ty:ty, $key:expr) => {{
            let mut slot = core::mem::MaybeUninit::new(<$ty>::new($key));
            let ptr = slot.as_mut_ptr();
            let bytes = ptr.cast::<u8>();
            let len = core::mem::size_of::<$ty>();

            // SAFETY: slot holds an initialized value of exactly this size.
            let live = unsafe { core::slice::from_raw_parts(bytes, len) };
            assert!(
                live.iter().any(|&b| b != 0),
                concat!(stringify!($ty), " held no schedule to begin with")
            );

            // SAFETY: the value is initialized and is never read as a value
            // again; only its storage is inspected below.
            unsafe { core::ptr::drop_in_place(ptr) };

            // SAFETY: the storage is ours and still allocated; the bytes
            // remain readable after the value has been dropped.
            let dead = unsafe { core::slice::from_raw_parts(bytes, len) };
            assert!(
                dead.iter().all(|&b| b == 0),
                concat!(stringify!($ty), " left key material behind")
            );
        }};
    }

    #[test]
    fn encryption_schedule_is_wiped_on_drop() {
        assert_wiped_on_drop!(Aes128Enc, &[0xab; 16]);
        assert_wiped_on_drop!(Aes256Enc, &[0xcd; 32]);
    }

    #[test]
    fn decryption_schedule_is_wiped_on_drop() {
        assert_wiped_on_drop!(Aes128Dec, &[0xab; 16]);
        assert_wiped_on_drop!(Aes192Dec, &[0xcd; 24]);
    }

    /// The combined type owns both halves, so both destructors must run.
    #[test]
    fn combined_schedules_are_wiped_on_drop() {
        assert_wiped_on_drop!(Aes128, &[0xab; 16]);
        assert_wiped_on_drop!(Aes256, &[0xcd; 32]);
    }

    #[test]
    fn debug_does_not_leak_round_keys() {
        let aes = Aes128Enc::new(&[0xab; 16]);
        assert_eq!(format!("{aes:?}"), "Aes128Enc { .. }");
        let aes = Aes128::new(&[0xab; 16]);
        assert_eq!(format!("{aes:?}"), "Aes128 { .. }");
    }
}
