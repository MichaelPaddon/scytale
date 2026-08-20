//! Slow AES tests.
//!
//! These are marked `#[ignore]`, so a plain `cargo test` compiles them
//! and skips them; `cargo test-extended` runs them. It is where
//! exhaustive and long-running checks live.

use scytale::symmetric::aes::{Aes128, Aes192, Aes256};

/// xorshift64*, so the sweep is wide but exactly reproducible on failure.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

const ROUNDTRIPS: usize = 200_000;

#[test]
#[ignore = "exhaustive sweep over many keys"]
fn aes128_roundtrips_over_many_keys() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for i in 0..ROUNDTRIPS {
        let mut key = [0u8; 16];
        let mut block = [0u8; 16];
        rng.fill(&mut key);
        rng.fill(&mut block);
        let original = block;

        let aes = Aes128::new(&key);
        aes.encrypt_block(&mut block);
        assert_ne!(block, original, "ciphertext equals plaintext at {i}");
        aes.decrypt_block(&mut block);
        assert_eq!(block, original, "roundtrip failed at iteration {i}");
    }
}

#[test]
#[ignore = "exhaustive sweep over many keys"]
fn aes192_roundtrips_over_many_keys() {
    let mut rng = Rng(0xfedc_ba98_7654_3210);
    for i in 0..ROUNDTRIPS {
        let mut key = [0u8; 24];
        let mut block = [0u8; 16];
        rng.fill(&mut key);
        rng.fill(&mut block);
        let original = block;

        let aes = Aes192::new(&key);
        aes.encrypt_block(&mut block);
        aes.decrypt_block(&mut block);
        assert_eq!(block, original, "roundtrip failed at iteration {i}");
    }
}

#[test]
#[ignore = "exhaustive sweep over many keys"]
fn aes256_roundtrips_over_many_keys() {
    let mut rng = Rng(0x2468_ace0_1357_9bdf);
    for i in 0..ROUNDTRIPS {
        let mut key = [0u8; 32];
        let mut block = [0u8; 16];
        rng.fill(&mut key);
        rng.fill(&mut block);
        let original = block;

        let aes = Aes256::new(&key);
        aes.encrypt_block(&mut block);
        aes.decrypt_block(&mut block);
        assert_eq!(block, original, "roundtrip failed at iteration {i}");
    }
}

/// Flipping one key bit must change the ciphertext. Catches a key schedule
/// that silently ignores part of the key, which the fixed vectors would not.
#[test]
#[ignore = "exhaustive sweep over many keys"]
fn every_key_bit_affects_the_ciphertext() {
    let base_key = [0x5au8; 32];
    let plaintext = [0xa5u8; 16];

    let mut baseline = plaintext;
    Aes256::new(&base_key).encrypt_block(&mut baseline);

    for bit in 0..256 {
        let mut key = base_key;
        key[bit / 8] ^= 1 << (bit % 8);

        let mut block = plaintext;
        Aes256::new(&key).encrypt_block(&mut block);
        assert_ne!(block, baseline, "key bit {bit} had no effect");
    }
}

/// The same, for every plaintext bit.
#[test]
#[ignore = "exhaustive sweep over many keys"]
fn every_plaintext_bit_affects_the_ciphertext() {
    let key = [0x5au8; 16];
    let base_plaintext = [0xa5u8; 16];
    let aes = Aes128::new(&key);

    let mut baseline = base_plaintext;
    aes.encrypt_block(&mut baseline);

    for bit in 0..128 {
        let mut block = base_plaintext;
        block[bit / 8] ^= 1 << (bit % 8);
        aes.encrypt_block(&mut block);
        assert_ne!(block, baseline, "plaintext bit {bit} had no effect");
    }
}
