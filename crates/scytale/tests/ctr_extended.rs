//! Extended CTR mode tests.
//!
//! Randomized cross-checks of the fused AES-CTR types against the
//! generic mode over the portable cipher, with random chunkings and a
//! dense sweep of near-wrap IVs hammering the carry fallback. This
//! tier trades minutes of run time for coverage the fast tier cannot
//! afford, so it is marked `#[ignore]`: run it with
//! `cargo test-extended`.


use scytale::symmetric::Ctr;
use scytale::symmetric::aes::arch::portable::ttable;
use scytale::symmetric::aes::{Aes128Ctr, Aes192Ctr, Aes256Ctr};

/// xorshift64*, so a divergence is reproducible from the seed alone.
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

/// Feed `data` through a fused CTR in random pieces and through the
/// generic portable mode whole, and demand identical bytes.
macro_rules! cross_check {
    ($ty:ident, $pe:path, $key_len:expr, $rng:expr, $iv:expr, $len:expr)
    => {{
        let mut key = [0u8; $key_len];
        $rng.fill(&mut key);
        let mut data = vec![0u8; $len];
        $rng.fill(&mut data);

        let mut ours = data.clone();
        let mut ctr = $ty::new(&key, &$iv);
        let mut rest = ours.as_mut_slice();
        while !rest.is_empty() {
            let take =
                (($rng.next() % 200) as usize + 1).min(rest.len());
            let (head, tail) = rest.split_at_mut(take);
            ctr.apply_keystream(head);
            rest = tail;
        }

        Ctr::try_new(<$pe>::new(&key), &$iv)
            .expect("block-size IV")
            .apply_keystream(&mut data);

        assert_eq!(
            ours, data,
            "{} bits, {} bytes, iv {:02x?}",
            $key_len * 8, $len, $iv
        );
    }};
}

#[test]
#[ignore = "exhaustive randomized cross-check"]
fn random_streams_agree_with_the_generic_portable_mode() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for _ in 0..300 {
        let len = (rng.next() % 4096) as usize;
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        cross_check!(Aes128Ctr, ttable::Aes128Enc, 16, rng, iv, len);
        cross_check!(Aes192Ctr, ttable::Aes192Enc, 24, rng, iv, len);
        cross_check!(Aes256Ctr, ttable::Aes256Enc, 32, rng, iv, len);
    }
}

/// A long stream crossing many kernel group boundaries in one call.
#[test]
#[ignore = "exhaustive randomized cross-check"]
fn long_streams_agree_with_the_generic_portable_mode() {
    let mut rng = Rng(0xfedc_ba98_7654_3210);
    for len in [64 * 1024, 256 * 1024 + 7] {
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        cross_check!(Aes128Ctr, ttable::Aes128Enc, 16, rng, iv, len);
    }
}

/// Every IV whose low 64 bits sit within a small window of the carry
/// boundary, so the fallback path runs at every offset within a group.
#[test]
#[ignore = "exhaustive randomized cross-check"]
fn near_wrap_ivs_take_the_carry_fallback() {
    let mut rng = Rng(0x2468_ace0_1357_9bdf);
    for k in 0..64u64 {
        let start = ((rng.next() as u128) << 64)
            | (u64::MAX - k) as u128;
        let iv = start.to_be_bytes();
        let len = 16 * 100 + (rng.next() % 16) as usize;
        cross_check!(Aes128Ctr, ttable::Aes128Enc, 16, rng, iv, len);
        cross_check!(Aes256Ctr, ttable::Aes256Enc, 32, rng, iv, len);
    }

    // The full 128-bit wrap as well.
    for k in 0..8u64 {
        let start = 0u128.wrapping_sub((k + 1) as u128);
        let iv = start.to_be_bytes();
        cross_check!(Aes128Ctr, ttable::Aes128Enc, 16, rng, iv, 4096);
    }
}
