//! Cross-check scytale against OpenSSL before trusting any timing.
//!
//! A benchmark only means something if both sides compute the same answer,
//! so this fails loudly if they ever diverge.

#![cfg(openssl_available)]

use scytale::symmetric::aes::{
    Aes128Dec, Aes128Enc, Aes192Dec, Aes192Enc, Aes256Dec, Aes256Enc,
};
use scytale_bench::openssl::OpensslAes;

/// xorshift64*, so a divergence is reproducible from the seed alone.
struct Rng(u64);

impl Rng {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            let bytes = x.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

macro_rules! check_key_size {
    ($enc:ty, $dec:ty, $key_len:expr, $seed:expr) => {{
        let mut rng = Rng($seed);
        for blocks in [1usize, 2, 3, 7, 16, 64] {
            let mut key = [0u8; $key_len];
            rng.fill(&mut key);
            let mut plaintext = vec![0u8; blocks * 16];
            rng.fill(&mut plaintext);

            let mut ours = plaintext.clone();
            let mut theirs = plaintext.clone();
            assert_eq!(
                <$enc>::new(&key).encrypt(&mut ours),
                blocks * 16,
                "scytale consumed the wrong length"
            );
            let openssl = OpensslAes::try_new_encrypt(&key)
                .expect("openssl rejected a valid key");
            assert_eq!(
                openssl.encrypt(&mut theirs),
                blocks * 16,
                "openssl consumed the wrong length"
            );
            assert_eq!(
                ours, theirs,
                "encrypt disagrees at {} blocks, {} bit key",
                blocks,
                $key_len * 8
            );

            <$dec>::new(&key).decrypt(&mut ours);
            OpensslAes::try_new_decrypt(&key)
                .expect("openssl rejected a valid key")
                .decrypt(&mut theirs);
            assert_eq!(ours, plaintext, "scytale failed to round trip");
            assert_eq!(theirs, plaintext, "openssl failed to round trip");
        }
    }};
}

#[test]
fn scytale_and_openssl_agree() {
    check_key_size!(Aes128Enc, Aes128Dec, 16, 0x0123_4567_89ab_cdef);
    check_key_size!(Aes192Enc, Aes192Dec, 24, 0xfedc_ba98_7654_3210);
    check_key_size!(Aes256Enc, Aes256Dec, 32, 0x2468_ace0_1357_9bdf);
}

/// The CTR pair must agree too, including on lengths that are not a
/// whole number of blocks and when fed in pieces.
#[test]
fn scytale_and_openssl_ctr_agree() {
    use scytale::symmetric::Ctr;
    use scytale_bench::openssl::OpensslCtr;

    let mut rng = Rng(0x1357_9bdf_2468_ace0);
    for len in [1usize, 15, 16, 17, 100, 256, 1000, 4096] {
        let mut key = [0u8; 16];
        rng.fill(&mut key);
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let mut plaintext = vec![0u8; len];
        rng.fill(&mut plaintext);

        let mut ours = plaintext.clone();
        let mut ctr = Ctr::try_new(Aes128Enc::new(&key), &iv)
            .expect("block-size IV");
        // Split the message so the resumable state is exercised too.
        let (head, tail) = ours.split_at_mut(len / 3);
        ctr.apply_keystream(head);
        ctr.apply_keystream(tail);

        let mut theirs = plaintext.clone();
        OpensslCtr::try_new(&key, &iv)
            .expect("openssl rejected a valid key")
            .apply_keystream(&mut theirs);

        assert_eq!(ours, theirs, "CTR disagrees at {len} bytes");
    }
}

/// The accelerated pair must agree too, or the accelerated tier of the
/// benchmark would be timing two different computations.
#[test]
fn scytale_and_openssl_aesni_agree() {
    use scytale_bench::openssl::OpensslAesni;

    let mut rng = Rng(0x0f1e_2d3c_4b5a_6978);
    for blocks in [1usize, 2, 7, 8, 9, 17, 64] {
        let mut key = [0u8; 16];
        rng.fill(&mut key);
        let mut plaintext = vec![0u8; blocks * 16];
        rng.fill(&mut plaintext);

        let mut ours = plaintext.clone();
        let mut theirs = plaintext.clone();
        Aes128Enc::new(&key).encrypt(&mut ours);
        let openssl = OpensslAesni::try_new_encrypt(&key)
            .expect("openssl rejected a valid key");
        assert_eq!(openssl.encrypt(&mut theirs), blocks * 16);
        assert_eq!(ours, theirs, "AES-NI encrypt differs at {blocks}");

        Aes128Dec::new(&key).decrypt(&mut ours);
        OpensslAesni::try_new_decrypt(&key)
            .expect("openssl rejected a valid key")
            .decrypt(&mut theirs);
        assert_eq!(ours, plaintext, "scytale AES-NI round trip");
        assert_eq!(theirs, plaintext, "openssl AES-NI round trip");
    }
}
