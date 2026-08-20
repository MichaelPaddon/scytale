//! Fast CTR mode known-answer tests.
//!
//! This tier runs under a plain `cargo test` and is kept to a few seconds
//! per algorithm. Exhaustive work belongs in the extended tier.

use scytale::symmetric::aes::arch::portable::ttable;
use scytale::symmetric::aes::{
    Aes128Ctr, Aes128Enc, Aes192Ctr, Aes192Enc, Aes256Ctr, Aes256Enc,
};
use scytale::symmetric::{BlockEncrypt, Ctr};

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex literal has an odd length");
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .expect("test vector is not valid hex")
        })
        .collect()
}

/// The initial counter block every SP 800-38A CTR example uses.
const IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/// The four-block message every SP 800-38A example uses.
const PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172a\
                         ae2d8a571e03ac9c9eb76fac45af8e51\
                         30c81c46a35ce411e5fbc1191a0a52ef\
                         f69f2445df4f9b17ad2b417be66c3710";

/// Check one cipher against a CTR vector in both directions.
///
/// CTR encryption and decryption are the same operation, but the
/// specification lists them as separate cases, so both are spelled out.
fn check<C: BlockEncrypt>(make: impl Fn() -> C, ct: &str) {
    let iv = unhex(IV);
    let ciphertext = unhex(ct);

    let mut data = unhex(PLAINTEXT);
    Ctr::try_new(make(), &iv)
        .expect("block-size IV")
        .apply_keystream(&mut data);
    assert_eq!(data, ciphertext, "encrypt");

    Ctr::try_new(make(), &iv)
        .expect("block-size IV")
        .apply_keystream(&mut data);
    assert_eq!(data, unhex(PLAINTEXT), "decrypt");
}

const CT_128: &str = "874d6191b620e3261bef6864990db6ce\
                      9806f66b7970fdff8617187bb9fffdff\
                      5ae4df3edbd5d35e5b4f09020db03eab\
                      1e031dda2fbe03d1792170a0f3009cee";

const CT_192: &str = "1abc932417521ca24f2b0459fe7e6e0b\
                      090339ec0aa6faefd5ccc2c6f4ce8e94\
                      1e36b26bd1ebc670d1bd1d665620abf7\
                      4f78a7f6d29809585a97daec58c6b050";

const CT_256: &str = "601ec313775789a5b7a7f504bbf3d228\
                      f443e3ca4d62b59aca84e990cacaf5c5\
                      2b0930daa23de94ce87017ba2d84988d\
                      dfc9c58db67aada613c2dd08457941a6";

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d7781\
                       1f352c073b6108d72d9810a30914dff4";

fn key<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().expect("key literal has the wrong length")
}

/// Check a fused AES-CTR type against a vector in both directions.
macro_rules! check_fused {
    ($ty:ident, $key:expr, $ct:expr) => {{
        let iv: [u8; 16] =
            unhex(IV).try_into().expect("IV literal is one block");
        let ciphertext = unhex($ct);

        let mut data = unhex(PLAINTEXT);
        $ty::new($key, &iv).apply_keystream(&mut data);
        assert_eq!(data, ciphertext, "encrypt");

        $ty::new($key, &iv).apply_keystream(&mut data);
        assert_eq!(data, unhex(PLAINTEXT), "decrypt");
    }};
}

/// NIST SP 800-38A, F.5.1 and F.5.2 (CTR-AES128), through the fused
/// type, the generic mode over the dispatching cipher, and the generic
/// mode over the portable backend they must both agree with.
#[test]
fn sp800_38a_aes128_ctr() {
    let k: [u8; 16] = key(KEY_128);
    check_fused!(Aes128Ctr, &k, CT_128);
    check(|| Aes128Enc::new(&k), CT_128);
    check(|| ttable::Aes128Enc::new(&k), CT_128);
}

/// NIST SP 800-38A, F.5.3 and F.5.4 (CTR-AES192).
#[test]
fn sp800_38a_aes192_ctr() {
    let k: [u8; 24] = key(KEY_192);
    check_fused!(Aes192Ctr, &k, CT_192);
    check(|| Aes192Enc::new(&k), CT_192);
    check(|| ttable::Aes192Enc::new(&k), CT_192);
}

/// NIST SP 800-38A, F.5.5 and F.5.6 (CTR-AES256).
#[test]
fn sp800_38a_aes256_ctr() {
    let k: [u8; 32] = key(KEY_256);
    check_fused!(Aes256Ctr, &k, CT_256);
    check(|| Aes256Enc::new(&k), CT_256);
    check(|| ttable::Aes256Enc::new(&k), CT_256);
}

/// F.5.1 again, fed in awkward pieces: the stream must not care how it
/// is chunked.
#[test]
fn chunked_feeding_matches_the_vector() {
    let k: [u8; 16] = key(KEY_128);
    let iv = unhex(IV);
    let ciphertext = unhex(CT_128);

    for size in [1, 3, 16, 37] {
        let mut data = unhex(PLAINTEXT);
        let mut ctr = Ctr::try_new(Aes128Enc::new(&k), &iv)
            .expect("block-size IV");
        for chunk in data.chunks_mut(size) {
            ctr.apply_keystream(chunk);
        }
        assert_eq!(data, ciphertext, "chunk size {size}");
    }
}

/// The backend `ctr` entry point must match the mode built on it.
#[test]
fn portable_ctr_kernel_matches_the_vector() {
    let k: [u8; 16] = key(KEY_128);
    let mut counter: [u8; 16] =
        unhex(IV).try_into().expect("IV literal is one block");

    let mut data = unhex(PLAINTEXT);
    let aes = ttable::Aes128Enc::new(&k);
    assert_eq!(aes.ctr(&mut counter, &mut data), data.len());
    assert_eq!(data, unhex(CT_128));

    // Four blocks consumed, so the counter must have advanced by four.
    // This IV ends in fd fe ff, so the carry crosses a byte boundary.
    let iv: [u8; 16] =
        unhex(IV).try_into().expect("IV literal is one block");
    assert_eq!(
        u128::from_be_bytes(counter),
        u128::from_be_bytes(iv).wrapping_add(4),
    );
}
