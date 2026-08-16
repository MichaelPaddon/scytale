//! Fast AES known-answer tests.
//!
//! This tier runs under a plain `cargo test` and is kept to a few seconds per
//! algorithm. Exhaustive work belongs in the extended tier.

use scytale::symmetric::aes::{Aes128, Aes192, Aes256};

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex literal has an odd length");
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .expect("test vector is not valid hex")
        })
        .collect()
}

fn array16(bytes: &[u8]) -> [u8; 16] {
    bytes.try_into().expect("expected a 16-byte block")
}

/// NIST SP 800-38A, F.1.1 and F.1.2 (ECB-AES128).
#[test]
fn sp800_38a_aes128_ecb() {
    let key = array16(&unhex("2b7e151628aed2a6abf7158809cf4f3c"));
    let cases = [
        (
            "6bc1bee22e409f96e93d7e117393172a",
            "3ad77bb40d7a3660a89ecaf32466ef97",
        ),
        (
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "f5d3d58503b9699de785895a96fdbaaf",
        ),
        (
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "43b1cd7f598ece23881b00e3ed030688",
        ),
        (
            "f69f2445df4f9b17ad2b417be66c3710",
            "7b0c785e27e8ad3f8223207104725dd4",
        ),
    ];

    let aes = Aes128::new(&key);
    for (pt, ct) in cases {
        let mut block = array16(&unhex(pt));
        aes.encrypt_block(&mut block);
        assert_eq!(block, array16(&unhex(ct)), "encrypt {pt}");
        aes.decrypt_block(&mut block);
        assert_eq!(block, array16(&unhex(pt)), "decrypt {ct}");
    }
}

/// NIST SP 800-38A, F.1.3 and F.1.4 (ECB-AES192).
#[test]
fn sp800_38a_aes192_ecb() {
    let key: [u8; 24] =
        unhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
            .try_into()
            .expect("expected a 24-byte key");
    let cases = [
        (
            "6bc1bee22e409f96e93d7e117393172a",
            "bd334f1d6e45f25ff712a214571fa5cc",
        ),
        (
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "974104846d0ad3ad7734ecb3ecee4eef",
        ),
        (
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "ef7afd2270e2e60adce0ba2face6444e",
        ),
        (
            "f69f2445df4f9b17ad2b417be66c3710",
            "9a4b41ba738d6c72fb16691603c18e0e",
        ),
    ];

    let aes = Aes192::new(&key);
    for (pt, ct) in cases {
        let mut block = array16(&unhex(pt));
        aes.encrypt_block(&mut block);
        assert_eq!(block, array16(&unhex(ct)), "encrypt {pt}");
        aes.decrypt_block(&mut block);
        assert_eq!(block, array16(&unhex(pt)), "decrypt {ct}");
    }
}

/// NIST SP 800-38A, F.1.5 and F.1.6 (ECB-AES256).
#[test]
fn sp800_38a_aes256_ecb() {
    let key: [u8; 32] = unhex(
        "603deb1015ca71be2b73aef0857d7781\
         1f352c073b6108d72d9810a30914dff4",
    )
    .try_into()
    .expect("expected a 32-byte key");
    let cases = [
        (
            "6bc1bee22e409f96e93d7e117393172a",
            "f3eed1bdb5d2a03c064b5a7e3db181f8",
        ),
        (
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "591ccb10d410ed26dc5ba74a31362870",
        ),
        (
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "b6ed21b99ca6f4f9f153e7b1beafed1d",
        ),
        (
            "f69f2445df4f9b17ad2b417be66c3710",
            "23304b7a39f9f3ff067d8d8f9e24ecc7",
        ),
    ];

    let aes = Aes256::new(&key);
    for (pt, ct) in cases {
        let mut block = array16(&unhex(pt));
        aes.encrypt_block(&mut block);
        assert_eq!(block, array16(&unhex(ct)), "encrypt {pt}");
        aes.decrypt_block(&mut block);
        assert_eq!(block, array16(&unhex(pt)), "decrypt {ct}");
    }
}

/// A key of all zeros is a common off-by-one trap in key expansion.
#[test]
fn all_zero_key_and_block() {
    let mut block = [0u8; 16];
    Aes128::new(&[0u8; 16]).encrypt_block(&mut block);
    assert_eq!(
        block,
        array16(&unhex("66e94bd4ef8a2c3b884cfa59ca342b2e")),
    );
}
