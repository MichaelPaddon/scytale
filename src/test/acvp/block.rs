use serde::Deserialize;
use typenum::Unsigned;
use crate::cipher::{BlockCipher, EncryptingBlockCipher, DecryptingBlockCipher};
use crate::convert::{AsBlocks, AsBlocksMut};
use crate::test::acvp::{deserialize_hex_string, deserialize_hex_string_opt};

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tests {
    vs_id: usize,
    algorithm: String,
    revision: String,
    is_sample: bool,
    test_groups: Vec<TestGroup>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(tag = "testType")]
#[serde(rename_all = "UPPERCASE")]
enum TestGroup {
    Aft(AftGroup),
    Mct(MctGroup),
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AftGroup {
    tg_id: usize,
    internal_test_type: String,
    direction: String,
    key_len: usize,
    tests: Vec<AftTest>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AftTest {
    tc_id: usize,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pt: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    ct: Vec<u8>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MctGroup {
    tg_id: usize,
    internal_test_type: String,
    direction: String,
    key_len: usize,
    tests: Vec<MctTest>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MctTest {
    pub tc_id: usize,
    #[serde(default, deserialize_with = "deserialize_hex_string_opt")]
    pt: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "deserialize_hex_string_opt")]
    ct: Option<Vec<u8>>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    key: Vec<u8>,
    results_array: Vec<MctResult>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MctResult {
    #[serde(deserialize_with = "deserialize_hex_string")]
    key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pt: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    ct: Vec<u8>
}

fn perform_aft_encryption<C: EncryptingBlockCipher>(group: &AftGroup) {
    for test in &group.tests {
        let mut cipher = C::new(&test.key).unwrap();
        let mut ct = vec![0u8; test.pt.len()];
        cipher.encrypt_blocks(
            test.pt.as_slice().as_blocks().0,
            ct.as_mut_slice().as_blocks_mut().0
        );
        assert_eq!(ct, test.ct);
    }
}

fn perform_aft_decryption<C: DecryptingBlockCipher>(group: &AftGroup) {
    for test in &group.tests {
        let mut cipher = C::new(&test.key).unwrap();
        let mut pt = vec![0u8; test.pt.len()];
        cipher.decrypt_blocks(
            test.ct.as_slice().as_blocks().0,
            pt.as_mut_slice().as_blocks_mut().0
        );
        assert_eq!(pt, test.pt);
    }
}

fn aes_key_shuffle(key: &mut [u8], x: &[u8], y: &[u8]) {
    match key.len() {
        16 => for i in 0..16 {
            key[i] ^= x[i];
        },
        24 => {
            for i in 0..8 {
                key[i] ^= y[i + 8];
            }
            for i in 8..24 {
                key[i] ^= x[i - 8];
            }
        },
        32 => {
            for i in 0..16 {
                key[i] ^= y[i];
            }
            for i in 16..32 {
                key[i] ^= x[i - 16];
            }
        },
        _ => panic!()
    }
}

fn test_aes_mct_encrypt<C: EncryptingBlockCipher>(group: &MctGroup) {
    for test in &group.tests {
        let mut key = test.key.clone();
        let mut cipher = C::new(&key).unwrap();
        let mut pt = test.pt.clone().unwrap();
        let mut ct = vec![0u8; pt.len()];
        let mut ct_prev = vec![0u8; pt.len()];
        for i in 0..100 {
            assert_eq!(key, test.results_array[i].key);
            assert_eq!(pt, test.results_array[i].pt);
            for _ in 0..1000 {
                ct_prev.copy_from_slice(&ct);
                cipher.encrypt_blocks(
                    pt.as_slice().as_blocks().0,
                    ct.as_mut_slice().as_blocks_mut().0
                );
                pt.copy_from_slice(&ct);
            }
            assert_eq!(ct, test.results_array[i].ct);
            aes_key_shuffle(&mut key, &ct, &ct_prev);
            cipher.rekey(&key).unwrap();
        }
    }
}

fn test_aes_mct_decrypt<C: DecryptingBlockCipher>(group: &MctGroup) {
    for test in &group.tests {
        let mut key = test.key.clone();
        let mut cipher = C::new(&key).unwrap();
        let mut ct = test.ct.clone().unwrap();
        let mut pt = vec![0u8; ct.len()];
        let mut pt_prev = vec![0u8; pt.len()];
        for i in 0..100 {
            assert_eq!(key, test.results_array[i].key);
            assert_eq!(ct, test.results_array[i].ct);
            for _ in 0..1000 {
                pt_prev.copy_from_slice(&pt);
                cipher.decrypt_blocks(
                    ct.as_slice().as_blocks().0,
                    pt.as_mut_slice().as_blocks_mut().0
                );
                ct.copy_from_slice(&pt);
            }
            assert_eq!(pt, test.results_array[i].pt);
            aes_key_shuffle(&mut key, &pt, &pt_prev);
            cipher.rekey(&key).unwrap();
        }
    }
}

fn test_mct_encrypt<C: EncryptingBlockCipher>(alg: &str, group: &MctGroup) {
    match alg {
        "ACVP-AES-ECB" => test_aes_mct_encrypt::<C>(group),
        _ => panic!()
    }
}

fn test_mct_decrypt<C: DecryptingBlockCipher>(alg: &str, group: &MctGroup) {
    match alg {
        "ACVP-AES-ECB" => test_aes_mct_decrypt::<C>(group),
        _ => panic!()
    }
}

pub fn test_encrypt<C: EncryptingBlockCipher>(name: &str) {
    let tests = match super::read_tests::<Tests>(name).unwrap() {
        Some(t) => t,
        None => return
    };

    let mut n = 0;
    for group in &tests.test_groups {
        match group {
            TestGroup::Aft(g)
                if g.direction.as_str() == "encrypt"
                    && g.key_len == C::KeySize::USIZE * 8 =>
            {
                perform_aft_encryption::<C>(g);
                n += 1;
            },
            TestGroup::Mct(g)
                if g.direction.as_str() == "encrypt"
                    && g.key_len == C::KeySize::USIZE * 8 =>
            {
                test_mct_encrypt::<C>(&tests.algorithm, g);
                n += 1;
            }
            _ => ()
        }
    }

    assert_ne!(n, 0);
}

pub fn test_decrypt<C: DecryptingBlockCipher>(name: &str) {
    let tests = match super::read_tests::<Tests>(name).unwrap() {
        Some(t) => t,
        None => return
    };

    let mut n = 0;
    for group in &tests.test_groups {
        match group {
            TestGroup::Aft(g)
                if g.direction.as_str() == "decrypt"
                    && g.key_len == C::KeySize::USIZE * 8 =>
            {
                perform_aft_decryption::<C>(g);
                n += 1;
            },
            TestGroup::Mct(g)
                if g.direction.as_str() == "decrypt"
                    && g.key_len == C::KeySize::USIZE * 8 =>
            {
                test_mct_decrypt::<C>(&tests.algorithm, g);
                n += 1;
            }
            _ => ()
        }
    }

    assert_ne!(n, 0);
}

pub fn test<C: BlockCipher>(name: &str) {
    test_encrypt::<C>(name);
    test_decrypt::<C>(name);
}
