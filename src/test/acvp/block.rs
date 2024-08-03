use typenum::Unsigned;
use serde::Deserialize;
use std::error::Error;
use crate::cipher::BlockCipher;
use crate::test::acvp::{deserialize_hex_string, deserialize_hex_string_opt};

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tests {
    pub vs_id: usize,
    pub algorithm: String,
    pub revision: String,
    pub is_sample: bool,
    pub test_groups: Vec<TestGroup>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(tag = "testType")]
#[serde(rename_all = "UPPERCASE")]
pub enum TestGroup {
    Aft(AftGroup),
    Mct(MctGroup),
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AftGroup {
    pub tg_id: usize,
    pub internal_test_type: String,
    pub direction: String,
    pub key_len: usize,
    pub tests: Vec<AftTest>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AftTest {
    pub tc_id: usize,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub pt: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub ct: Vec<u8>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MctGroup {
    pub tg_id: usize,
    pub internal_test_type: String,
    pub direction: String,
    pub key_len: usize,
    pub tests: Vec<MctTest>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MctTest {
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
pub struct MctResult {
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub pt: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub ct: Vec<u8>
}

fn perform_aft_group<C: BlockCipher>(group: &AftGroup)
    -> Result<(), Box<dyn Error>>
{
    match group.direction.as_str() {
        "encrypt" => {
            for test in &group.tests {
                let cipher = C::new_encrypt_only(&test.key)?;
                let mut output = vec![0u8; test.ct.len()];
                cipher.encrypt(&test.pt, &mut output);
                assert_eq!(output, test.ct);
            }
        },
        "decrypt" => {
            for test in &group.tests {
                let cipher = C::new_decrypt_only(&test.key)?;
                let mut output = vec![0u8; test.pt.len()];
                cipher.decrypt(&test.ct, &mut output);
                assert_eq!(output, test.pt);
            }
        },
        _ => panic!()
    }

    Ok(())
}

fn perform_tests<C: BlockCipher>(tests: &Tests)
    -> Result<(), Box<dyn Error>>
{
    for group in &tests.test_groups {
        match group {
            TestGroup::Aft(group) if group.key_len == C::KeySize::USIZE * 8 =>
                perform_aft_group::<C>(group)?,
            TestGroup::Mct(_) => (),
            _ => ()
        }
    }

    Ok(())
}

pub fn test<C: BlockCipher>(name: &str) 
    -> Result<(), Box<dyn Error>>
{
    match &super::read_tests(name)? {
        Some(tests) => perform_tests::<C>(tests),
        None => Ok(())
    }
}
