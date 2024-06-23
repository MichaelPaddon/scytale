use hybrid_array::Array;
use hybrid_array::typenum::Unsigned;
use serde::{Deserialize, Deserializer};
use std::fs::File;
use std::path::PathBuf;
use std::error::Error;

use crate::cipher::BlockCipher;
use crate::cipher::aes::soft::{Aes128, Aes192, Aes256};

fn deserialize_hex_string<'de, D:Deserializer<'de>>(deserializer: D)
    -> Result<Vec<u8>, D::Error>
{
    let s = String::deserialize(deserializer)?;
    hex::decode(s).map_err(serde::de::Error::custom)
}

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
    internalTestType: String,
    direction: String,
    keyLen: usize,
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
    internalTestType: String,
    direction: String,
    keyLen: usize,
    tests: Vec<MctTest>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MctTest {
    tc_id: usize,
    /*
    #[serde(deserialize_with = "deserialize_hex_string")]
    ct: Option<Vec<u8>>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pt: Option<Vec<u8>>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    key: Vec<u8>,
    results_array: Vec<MctResult>
    */
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

use hybrid_array::consts::U16;

fn perform_aft_tests<C: BlockCipher>(tests: &Tests)
    -> Result<(), Box<dyn Error>>
{
    let groups = tests.test_groups.iter()
        .filter_map(|x| match x {
            TestGroup::Aft(x) => Some(x),
            _ => None
        })
        .filter(|x| x.keyLen == C::BlockSize::USIZE);

    for g in groups {
        for t in &g.tests {
            let cipher = C::new(&t.key)?;
            for (pt, ct) in std::iter::zip(t.pt.chunks(16), t.ct.chunks(16)) {
                let block = Array::<u8, C::BlockSize>::from_slice(pt);
                let x = cipher.encrypt(&block);
                assert_eq!(&x.as_slice(), &t.ct.as_slice());
            }
        }
    }

    Ok(())
}

fn test_block_cipher<C: BlockCipher>(alg: &str)
    -> Result<(), Box<dyn Error>>
{
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "resources",
        "acvp",
        alg,
        "internalProjection.json"
    ].into_iter().collect();
    let file = File::open(path)?;
    let tests: Tests = serde_json::from_reader(file)?;

    perform_aft_tests::<C>(&tests)
}

#[test]
fn test_aes128() -> Result<(), Box<dyn Error>> {
    test_block_cipher::<Aes128>("aes_ecb")
}

#[test]
fn test_aes192() -> Result<(), Box<dyn Error>> {
    test_block_cipher::<Aes192>("aes_ecb")
}

#[test]
fn test_aes256() -> Result<(), Box<dyn Error>> {
    test_block_cipher::<Aes256>("aes_ecb")
}
