use serde::{Deserialize, Deserializer};
use std::fs::File;
use std::path::PathBuf;
use std::error::Error;
use crate::hash::sha2::*;
use crate::mac::hmac::*;

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
    Aft(AftGroup)
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AftGroup {
    tg_id: usize,
    key_len: usize,
    msg_len: usize,
    mac_len: usize,
    tests: Vec<AftTest>
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AftTest {
    tc_id: usize,
    #[serde(deserialize_with = "deserialize_hex_string")]
    key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    msg: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    mac: Vec<u8>
}

fn test_hmac<M: Mac>(alg: &str) -> Result<(), Box<dyn Error>> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "resources",
        "acvp",
        alg,
        "internalProjection.json"
    ].into_iter().collect();
    let file = File::open(path)?;
    let tests: Tests = serde_json::from_reader(file)?;

    perform_aft_tests::<M>(&tests)
}

fn perform_aft_tests<M: Mac>(tests: &Tests) -> Result<(), Box<dyn Error>> {
    let groups = tests.test_groups.iter()
        .filter_map(|x| match x {
            TestGroup::Aft(x) => Some(x)
        });

    for g in groups {
        let mac_len = g.mac_len / 8;
        for t in &g.tests {
            let mut mac = M::new(&t.key);
            mac.update(&t.msg);
            let tag = mac.finalize();
            let truncated = &tag[..mac_len];
            assert_eq!(truncated, t.mac);
        }
    }

    Ok(())
}

#[test]
fn test_hmac_sha224() -> Result<(), Box<dyn Error>> {
    test_hmac::<Hmac<Sha224>>("hmac_sha2_224")
}

#[test]
fn test_hmac_sha256() -> Result<(), Box<dyn Error>> {
    test_hmac::<Hmac<Sha256>>("hmac_sha2_256")
}

#[test]
fn test_hmac_sha384() -> Result<(), Box<dyn Error>> {
    test_hmac::<Hmac<Sha384>>("hmac_sha2_384")
}

#[test]
fn test_hmac_sha512() -> Result<(), Box<dyn Error>> {
    test_hmac::<Hmac<Sha512>>("hmac_sha2_512")
}

#[test]
fn test_hmac_sha512_224() -> Result<(), Box<dyn Error>> {
    test_hmac::<Hmac<Sha512_224>>("hmac_sha2_512_224")
}

#[test]
fn test_hmac_sha512_256() -> Result<(), Box<dyn Error>> {
    test_hmac::<Hmac<Sha512_256>>("hmac_sha2_512_256")
}
