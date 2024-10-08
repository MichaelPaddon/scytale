use crate::hash::sha2::*;
use crate::hash::Hash;
use serde::{Deserialize, Deserializer};
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;

fn deserialize_hex_string<'de, D: Deserializer<'de>>(deserializer: D)
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
    test_groups: Vec<TestGroup>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(tag = "testType")]
#[serde(rename_all = "UPPERCASE")]
enum TestGroup {
    Aft(AftGroup),
    Mct(MctGroup),
    Ldt(LdtGroup),
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AftGroup {
    _tg_id: usize,
    tests: Vec<AftTest>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AftTest {
    tc_id: usize,
    #[serde(deserialize_with = "deserialize_hex_string")]
    msg: Vec<u8>,
    len: usize,
    #[serde(deserialize_with = "deserialize_hex_string")]
    md: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MctGroup {
    tg_id: usize,
    function: String,
    digest_size: String,
    tests: Vec<MctTest>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MctTest {
    tc_id: usize,
    #[serde(deserialize_with = "deserialize_hex_string")]
    msg: Vec<u8>,
    len: usize,
    results_array: Vec<MctResult>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MctResult {
    #[serde(deserialize_with = "deserialize_hex_string")]
    md: Vec<u8>,
    out_len: usize,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LdtGroup {
    tg_id: usize,
    tests: Vec<LdtTest>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LdtTest {
    tc_id: usize,
    len: usize,
    #[serde(deserialize_with = "deserialize_hex_string")]
    md: Vec<u8>,
    large_msg: LargeMsg,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LargeMsg {
    #[serde(deserialize_with = "deserialize_hex_string")]
    content: Vec<u8>,
    content_length: usize,
    full_length: usize,
    expansion_technique: String,
}

fn read_tests(alg: &str) -> Result<Tests, Box<dyn Error>> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "resources",
        "acvp",
        alg,
        "internalProjection.json",
    ]
    .into_iter()
    .collect();
    let file = File::open(path)?;
    let tests: Tests = serde_json::from_reader(file)?;
    Ok(tests)
}

macro_rules! test_suite {
    ($test: ident, $test_extra: ident, $hash: ty, $path: literal) => {
        #[test]
        fn $test() -> Result<(), Box<dyn Error>> {
            let tests = read_tests($path)?;
            aft_tests::<$hash>(&tests)?;
            Ok(())
        }

        #[test]
        #[ignore]
        fn $test_extra() -> Result<(), Box<dyn Error>> {
            let tests = read_tests($path)?;
            mct_tests::<$hash>(&tests)?;
            lct_tests::<$hash>(&tests)?;
            Ok(())
        }
    };
}

test_suite! {test_sha224, test_sha224_extended, Sha224, "sha2_224"}
test_suite! {test_sha256, test_sha256_extended, Sha256, "sha2_256"}
test_suite! {test_sha384, test_sha384_extended, Sha384, "sha2_384"}
test_suite! {test_sha512, test_sha512_extended, Sha512, "sha2_512"}
test_suite! {test_sha512_224, test_sha512_224_extended, Sha512_224, "sha2_512_224"}
test_suite! {test_sha512_256, test_sha512_256_extended, Sha512_256, "sha2_512_256"}

fn aft_tests<H: Hash>(tests: &Tests) -> Result<(), Box<dyn Error>> {
    let groups = tests.test_groups.iter().filter_map(|x| match x {
        TestGroup::Aft(x) => Some(x),
        _ => None,
    });

    let mut hash = H::new();
    for g in groups {
        for t in &g.tests {
            hash.update(&t.msg);
            let md = hash.finalize();
            assert_eq!(md.as_ref(), t.md);
            hash.reset()
        }
    }

    Ok(())
}

fn mct_tests<H: Hash>(tests: &Tests) -> Result<(), Box<dyn Error>> {
    let groups = tests.test_groups.iter().filter_map(|x| match x {
        TestGroup::Mct(x) => Some(x),
        _ => None,
    });

    let mut hash = H::new();
    for g in groups {
        for t in &g.tests {
            let mut seed = t.msg.clone();
            let length = t.len / 8;
            for result in &t.results_array {
                let (mut a, mut b, mut c) =
                    (seed.clone(), seed.clone(), seed.clone());
                for _ in 0..1000 {
                    let mut msg = a;
                    msg.extend(&b);
                    msg.extend(&c);
                    hash.update(&msg);
                    let md = hash.finalize();
                    a = b;
                    b = c;
                    c = md.to_vec();
                    c.resize(length, 0);
                    hash.reset();
                }
                assert_eq!(c[..result.md.len()], result.md);
                seed = c;
            }
        }
    }

    Ok(())
}

fn lct_tests<H: Hash>(tests: &Tests) -> Result<(), Box<dyn Error>> {
    let groups = tests.test_groups.iter().filter_map(|x| match x {
        TestGroup::Ldt(x) => Some(x),
        _ => None,
    });

    let mut hash = H::new();
    for g in groups {
        for t in &g.tests {
            for _ in 0..(t.large_msg.full_length / t.large_msg.content_length) {
                hash.update(&t.large_msg.content);
            }
            let md = hash.finalize();
            assert_eq!(md.as_ref(), t.md);
            hash.reset();
        }
    }

    Ok(())
}
