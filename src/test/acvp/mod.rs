use serde::{Deserialize, Deserializer};
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;

pub fn deserialize_hex_string<'de, D: Deserializer<'de>>(deserializer: D)
    -> Result<Vec<u8>, D::Error>
{
    let s = String::deserialize(deserializer)?;
    hex::decode(s).map_err(serde::de::Error::custom)
}

pub fn deserialize_hex_string_opt<'de, D: Deserializer<'de>>(deserializer: D)
    -> Result<Option<Vec<u8>>, D::Error>
{
    Ok(Some(deserialize_hex_string(deserializer)?))
}

pub fn read_tests<T: for<'de> Deserialize<'de>>(name: &str)
    -> Result<Option<T>, Box<dyn Error>>
{
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "resources",
        "acvp",
        name,
        "internalProjection.json"
    ].into_iter().collect();
    if path.exists() {
        let file = File::open(path)?;
        let tests = serde_json::from_reader(file)?;
        Ok(Some(tests))
    }
    else {
        Ok(None)
    }
}

pub mod block;
