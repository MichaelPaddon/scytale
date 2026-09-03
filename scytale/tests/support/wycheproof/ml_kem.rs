//! Wycheproof's ML-KEM cases, all three parameter sets and four
//! files each: key generation from a seed, encapsulation with the
//! message fixed, decapsulation with the key given expanded, and the
//! combined file that generates from a seed and decapsulates. The
//! invalid cases are keys that are not reduced, keys whose hash does
//! not match, and keys and ciphertexts of the wrong length, every
//! one of which must be refused before any secret comes out.

use super::super::acvp::hex;
use super::load;
use scytale::kem::ml_kem::{ml_kem_1024, ml_kem_512, ml_kem_768};
use scytale::random::Random;
use scytale::Error;
use serde_json::Value;

/// A random source that yields fixed bytes.
struct Fixed(Vec<u8>);

impl Random for Fixed {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        assert!(self.0.len() >= out.len(), "vector shorter than the draw");
        let rest = self.0.split_off(out.len());
        out.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

/// Runs every vendored file; each is separately optional.
pub fn run() {
    let mut c = Counts::default();
    for set in ["512", "768", "1024"] {
        let file =
            |kind: &str| format!("wycheproof/mlkem_{set}_{kind}test.json");
        match set {
            "512" => run_set::<Set512>(&file, &mut c),
            "768" => run_set::<Set768>(&file, &mut c),
            _ => run_set::<Set1024>(&file, &mut c),
        }
    }
    if c.files > 0 {
        assert!(c.valid >= 1000, "only {} valid cases", c.valid);
        assert!(c.invalid >= 400, "only {} invalid cases", c.invalid);
    }
}

#[derive(Default)]
struct Counts {
    files: usize,
    valid: usize,
    invalid: usize,
}

/// One parameter set's types. Each returns `None` where the key or
/// ciphertext is refused, which every invalid case must be.
trait Set {
    fn key_gen(seed: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
    fn encapsulate(ek: &[u8], m: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
    fn decapsulate(dk: &[u8], c: &[u8]) -> Option<Vec<u8>>;
    fn decapsulate_seed(seed: &[u8], c: &[u8]) -> Option<Vec<u8>>;
}

macro_rules! set {
    ($name:ident, $module:ident) => {
        struct $name;
        impl Set for $name {
            fn key_gen(seed: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
                let seed: [u8; 64] = seed.try_into().ok()?;
                let key = $module::PrivateKey::try_from_seed(&seed).ok()?;
                let ek = key.public_key().bytes().to_vec();
                Some((ek, key.key_bytes().to_vec()))
            }
            fn encapsulate(ek: &[u8], m: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
                let ek: [u8; $module::PUBLIC_KEY_SIZE] = ek.try_into().ok()?;
                let key = $module::PublicKey::try_new(&ek).ok()?;
                let (c, k) = key.encapsulate(&mut Fixed(m.to_vec())).ok()?;
                Some((c.to_vec(), k.to_vec()))
            }
            fn decapsulate(dk: &[u8], c: &[u8]) -> Option<Vec<u8>> {
                let dk: [u8; $module::KEY_SIZE] = dk.try_into().ok()?;
                let key = $module::PrivateKey::try_new(&dk).ok()?;
                let c: [u8; $module::CIPHERTEXT_SIZE] = c.try_into().ok()?;
                Some(key.decapsulate(&c).to_vec())
            }
            fn decapsulate_seed(seed: &[u8], c: &[u8]) -> Option<Vec<u8>> {
                let seed: [u8; 64] = seed.try_into().ok()?;
                let key = $module::PrivateKey::try_from_seed(&seed).ok()?;
                let c: [u8; $module::CIPHERTEXT_SIZE] = c.try_into().ok()?;
                Some(key.decapsulate(&c).to_vec())
            }
        }
    };
}

set!(Set512, ml_kem_512);
set!(Set768, ml_kem_768);
set!(Set1024, ml_kem_1024);

fn run_set<S: Set>(file: &dyn Fn(&str) -> String, counts: &mut Counts) {
    // Key generation: seed to both keys.
    if let Some(doc) = load(&file("keygen_seed_"), "ML-KEM") {
        counts.files += 1;
        for t in tests(&doc) {
            let outcome = S::key_gen(&hex(&t["seed"])).map(|(ek, dk)| {
                assert_eq!(ek, hex(&t["ek"]), "tcId {} ek", t["tcId"]);
                assert_eq!(dk, hex(&t["dk"]), "tcId {} dk", t["tcId"]);
            });
            judge(t, outcome.is_some(), counts);
        }
    }
    // Encapsulation with the message fixed.
    if let Some(doc) = load(&file("encaps_"), "ML-KEM") {
        counts.files += 1;
        for t in tests(&doc) {
            let outcome =
                S::encapsulate(&hex(&t["ek"]), &hex(&t["m"])).map(|(c, k)| {
                    assert_eq!(c, hex(&t["c"]), "tcId {} c", t["tcId"]);
                    assert_eq!(k, hex(&t["K"]), "tcId {} K", t["tcId"]);
                });
            judge(t, outcome.is_some(), counts);
        }
    }
    // Decapsulation from an expanded key.
    if let Some(doc) = load(&file("semi_expanded_decaps_"), "ML-KEM") {
        counts.files += 1;
        for t in tests(&doc) {
            let outcome = S::decapsulate(&hex(&t["dk"]), &hex(&t["c"]))
                .map(|k| assert_eq!(k, hex(&t["K"]), "tcId {}", t["tcId"]));
            judge(t, outcome.is_some(), counts);
        }
    }
    // Generation from a seed, then decapsulation.
    if let Some(doc) = load(&file(""), "ML-KEM") {
        counts.files += 1;
        for t in tests(&doc) {
            let seed = hex(&t["seed"]);
            let outcome = S::key_gen(&seed).and_then(|(ek, _)| {
                assert_eq!(ek, hex(&t["ek"]), "tcId {} ek", t["tcId"]);
                S::decapsulate_seed(&seed, &hex(&t["c"]))
            });
            let outcome = outcome
                .map(|k| assert_eq!(k, hex(&t["K"]), "tcId {}", t["tcId"]));
            judge(t, outcome.is_some(), counts);
        }
    }
}

fn tests(doc: &Value) -> impl Iterator<Item = &Value> {
    doc["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .flat_map(|g| g["tests"].as_array().expect("tests"))
}

fn judge(t: &Value, accepted: bool, counts: &mut Counts) {
    let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
    match t["result"].as_str() {
        Some("valid") => {
            assert!(accepted, "{tag} rejected");
            counts.valid += 1;
        }
        Some("invalid") => {
            assert!(!accepted, "{tag} accepted");
            counts.invalid += 1;
        }
        Some("acceptable") => {
            if accepted {
                counts.valid += 1;
            } else {
                counts.invalid += 1;
            }
        }
        other => panic!("{tag}: unknown result {other:?}"),
    }
}
