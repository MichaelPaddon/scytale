//! ML-KEM keyGen and encapDecap (FIPS 203), all three parameter
//! sets. The vectors fix the randomness, `d || z` for a key and `m`
//! for an encapsulation, so both run through the public API with a
//! random source that hands back exactly those bytes; decapsulation
//! runs from the seed form and the expanded form alike, and its
//! damaged ciphertexts must come out as the implicitly rejected
//! secret the file gives.

use super::{hex, load};
use scytale::kem::ml_kem::{ml_kem_1024, ml_kem_512, ml_kem_768};
use scytale::random::Random;
use scytale::Error;
use serde_json::Value;

/// A random source that yields fixed bytes, so a vector's `d`, `z`
/// or `m` reaches the scheme through the same call a caller makes.
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

/// One parameter set's types, so each suite is written once.
trait Set {
    const NAME: &'static str;
    /// `ek || dk` from the seed `d || z`.
    fn key_gen(seed: &[u8]) -> (Vec<u8>, Vec<u8>);
    /// `c || k` from `ek` and `m`.
    fn encapsulate(ek: &[u8], m: &[u8]) -> (Vec<u8>, Vec<u8>);
    /// `k` from the expanded `dk` and `c`.
    fn decapsulate(dk: &[u8], c: &[u8]) -> Vec<u8>;
    /// `k` from the seed and `c`.
    fn decapsulate_seed(seed: &[u8], c: &[u8]) -> Vec<u8>;
    /// Whether an expanded `dk` passes the key check.
    fn private_ok(dk: &[u8]) -> bool;
    /// Whether an `ek` passes the key check.
    fn public_ok(ek: &[u8]) -> bool;
}

macro_rules! set {
    ($name:ident, $module:ident, $acvp:literal) => {
        struct $name;
        impl Set for $name {
            const NAME: &'static str = $acvp;
            fn key_gen(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
                let mut rng = Fixed(seed.to_vec());
                let key =
                    $module::PrivateKey::generate(&mut rng).expect("generate");
                (key.public_key().bytes().to_vec(), key.key_bytes().to_vec())
            }
            fn encapsulate(ek: &[u8], m: &[u8]) -> (Vec<u8>, Vec<u8>) {
                let ek: [u8; $module::PUBLIC_KEY_SIZE] =
                    ek.try_into().expect("ek width");
                let key = $module::PublicKey::try_new(&ek).expect("public");
                let mut rng = Fixed(m.to_vec());
                let (c, k) = key.encapsulate(&mut rng).expect("encapsulate");
                (c.to_vec(), k.to_vec())
            }
            fn decapsulate(dk: &[u8], c: &[u8]) -> Vec<u8> {
                let dk: [u8; $module::KEY_SIZE] = dk.try_into().expect("dk");
                let key = $module::PrivateKey::try_new(&dk).expect("private");
                let c: [u8; $module::CIPHERTEXT_SIZE] =
                    c.try_into().expect("c width");
                key.decapsulate(&c).to_vec()
            }
            fn decapsulate_seed(seed: &[u8], c: &[u8]) -> Vec<u8> {
                let seed: [u8; 64] = seed.try_into().expect("seed width");
                let key =
                    $module::PrivateKey::try_from_seed(&seed).expect("seed");
                let c: [u8; $module::CIPHERTEXT_SIZE] =
                    c.try_into().expect("c width");
                key.decapsulate(&c).to_vec()
            }
            fn private_ok(dk: &[u8]) -> bool {
                <[u8; $module::KEY_SIZE]>::try_from(dk)
                    .is_ok_and(|dk| $module::PrivateKey::try_new(&dk).is_ok())
            }
            fn public_ok(ek: &[u8]) -> bool {
                <[u8; $module::PUBLIC_KEY_SIZE]>::try_from(ek)
                    .is_ok_and(|ek| $module::PublicKey::try_new(&ek).is_ok())
            }
        }
    };
}

set!(Set512, ml_kem_512, "ML-KEM-512");
set!(Set768, ml_kem_768, "ML-KEM-768");
set!(Set1024, ml_kem_1024, "ML-KEM-1024");

/// Runs `$f::<S>($args)` for the group's parameter set.
macro_rules! with_set {
    ($set:expr, $f:ident($($arg:expr),*)) => {
        match $set {
            Set512::NAME => $f::<Set512>($($arg),*),
            Set768::NAME => $f::<Set768>($($arg),*),
            Set1024::NAME => $f::<Set1024>($($arg),*),
            other => panic!("unknown parameter set {other}"),
        }
    };
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors.
pub fn run_key_gen() {
    let file = "ML-KEM-keyGen-FIPS203/internalProjection.json";
    let Some(doc) = load(file, "ML-KEM", "FIPS203") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let set = group["parameterSet"].as_str().expect("parameterSet");
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            with_set!(set, key_gen(t, &tag));
            cases += 1;
        }
    }
    assert!(cases >= 75, "only {cases} keyGen cases");
}

fn key_gen<S: Set>(t: &Value, tag: &str) {
    let mut seed = hex(&t["d"]);
    seed.extend(hex(&t["z"]));
    let (ek, dk) = S::key_gen(&seed);
    assert_eq!(ek, hex(&t["ek"]), "{tag} ek");
    assert_eq!(dk, hex(&t["dk"]), "{tag} dk");
}

/// Runs the encapsulation and decapsulation suite; a no-op without
/// the vendored vectors.
pub fn run_encap_decap() {
    let file = "ML-KEM-encapDecap-FIPS203-tr1/internalProjection.json";
    let Some(doc) = load(file, "ML-KEM", "FIPS203-tr1") else {
        return;
    };
    let mut encapsulations = 0;
    let mut decapsulations = 0;
    let mut rejections = 0;
    let mut checks = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let set = group["parameterSet"].as_str().expect("parameterSet");
        let function = group["function"].as_str().expect("function");
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            match function {
                "encapsulation" => {
                    with_set!(set, encapsulation(t, &tag));
                    encapsulations += 1;
                }
                "decapsulation" => {
                    let seed = group["keyFormat"] == "seed";
                    with_set!(set, decapsulation(t, seed, &tag));
                    decapsulations += 1;
                    let reason = t["reason"].as_str().unwrap_or("");
                    if reason.contains("modified") {
                        rejections += 1;
                    }
                }
                "decapsulationKeyCheck" | "encapsulationKeyCheck" => {
                    let expected =
                        t["testPassed"].as_bool().expect("testPassed");
                    let ok = if function.starts_with("decaps") {
                        with_set!(set, private_ok(&hex(&t["dk"])))
                    } else {
                        with_set!(set, public_ok(&hex(&t["ek"])))
                    };
                    fn private_ok<S: Set>(dk: &[u8]) -> bool {
                        S::private_ok(dk)
                    }
                    fn public_ok<S: Set>(ek: &[u8]) -> bool {
                        S::public_ok(ek)
                    }
                    assert_eq!(ok, expected, "{tag}: {}", t["reason"]);
                    checks += 1;
                }
                other => panic!("unknown function {other}"),
            }
        }
    }
    assert!(encapsulations >= 75, "only {encapsulations} encapsulations");
    assert!(decapsulations >= 60, "only {decapsulations} decapsulations");
    assert!(rejections >= 20, "only {rejections} implicit rejections");
    assert!(checks >= 30, "only {checks} key checks");
}

fn encapsulation<S: Set>(t: &Value, tag: &str) {
    let (c, k) = S::encapsulate(&hex(&t["ek"]), &hex(&t["m"]));
    assert_eq!(c, hex(&t["c"]), "{tag} c");
    assert_eq!(k, hex(&t["k"]), "{tag} k");
}

fn decapsulation<S: Set>(t: &Value, seed: bool, tag: &str) {
    let c = hex(&t["c"]);
    let k = if seed {
        let mut seed = hex(&t["d"]);
        seed.extend(hex(&t["z"]));
        S::decapsulate_seed(&seed, &c)
    } else {
        S::decapsulate(&hex(&t["dk"]), &c)
    };
    assert_eq!(k, hex(&t["k"]), "{tag}: {}", t["reason"]);
}
