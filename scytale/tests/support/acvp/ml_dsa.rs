//! ML-DSA keyGen, sigGen and sigVer (FIPS 204), all three parameter
//! sets, for the pure external interface the crate offers: the
//! groups for the internal interface, the pre-hashed variant and an
//! externally supplied `mu` are skipped. Signing runs hedged with the
//! vector's `rnd` supplied through a fixed random source, or
//! deterministically where the group says so, and must reproduce
//! the signature byte for byte; keys come from the seed and from the
//! expanded form alike.

use super::{hex, load};
use scytale::random::Random;
use scytale::sig::ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
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

trait Set {
    const NAME: &'static str;
    /// `pk || sk` from the seed.
    fn key_gen(seed: &[u8]) -> (Vec<u8>, Vec<u8>);
    /// A signature from the seed or the expanded key, hedged with
    /// `rnd` when given and deterministic otherwise.
    fn sign(
        seed: Option<&[u8]>,
        sk: &[u8],
        rnd: Option<&[u8]>,
        context: &[u8],
        message: &[u8],
    ) -> Vec<u8>;
    fn verify(pk: &[u8], context: &[u8], message: &[u8], sig: &[u8]) -> bool;
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
            fn sign(
                seed: Option<&[u8]>,
                sk: &[u8],
                rnd: Option<&[u8]>,
                context: &[u8],
                message: &[u8],
            ) -> Vec<u8> {
                let key = match seed {
                    Some(seed) => {
                        let seed: [u8; 32] = seed.try_into().expect("seed");
                        $module::PrivateKey::try_from_seed(&seed).expect("seed")
                    }
                    None => {
                        let sk: [u8; $module::KEY_SIZE] =
                            sk.try_into().expect("sk width");
                        $module::PrivateKey::try_new(&sk).expect("sk")
                    }
                };
                let sig = match rnd {
                    Some(rnd) => key
                        .sign(&mut Fixed(rnd.to_vec()), context, message)
                        .expect("sign"),
                    None => {
                        key.sign_deterministic(context, message).expect("sign")
                    }
                };
                sig.to_vec()
            }
            fn verify(
                pk: &[u8],
                context: &[u8],
                message: &[u8],
                sig: &[u8],
            ) -> bool {
                let Ok(pk) = <[u8; $module::PUBLIC_KEY_SIZE]>::try_from(pk)
                else {
                    return false;
                };
                let Ok(sig) = <[u8; $module::SIGNATURE_SIZE]>::try_from(sig)
                else {
                    return false;
                };
                let key = $module::PublicKey::try_new(&pk).expect("pk");
                key.verify(context, message, &sig).is_ok()
            }
        }
    };
}

set!(Set44, ml_dsa_44, "ML-DSA-44");
set!(Set65, ml_dsa_65, "ML-DSA-65");
set!(Set87, ml_dsa_87, "ML-DSA-87");

macro_rules! with_set {
    ($set:expr, $f:ident($($arg:expr),*)) => {
        match $set {
            Set44::NAME => $f::<Set44>($($arg),*),
            Set65::NAME => $f::<Set65>($($arg),*),
            Set87::NAME => $f::<Set87>($($arg),*),
            other => panic!("unknown parameter set {other}"),
        }
    };
}

/// Whether a group is one the pure external interface can run.
fn pure_external(group: &Value) -> bool {
    group["signatureInterface"] == "external"
        && group["preHash"] == "pure"
        && group["externalMu"] != true
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors.
pub fn run_key_gen() {
    let file = "ML-DSA-keyGen-FIPS204/internalProjection.json";
    let Some(doc) = load(file, "ML-DSA", "FIPS204") else {
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
    let (pk, sk) = S::key_gen(&hex(&t["seed"]));
    assert_eq!(pk, hex(&t["pk"]), "{tag} pk");
    assert_eq!(sk, hex(&t["sk"]), "{tag} sk");
}

/// Runs the signature generation suite; a no-op without the
/// vendored vectors.
pub fn run_sig_gen() {
    let file = "ML-DSA-sigGen-FIPS204-tr1/internalProjection.json";
    let Some(doc) = load(file, "ML-DSA", "FIPS204-tr1") else {
        return;
    };
    let mut cases = 0;
    let mut hedged = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if !pure_external(group) {
            continue;
        }
        let set = group["parameterSet"].as_str().expect("parameterSet");
        let deterministic = group["deterministic"] == true;
        let seed = group["keyFormat"] == "seed";
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            with_set!(set, sig_gen(t, deterministic, seed, &tag));
            cases += 1;
            if !deterministic {
                hedged += 1;
            }
        }
    }
    assert!(cases >= 180, "only {cases} sigGen cases");
    assert!(hedged >= 90, "only {hedged} hedged cases");
}

fn sig_gen<S: Set>(t: &Value, deterministic: bool, seed: bool, tag: &str) {
    // Only the fields a group uses are present in its cases.
    let rnd = (!deterministic).then(|| hex(&t["rnd"]));
    let seed_bytes = seed.then(|| hex(&t["seed"]));
    let sk = if seed { Vec::new() } else { hex(&t["sk"]) };
    let sig = S::sign(
        seed_bytes.as_deref(),
        &sk,
        rnd.as_deref(),
        &hex(&t["context"]),
        &hex(&t["message"]),
    );
    assert_eq!(sig, hex(&t["signature"]), "{tag}");
}

/// Runs the signature verification suite; a no-op without the
/// vendored vectors.
pub fn run_sig_ver() {
    let file = "ML-DSA-sigVer-FIPS204/internalProjection.json";
    let Some(doc) = load(file, "ML-DSA", "FIPS204") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if !pure_external(group) {
            continue;
        }
        let set = group["parameterSet"].as_str().expect("parameterSet");
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let accepted = with_set!(set, sig_ver(t));
            let should_pass = t["testPassed"].as_bool().expect("testPassed");
            assert_eq!(accepted, should_pass, "{tag}: {}", t["reason"]);
            cases += 1;
            if !should_pass {
                rejections += 1;
            }
        }
    }
    assert!(cases >= 45, "only {cases} sigVer cases");
    assert!(rejections >= 20, "only {rejections} rejections");
}

fn sig_ver<S: Set>(t: &Value) -> bool {
    S::verify(
        &hex(&t["pk"]),
        &hex(&t["context"]),
        &hex(&t["message"]),
        &hex(&t["signature"]),
    )
}
