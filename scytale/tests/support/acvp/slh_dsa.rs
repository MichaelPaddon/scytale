//! SLH-DSA keyGen, sigGen and sigVer (FIPS 205), all twelve
//! parameter sets, for the pure external interface: the groups for
//! the internal interface and the pre-hashed variant are skipped.
//! Key generation runs with the three seeds supplied through a fixed
//! random source, and hedged signing with the file's additional
//! randomness the same way; both must reproduce the file's bytes.

use super::{hex, load};
use scytale::random::Random;
use scytale::sig::slh_dsa::*;
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
    /// `pk || sk` from `SK.seed || SK.prf || PK.seed`.
    fn key_gen(seeds: &[u8]) -> (Vec<u8>, Vec<u8>);
    /// A signature, hedged with `rnd` when given.
    fn sign(
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
            fn key_gen(seeds: &[u8]) -> (Vec<u8>, Vec<u8>) {
                let mut rng = Fixed(seeds.to_vec());
                let key =
                    $module::PrivateKey::generate(&mut rng).expect("generate");
                (key.public_key().bytes().to_vec(), key.key_bytes().to_vec())
            }
            fn sign(
                sk: &[u8],
                rnd: Option<&[u8]>,
                context: &[u8],
                message: &[u8],
            ) -> Vec<u8> {
                let sk: [u8; $module::KEY_SIZE] = sk.try_into().expect("sk");
                let key = $module::PrivateKey::try_new(&sk).expect("key");
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

set!(Sha2_128s, sha2_128s, "SLH-DSA-SHA2-128s");
set!(Sha2_128f, sha2_128f, "SLH-DSA-SHA2-128f");
set!(Sha2_192s, sha2_192s, "SLH-DSA-SHA2-192s");
set!(Sha2_192f, sha2_192f, "SLH-DSA-SHA2-192f");
set!(Sha2_256s, sha2_256s, "SLH-DSA-SHA2-256s");
set!(Sha2_256f, sha2_256f, "SLH-DSA-SHA2-256f");
set!(Shake128s, shake_128s, "SLH-DSA-SHAKE-128s");
set!(Shake128f, shake_128f, "SLH-DSA-SHAKE-128f");
set!(Shake192s, shake_192s, "SLH-DSA-SHAKE-192s");
set!(Shake192f, shake_192f, "SLH-DSA-SHAKE-192f");
set!(Shake256s, shake_256s, "SLH-DSA-SHAKE-256s");
set!(Shake256f, shake_256f, "SLH-DSA-SHAKE-256f");

macro_rules! with_set {
    ($set:expr, $f:ident($($arg:expr),*)) => {
        match $set {
            Sha2_128s::NAME => $f::<Sha2_128s>($($arg),*),
            Sha2_128f::NAME => $f::<Sha2_128f>($($arg),*),
            Sha2_192s::NAME => $f::<Sha2_192s>($($arg),*),
            Sha2_192f::NAME => $f::<Sha2_192f>($($arg),*),
            Sha2_256s::NAME => $f::<Sha2_256s>($($arg),*),
            Sha2_256f::NAME => $f::<Sha2_256f>($($arg),*),
            Shake128s::NAME => $f::<Shake128s>($($arg),*),
            Shake128f::NAME => $f::<Shake128f>($($arg),*),
            Shake192s::NAME => $f::<Shake192s>($($arg),*),
            Shake192f::NAME => $f::<Shake192f>($($arg),*),
            Shake256s::NAME => $f::<Shake256s>($($arg),*),
            Shake256f::NAME => $f::<Shake256f>($($arg),*),
            other => panic!("unknown parameter set {other}"),
        }
    };
}

/// Whether a group is one the pure external interface can run.
fn pure_external(group: &Value) -> bool {
    group["signatureInterface"] == "external" && group["preHash"] == "pure"
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors.
pub fn run_key_gen() {
    let file = "SLH-DSA-keyGen-FIPS205/internalProjection.json";
    let Some(doc) = load(file, "SLH-DSA", "FIPS205") else {
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
    assert!(cases >= 120, "only {cases} keyGen cases");
}

fn key_gen<S: Set>(t: &Value, tag: &str) {
    let mut seeds = hex(&t["skSeed"]);
    seeds.extend(hex(&t["skPrf"]));
    seeds.extend(hex(&t["pkSeed"]));
    let (pk, sk) = S::key_gen(&seeds);
    assert_eq!(pk, hex(&t["pk"]), "{tag} pk");
    assert_eq!(sk, hex(&t["sk"]), "{tag} sk");
}

/// Runs the signature generation suite, every case when `all` and
/// otherwise the first of each group, since the slow sets make the
/// whole file a minute's work; a no-op without the vendored vectors.
pub fn run_sig_gen(all: bool) {
    let file = "SLH-DSA-sigGen-FIPS205/internalProjection.json";
    let Some(doc) = load(file, "SLH-DSA", "FIPS205") else {
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
        let tests = group["tests"].as_array().expect("tests");
        let take = if all { tests.len() } else { 1 };
        for t in &tests[..take] {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            with_set!(set, sig_gen(t, deterministic, &tag));
            cases += 1;
            if !deterministic {
                hedged += 1;
            }
        }
    }
    let (floor, hedged_floor) = if all { (150, 75) } else { (24, 12) };
    assert!(cases >= floor, "only {cases} sigGen cases");
    assert!(hedged >= hedged_floor, "only {hedged} hedged cases");
}

fn sig_gen<S: Set>(t: &Value, deterministic: bool, tag: &str) {
    let rnd = (!deterministic).then(|| hex(&t["additionalRandomness"]));
    let sig = S::sign(
        &hex(&t["sk"]),
        rnd.as_deref(),
        &hex(&t["context"]),
        &hex(&t["message"]),
    );
    assert_eq!(sig, hex(&t["signature"]), "{tag}");
}

/// Runs the signature verification suite; a no-op without the
/// vendored vectors.
pub fn run_sig_ver() {
    let file = "SLH-DSA-sigVer-FIPS205/internalProjection.json";
    let Some(doc) = load(file, "SLH-DSA", "FIPS205") else {
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
    assert!(cases >= 100, "only {cases} sigVer cases");
    assert!(rejections >= 30, "only {rejections} rejections");
}

fn sig_ver<S: Set>(t: &Value) -> bool {
    S::verify(
        &hex(&t["pk"]),
        &hex(&t["context"]),
        &hex(&t["message"]),
        &hex(&t["signature"]),
    )
}
