//! Wycheproof's ML-DSA cases, all three parameter sets and three
//! files each: signing from an expanded key, signing from a seed
//! whose PKCS#8 form is given too, and verification. The signing
//! files carry the hedging bytes where a case is randomized and
//! omit them where it is deterministic; cases for the internal
//! interface are skipped. The invalid cases are keys of the wrong
//! length or content, contexts too long, and signatures bent every
//! way the encoding allows, hint packing included.

use super::super::acvp::hex;
use super::load;
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

/// Runs every vendored file; each is separately optional.
pub fn run() {
    let mut c = Counts::default();
    run_set::<Set44>("44", &mut c);
    run_set::<Set65>("65", &mut c);
    run_set::<Set87>("87", &mut c);
    if c.files > 0 {
        assert!(c.valid >= 500, "only {} valid cases", c.valid);
        assert!(c.invalid >= 300, "only {} invalid cases", c.invalid);
    }
}

#[derive(Default)]
struct Counts {
    files: usize,
    valid: usize,
    invalid: usize,
}

/// One parameter set's types; `None` where a key, context or
/// signature is refused.
trait Set {
    fn sign(
        sk: &[u8],
        rnd: Option<&[u8]>,
        context: &[u8],
        message: &[u8],
    ) -> Option<Vec<u8>>;
    fn sign_seed(
        seed: &[u8],
        pkcs8: Option<&[u8]>,
        rnd: Option<&[u8]>,
        context: &[u8],
        message: &[u8],
    ) -> Option<Vec<u8>>;
    fn verify(
        pk: &[u8],
        der: &[u8],
        context: &[u8],
        message: &[u8],
        sig: &[u8],
    ) -> bool;
}

macro_rules! set {
    ($name:ident, $module:ident) => {
        pub struct $name;
        impl Set for $name {
            fn sign(
                sk: &[u8],
                rnd: Option<&[u8]>,
                context: &[u8],
                message: &[u8],
            ) -> Option<Vec<u8>> {
                let sk: [u8; $module::KEY_SIZE] = sk.try_into().ok()?;
                let key = $module::PrivateKey::try_new(&sk).ok()?;
                sign_with(&key, rnd, context, message)
            }
            fn sign_seed(
                seed: &[u8],
                pkcs8: Option<&[u8]>,
                rnd: Option<&[u8]>,
                context: &[u8],
                message: &[u8],
            ) -> Option<Vec<u8>> {
                let seed: [u8; 32] = seed.try_into().ok()?;
                let key = $module::PrivateKey::try_from_seed(&seed).ok()?;
                // The PKCS#8, where the group has one, names the same
                // key, and the key writes it back byte for byte.
                if let Some(pkcs8) = pkcs8 {
                    let from_der = $module::PrivateKey::try_from_der(pkcs8)
                        .expect("privateKeyPkcs8");
                    assert_eq!(from_der.key_bytes(), key.key_bytes());
                    let mut out = [0u8; 8192];
                    let n = key.der_bytes(&mut out).expect("der");
                    assert_eq!(&out[..n], pkcs8);
                }
                sign_with(&key, rnd, context, message)
            }
            fn verify(
                pk: &[u8],
                der: &[u8],
                context: &[u8],
                message: &[u8],
                sig: &[u8],
            ) -> bool {
                let Ok(pk) = <[u8; $module::PUBLIC_KEY_SIZE]>::try_from(pk)
                else {
                    return false;
                };
                let key = $module::PublicKey::try_new(&pk).expect("pk");
                let from_der = $module::PublicKey::try_from_der(der)
                    .expect("publicKeyDer");
                assert_eq!(from_der.bytes(), pk);
                let mut out = [0u8; 8192];
                let n = key.der_bytes(&mut out).expect("der");
                assert_eq!(&out[..n], der);
                let Ok(sig) = <[u8; $module::SIGNATURE_SIZE]>::try_from(sig)
                else {
                    return false;
                };
                key.verify(context, message, &sig).is_ok()
            }
        }

        fn sign_with(
            key: &$module::PrivateKey,
            rnd: Option<&[u8]>,
            context: &[u8],
            message: &[u8],
        ) -> Option<Vec<u8>> {
            let sig = match rnd {
                Some(rnd) => {
                    key.sign(&mut Fixed(rnd.to_vec()), context, message)
                }
                None => key.sign_deterministic(context, message),
            };
            sig.ok().map(|s| s.to_vec())
        }
    };
}

mod s44 {
    use super::*;
    set!(Set44, ml_dsa_44);
}
mod s65 {
    use super::*;
    set!(Set65, ml_dsa_65);
}
mod s87 {
    use super::*;
    set!(Set87, ml_dsa_87);
}
use s44::Set44;
use s65::Set65;
use s87::Set87;

fn run_set<S: Set>(set: &str, counts: &mut Counts) {
    let file = |kind: &str| format!("wycheproof/mldsa_{set}_{kind}_test.json");
    let algorithm = format!("ML-DSA-{set}");
    if let Some(doc) = load(&file("sign_noseed"), &algorithm) {
        counts.files += 1;
        for group in groups(&doc) {
            let sk = hex(&group["privateKey"]);
            for t in tests(group) {
                if internal(t) {
                    continue;
                }
                let rnd = t["rnd"].as_str().map(|_| hex(&t["rnd"]));
                let sig = S::sign(
                    &sk,
                    rnd.as_deref(),
                    &opt_hex(&t["ctx"]),
                    &opt_hex(&t["msg"]),
                );
                judge(t, sig.as_deref(), counts);
            }
        }
    }
    if let Some(doc) = load(&file("sign_seed"), &algorithm) {
        counts.files += 1;
        for group in groups(&doc) {
            let seed = hex(&group["privateSeed"]);
            let pkcs8 = group["privateKeyPkcs8"]
                .as_str()
                .map(|_| hex(&group["privateKeyPkcs8"]));
            for t in tests(group) {
                if internal(t) {
                    continue;
                }
                let rnd = t["rnd"].as_str().map(|_| hex(&t["rnd"]));
                let sig = S::sign_seed(
                    &seed,
                    pkcs8.as_deref(),
                    rnd.as_deref(),
                    &opt_hex(&t["ctx"]),
                    &opt_hex(&t["msg"]),
                );
                judge(t, sig.as_deref(), counts);
            }
        }
    }
    if let Some(doc) = load(&file("verify"), &algorithm) {
        counts.files += 1;
        for group in groups(&doc) {
            let pk = hex(&group["publicKey"]);
            let der = hex(&group["publicKeyDer"]);
            for t in tests(group) {
                let accepted = S::verify(
                    &pk,
                    &der,
                    &opt_hex(&t["ctx"]),
                    &opt_hex(&t["msg"]),
                    &hex(&t["sig"]),
                );
                judge(t, accepted.then_some(&[][..]), counts);
            }
        }
    }
}

/// A hex field that may be absent, standing for the empty string.
fn opt_hex(v: &Value) -> Vec<u8> {
    if v.is_null() {
        Vec::new()
    } else {
        hex(v)
    }
}

/// Whether a case is for the internal interface, which signs the
/// formatted message directly and is not offered.
fn internal(t: &Value) -> bool {
    t["flags"]
        .as_array()
        .is_some_and(|f| f.iter().any(|x| x == "Internal"))
}

fn groups(doc: &Value) -> impl Iterator<Item = &Value> {
    doc["testGroups"].as_array().expect("testGroups").iter()
}

fn tests(group: &Value) -> impl Iterator<Item = &Value> {
    group["tests"].as_array().expect("tests").iter()
}

/// Compares an outcome with the file's verdict: for a signing case,
/// the signature made against the one expected; for a verification
/// case, whether it was accepted.
fn judge(t: &Value, outcome: Option<&[u8]>, counts: &mut Counts) {
    let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
    match t["result"].as_str() {
        Some("valid") => {
            let sig = outcome.unwrap_or_else(|| panic!("{tag} rejected"));
            if !sig.is_empty() {
                assert_eq!(sig, hex(&t["sig"]), "{tag}");
            }
            counts.valid += 1;
        }
        Some("invalid") => {
            assert!(outcome.is_none(), "{tag} accepted");
            counts.invalid += 1;
        }
        other => panic!("{tag}: unknown result {other:?}"),
    }
}
