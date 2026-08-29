//! ACVP-SHA2 1.0 and ACVP-SHA3 2.0, run through the [`Hash`] trait.
//! One driver serves every variant of both families; the caller
//! names the file and the family, which decides the revision, how
//! the last bits of a bit-string message sit in their byte, and the
//! Monte Carlo chaining.

use super::{hex, load};
use scytale::hash::{BitHash, Hash};
use serde_json::Value;

/// Which standard a file belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Sha2,
    Sha3,
}

impl Family {
    fn revision(self) -> &'static str {
        match self {
            Family::Sha2 => "1.0",
            Family::Sha3 => "2.0",
        }
    }
}

/// Runs the one-shot (AFT) groups against `H`; a no-op without the
/// vendored vectors.
pub fn run_aft<H: BitHash>(file: &str, algorithm: &str, family: Family)
where
    H::Output: AsRef<[u8]>,
{
    let Some(groups) = groups(file, algorithm, family, "AFT") else {
        return;
    };
    let count: usize = groups.iter().map(|g| aft::<H>(g, family)).sum();
    // Guard against a truncated or wrong file passing vacuously.
    assert!(count >= 500, "only {count} AFT cases");
}

/// Runs the Monte Carlo (MCT) groups against `H`; a no-op without the
/// vendored vectors. Slow: 100,000 hashes per group.
pub fn run_mct<H: BitHash>(file: &str, algorithm: &str, family: Family)
where
    H::Output: AsRef<[u8]>,
{
    let Some(groups) = groups(file, algorithm, family, "MCT") else {
        return;
    };
    let count: usize = groups.iter().map(|g| mct::<H>(g, family)).sum();
    assert!(count >= 100, "only {count} MCT steps");
}

/// Runs the large data (LDT) groups against `H`, each of which
/// hashes several gigabytes; a no-op without the vendored vectors.
pub fn run_ldt<H: Hash>(file: &str, algorithm: &str, family: Family)
where
    H::Output: AsRef<[u8]>,
{
    let Some(groups) = groups(file, algorithm, family, "LDT") else {
        return;
    };
    let count: usize = groups.iter().map(ldt::<H>).sum();
    assert!(count >= 1, "only {count} LDT cases");
}

/// The groups of one test type; `None` without the vectors.
fn groups(
    file: &str,
    algorithm: &str,
    family: Family,
    test_type: &str,
) -> Option<Vec<Value>> {
    let doc = load(file, algorithm, family.revision())?;
    let selected = doc["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .filter(|group| group["testType"] == test_type)
        .cloned()
        .collect();
    Some(selected)
}

/// A message of the vectors: bytes, and a length in bits, which is
/// not always a whole number of bytes. ACVP keeps any last bits at
/// the top of the last byte. That is where SHA-2 reads them; SHA-3
/// numbers bits from the bottom of a byte, so they are shifted down
/// for it.
pub struct Message {
    pub bytes: Vec<u8>,
    pub bits: usize,
}

impl Message {
    pub fn of(t: &Value) -> Self {
        let bits = t["len"].as_u64().expect("len") as usize;
        let bytes = hex(&t["msg"]);
        assert_eq!(bytes.len(), bits.div_ceil(8), "tcId {}", t["tcId"]);
        Message { bytes, bits }
    }

    /// The whole bytes, and the last byte with its bits placed as
    /// the family reads them, if the length is not a whole number of
    /// bytes.
    pub fn split(&self, family: Family) -> (&[u8], Option<(u8, u32)>) {
        let extra = (self.bits % 8) as u32;
        if extra == 0 {
            return (&self.bytes, None);
        }
        let (last, whole) = self.bytes.split_last().expect("last");
        let last = match family {
            Family::Sha2 => *last,
            Family::Sha3 => *last >> (8 - extra),
        };
        (whole, Some((last, extra)))
    }

    /// Hashes the message with `hash`, which is consumed.
    fn digest<H: BitHash>(&self, mut hash: H, family: Family) -> H::Output {
        let (whole, tail) = self.split(family);
        hash.update(whole);
        match tail {
            None => hash.finalize(),
            Some((last, extra)) => {
                hash.finalize_bits(last, extra).expect("bits")
            }
        }
    }
}

/// Algorithm Functional Test: one message, one digest.
fn aft<H: BitHash>(group: &Value, family: Family) -> usize
where
    H::Output: AsRef<[u8]>,
{
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let digest = Message::of(t).digest(H::try_new().expect("hash"), family);
        assert_eq!(
            digest.as_ref(),
            hex(&t["md"]),
            "tgId {} tcId {}",
            group["tgId"],
            t["tcId"]
        );
        count += 1;
    }
    count
}

/// Monte Carlo Test: 100 steps of 1000 chained hashes. SHA-2 hashes
/// the previous three digests each time, in the standard version as
/// they are and in the alternate one cut or padded with zeros to the
/// length of the seed; SHA-3 hashes just the previous digest.
fn mct<H: BitHash>(group: &Value, family: Family) -> usize
where
    H::Output: AsRef<[u8]>,
{
    let alternate = match group["mctVersion"].as_str() {
        Some("standard") => false,
        Some("alternate") => true,
        other => panic!("unknown mctVersion {other:?}"),
    };
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let seed = Message::of(t);
        assert_eq!(seed.bits % 8, 0, "tcId {}: bit seed", t["tcId"]);
        let seed = seed.bytes;
        let steps = t["resultsArray"].as_array().expect("resultsArray");
        let mut hash = H::try_new().expect("hash");
        let mut md: Vec<u8> = seed.clone();
        for (i, step) in steps.iter().enumerate() {
            md = match family {
                Family::Sha2 => {
                    sha2_step(&mut hash, &md, seed.len(), alternate)
                }
                Family::Sha3 => sha3_step(&mut hash, &md),
            };
            let expected = hex(&step["md"]);
            assert_eq!(
                md[..expected.len()],
                expected,
                "tgId {} tcId {} step {i}",
                group["tgId"],
                t["tcId"]
            );
            count += 1;
        }
    }
    count
}

/// One SHA-2 Monte Carlo step.
fn sha2_step<H: Hash>(
    hash: &mut H,
    md: &[u8],
    seed_len: usize,
    alternate: bool,
) -> Vec<u8>
where
    H::Output: AsRef<[u8]>,
{
    let mut a = md.to_vec();
    let mut b = md.to_vec();
    let mut c = md.to_vec();
    for _ in 0..1000 {
        let mut msg = a.clone();
        msg.extend_from_slice(&b);
        msg.extend_from_slice(&c);
        if alternate {
            msg.resize(seed_len, 0);
        }
        hash.reset();
        hash.update(&msg);
        let digest = hash.clone().finalize().as_ref().to_vec();
        a = b;
        b = c;
        c = digest;
    }
    c
}

/// One SHA-3 Monte Carlo step.
fn sha3_step<H: Hash>(hash: &mut H, md: &[u8]) -> Vec<u8>
where
    H::Output: AsRef<[u8]>,
{
    let mut md = md.to_vec();
    for _ in 0..1000 {
        hash.reset();
        hash.update(&md);
        md = hash.clone().finalize().as_ref().to_vec();
    }
    md
}

/// Large Data Test: a short piece repeated to gigabytes, hashed as
/// it is generated.
fn ldt<H: Hash>(group: &Value) -> usize
where
    H::Output: AsRef<[u8]>,
{
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let large = &t["largeMsg"];
        assert_eq!(large["expansionTechnique"], "repeating");
        let piece = hex(&large["content"]);
        let piece_bits = large["contentLength"].as_u64().expect("bits");
        assert_eq!(piece.len() as u64 * 8, piece_bits);
        let full_bits = large["fullLength"].as_u64().expect("bits");
        assert_eq!(full_bits % piece_bits, 0);
        let repeats = full_bits / piece_bits;
        // Feed in chunks of many pieces to keep the call count sane.
        let per_chunk = (1 << 20) / piece.len().max(1);
        let chunk: Vec<u8> = piece.repeat(per_chunk);
        let mut hash = H::try_new().expect("hash");
        let mut left = repeats;
        while left > 0 {
            let n = left.min(per_chunk as u64) as usize;
            hash.update(&chunk[..n * piece.len()]);
            left -= n as u64;
        }
        assert_eq!(
            hash.finalize().as_ref(),
            hex(&t["md"]),
            "tgId {} tcId {}",
            group["tgId"],
            t["tcId"]
        );
        count += 1;
    }
    count
}
