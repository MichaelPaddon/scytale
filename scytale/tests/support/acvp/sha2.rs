//! ACVP-SHA2 1.0, run through the [`Hash`] trait. One driver serves
//! the four variants; the caller names the file.

use super::{hex, load};
use scytale::hash::{BitHash, Hash};
use serde_json::Value;

/// Runs the one-shot (AFT) groups against `H`; a no-op without the
/// vendored vectors.
pub fn run_aft<H: BitHash>(file: &str, algorithm: &str)
where
    H::Output: AsRef<[u8]>,
{
    let Some(groups) = groups(file, algorithm, "AFT") else {
        return;
    };
    let count: usize = groups.iter().map(aft::<H>).sum();
    // Guard against a truncated or wrong file passing vacuously.
    assert!(count >= 500, "only {count} AFT cases");
}

/// Runs the Monte Carlo (MCT) groups against `H`; a no-op without the
/// vendored vectors. Slow: 100,000 hashes per group.
pub fn run_mct<H: BitHash>(file: &str, algorithm: &str)
where
    H::Output: AsRef<[u8]>,
{
    let Some(groups) = groups(file, algorithm, "MCT") else {
        return;
    };
    let count: usize = groups.iter().map(mct::<H>).sum();
    assert!(count >= 100, "only {count} MCT steps");
}

/// Runs the large data (LDT) groups against `H`, each of which
/// hashes several gigabytes; a no-op without the vendored vectors.
pub fn run_ldt<H: Hash>(file: &str, algorithm: &str)
where
    H::Output: AsRef<[u8]>,
{
    let Some(groups) = groups(file, algorithm, "LDT") else {
        return;
    };
    let count: usize = groups.iter().map(ldt::<H>).sum();
    assert!(count >= 1, "only {count} LDT cases");
}

/// The groups of one test type; `None` without the vectors.
fn groups(file: &str, algorithm: &str, test_type: &str) -> Option<Vec<Value>> {
    let doc = load(file, algorithm, "1.0")?;
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
/// not always a whole number of bytes. Any last bits are the top of
/// the last byte.
struct Message {
    bytes: Vec<u8>,
    bits: usize,
}

impl Message {
    fn of(t: &Value) -> Self {
        let bits = t["len"].as_u64().expect("len") as usize;
        let bytes = hex(&t["msg"]);
        assert_eq!(bytes.len(), bits.div_ceil(8), "tcId {}", t["tcId"]);
        Message { bytes, bits }
    }

    /// Hashes the message with `hash`, which is consumed.
    fn digest<H: BitHash>(&self, mut hash: H) -> H::Output {
        let extra = (self.bits % 8) as u32;
        if extra == 0 {
            hash.update(&self.bytes);
            hash.finalize()
        } else {
            let (last, whole) = self.bytes.split_last().expect("last");
            hash.update(whole);
            hash.finalize_bits(*last, extra).expect("bits")
        }
    }
}

/// Algorithm Functional Test: one message, one digest.
fn aft<H: BitHash>(group: &Value) -> usize
where
    H::Output: AsRef<[u8]>,
{
    let mut count = 0;
    for t in group["tests"].as_array().expect("tests") {
        let digest = Message::of(t).digest(H::try_new().expect("hash"));
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

/// Monte Carlo Test: 100 steps of 1000 chained hashes, each hashing
/// the previous three digests. In the standard version the message
/// is those three digests; in the alternate one it is cut or padded
/// with zeros to the length of the seed.
fn mct<H: BitHash>(group: &Value) -> usize
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
            let mut a = md.clone();
            let mut b = md.clone();
            let mut c = md.clone();
            for _ in 0..1000 {
                let mut msg = a.clone();
                msg.extend_from_slice(&b);
                msg.extend_from_slice(&c);
                if alternate {
                    msg.resize(seed.len(), 0);
                }
                hash.reset();
                hash.update(&msg);
                let digest = hash.clone().finalize().as_ref().to_vec();
                a = b;
                b = c;
                c = digest;
            }
            md = c;
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
