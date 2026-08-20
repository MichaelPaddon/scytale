//! Shared plumbing for the vendored NIST ACVP vector files.
//!
//! The vectors live at `vectors/acvp/` in the repository and are deliberately
//! not part of the published crate, so a runner that cannot find them says so
//! and skips rather than failing.
//!
//! # What gets its own test
//!
//! Every kernel is certified once, and every construct built on them is
//! certified once. Not the cross product: a mode driven over each kernel
//! in turn re-certifies ciphers that the block cipher vectors already
//! cover, and modes times kernels times key sizes grows faster than the
//! coverage it buys. A generic mode is therefore run over the
//! dispatching cipher, which is the widest kernel the machine has, and
//! each kernel answers for itself against the vectors for the primitive
//! it implements.
//!
//! A kernel with its own fused path for a mode, such as the counter
//! kernels, is a separate piece of code that the block cipher vectors
//! never reach, so that path is certified in its own right.

// Each test binary compiles this module separately and uses a different part
// of it, so unused items here are expected rather than dead.
#![allow(dead_code)]

use std::path::PathBuf;

use serde_json::Value;

use scytale::symmetric::Ctr as GenericCtr;
use scytale::symmetric::aes;
use scytale::symmetric::aes::arch::portable::ttable;

#[cfg(target_arch = "aarch64")]
use scytale::symmetric::aes::arch::aarch64::armv8;
#[cfg(target_arch = "x86_64")]
use scytale::symmetric::aes::arch::x86_64::{aesni, vaes};

/// The AES block size in bytes.
pub const BLOCK_SIZE: usize = 16;

/// Locate a vendored ACVP file, or `None` when the vectors are absent.
pub fn vector_path(relative: &str) -> Option<PathBuf> {
    // CARGO_MANIFEST_DIR is crates/scytale, so the repository root is two
    // levels up.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/acvp")
        .join(relative);
    if path.exists() { Some(path) } else { None }
}

/// Parse a vendored ACVP file, or `None` when the vectors are absent.
pub fn load(relative: &str) -> Option<Value> {
    let path = vector_path(relative)?;
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let json = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()));
    Some(json)
}

/// Announce a skip in a way that shows up under `cargo test -- --nocapture`.
pub fn skipped(relative: &str) {
    eprintln!(
        "skipping: {relative} not vendored; ACVP vectors are excluded from \
         the published crate"
    );
}

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex in vector file");
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .expect("invalid hex in vector file")
        })
        .collect()
}

pub fn hex_field<'a>(v: &'a Value, name: &str) -> &'a str {
    v.get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("test case has no string field {name}"))
}

/// ACVP ECB payloads are whole numbers of blocks, up to ten of them, so a
/// case is a byte string rather than a single block.
pub fn payload(s: &str) -> Vec<u8> {
    let bytes = unhex(s);
    assert!(
        !bytes.is_empty() && bytes.len().is_multiple_of(16),
        "payload of {} bytes is not a whole number of blocks",
        bytes.len()
    );
    bytes
}

/// ACVP CTR payloads are bit strings: a payload of `bits` bits arrives
/// as the smallest whole number of bytes, with the unused low bits of
/// the final byte zero.
pub fn payload_bits(s: &str, bits: u64) -> Vec<u8> {
    let bytes = unhex(s);
    assert_eq!(
        bytes.len() as u64,
        bits.div_ceil(8),
        "payload does not match its declared bit length"
    );
    let mut check = bytes.clone();
    mask_to_bits(&mut check, bits);
    assert_eq!(check, bytes, "payload has nonzero pad bits");
    bytes
}

/// Zero everything past the first `bits` bits.
///
/// The vector files zero the pad bits of bit-granular payloads, so a
/// byte-oriented implementation's output must be masked the same way
/// before comparing.
pub fn mask_to_bits(data: &mut [u8], bits: u64) {
    let partial = (bits % 8) as u32;
    if partial != 0 {
        let last = (bits / 8) as usize;
        data[last] &= 0xffu8 << (8 - partial);
    }
}

pub fn test_payload_len(test: &Value) -> u64 {
    test.get("payloadLen")
        .and_then(Value::as_u64)
        .expect("test case has no payloadLen")
}

/// Every AES key length ACVP exercises, as a fixed-size array.
pub enum Key {
    K128([u8; 16]),
    K192([u8; 24]),
    K256([u8; 32]),
}

impl Key {
    pub fn from_hex(s: &str, key_len: u64) -> Self {
        let bytes = unhex(s);
        match key_len {
            128 => Key::K128(bytes.try_into().expect("128-bit key")),
            192 => Key::K192(bytes.try_into().expect("192-bit key")),
            256 => Key::K256(bytes.try_into().expect("256-bit key")),
            other => panic!("unexpected keyLen {other}"),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Key::K128(k) => k,
            Key::K192(k) => k,
            Key::K256(k) => k,
        }
    }
}

/// One ECB implementation, named so a failure says which one broke.
///
/// The backends are duck typed rather than sharing a trait, so each is
/// reached through a pair of functions of a common shape. Running the
/// vectors through a dispatching type alone would certify only whichever
/// backend this machine happens to pick, leaving the others uncertified
/// on the machines where they are the ones that run.
pub struct EcbImpl {
    pub name: &'static str,
    pub encrypt: fn(&Key, &mut [u8]),
    pub decrypt: fn(&Key, &mut [u8]),
}

/// One CTR implementation.
pub struct CtrImpl {
    pub name: &'static str,
    /// Whether this entry point takes whole blocks only. The fused
    /// counter kernels do; the modes built on them do not, so the
    /// bit-granular vector cases are theirs alone to answer for.
    pub whole_blocks_only: bool,
    pub apply: fn(&Key, &[u8; BLOCK_SIZE], &mut [u8]),
}

/// An entry built from a backend's split `Enc` and `Dec` types.
macro_rules! ecb_split {
    ($name:literal, $m:ident) => {{
        fn encrypt(key: &Key, data: &mut [u8]) {
            match key {
                Key::K128(k) => $m::Aes128Enc::new(k).encrypt(data),
                Key::K192(k) => $m::Aes192Enc::new(k).encrypt(data),
                Key::K256(k) => $m::Aes256Enc::new(k).encrypt(data),
            };
        }
        fn decrypt(key: &Key, data: &mut [u8]) {
            match key {
                Key::K128(k) => $m::Aes128Dec::new(k).decrypt(data),
                Key::K192(k) => $m::Aes192Dec::new(k).decrypt(data),
                Key::K256(k) => $m::Aes256Dec::new(k).decrypt(data),
            };
        }
        EcbImpl { name: $name, encrypt, decrypt }
    }};
}

/// An entry built from a backend's combined both-directions types.
macro_rules! ecb_combined {
    ($name:literal, $m:ident) => {{
        fn encrypt(key: &Key, data: &mut [u8]) {
            match key {
                Key::K128(k) => $m::Aes128::new(k).encrypt(data),
                Key::K192(k) => $m::Aes192::new(k).encrypt(data),
                Key::K256(k) => $m::Aes256::new(k).encrypt(data),
            };
        }
        fn decrypt(key: &Key, data: &mut [u8]) {
            match key {
                Key::K128(k) => $m::Aes128::new(k).decrypt(data),
                Key::K192(k) => $m::Aes192::new(k).decrypt(data),
                Key::K256(k) => $m::Aes256::new(k).decrypt(data),
            };
        }
        EcbImpl { name: $name, encrypt, decrypt }
    }};
}

// One constructor per AES *kernel*, plus the dispatching type a caller
// actually names. Each becomes its own test, so a run says which
// kernels it certified. The combined both-directions types are thin
// delegations to these and are covered by unit tests instead.

pub fn ecb_ttable() -> EcbImpl {
    ecb_split!("portable/ttable", ttable)
}

pub fn ecb_dispatch() -> EcbImpl {
    ecb_split!("dispatch", aes)
}

/// `None` where the CPU cannot run this kernel, which is not a failure:
/// it simply is not this machine's to certify.
#[cfg(target_arch = "x86_64")]
pub fn ecb_aesni() -> Option<EcbImpl> {
    aesni::supported().then(|| ecb_split!("x86_64/aesni", aesni))
}

#[cfg(target_arch = "x86_64")]
pub fn ecb_vaes() -> Option<EcbImpl> {
    vaes::supported().then(|| ecb_split!("x86_64/vaes", vaes))
}

#[cfg(target_arch = "aarch64")]
pub fn ecb_armv8() -> Option<EcbImpl> {
    armv8::supported().then(|| ecb_split!("aarch64/armv8", armv8))
}

/// The generic mode driving one backend's bulk block interface.
macro_rules! generic_ctr {
    ($name:literal, $m:ident) => {{
        fn apply(key: &Key, iv: &[u8; BLOCK_SIZE], data: &mut [u8]) {
            match key {
                Key::K128(k) => {
                    GenericCtr::try_new($m::Aes128Enc::new(k), iv)
                        .expect("block-size IV")
                        .apply_keystream(data)
                }
                Key::K192(k) => {
                    GenericCtr::try_new($m::Aes192Enc::new(k), iv)
                        .expect("block-size IV")
                        .apply_keystream(data)
                }
                Key::K256(k) => {
                    GenericCtr::try_new($m::Aes256Enc::new(k), iv)
                        .expect("block-size IV")
                        .apply_keystream(data)
                }
            }
        }
        CtrImpl { name: $name, whole_blocks_only: false, apply }
    }};
}

/// A backend's own fused counter entry point.
macro_rules! fused_ctr {
    ($name:literal, $m:ident) => {{
        fn apply(key: &Key, iv: &[u8; BLOCK_SIZE], data: &mut [u8]) {
            let mut counter = *iv;
            match key {
                Key::K128(k) => {
                    $m::Aes128Enc::new(k).ctr(&mut counter, data)
                }
                Key::K192(k) => {
                    $m::Aes192Enc::new(k).ctr(&mut counter, data)
                }
                Key::K256(k) => {
                    $m::Aes256Enc::new(k).ctr(&mut counter, data)
                }
            };
        }
        CtrImpl { name: $name, whole_blocks_only: true, apply }
    }};
}

/// The generic mode over the dispatching cipher, which is the best
/// kernel this CPU has.
///
/// The mode is one construct, so running it over several kernels would
/// re-certify the ciphers rather than the mode, and the ciphers are
/// already certified against the ECB vectors. One instance over the
/// widest kernel exercises the multi-block staging path the mode uses.
pub fn ctr_generic() -> CtrImpl {
    generic_ctr!("generic mode", aes)
}

/// The dispatching CTR types, which are what a caller naming AES-CTR
/// gets.
pub fn ctr_dispatch() -> CtrImpl {
    fn apply(key: &Key, iv: &[u8; BLOCK_SIZE], data: &mut [u8]) {
        match key {
            Key::K128(k) => {
                aes::Aes128Ctr::new(k, iv).apply_keystream(data)
            }
            Key::K192(k) => {
                aes::Aes192Ctr::new(k, iv).apply_keystream(data)
            }
            Key::K256(k) => {
                aes::Aes256Ctr::new(k, iv).apply_keystream(data)
            }
        }
    }
    CtrImpl {
        name: "dispatch",
        whole_blocks_only: false,
        apply,
    }
}

// The fused counter kernels are new code that the ECB vectors never
// touch, so each is certified here in its own right.

pub fn ctr_fused_ttable() -> CtrImpl {
    fused_ctr!("portable/ttable counter kernel", ttable)
}

#[cfg(target_arch = "x86_64")]
pub fn ctr_fused_aesni() -> Option<CtrImpl> {
    aesni::ctr_supported()
        .then(|| fused_ctr!("x86_64/aesni counter kernel", aesni))
}

#[cfg(target_arch = "x86_64")]
pub fn ctr_fused_vaes() -> Option<CtrImpl> {
    vaes::supported()
        .then(|| fused_ctr!("x86_64/vaes counter kernel", vaes))
}

#[cfg(target_arch = "aarch64")]
pub fn ctr_fused_armv8() -> Option<CtrImpl> {
    armv8::ctr_supported()
        .then(|| fused_ctr!("aarch64/armv8 counter kernel", armv8))
}

/// Iterate the test groups of one testType, e.g. "AFT" or "MCT".
pub fn groups<'a>(
    vectors: &'a Value,
    test_type: &str,
) -> impl Iterator<Item = &'a Value> {
    vectors
        .get("testGroups")
        .and_then(Value::as_array)
        .expect("vector file has no testGroups array")
        .iter()
        .filter(move |g| {
            g.get("testType").and_then(Value::as_str) == Some(test_type)
        })
}

pub fn group_key_len(group: &Value) -> u64 {
    group
        .get("keyLen")
        .and_then(Value::as_u64)
        .expect("test group has no keyLen")
}

pub fn group_is_encrypt(group: &Value) -> bool {
    match group.get("direction").and_then(Value::as_str) {
        Some("encrypt") => true,
        Some("decrypt") => false,
        other => panic!("unexpected direction {other:?}"),
    }
}

pub fn group_tests(group: &Value) -> &[Value] {
    group
        .get("tests")
        .and_then(Value::as_array)
        .expect("test group has no tests array")
}
