//! Running the binary, for the integration tests.

#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub const BIN: &str = env!("CARGO_BIN_EXE_scytale");

pub const KEY16: &str = "hex:000102030405060708090a0b0c0d0e0f";
pub const KEY32: &str =
    "hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
pub const IV: &str = "hex:0f0e0d0c0b0a09080706050403020100";
pub const NONCE: &str = "hex:000000000000000000000001";

/// A directory of this test's own, under the target directory.
pub fn dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs `scytale` with `args`, `stdin` on its standard input.
pub fn run(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A child that refuses its arguments exits without reading its
    // input, and the write then fails with a broken pipe; that is the
    // child's answer, not the test's failure.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().unwrap()
}

/// Runs and requires success, returning standard output.
pub fn ok(args: &[&str], stdin: &[u8]) -> Vec<u8> {
    let out = run(args, stdin);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Runs and requires the exit status `code`, returning standard
/// error.
pub fn fails(args: &[&str], stdin: &[u8], code: i32) -> String {
    let out = run(args, stdin);
    assert_eq!(
        out.status.code(),
        Some(code),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap().trim_end().to_owned()
}

/// Runs openssl, `None` where it is absent or the call failed.
pub fn openssl(args: &[&str], stdin: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(stdin).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}
