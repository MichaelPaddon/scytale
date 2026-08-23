//! Locates vendored vector files.
//!
//! The ACVP vectors live in `tests/vectors` in the source tree and are
//! not shipped in the crate, to keep it small. From a checkout the
//! suites run against them; from a downloaded crate they are absent
//! and the suites skip, leaving the built-in FIPS 197 and SP 800-38A
//! vectors in the unit tests as the check.

use std::fs;
use std::path::PathBuf;

/// Returns the contents of `tests/vectors/<name>`, or `None` if the
/// vectors are not vendored in this copy of the crate.
pub fn load(name: &str) -> Option<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    match fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("{name}: not vendored in this copy; skipping");
            None
        }
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    }
}
