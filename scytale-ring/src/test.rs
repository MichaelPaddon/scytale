//! ring's harness for tests written against files of vectors, so that
//! its own tests run here unchanged. Deprecated in ring, and hidden
//! there; only tests reach for it.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{digest, error};

/// A test vector file, made by [`test_file!`](crate::test_file).
pub struct File<'a> {
    /// Its name, for messages.
    pub file_name: &'a str,
    /// Its whole text.
    pub contents: &'a str,
}

/// One case from a file: its attributes, each consumed once.
#[derive(Debug)]
pub struct TestCase {
    attributes: Vec<(String, String, bool)>,
}

impl TestCase {
    /// The attribute `key`, which must be `true` or `false`.
    pub fn consume_bool(&mut self, key: &str) -> bool {
        match self.consume_string(key).as_ref() {
            "true" => true,
            "false" => false,
            s => panic!("Invalid bool value: {s}"),
        }
    }

    /// The attribute `key` as a digest algorithm; `None` for SHA-224,
    /// which ring leaves out.
    pub fn consume_digest_alg(
        &mut self,
        key: &str,
    ) -> Option<&'static digest::Algorithm> {
        let name = self.consume_string(key);
        match name.as_ref() {
            "SHA1" => Some(&digest::SHA1_FOR_LEGACY_USE_ONLY),
            "SHA224" => None,
            "SHA256" => Some(&digest::SHA256),
            "SHA384" => Some(&digest::SHA384),
            "SHA512" => Some(&digest::SHA512),
            "SHA512_256" => Some(&digest::SHA512_256),
            _ => panic!("Unsupported digest algorithm: {name}"),
        }
    }

    /// The attribute `key` as bytes: hex, or a quoted string.
    pub fn consume_bytes(&mut self, key: &str) -> Vec<u8> {
        self.consume_optional_bytes(key)
            .unwrap_or_else(|| panic!("No attribute named \"{key}\""))
    }

    /// As [`consume_bytes`](Self::consume_bytes), if the attribute
    /// is there.
    pub fn consume_optional_bytes(&mut self, key: &str) -> Option<Vec<u8>> {
        let s = self.consume_optional_string(key)?;
        let result = if let [b'\"', s @ ..] = s.as_bytes() {
            let mut s = s.iter();
            let mut bytes = Vec::with_capacity(s.len() - 1);
            loop {
                let b = match s.next() {
                    Some(b'\\') => match s.next() {
                        Some(b'0') => 0u8,
                        Some(b't') => b'\t',
                        Some(b'n') => b'\n',
                        Some(b'x') => match (s.next(), s.next()) {
                            (Some(&hi), Some(&lo)) => {
                                match (from_hex_digit(hi), from_hex_digit(lo)) {
                                    (Ok(hi), Ok(lo)) => (hi << 4) | lo,
                                    _ => panic!("Invalid hex escape."),
                                }
                            }
                            _ => panic!("Invalid hex escape sequence."),
                        },
                        _ => panic!("Invalid escape sequence in string."),
                    },
                    Some(b'"') => {
                        if s.next().is_some() {
                            panic!("characters after the closing quote.");
                        }
                        break;
                    }
                    Some(b) => *b,
                    None => panic!("Missing terminating '\"' in string."),
                };
                bytes.push(b);
            }
            bytes
        } else {
            match from_hex(&s) {
                Ok(s) => s,
                Err(err_str) => panic!("{err_str} in {s}"),
            }
        };
        Some(result)
    }

    /// The attribute `key` as a number.
    pub fn consume_usize(&mut self, key: &str) -> usize {
        let s = self.consume_string(key);
        match s.parse::<usize>() {
            Ok(n) => n,
            Err(_) => panic!("{key} is not a number: {s}"),
        }
    }

    /// The attribute `key` as text.
    pub fn consume_string(&mut self, key: &str) -> String {
        self.consume_optional_string(key)
            .unwrap_or_else(|| panic!("No attribute named \"{key}\""))
    }

    /// As [`consume_string`](Self::consume_string), if the attribute
    /// is there.
    pub fn consume_optional_string(&mut self, key: &str) -> Option<String> {
        for (name, value, consumed) in &mut self.attributes {
            if key == name {
                if *consumed {
                    panic!("Attribute {key} was already consumed");
                }
                *consumed = true;
                return Some(value.clone());
            }
        }
        None
    }
}

/// Runs `f` on every case in `test_file`, and fails if any case fails
/// or leaves an attribute unread.
pub fn run<F>(test_file: File, mut f: F)
where
    F: FnMut(&str, &mut TestCase) -> Result<(), error::Unspecified>,
{
    let lines = &mut test_file.contents.lines();
    let mut current_section = String::from("");
    let mut failed = false;
    while let Some(mut test_case) = parse_test_case(&mut current_section, lines)
    {
        let result = match f(&current_section, &mut test_case) {
            Ok(()) => {
                if test_case
                    .attributes
                    .iter()
                    .all(|&(_, _, consumed)| consumed)
                {
                    Ok(())
                } else {
                    Err("Test didn't consume all attributes.")
                }
            }
            Err(error::Unspecified) => {
                Err("Test returned Err(error::Unspecified).")
            }
        };
        if result.is_err() {
            failed = true;
        }
        // ring's own way of saying which case failed: a feature, so
        // that a passing run prints nothing.
        #[cfg(feature = "test_logging")]
        if let Err(msg) = result {
            std::println!("{}: {}", test_file.file_name, msg);
            for (name, value, consumed) in test_case.attributes {
                let consumed_str = if consumed { "" } else { " (unconsumed)" };
                std::println!("{name}{consumed_str} = {value}");
            }
        }
    }
    if failed {
        panic!("Test failed.")
    }
}

/// Bytes from hex, as the files write them.
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if !hex_str.len().is_multiple_of(2) {
        return Err(String::from(
            "Hex string does not have an even number of digits",
        ));
    }
    let mut result = Vec::with_capacity(hex_str.len() / 2);
    for digits in hex_str.as_bytes().chunks(2) {
        let hi = from_hex_digit(digits[0])?;
        let lo = from_hex_digit(digits[1])?;
        result.push((hi * 0x10) | lo);
    }
    Ok(result)
}

fn from_hex_digit(d: u8) -> Result<u8, String> {
    match d {
        b'0'..=b'9' => Ok(d - b'0'),
        b'a'..=b'f' => Ok(d - b'a' + 10),
        b'A'..=b'F' => Ok(d - b'A' + 10),
        _ => Err(alloc::format!("Invalid hex digit '{}'", d as char)),
    }
}

fn parse_test_case(
    current_section: &mut String,
    lines: &mut dyn Iterator<Item = &str>,
) -> Option<TestCase> {
    let mut attributes = Vec::new();
    let mut is_first_line = true;
    loop {
        match lines.next() {
            None if is_first_line => return None,
            None => return Some(TestCase { attributes }),
            Some("") => {
                if !is_first_line {
                    return Some(TestCase { attributes });
                }
            }
            Some(line) if line.starts_with('#') => (),
            Some(line) if line.starts_with('[') => {
                assert!(is_first_line);
                assert!(line.ends_with(']'));
                current_section.clear();
                current_section.push_str(&line[1..line.len() - 1]);
            }
            Some(line) => {
                is_first_line = false;
                let Some((key, value)) = line.split_once(" = ") else {
                    panic!("Syntax error: Expected Key = Value.");
                };
                let (key, value) = (key.trim(), value.trim());
                assert!(!value.is_empty());
                attributes.push((
                    String::from(key),
                    String::from(value),
                    false,
                ));
            }
        }
    }
}

/// Holds at compile time if `T` is `Clone`.
pub const fn compile_time_assert_clone<T: Clone>() {}
/// Holds at compile time if `T` is `Copy`.
pub const fn compile_time_assert_copy<T: Copy>() {}
/// Holds at compile time if `T` is `Eq`.
pub const fn compile_time_assert_eq<T: Eq>() {}
/// Holds at compile time if `T` is `Send`.
pub const fn compile_time_assert_send<T: Send>() {}
/// Holds at compile time if `T` is `Sync`.
pub const fn compile_time_assert_sync<T: Sync>() {}
/// Holds at compile time if `T` is a standard error.
#[cfg(feature = "std")]
pub const fn compile_time_assert_std_error_error<T: std::error::Error>() {}

/// Sources of fixed bytes, for tests that need a known key.
pub mod rand {
    use core::cell::Cell;

    use crate::{error, rand};

    /// Fills with one byte value.
    #[derive(Debug)]
    pub struct FixedByteRandom {
        /// The byte.
        pub byte: u8,
    }

    impl rand::sealed::SecureRandom for FixedByteRandom {
        fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
            dest.fill(self.byte);
            Ok(())
        }
    }

    /// Fills with one slice, which must be exactly the length asked.
    #[derive(Debug)]
    pub struct FixedSliceRandom<'a> {
        /// The bytes.
        pub bytes: &'a [u8],
    }

    impl rand::sealed::SecureRandom for FixedSliceRandom<'_> {
        fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
            dest.copy_from_slice(self.bytes);
            Ok(())
        }
    }

    /// Fills each call from the next slice, and insists on drop that
    /// every slice was used.
    #[derive(Debug)]
    pub struct FixedSliceSequenceRandom<'a> {
        /// The slices, one per call.
        pub bytes: &'a [&'a [u8]],
        /// How many calls have been made.
        pub current: Cell<usize>,
    }

    impl rand::sealed::SecureRandom for FixedSliceSequenceRandom<'_> {
        fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
            let current = self.current.get();
            dest.copy_from_slice(self.bytes[current]);
            self.current.set(current + 1);
            Ok(())
        }
    }

    impl Drop for FixedSliceSequenceRandom<'_> {
        fn drop(&mut self) {
            assert_eq!(self.current.get(), self.bytes.len());
        }
    }
}
