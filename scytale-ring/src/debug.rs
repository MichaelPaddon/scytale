//! How values print: in hex, as ring prints them, because callers and
//! ring's own tests compare the text.

use core::fmt;

pub(crate) fn write_hex_bytes(
    f: &mut fmt::Formatter,
    bytes: &[u8],
) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

/// `bytes` in hex, in quotes: a field of a type's `Debug`.
pub(crate) struct HexStr<'a>(pub(crate) &'a [u8]);

impl fmt::Debug for HexStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("\"")?;
        write_hex_bytes(f, self.0)?;
        f.write_str("\"")
    }
}

/// `Name("hex")`, the form ring gives values that are only bytes.
pub(crate) fn write_hex_tuple(
    f: &mut fmt::Formatter,
    name: &str,
    bytes: &[u8],
) -> fmt::Result {
    f.debug_tuple(name).field(&HexStr(bytes)).finish()
}
