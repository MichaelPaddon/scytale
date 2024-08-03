//! Scytale (pronounced /ˈskɪtəliː/) is a **fast** and **correct**
//! cryptographic library.

use derive_more::{Constructor, Display, Error};

#[derive(Clone, Constructor, Debug, Display, Error)]
#[display(fmt = "{}: unknown algorithm", name)]
pub struct UnknownAlgorithmError {
    name: String
}

#[derive(Clone, Constructor, Debug, Display, Error)]
#[display(fmt = "invalid key length")]
pub struct InvalidKeyLengthError;

pub mod cipher;
pub mod error;
pub mod hash;
pub mod mac;
pub(crate) mod util;

#[cfg(test)]
pub mod test;
