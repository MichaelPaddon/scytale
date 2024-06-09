//! Scytale (pronounced /ˈskɪtəliː/) is a **fast** and **correct**
//! cryptographic library.

use derive_more::{Constructor, Display, Error};

#[derive(Clone, Constructor, Debug, Display, Error)]
#[display(fmt = "{}: unknown algorithm", name)]
pub struct UnknownAlgorithmError {
    name: String
}

pub mod hash;
pub mod mac;
pub(crate) mod util;
