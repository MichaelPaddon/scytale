//! PKCS#8 documents a key pair is generated into.

use scytale::sig::{ecdsa, ed25519};
use zeroize::Zeroize;

/// The longest document generated here: a P-384 key pair.
const MAX_LEN: usize = if ecdsa::p384::DER_SIZE > ed25519::PAIR_DER_SIZE {
    ecdsa::p384::DER_SIZE
} else {
    ed25519::PAIR_DER_SIZE
};

/// A generated PKCS#8 `PrivateKeyInfo`. It is a secret, and is wiped
/// when dropped.
pub struct Document {
    bytes: [u8; MAX_LEN],
    len: usize,
}

impl Document {
    pub(crate) fn new(der: &[u8]) -> Self {
        let mut bytes = [0u8; MAX_LEN];
        bytes[..der.len()].copy_from_slice(der);
        Document {
            bytes,
            len: der.len(),
        }
    }
}

impl AsRef<[u8]> for Document {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Drop for Document {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
