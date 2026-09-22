//! ring's first check on a PKCS#8 structure, made before anything
//! else is read.
//!
//! ring compares the AlgorithmIdentifier's bytes with the exact
//! encoding it expects and reports `WrongAlgorithm` on any
//! difference, before it reads the rest. scytale reads the whole
//! structure first, so a key that is both the wrong algorithm and
//! malformed after the identifier is an encoding error to scytale and
//! a wrong algorithm to ring. Callers make ring's check first, from
//! the bytes alone, and leave everything else to scytale.

/// The AlgorithmIdentifier of a PrivateKeyInfo, tag and length
/// included, if the bytes begin as one: a SEQUENCE holding a
/// one-byte INTEGER version and then a SEQUENCE. `None` where they
/// do not, which scytale will then refuse for its own reasons.
pub(crate) fn algorithm_identifier(pkcs8: &[u8]) -> Option<&[u8]> {
    let (_, inner) = element(pkcs8, 0x30)?;
    let rest = match inner {
        [0x02, 0x01, _, rest @ ..] => rest,
        _ => return None,
    };
    let (tlv, _) = element(rest, 0x30)?;
    Some(tlv)
}

/// An element with tag `tag` at the front of `bytes`: the whole
/// element, and its contents. Lengths up to two bytes long, which
/// is more than any key here.
fn element(bytes: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (header, len): (usize, usize) = match *bytes {
        [t, len, ..] if t == tag && len < 0x80 => (2, usize::from(len)),
        [t, 0x81, len, ..] if t == tag => (3, usize::from(len)),
        [t, 0x82, hi, lo, ..] if t == tag => {
            (4, usize::from(u16::from_be_bytes([hi, lo])))
        }
        _ => return None,
    };
    let end = header.checked_add(len)?;
    let tlv = bytes.get(..end)?;
    Some((tlv, &tlv[header..]))
}

/// The version of a PrivateKeyInfo, if the bytes begin as one: ring
/// reads it before anything else, and a version it does not read is
/// refused as such rather than for whatever follows.
pub(crate) fn version(pkcs8: &[u8]) -> Option<u8> {
    let (_, inner) = element(pkcs8, 0x30)?;
    match inner {
        [0x02, 0x01, v, ..] => Some(*v),
        _ => None,
    }
}

/// `rsaEncryption` with its NULL parameters, as RFC 8017 writes it
/// and ring requires.
pub(crate) const RSA_ENCRYPTION: &[u8] =
    b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

/// `id-Ed25519` with no parameters.
pub(crate) const ED25519: &[u8] = b"\x30\x05\x06\x03\x2b\x65\x70";

/// `id-ecPublicKey` naming P-256.
pub(crate) const EC_P256: &[u8] =
    b"\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\
\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

/// `id-ecPublicKey` naming P-384.
pub(crate) const EC_P384: &[u8] =
    b"\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\
\x06\x05\x2b\x81\x04\x00\x22";

/// ring's check: the identifier, when the bytes have one, must be
/// exactly `expected`.
pub(crate) fn check(
    pkcs8: &[u8],
    expected: &[u8],
) -> Result<(), crate::error::KeyRejected> {
    match algorithm_identifier(pkcs8) {
        Some(found) if found != expected => {
            Err(crate::error::KeyRejected::wrong_algorithm())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identifier_is_found_in_every_length_form() {
        let short = [
            0x30, 0x0b, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x70, 0x04,
        ];
        assert_eq!(algorithm_identifier(&short), Some(ED25519));
        let mut long = [0u8; 0x85];
        long[..7].copy_from_slice(&[0x30, 0x81, 0x82, 0x02, 0x01, 0x01, 0x30]);
        long[7] = 0x05;
        long[8..12].copy_from_slice(&ED25519[2..6]);
        long[12] = 0x70;
        assert_eq!(algorithm_identifier(&long), Some(ED25519));
        let mut longer = [0u8; 0x104];
        longer[..8]
            .copy_from_slice(&[0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30]);
        longer[8] = 0x05;
        longer[9..14].copy_from_slice(&ED25519[2..]);
        assert_eq!(algorithm_identifier(&longer), Some(ED25519));
    }

    #[test]
    fn what_is_not_a_private_key_info_is_left_to_scytale() {
        assert_eq!(algorithm_identifier(b""), None);
        assert_eq!(algorithm_identifier(&[0x30, 0x03, 0x02, 0x01]), None);
        assert_eq!(algorithm_identifier(&[0x31, 0x03, 0x02, 0x01, 0x00]), None);
        assert_eq!(
            algorithm_identifier(&[0x30, 0x05, 0x02, 0x01, 0x00, 0x04, 0x00]),
            None
        );
        assert!(check(b"junk", RSA_ENCRYPTION).is_ok());
    }

    #[test]
    fn another_identifier_is_the_wrong_algorithm_before_anything_else() {
        // An Ed25519 identifier, and then bytes that are not a key at
        // all: ring says which algorithm it was for, not that the
        // rest was wrong.
        let mut der = [0u8; 14];
        der[..5].copy_from_slice(&[0x30, 0x0c, 0x02, 0x01, 0x00]);
        der[5..12].copy_from_slice(ED25519);
        der[12] = 0xff;
        assert!(check(&der, ED25519).is_ok());
        assert!(check(&der, RSA_ENCRYPTION).is_err());
        assert!(check(&der, EC_P256).is_err());
    }
}
