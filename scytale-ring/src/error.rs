//! The two errors ring reports.
//!
//! ring says as little as it can about why an operation failed, so
//! nearly everything is [`Unspecified`]. The exception is a key that
//! could not be loaded, where [`KeyRejected`] carries a short reason.
//! Those reasons are ring's own words: callers print them, and some
//! tests compare them.

#[cfg(feature = "std")]
extern crate std;

/// An operation failed, and nothing more is said.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Unspecified;

impl core::fmt::Display for Unspecified {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        // The name ring prints, so that logs read the same.
        f.write_str("ring::error::Unspecified")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Unspecified {}

impl From<untrusted::EndOfInput> for Unspecified {
    fn from(_: untrusted::EndOfInput) -> Self {
        Unspecified
    }
}

impl From<core::array::TryFromSliceError> for Unspecified {
    fn from(_: core::array::TryFromSliceError) -> Self {
        Unspecified
    }
}

impl From<KeyRejected> for Unspecified {
    fn from(_: KeyRejected) -> Self {
        Unspecified
    }
}

/// A key was refused, with ring's name for the reason.
#[derive(Clone, Copy, Debug)]
pub struct KeyRejected(&'static str);

impl KeyRejected {
    pub(crate) fn inconsistent_components() -> Self {
        Self("InconsistentComponents")
    }

    pub(crate) fn invalid_component() -> Self {
        Self("InvalidComponent")
    }

    pub(crate) fn invalid_encoding() -> Self {
        Self("InvalidEncoding")
    }

    pub(crate) fn rng_failed() -> Self {
        Self("RNG failed")
    }

    pub(crate) fn too_small() -> Self {
        Self("TooSmall")
    }

    pub(crate) fn too_large() -> Self {
        Self("TooLarge")
    }

    pub(crate) fn wrong_algorithm() -> Self {
        Self("WrongAlgorithm")
    }

    pub(crate) fn private_modulus_len_not_multiple_of_512_bits() -> Self {
        Self("PrivateModulusLenNotMultipleOf512Bits")
    }

    pub(crate) fn unexpected_error() -> Self {
        Self("UnexpectedError")
    }

    /// The reason scytale gave, in ring's words: a value out of range
    /// is a bad component, a failed source is the generator's fault,
    /// and anything else wrong with the bytes is an encoding error.
    pub(crate) fn from_scytale(e: scytale::Error) -> Self {
        use scytale::Error as E;
        match e {
            E::InvalidPrivateKey | E::InvalidPublicKey => {
                Self::invalid_component()
            }
            E::InvalidKeyLength(_) => Self::invalid_encoding(),
            E::KeyGenerationFailed | E::EntropyUnavailable(_) => {
                Self::rng_failed()
            }
            E::NotSupported => Self::wrong_algorithm(),
            _ => Self::invalid_encoding(),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KeyRejected {}

impl core::fmt::Display for KeyRejected {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

/// scytale's reason is dropped: ring does not give one.
pub(crate) fn erase(_: scytale::Error) -> Unspecified {
    Unspecified
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::format;

    #[test]
    fn the_errors_print_as_ring_prints_them() {
        assert_eq!(format!("{Unspecified}"), "ring::error::Unspecified");
        assert_eq!(
            format!("{}", KeyRejected::invalid_encoding()),
            "InvalidEncoding"
        );
        assert_eq!(format!("{}", KeyRejected::rng_failed()), "RNG failed");
    }

    #[test]
    fn scytale_reasons_fold_into_ring_reasons() {
        use scytale::Error as E;
        let name = |e| format!("{}", KeyRejected::from_scytale(e));
        assert_eq!(name(E::InvalidEncoding), "InvalidEncoding");
        assert_eq!(name(E::InvalidKeyLength(3)), "InvalidEncoding");
        assert_eq!(name(E::InvalidPrivateKey), "InvalidComponent");
        assert_eq!(name(E::InvalidPublicKey), "InvalidComponent");
        assert_eq!(name(E::EntropyUnavailable(0)), "RNG failed");
    }
}
