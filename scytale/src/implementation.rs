//! The names implementations go by.
//!
//! A suite is written more than once: for the instructions a
//! processor offers, and for a processor that offers none. Which one
//! ran is not an internal detail -- it is the first thing a benchmark
//! or a vector suite has to say, and it decides whether a processor
//! can run the code at all. So they are named for their instructions,
//! and the names are kept here rather than invented separately by
//! each suite.
//!
//! Only the names a mode or an AEAD can be written against are here.
//! A suite whose implementations turn on some other instruction --
//! GHASH on RISC-V, which has three ways to multiply -- names those
//! itself, since they are its own and no other suite shares them.

/// Which implementation of a suite is meant.
///
/// The hardware names exist only on the architecture that has them,
/// so naming one that cannot be built is a compile error rather than
/// a run-time nothing. Every architecture has [`Portable`].
///
/// [`Portable`]: Implementation::Portable
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Implementation {
    /// AES-NI, with PCLMULQDQ where a hash runs beside the cipher.
    #[cfg(target_arch = "x86_64")]
    Aesni,
    /// VAES, two blocks to a register, with VPCLMULQDQ likewise.
    #[cfg(target_arch = "x86_64")]
    Vaes,
    /// The ARMv8 cryptographic extension.
    #[cfg(target_arch = "aarch64")]
    Armv8,
    /// RISC-V vector AES, Zvkned, with whatever vector hash the suite
    /// needs beside it.
    #[cfg(target_arch = "riscv64")]
    Zvkned,
    /// The construction over the cipher's own calls, which every
    /// processor can run whatever cipher it was given.
    Portable,
}

impl Implementation {
    /// What it is called, in a benchmark row or a suite's log.
    #[cfg(test)]
    pub(crate) fn name(self) -> &'static str {
        match self {
            #[cfg(target_arch = "x86_64")]
            Implementation::Aesni => "aesni",
            #[cfg(target_arch = "x86_64")]
            Implementation::Vaes => "vaes",
            #[cfg(target_arch = "aarch64")]
            Implementation::Armv8 => "armv8",
            #[cfg(target_arch = "riscv64")]
            Implementation::Zvkned => "zvkned",
            Implementation::Portable => "portable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every suite that names implementations lists the portable one,
    /// since that is the one no processor can refuse.
    #[test]
    fn every_suite_has_the_portable_one() {
        for list in [
            crate::cipher::mode::cbc::CHOICES,
            crate::cipher::mode::ctr::CHOICES,
            crate::cipher::mode::xts::CHOICES,
            crate::aead::gcm::CHOICES,
            crate::aead::gcm_siv::CHOICES,
        ] {
            assert_eq!(list.last(), Some(&Implementation::Portable));
            // Named once each: a suite that listed one twice would
            // measure and validate it twice over.
            for (i, one) in list.iter().enumerate() {
                assert!(!list[i + 1..].contains(one), "{one:?} twice");
            }
        }
    }
}
