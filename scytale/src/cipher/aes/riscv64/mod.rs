//! AES implementations for RISC-V (RV64).
//!
//! [`zkn`] uses the scalar cryptography extension (Zkne/Zknd) and
//! [`zvkned`] the vector cryptography extension (Zvkned). Both probe
//! for their instructions at run time.

// The implementations below need unsafe; they inherit this.
#![allow(unsafe_code)]

pub mod zkn;
pub mod zvkned;

use crate::arch::riscv64::{
    EXT_ZKND, EXT_ZKNE, EXT_ZVBB, EXT_ZVKNED, IMA_V, hwprobe_ima_ext_0, vlenb,
};

/// Whether the scalar AES instructions (Zkne and Zknd) are available.
pub(crate) fn has_zkn() -> bool {
    if cfg!(all(target_feature = "zkne", target_feature = "zknd")) {
        return true;
    }
    let want = EXT_ZKNE | EXT_ZKND;
    hwprobe_ima_ext_0().is_some_and(|ext| ext & want == want)
}

/// Whether the vector AES instructions are available: the vector
/// extension, Zvkned, and registers of at least 128 bits, which the
/// 128-bit element groups need.
pub(crate) fn has_zvkned() -> bool {
    let present = cfg!(all(target_feature = "v", target_feature = "zvkned"))
        || {
            let want = IMA_V | EXT_ZVKNED;
            hwprobe_ima_ext_0().is_some_and(|ext| ext & want == want)
        };
    present && vlenb() >= 16
}

/// Whether the vector byte reverse `vrev8.v` is here, which comes
/// with Zvbb.
///
/// The counter loop uses it and the cipher does not, so it is asked
/// for separately. RVA23 requires both, so a machine that conforms to
/// the profile has it; one that does not takes the shared loop.
pub(crate) fn has_zvbb() -> bool {
    cfg!(all(target_feature = "v", target_feature = "zvbb")) || {
        let want = IMA_V | EXT_ZVBB;
        hwprobe_ima_ext_0().is_some_and(|ext| ext & want == want)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_agree_with_constructors() {
        assert_eq!(zkn::Aes::<16>::supported(), has_zkn());
        assert_eq!(zvkned::Aes::<16>::supported(), has_zvkned());
    }
}
