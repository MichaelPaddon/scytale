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
    hwprobe_ima_ext_0, vlenb, EXT_ZKND, EXT_ZKNE, EXT_ZVKNED, IMA_V,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_agree_with_constructors() {
        assert_eq!(zkn::Aes::try_new(&[0; 16]).is_ok(), has_zkn());
        assert_eq!(zvkned::Aes::try_new(&[0; 16]).is_ok(), has_zvkned());
    }
}
