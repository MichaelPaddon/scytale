//! AES implementations for RISC-V (RV64).
//!
//! [`zkn`] uses the scalar cryptography extension (Zkne/Zknd) and
//! [`zvkned`] the vector cryptography extension (Zvkned). Both probe
//! for their instructions at run time.

#![allow(unsafe_code)]

pub mod zkn;
pub mod zvkned;

/// Linux `riscv_hwprobe` (since 6.4): fills `value` for key
/// `RISCV_HWPROBE_KEY_IMA_EXT_0`, a bit set of extensions present on
/// every hart. Returns `None` if the kernel lacks the call or the key.
#[cfg(target_os = "linux")]
fn hwprobe_ima_ext_0() -> Option<u64> {
    const SYS_RISCV_HWPROBE: usize = 258;
    const KEY_IMA_EXT_0: i64 = 4;

    // struct riscv_hwprobe { __s64 key; __u64 value; }
    let mut pair: [u64; 2] = [KEY_IMA_EXT_0 as u64, 0];
    let ret: isize;
    // SAFETY: a plain system call with one valid pair, no cpu set and
    // no flags; the kernel writes only into `pair`.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") pair.as_mut_ptr() as usize => ret,
            in("a1") 1usize,
            in("a2") 0usize,
            in("a3") 0usize,
            in("a4") 0usize,
            in("a7") SYS_RISCV_HWPROBE,
            options(nostack),
        );
    }
    // The kernel sets the key to -1 when it does not know it.
    if ret != 0 || pair[0] as i64 != KEY_IMA_EXT_0 {
        return None;
    }
    Some(pair[1])
}

#[cfg(not(target_os = "linux"))]
fn hwprobe_ima_ext_0() -> Option<u64> {
    None
}

/// Bits in `RISCV_HWPROBE_KEY_IMA_EXT_0` (Linux `asm/hwprobe.h`).
const IMA_V: u64 = 1 << 2;
const EXT_ZKND: u64 = 1 << 11;
const EXT_ZKNE: u64 = 1 << 12;
const EXT_ZVKNED: u64 = 1 << 21;

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

/// Bytes in one vector register. Only valid once the vector extension
/// is known to be present, as the CSR read traps otherwise.
fn vlenb() -> usize {
    let bytes: usize;
    // SAFETY: reads a read-only CSR; no memory is touched. Callers
    // have confirmed the vector extension exists.
    unsafe {
        core::arch::asm!(
            "csrr {}, vlenb",
            out(reg) bytes,
            options(nomem, nostack, preserves_flags),
        );
    }
    bytes
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
