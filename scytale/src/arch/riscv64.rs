//! Which RISC-V extensions this processor has.
//!
//! RISC-V puts nearly every optional instruction behind a named
//! extension, and user code cannot read the machine registers that
//! list them. On Linux the kernel answers instead.

#![allow(unsafe_code)]

/// Linux `riscv_hwprobe` (since 6.4): fills `value` for key
/// `RISCV_HWPROBE_KEY_IMA_EXT_0`, a bit set of extensions present on
/// every hart. Returns `None` if the kernel lacks the call or the key.
#[cfg(target_os = "linux")]
pub(crate) fn hwprobe_ima_ext_0() -> Option<u64> {
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
pub(crate) fn hwprobe_ima_ext_0() -> Option<u64> {
    None
}

/// Bits in `RISCV_HWPROBE_KEY_IMA_EXT_0` (Linux `asm/hwprobe.h`).
pub(crate) const IMA_V: u64 = 1 << 2;
pub(crate) const EXT_ZKND: u64 = 1 << 11;
pub(crate) const EXT_ZKNE: u64 = 1 << 12;
pub(crate) const EXT_ZKNH: u64 = 1 << 13;
pub(crate) const EXT_ZVBB: u64 = 1 << 17;
pub(crate) const EXT_ZVKG: u64 = 1 << 20;
pub(crate) const EXT_ZVKNED: u64 = 1 << 21;

/// Bytes in one vector register. Only valid once the vector extension
/// is known to be present, as the CSR read traps otherwise.
pub(crate) fn vlenb() -> usize {
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
