//! Which RISC-V extensions this processor has.
//!
//! RISC-V puts nearly every optional instruction behind a named
//! extension, and user code cannot read the machine registers that
//! list them. On Linux the kernel answers instead.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
pub(crate) const EXT_ZBB: u64 = 1 << 4;
pub(crate) const EXT_ZBC: u64 = 1 << 7;
pub(crate) const EXT_ZBKB: u64 = 1 << 8;
pub(crate) const EXT_ZBKC: u64 = 1 << 9;
pub(crate) const EXT_ZKND: u64 = 1 << 11;
pub(crate) const EXT_ZKNE: u64 = 1 << 12;
pub(crate) const EXT_ZKNH: u64 = 1 << 13;
pub(crate) const EXT_ZVBB: u64 = 1 << 17;
pub(crate) const EXT_ZVBC: u64 = 1 << 18;
pub(crate) const EXT_ZVKB: u64 = 1 << 19;
pub(crate) const EXT_ZVKG: u64 = 1 << 20;
pub(crate) const EXT_ZVKNED: u64 = 1 << 21;
pub(crate) const EXT_ZVKNHA: u64 = 1 << 22;
pub(crate) const EXT_ZVKNHB: u64 = 1 << 23;

/// Every extension this processor has, as a `hwprobe` bit set, and
/// the one thing every decision in the crate is made from.
///
/// A target feature named at build time is added to what the kernel
/// reports: naming it is a promise the instruction is there, and it
/// covers a target with no kernel to ask. So the answer is a bit set
/// whatever the build, and choosing an implementation is then a
/// function of a single word, which a test can supply.
pub(crate) fn extensions() -> u64 {
    // Kept: `hwprobe` is a system call, and the answer cannot change
    // while the program runs. Everything on this architecture is
    // decided from this word, a key expansion and the start of a hash
    // included, so asking each time would put a system call on paths
    // that run for every message.
    let kept = EXTENSIONS.load(Ordering::Relaxed);
    if kept & ASKED != 0 {
        return kept & !ASKED;
    }
    let ext = ask_extensions();
    EXTENSIONS.store(ext | ASKED, Ordering::Relaxed);
    ext
}

/// What [`extensions`] found, with [`ASKED`] set once it has looked.
/// A race is harmless: the question has one answer, so two threads
/// store the same word. See [`crate::probe`].
static EXTENSIONS: AtomicU64 = AtomicU64::new(0);

/// Marks the kept word as filled in, since no extension owns the top
/// bit and an empty answer is a real one.
const ASKED: u64 = 1 << 63;

fn ask_extensions() -> u64 {
    let mut ext = hwprobe_ima_ext_0().unwrap_or(0);
    // One arm per extension the crate looks for; `cfg!` folds each to
    // a constant, so this is a handful of ors.
    for (named, bit) in [
        (cfg!(target_feature = "v"), IMA_V),
        (cfg!(target_feature = "zbb"), EXT_ZBB),
        (cfg!(target_feature = "zbc"), EXT_ZBC),
        (cfg!(target_feature = "zbkb"), EXT_ZBKB),
        (cfg!(target_feature = "zbkc"), EXT_ZBKC),
        (cfg!(target_feature = "zknd"), EXT_ZKND),
        (cfg!(target_feature = "zkne"), EXT_ZKNE),
        (cfg!(target_feature = "zknh"), EXT_ZKNH),
        (cfg!(target_feature = "zvbb"), EXT_ZVBB),
        (cfg!(target_feature = "zvbc"), EXT_ZVBC),
        (cfg!(target_feature = "zvkb"), EXT_ZVKB),
        (cfg!(target_feature = "zvkg"), EXT_ZVKG),
        (cfg!(target_feature = "zvkned"), EXT_ZVKNED),
        (cfg!(target_feature = "zvknha"), EXT_ZVKNHA),
        (cfg!(target_feature = "zvknhb"), EXT_ZVKNHB),
    ] {
        if named {
            ext |= bit;
        }
    }
    ext
}

/// Bytes in one vector register, or zero where `ext` says there is no
/// vector unit.
///
/// Every caller has to ask it that way round, because reading the CSR
/// on a processor without the extension traps.
pub(crate) fn vector_bytes(ext: u64) -> usize {
    if ext & IMA_V == 0 {
        return 0;
    }
    // Kept for the same reason as [`extensions`]: a CSR read on every
    // call, on paths that run for every message.
    match VECTOR_BYTES.load(Ordering::Relaxed) {
        0 => {
            let bytes = vlenb();
            VECTOR_BYTES.store(bytes, Ordering::Relaxed);
            bytes
        }
        bytes => bytes,
    }
}

/// The width [`vector_bytes`] read, or zero before it has looked. A
/// vector register is never zero bytes wide, so zero can mean both.
static VECTOR_BYTES: AtomicUsize = AtomicUsize::new(0);

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

/// The umbrella extensions, as the profiles define them and as real
/// hardware therefore ships them. Nothing here chooses an
/// implementation from these -- the probes look at one bit at a time,
/// so that an unusual processor still gets what it has -- but a test
/// that asks what a real processor would be given needs to know what
/// combinations are real. Only the bits this crate looks for are
/// listed.
#[cfg(test)]
pub(crate) mod profile {
    use super::*;

    /// `Zkn`, the scalar NIST set: AES, SHA-2, and the bit
    /// manipulation and carry-less multiply they are specified with.
    pub(crate) const ZKN: u64 =
        EXT_ZBKB | EXT_ZBKC | EXT_ZKND | EXT_ZKNE | EXT_ZKNH;

    /// `Zvkn`, the vector NIST set: vector AES and SHA-2, with Zvkb
    /// but not the whole of Zvbb.
    pub(crate) const ZVKN: u64 =
        IMA_V | EXT_ZVKB | EXT_ZVKNED | EXT_ZVKNHA | EXT_ZVKNHB;

    /// `Zvkng`: [`ZVKN`] with the GHASH instruction.
    pub(crate) const ZVKNG: u64 = ZVKN | EXT_ZVKG;

    /// `Zvknc`: [`ZVKN`] with the vector carry-less multiply instead.
    pub(crate) const ZVKNC: u64 = ZVKN | EXT_ZVBC;

    /// What RVA23 requires of every conforming processor, and no
    /// cryptography at all: a vector unit and the bit manipulation.
    pub(crate) const RVA23: u64 = IMA_V | EXT_ZBB | EXT_ZVBB;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kept answer is what the kernel said, and it is kept: every
    /// decision on this architecture reads it, a key expansion and
    /// the start of a hash included, and asking is a system call.
    #[test]
    fn the_extensions_are_asked_for_once() {
        let asked = ask_extensions();
        assert_eq!(extensions(), asked);
        assert_eq!(extensions(), asked);
        assert_ne!(EXTENSIONS.load(Ordering::Relaxed) & ASKED, 0);
    }

    /// The vector width is kept the same way, and is only read where
    /// the processor has a vector unit to read it from.
    #[test]
    fn the_vector_width_is_asked_for_once() {
        let ext = extensions();
        let bytes = vector_bytes(ext);
        assert_eq!(vector_bytes(ext), bytes);
        if ext & IMA_V == 0 {
            assert_eq!(bytes, 0);
        } else {
            assert_ne!(bytes, 0);
            assert_eq!(VECTOR_BYTES.load(Ordering::Relaxed), bytes);
        }
    }
}
