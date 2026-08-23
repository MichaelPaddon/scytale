//! No operating system: ask the processor itself.
//!
//! On bare metal there is no kernel to ask, and none of the reasons
//! to prefer one apply. There is nothing to fork, no virtual machine
//! to snapshot, and nobody else to mix the processor's generator with
//! everything they collected. It is the source, so it is used
//! directly.
//!
//! Each of these instructions can decline. They draw from a physical
//! process that needs time to gather, and a burst of requests can
//! outrun it, so every one of them is asked again a bounded number of
//! times before the attempt is given up. Retrying forever would hang
//! a machine whose generator has failed outright, which is a thing
//! these instructions are specified to report.
//!
//! Where the processor has no such instruction there is nothing left
//! to try, and the answer is a refusal rather than something weaker.
//! Supply a source of your own through the
//! [`Random`](crate::random::Random) trait: on a board with a
//! hardware generator on a bus, or a ring oscillator, that is the
//! way in.

#![allow(unsafe_code)]
// Built on every system, so that the tests below run somewhere they
// can be watched, but used only where there is no operating system.
#![allow(dead_code)]

use crate::Error;

/// Whether this build has an instruction to use.
pub(crate) const AVAILABLE: bool = cfg!(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
));

/// How many times one word is asked for before giving up. Ten is
/// what Intel suggests, and these instructions are specified to
/// report a generator that has actually failed rather than simply
/// staying busy, so a bound is safe to have.
const TRIES: usize = 10;

/// Fills `out` with random bytes from the processor.
pub(crate) fn fill(out: &mut [u8]) -> Result<(), Error> {
    for piece in out.chunks_mut(8) {
        let word = word()?;
        piece.copy_from_slice(&word.to_ne_bytes()[..piece.len()]);
    }
    Ok(())
}

/// Eight random bytes from the processor, or a refusal once it has
/// declined [`TRIES`] times running.
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
))]
fn word() -> Result<u64, Error> {
    for _ in 0..TRIES {
        if let Some(word) = draw() {
            return Ok(word);
        }
    }
    // The number a system uses for a device that is not working.
    Err(Error::EntropyUnavailable(5))
}

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
)))]
fn word() -> Result<u64, Error> {
    // The number a system uses for a call it does not implement.
    Err(Error::EntropyUnavailable(38))
}

/// One attempt at `rdrand`, which reports whether it had anything to
/// give in the carry flag.
///
/// `rdrand`, not `rdseed`. The two look interchangeable and are not.
/// `rdseed` is the raw entropy source, deliberately rate limited, and
/// asking it for a buffer's worth in a row exhausts it: this was
/// written with `rdseed` first and the tests refused the second call.
/// `rdrand` is what the processor builds on top, a generator of the
/// approved kind reseeded from that source, and it is the one Intel
/// says to use for random numbers rather than for seeding. Since
/// nothing here keeps a generator of its own, that is exactly the job.
#[cfg(target_arch = "x86_64")]
fn draw() -> Option<u64> {
    if !has_rdrand() {
        return None;
    }
    let word: u64;
    let ok: u8;
    // SAFETY: the instruction touches no memory, and was confirmed
    // present just above.
    unsafe {
        core::arch::asm!(
            "rdrand {word}",
            "setc {ok}",
            word = out(reg) word,
            ok = out(reg_byte) ok,
            options(nomem, nostack),
        );
    }
    if ok == 0 {
        // Busy rather than broken. Standing back for a moment is what
        // Intel asks for, and costs nothing when it succeeds first
        // time, which it nearly always does.
        // SAFETY: a hint to the processor; it touches nothing.
        unsafe { core::arch::asm!("pause", options(nomem, nostack)) };
        return None;
    }
    Some(word)
}

/// Whether the processor has `rdrand` (CPUID leaf 1, ECX bit 30).
#[cfg(target_arch = "x86_64")]
fn has_rdrand() -> bool {
    core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0
}

/// One attempt at `rndr`, which reports failure by setting the zero
/// flag and returning nothing.
#[cfg(target_arch = "aarch64")]
fn draw() -> Option<u64> {
    if !has_rndr() {
        return None;
    }
    let word: u64;
    let failed: u64;
    // SAFETY: reads a register the architecture provides for this,
    // confirmed present just above. It touches no memory, but it does
    // set the flags, so it cannot claim to preserve them.
    unsafe {
        core::arch::asm!(
            // Named by its encoding rather than as RNDR, which the
            // assembler only accepts when told the target has it.
            // This always assembles, and the check above is what
            // decides whether it runs.
            "mrs {word}, S3_3_C2_C4_0",
            "cset {failed}, eq",
            word = out(reg) word,
            failed = out(reg) failed,
            options(nomem, nostack),
        );
    }
    (failed == 0).then_some(word)
}

/// Whether the processor has `rndr` (ID_AA64ISAR0_EL1 bits 63:60).
#[cfg(target_arch = "aarch64")]
fn has_rndr() -> bool {
    let isar0: u64;
    // SAFETY: reads an identification register, which is what they
    // are for; no memory is touched.
    unsafe {
        core::arch::asm!(
            "mrs {}, ID_AA64ISAR0_EL1",
            out(reg) isar0,
            options(nomem, nostack, preserves_flags),
        );
    }
    isar0 >> 60 != 0
}

/// One attempt at the `seed` register, which yields sixteen bits at a
/// time and says in its top half whether those bits are any good.
///
/// Four reads make a word. A read that is still warming up is not a
/// failure, so it does not count against the attempts; a generator
/// reporting itself broken is, and stops immediately.
#[cfg(target_arch = "riscv64")]
fn draw() -> Option<u64> {
    /// The register's verdict, in bits 31:16 of what it returns.
    const WAIT: u64 = 1;
    const READY: u64 = 2;

    let mut word = 0u64;
    for half in 0..4 {
        let mut got = None;
        for _ in 0..TRIES {
            let seed: u64;
            // SAFETY: reads the register the Zkr extension provides
            // for this. Reading it consumes entropy, so it can be
            // neither dropped nor repeated: not `nomem`, not `pure`.
            unsafe {
                core::arch::asm!(
                    "csrrw {seed}, 0x015, x0",
                    seed = out(reg) seed,
                    options(nostack, preserves_flags),
                );
            }
            match seed >> 16 {
                READY => {
                    got = Some(seed & 0xffff);
                    break;
                }
                // Still gathering. Worth asking again.
                WAIT => continue,
                // Self-test, or reporting itself dead. Neither will
                // improve by asking again.
                _ => return None,
            }
        }
        word |= got? << (16 * half);
    }
    Some(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether the instruction can be tried from an ordinary program
    /// here.
    ///
    /// x86-64 and aarch64 both report a refusal in the flags, so an
    /// attempt is harmless either way. RISC-V is left out on purpose:
    /// its `seed` register is closed to unprivileged code unless the
    /// machine has opened it, and reading it anyway raises an illegal
    /// instruction rather than returning a refusal, which would end
    /// the test run rather than fail a test.
    const TESTABLE: bool =
        cfg!(any(target_arch = "aarch64", target_arch = "x86_64"));

    /// The processor's own generator, where the machine running the
    /// tests has one, must behave like any other source.
    #[test]
    fn the_processor_fills_a_buffer() {
        if !TESTABLE || !AVAILABLE {
            return;
        }
        let mut first = [0u8; 64];
        if fill(&mut first).is_err() {
            // No such instruction on this particular processor.
            return;
        }
        let mut second = [0u8; 64];
        fill(&mut second).expect("second");
        assert_ne!(first, second);

        let set: u32 = first.iter().map(|b| b.count_ones()).sum();
        assert!((190..=326).contains(&set), "{set} bits set of 512");
    }

    /// Lengths that are not a whole number of words must still be
    /// filled exactly, without running past the end.
    #[test]
    fn odd_lengths_stay_inside_the_buffer() {
        if !TESTABLE || !AVAILABLE {
            return;
        }
        const PAD: usize = 16;
        let mut buf = [0xaau8; PAD + 40 + PAD];
        for len in [0, 1, 7, 8, 9, 31, 40] {
            buf.fill(0xaa);
            if fill(&mut buf[PAD..PAD + len]).is_err() {
                return;
            }
            assert!(
                buf[..PAD].iter().all(|&b| b == 0xaa),
                "{len}: wrote before the start"
            );
            assert!(
                buf[PAD + len..].iter().all(|&b| b == 0xaa),
                "{len}: wrote past the end"
            );
        }
    }
}
