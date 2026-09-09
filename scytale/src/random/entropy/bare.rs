//! Taking raw samples from the processor's own generator.
//!
//! This is a noise source and nothing more. What comes out of it is
//! not fit to hand to a caller: it is unconditioned, it is credited
//! with less entropy than it holds bits, and on RISC-V the register
//! that produces it says outright that its output must be conditioned
//! before use. Everything above turns these samples into random bytes
//! by way of health tests and a derivation function; nothing here
//! does, which is why this offers no way to fill a buffer.
//!
//! Each of these instructions can decline. They draw from a physical
//! process that needs time to gather, and a burst of requests can
//! outrun it, so every one is asked again a bounded number of times
//! before the attempt is given up. Retrying forever would hang a
//! machine whose generator has failed outright, which is a thing
//! these instructions are specified to report.
//!
//! Where the processor has no such instruction there is nothing left
//! to try, and [`Sampler::try_new`] refuses at once rather than
//! leaving a generator that fails on every use. Supply a source of
//! your own through the [`Entropy`](crate::random::Entropy) trait: on
//! a board with a hardware generator on a bus, or a ring oscillator,
//! that is the way in.
//!
//! # Why `rdseed` here, and `rdrand` only if it is missing
//!
//! `rdseed` is the raw entropy source and `rdrand` is the generator
//! Intel builds on top of it, so which to ask depends on what is
//! being built. Asking `rdseed` for every word of output exhausts it,
//! and an earlier version of this file did exactly that and had its
//! second call refused. It is not asked for output any more: it is
//! asked for a seed, which is what its name says and what Intel says
//! to use it for, and two dozen words cover a whole generator. Where
//! `rdseed` is absent, `rdrand` is asked instead, and the derivation
//! function above treats either with the same suspicion.

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

/// How many times one word is asked for before giving up. Ten is what
/// Intel suggests for `rdrand`, and these instructions are specified
/// to report a generator that has actually failed rather than simply
/// staying busy, so a bound is safe to have.
const TRIES: usize = 10;

/// The same for `rdseed`, which is rate limited by design and needs
/// more patience: it is gathering, not expanding.
const SEED_TRIES: usize = 100;

/// The number a system uses for a device that is not working.
const BROKEN: i32 = 5;

/// The processor's noise source, once it is known to be there.
///
/// Holding it rather than looking it up per call keeps `cpuid` out of
/// the sampling loop, where under a hypervisor it can cost more than
/// the instruction it is asking about.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sampler {
    /// Which instruction answers. A unit on the architectures that
    /// offer only one.
    choice: Choice,
}

impl Sampler {
    /// The processor's noise source, or [`Error::NotSupported`] where
    /// it has none.
    pub(crate) fn try_new() -> Result<Self, Error> {
        Ok(Sampler {
            choice: Choice::try_new()?,
        })
    }

    /// One sixty-four bit sample, or a refusal once the processor has
    /// declined often enough to mean it is not merely busy.
    pub(crate) fn draw(&self) -> Result<u64, Error> {
        for _ in 0..self.choice.tries() {
            if let Some(word) = self.choice.attempt() {
                return Ok(word);
            }
        }
        Err(Error::EntropyUnavailable(BROKEN))
    }
}

/// Stands back for a moment after a refusal. Intel asks for this, and
/// it costs nothing when the instruction succeeds first time, which
/// it nearly always does.
#[cfg(target_arch = "x86_64")]
fn pause() {
    // SAFETY: a hint to the processor; it touches nothing.
    unsafe { core::arch::asm!("pause", options(nomem, nostack)) };
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug)]
enum Choice {
    /// The raw source, preferred.
    Seed,
    /// The generator built on it, where the raw source is absent.
    Rand,
}

#[cfg(target_arch = "x86_64")]
impl Choice {
    fn try_new() -> Result<Self, Error> {
        if has_rdseed() {
            Ok(Choice::Seed)
        } else if has_rdrand() {
            Ok(Choice::Rand)
        } else {
            Err(Error::NotSupported)
        }
    }

    fn tries(&self) -> usize {
        match self {
            Choice::Seed => SEED_TRIES,
            Choice::Rand => TRIES,
        }
    }

    fn attempt(&self) -> Option<u64> {
        let word: u64;
        let ok: u8;
        // SAFETY: neither instruction touches memory, and the one
        // named was confirmed present before this sampler was built.
        // Each reports in the carry flag whether it had anything to
        // give, so neither can claim to preserve the flags.
        unsafe {
            match self {
                Choice::Seed => core::arch::asm!(
                    "rdseed {word}",
                    "setc {ok}",
                    word = out(reg) word,
                    ok = out(reg_byte) ok,
                    options(nomem, nostack),
                ),
                Choice::Rand => core::arch::asm!(
                    "rdrand {word}",
                    "setc {ok}",
                    word = out(reg) word,
                    ok = out(reg_byte) ok,
                    options(nomem, nostack),
                ),
            }
        }
        if ok == 0 {
            // Busy rather than broken.
            pause();
            return None;
        }
        Some(word)
    }
}

/// Whether the processor has `rdrand` (CPUID leaf 1, ECX bit 30).
#[cfg(target_arch = "x86_64")]
fn has_rdrand() -> bool {
    core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0
}

/// Whether the processor has `rdseed` (CPUID leaf 7, subleaf 0, EBX
/// bit 18), on a processor that reports that leaf at all.
#[cfg(target_arch = "x86_64")]
fn has_rdseed() -> bool {
    core::arch::x86_64::__cpuid(0).eax >= 7
        && core::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 18) != 0
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, Debug)]
struct Choice;

#[cfg(target_arch = "aarch64")]
impl Choice {
    /// Whether the processor has `rndr` (ID_AA64ISAR0_EL1 bits
    /// 63:60).
    fn try_new() -> Result<Self, Error> {
        let isar0: u64;
        // SAFETY: reads an identification register, which is what
        // they are for; no memory is touched.
        unsafe {
            core::arch::asm!(
                "mrs {}, ID_AA64ISAR0_EL1",
                out(reg) isar0,
                options(nomem, nostack, preserves_flags),
            );
        }
        if isar0 >> 60 != 0 {
            Ok(Choice)
        } else {
            Err(Error::NotSupported)
        }
    }

    fn tries(&self) -> usize {
        TRIES
    }

    /// One attempt at `rndr`, which reports failure by setting the
    /// zero flag and returning nothing.
    fn attempt(&self) -> Option<u64> {
        let word: u64;
        let failed: u64;
        // SAFETY: reads a register the architecture provides for
        // this, confirmed present when this sampler was built. It
        // touches no memory, but it does set the flags, so it cannot
        // claim to preserve them.
        unsafe {
            core::arch::asm!(
                // Named by its encoding rather than as RNDR, which
                // the assembler only accepts when told the target has
                // it. This always assembles, and the check above is
                // what decides whether it runs.
                "mrs {word}, S3_3_C2_C4_0",
                "cset {failed}, eq",
                word = out(reg) word,
                failed = out(reg) failed,
                options(nomem, nostack),
            );
        }
        (failed == 0).then_some(word)
    }
}

#[cfg(target_arch = "riscv64")]
#[derive(Clone, Copy, Debug)]
struct Choice;

#[cfg(target_arch = "riscv64")]
impl Choice {
    /// There is no register to ask whether the `seed` register may be
    /// read: where the machine has not opened it, reading raises an
    /// illegal instruction rather than answering. So there is nothing
    /// to check here, and a machine that has not opened it does not
    /// reach this code at all.
    fn try_new() -> Result<Self, Error> {
        Ok(Choice)
    }

    fn tries(&self) -> usize {
        TRIES
    }

    /// One attempt at the `seed` register, which yields sixteen bits
    /// at a time and says in its top half whether those bits are any
    /// good.
    ///
    /// Four reads make a word. A read that is still warming up is not
    /// a failure, so it does not count against the attempts; a
    /// generator reporting itself broken is, and stops immediately.
    fn attempt(&self) -> Option<u64> {
        /// The register's verdict, in bits 31:16 of what it returns.
        const WAIT: u64 = 1;
        const READY: u64 = 2;

        let mut word = 0u64;
        for half in 0..4 {
            let mut got = None;
            for _ in 0..TRIES {
                let seed: u64;
                // SAFETY: reads the register the Zkr extension
                // provides for this. Reading it consumes entropy, so
                // it can be neither dropped nor repeated: not
                // `nomem`, not `pure`.
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
                    // Self-test, or reporting itself dead. Neither
                    // will improve by asking again.
                    _ => return None,
                }
            }
            word |= got? << (16 * half);
        }
        Some(word)
    }
}

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
)))]
#[derive(Clone, Copy, Debug)]
struct Choice;

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
)))]
impl Choice {
    fn try_new() -> Result<Self, Error> {
        Err(Error::NotSupported)
    }

    fn tries(&self) -> usize {
        TRIES
    }

    fn attempt(&self) -> Option<u64> {
        None
    }
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

    /// The processor's own noise source, where the machine running
    /// the tests has one, must produce samples that differ.
    #[test]
    fn the_processor_draws_samples() {
        if !TESTABLE || !AVAILABLE {
            return;
        }
        let Ok(sampler) = Sampler::try_new() else {
            // No such instruction on this particular processor.
            return;
        };
        let first = sampler.draw().expect("first");
        let second = sampler.draw().expect("second");
        assert_ne!(first, second);
        assert_ne!(first, 0);
        assert_ne!(first, u64::MAX);
    }

    /// Enough draws in a row to seed a generator many times over must
    /// all succeed. This is the case that failed when `rdseed` was
    /// being asked for output rather than for a seed, so it is worth
    /// asking for rather more than one seed's worth.
    #[test]
    fn a_burst_of_draws_all_succeed() {
        if !TESTABLE || !AVAILABLE {
            return;
        }
        let Ok(sampler) = Sampler::try_new() else {
            return;
        };
        let mut previous = 0;
        for n in 0..512 {
            let word = sampler.draw().unwrap_or_else(|e| panic!("{n}: {e}"));
            assert_ne!(word, previous, "{n}: repeated");
            previous = word;
        }
    }

    /// Where there is no instruction, the refusal comes at
    /// construction rather than at every use.
    #[test]
    fn a_processor_without_one_refuses_at_construction() {
        if AVAILABLE {
            return;
        }
        assert_eq!(Sampler::try_new().err(), Some(Error::NotSupported));
    }
}
