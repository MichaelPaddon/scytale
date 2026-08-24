//! Where seed material comes from.
//!
//! Each of these is a source of raw material, not a source of random
//! bytes: what they hand back is conditioned by the generator above
//! them before any of it reaches a caller. That is why they implement
//! [`Entropy`] and not [`Random`](crate::random::Random).
//!
//! | Source | What it asks |
//! | --- | --- |
//! | [`System`] | whoever on this machine is best placed to know |
//! | [`Processor`] | the processor's own generator, health tested |
//! | [`External`] | nothing at all; the caller supplies everything |
//!
//! # Why the operating systems are not written out here
//!
//! They used to be: a system call made by number on Linux, a named C
//! function on the BSDs and Apple's systems, another on Windows.
//! Every one of those is a fact about somebody else's kernel that has
//! to be kept true, and the list was never complete. Linux was
//! supported on three architectures and quietly unsupported on the
//! rest.
//!
//! The `getrandom` crate is where that work is already being done,
//! for far more platforms than were ever listed here, so [`System`]
//! asks it. On Linux with no C library it still makes the system call
//! directly, so a static binary is no worse off.
//!
//! The processor's instructions are still written out here, because
//! what is wanted from them is not what that crate offers: raw
//! samples to seed a generator with, watched for signs the hardware
//! has failed.

mod bare;

use crate::random::health::{Health, STARTUP};
use crate::random::Entropy;
use crate::Error;

use bare::Sampler;

/// The processor's own generator, watched as it is used.
///
/// Construction runs the startup test SP 800-90B asks for, so a
/// processor whose generator is dead or stuck yields no `Processor`
/// at all rather than one that hands out its output. Every sample
/// drawn afterwards is examined too.
///
/// Available on every architecture with an instruction for it:
/// `rdseed` or `rdrand`, `rndr`, or the `seed` register. Elsewhere
/// [`try_new`](Processor::try_new) returns [`Error::NotSupported`].
#[derive(Clone, Debug)]
pub struct Processor {
    sampler: Sampler,
    health: Health,
}

impl Processor {
    /// Finds the processor's generator and satisfies itself that it
    /// is working.
    ///
    /// Draws and examines a thousand samples, which takes well under
    /// a millisecond and happens once for the life of the object.
    ///
    /// # Errors
    ///
    /// [`Error::NotSupported`] where the processor has no such
    /// instruction, and [`Error::EntropyUnavailable`] where it has
    /// one that is not working.
    pub fn try_new() -> Result<Self, Error> {
        let sampler = Sampler::try_new()?;
        let mut health = Health::new();
        // Four samples to a word, and the startup test is counted in
        // samples.
        for _ in 0..STARTUP / 4 {
            health.word(sampler.draw()?)?;
        }
        Ok(Processor { sampler, health })
    }
}

impl Entropy for Processor {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for piece in out.chunks_mut(8) {
            let word = self.sampler.draw()?;
            self.health.word(word)?;
            piece.copy_from_slice(&word.to_ne_bytes()[..piece.len()]);
        }
        Ok(())
    }
}

/// Whoever on this machine is best placed to know.
///
/// The operating system where there is one: it is seeded from far
/// more than a library can reach, it is told when a virtual machine
/// has been cloned, and it already mixes in the processor's generator
/// along with everything else. Where there is no operating system,
/// the processor itself, by way of [`Processor`].
#[derive(Clone, Debug)]
pub struct System(Inner);

impl System {
    /// Finds this machine's source.
    ///
    /// # Errors
    ///
    /// Where there is no operating system and the processor has no
    /// generator either, the same errors as [`Processor::try_new`].
    /// Where there is an operating system, this does not fail.
    pub fn try_new() -> Result<Self, Error> {
        Inner::try_new().map(System)
    }
}

impl Entropy for System {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.0.fill(out)
    }
}

/// With an operating system, it is the thing to ask. On wasm the same
/// call reaches the surrounding JavaScript instead. The condition here
/// is also what gates the dependency in `Cargo.toml`, so the two have
/// to agree.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Debug)]
struct Inner;

#[cfg(not(target_os = "none"))]
impl Inner {
    fn try_new() -> Result<Self, Error> {
        Ok(Inner)
    }
}

#[cfg(not(target_os = "none"))]
impl Entropy for Inner {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        // A call made very early in boot waits until the kernel's
        // generator is ready. That is deliberate: the alternative is
        // bytes that are not yet unpredictable.
        getrandom::fill(out).map_err(|e| {
            // The number the system gave, where it gave one.
            Error::EntropyUnavailable(e.raw_os_error().unwrap_or(0))
        })
    }
}

/// With none, there is nobody to ask but the processor, which already
/// answers to both of the names used above.
#[cfg(target_os = "none")]
type Inner = Processor;

/// No source of its own: entropy arrives only when the caller brings
/// it.
///
/// A generator built on this works exactly as any other until it has
/// drawn as much as one seeding allows, and then stops with
/// [`Error::ReseedRequired`] until it is given fresh material. It
/// never quietly carries on, and it never invents anything.
///
/// This is what a generator seeded by
/// [`Rng::from_seed`](crate::random::Rng::from_seed) holds.
#[derive(Clone, Copy, Debug, Default)]
pub struct External;

impl Entropy for External {
    fn fill(&mut self, _out: &mut [u8]) -> Result<(), Error> {
        Err(Error::ReseedRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether this build has an operating system to ask.
    const HOSTED: bool = cfg!(not(target_os = "none"));

    /// Guard bytes either side of the target catch a length or
    /// pointer slip. Sizes straddle 256, where some systems stop
    /// promising to answer in full.
    #[test]
    fn the_system_writes_the_whole_buffer_and_no_more() {
        if !HOSTED {
            return;
        }
        let mut system = System::try_new().expect("system");
        const PAD: usize = 32;
        let mut buf = [0xaau8; PAD + 4096 + PAD];
        for len in [0, 1, 7, 16, 31, 255, 256, 257, 1000, 4096] {
            buf.fill(0xaa);
            system.fill(&mut buf[PAD..PAD + len]).expect("fill");
            assert!(
                buf[..PAD].iter().all(|&b| b == 0xaa),
                "{len}: wrote before the start"
            );
            assert!(
                buf[PAD + len..].iter().all(|&b| b == 0xaa),
                "{len}: wrote past the end"
            );
            // One byte in 256 matches the padding by chance, so ask
            // whether any byte moved rather than all of them.
            assert!(
                len == 0 || buf[PAD..PAD + len].iter().any(|&b| b != 0xaa),
                "{len}: wrote nothing"
            );
        }
    }

    /// Two equal draws would mean the system is not being asked.
    #[test]
    fn successive_system_draws_differ() {
        if !HOSTED {
            return;
        }
        let mut system = System::try_new().expect("system");
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        system.fill(&mut first).expect("first");
        system.fill(&mut second).expect("second");
        assert_ne!(first, second);
    }

    /// Catches output that is technically written but obviously not
    /// random. The band is about nine standard deviations wide, so a
    /// true source will not fall outside it in the life of this
    /// library.
    #[test]
    fn system_bits_are_not_wildly_skewed() {
        if !HOSTED {
            return;
        }
        let mut system = System::try_new().expect("system");
        let mut buf = [0u8; 4096];
        system.fill(&mut buf).expect("fill");
        let set: u32 = buf.iter().map(|b| b.count_ones()).sum();
        assert!((15600..17200).contains(&set), "{set} bits set of 32768");
    }

    /// A source that has nothing to give must say so, every time,
    /// rather than returning a buffer it did not fill.
    #[test]
    fn external_refuses_rather_than_inventing() {
        let mut buf = [0xaau8; 16];
        assert_eq!(External.fill(&mut buf).err(), Some(Error::ReseedRequired));
        assert_eq!(buf, [0xaau8; 16], "left the buffer alone");
    }

    /// The processor, where the machine running the tests has one and
    /// can be asked from an ordinary program.
    #[test]
    fn the_processor_fills_a_buffer() {
        if !cfg!(any(target_arch = "aarch64", target_arch = "x86_64")) {
            return;
        }
        let Ok(mut processor) = Processor::try_new() else {
            // No such instruction on this particular processor.
            return;
        };
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        processor.fill(&mut first).expect("first");
        processor.fill(&mut second).expect("second");
        assert_ne!(first, second);
        // Odd lengths must stay inside the buffer.
        let mut odd = [0u8; 5];
        processor.fill(&mut odd).expect("odd");
    }
}
