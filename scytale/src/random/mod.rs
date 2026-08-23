//! Random numbers, from the operating system.
//!
//! # Where the bytes come from
//!
//! Whoever is best placed to know, asked afresh every call. There is
//! no generator kept in this process, and that is the point: a
//! generator has state, and state gets duplicated. `fork` gives both
//! processes the same next bytes, and restoring a virtual machine
//! snapshot gives every restored copy the same. Either one repeats a
//! nonce, and a repeated nonce is enough to lose the key.
//!
//! | Where it runs | What it asks |
//! | --- | --- |
//! | Linux | the `getrandom` system call, made directly |
//! | Apple systems, the BSDs, Solaris | `getentropy` |
//! | Windows | `ProcessPrng` |
//! | No operating system | the processor's own generator |
//!
//! With an operating system present, it is the thing to ask: it is
//! seeded from far more than a library can reach, is told when a
//! virtual machine has been cloned, and already mixes in the
//! processor's generator along with everything else.
//!
//! With no operating system none of that applies. There is nothing to
//! fork, no snapshot, and nobody else collecting anything, so the
//! processor is asked directly where it has an instruction for it:
//! `rdrand`, `rndr`, or the `seed` register. Where it has none, the
//! answer is a refusal, and the way in is the [`Random`] trait: a
//! board with a generator of its own is reached that way.
//!
//! # Using it safely
//!
//! - **Check the result.** Where nothing above can be reached, every
//!   call fails with [`Error::EntropyUnavailable`]. Nothing weaker is
//!   ever quietly substituted, because randomness invented from a
//!   clock or a process number is worse than none: it looks as though
//!   it worked.
//! - Not everything wants randomness. An initialisation vector for
//!   CBC or CFB must be *unpredictable*, which is what this gives.
//!   A counter for CTR, or a nonce for GCM, must be *unique*, which
//!   is a different and stronger requirement, and one a counter
//!   answers with certainty where a draw only answers it with high
//!   probability: see [`Nonces`](crate::symmetric::mode::Nonces).
//! - A call made very early in boot waits until the kernel's
//!   generator is ready. That is deliberate. The alternative is
//!   bytes that are not yet unpredictable.
//! - Wiping whatever these bytes become is the caller's job.
//!
//! # Speed
//!
//! On Linux, going straight to the kernel means a real system call
//! every time, rather than the faster path the C library uses. That
//! costs hundreds of nanoseconds rather than tens. It does not matter
//! for keys, which are drawn once. It does matter for a nonce per
//! message, which is the better reason to count nonces than to draw
//! them.
//!
//! # Assurance
//!
//! There is no NIST vector suite for any of this, unlike the rest of
//! the library. The kernel is the generator and the validated part;
//! this is a caller. What is tested here is the plumbing.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), scytale::Error> {
//! let mut key = [0u8; 32];
//! scytale::random::fill(&mut key)?;
//! # Ok(())
//! # }
//! ```

mod source;

use crate::Error;

/// A source of random bytes.
///
/// [`System`] is the one that matters. The trait exists so that work
/// which consumes randomness can be handed a fixed sequence instead
/// and tested for an exact answer.
pub trait Random {
    /// Fills the whole of `out`, or fails without leaving anything
    /// worth relying on.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;
}

/// The operating system's generator.
#[derive(Clone, Copy, Debug, Default)]
pub struct System;

impl Random for System {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        fill(out)
    }
}

/// Fills `out` with random bytes from the operating system.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), scytale::Error> {
/// let mut iv = [0u8; 16];
/// scytale::random::fill(&mut iv)?;
/// # Ok(())
/// # }
/// ```
pub fn fill(out: &mut [u8]) -> Result<(), Error> {
    source::fill(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether this build has anything to ask.
    const HAVE_SYSTEM: bool = source::AVAILABLE;

    /// Guard bytes either side of the target catch a length or
    /// pointer slip in the assembly, on the architecture that made
    /// it. Sizes straddle 256, where the kernel stops promising to
    /// answer in full.
    #[test]
    fn writes_the_whole_buffer_and_no_more() {
        if !HAVE_SYSTEM {
            return;
        }
        const PAD: usize = 32;
        let mut buf = [0xaau8; PAD + 4096 + PAD];
        for len in [0, 1, 7, 16, 31, 255, 256, 257, 1000, 4096] {
            buf.fill(0xaa);
            fill(&mut buf[PAD..PAD + len]).expect("fill");
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

    /// Two equal draws would mean the kernel is not being asked.
    #[test]
    fn successive_calls_differ() {
        if !HAVE_SYSTEM {
            return;
        }
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        fill(&mut first).expect("fill");
        fill(&mut second).expect("fill");
        assert_ne!(first, second);
    }

    /// Catches output that is technically written but obviously not
    /// random: all zeros, all ones, a byte counter, text. The band is
    /// about nine standard deviations wide, so a true generator will
    /// not fall outside it in the life of this library.
    #[test]
    fn bits_are_not_wildly_skewed() {
        if !HAVE_SYSTEM {
            return;
        }
        let mut buf = [0u8; 4096];
        fill(&mut buf).expect("fill");
        let set: u32 = buf.iter().map(|b| b.count_ones()).sum();
        assert!((15600..17200).contains(&set), "{set} bits set of 32768");
    }

    /// The trait has to be usable with a source of one's own, since
    /// that is the only reason it exists.
    #[test]
    fn a_fixed_source_can_stand_in() {
        struct Tape(u8);
        impl Random for Tape {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
                for byte in out.iter_mut() {
                    *byte = self.0;
                    self.0 = self.0.wrapping_add(1);
                }
                Ok(())
            }
        }
        fn draw(source: &mut impl Random) -> [u8; 4] {
            let mut out = [0u8; 4];
            source.fill(&mut out).expect("tape");
            out
        }
        assert_eq!(draw(&mut Tape(7)), [7, 8, 9, 10]);
    }
}
