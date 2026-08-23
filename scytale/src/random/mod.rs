//! Random numbers, from the operating system.
//!
//! # Where the bytes come from
//!
//! Every call asks the kernel, through `getrandom`. There is no
//! generator kept in this process, and that is the point: a generator
//! has state, and state gets duplicated. `fork` gives both processes
//! the same next bytes, and restoring a virtual machine snapshot
//! gives every restored copy the same. Either one repeats a nonce,
//! and a repeated nonce is enough to lose the key.
//!
//! The kernel is seeded from far more than a library can reach, is
//! told when a virtual machine has been cloned, and mixes in the
//! processor's own generator where there is one. Reading it directly
//! is both simpler and safer than anything that could be built here.
//!
//! # Using it safely
//!
//! - **This needs Linux.** Everywhere else every call fails with
//!   [`Error::EntropyUnavailable`]. It never quietly substitutes
//!   something weaker.
//! - Not everything wants randomness. An initialisation vector for
//!   CBC or CFB must be *unpredictable*, which is what this gives.
//!   A counter for CTR, or a nonce for GCM, must be *unique*, which
//!   is a different and stronger requirement, and one a counter
//!   answers with certainty where a draw only answers it with high
//!   probability.
//! - A call made very early in boot waits until the kernel's
//!   generator is ready. That is deliberate. The alternative is
//!   bytes that are not yet unpredictable.
//! - Wiping whatever these bytes become is the caller's job.
//!
//! # Speed
//!
//! Going straight to the kernel means a real system call every time,
//! rather than the faster path the C library uses. That costs
//! hundreds of nanoseconds rather than tens. It does not matter for
//! keys, which are drawn once. It does matter for a nonce per
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

mod system;

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
    fill_from(system::getrandom, out)
}

/// A signal arrived before the kernel had written anything.
const EINTR: isize = -4;

/// Kernels report failure as a small negative number; anything
/// outside this range is not an error code at all.
const FAILURES: core::ops::Range<isize> = -4095..0;

/// Drives `source` until `out` is full.
///
/// Split out from [`fill`] so it can be tested. A request of 256
/// bytes or fewer is never answered in part and never interrupted,
/// so on the sizes anything here actually asks for, the loop below
/// never goes round twice. Handing it a stand-in source is the only
/// way to reach those paths on purpose.
fn fill_from(
    mut source: impl FnMut(&mut [u8]) -> isize,
    out: &mut [u8],
) -> Result<(), Error> {
    let mut done = 0;
    while done < out.len() {
        let got = source(&mut out[done..]);
        if got > 0 {
            // The kernel cannot report more than it was offered.
            done += (got as usize).min(out.len() - done);
        } else if got == EINTR {
            // Nothing was written. Ask again from the same place.
            continue;
        } else if FAILURES.contains(&got) {
            return Err(Error::EntropyUnavailable(-got as i32));
        } else {
            // Zero written with bytes still wanted, or a return no
            // kernel makes. Neither should happen, and treating it
            // as progress would loop here forever.
            return Err(Error::EntropyUnavailable(0));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the supported targets have a call to make; elsewhere
    /// every request is expected to fail.
    const HAVE_SYSTEM: bool = cfg!(all(
        target_os = "linux",
        any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "x86_64"
        )
    ));

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

    /// An empty request must not reach the kernel at all: a call
    /// asking for nothing returns nothing, which the loop would
    /// otherwise read as failure to make progress.
    #[test]
    fn an_empty_request_asks_for_nothing() {
        let mut asked = 0;
        fill_from(
            |_| {
                asked += 1;
                0
            },
            &mut [],
        )
        .expect("empty");
        assert_eq!(asked, 0);
    }

    /// A kernel answering a byte at a time must still fill the
    /// buffer, and must not write the same byte repeatedly.
    #[test]
    fn short_answers_still_fill_the_buffer() {
        let mut out = [0u8; 64];
        let mut next = 1u8;
        fill_from(
            |chunk| {
                chunk[0] = next;
                next = next.wrapping_add(1);
                1
            },
            &mut out,
        )
        .expect("short");
        let want: [u8; 64] = core::array::from_fn(|i| i as u8 + 1);
        assert_eq!(out, want);
    }

    /// An interrupted call wrote nothing, so the next one must start
    /// from the same place rather than skipping it.
    #[test]
    fn an_interrupted_call_is_retried() {
        let mut left = 2;
        let mut out = [0u8; 8];
        fill_from(
            |chunk| {
                if left > 0 {
                    left -= 1;
                    return EINTR;
                }
                chunk.fill(0xff);
                chunk.len() as isize
            },
            &mut out,
        )
        .expect("interrupted");
        assert_eq!(left, 0, "the failures were not all seen");
        assert_eq!(out, [0xff; 8]);
    }

    /// A kernel error is reported with its number, not swallowed.
    #[test]
    fn a_refusal_is_reported() {
        let mut out = [0u8; 8];
        assert_eq!(
            fill_from(|_| -38, &mut out).unwrap_err(),
            Error::EntropyUnavailable(38)
        );
    }

    /// The one return that could hang: no progress, no error. It has
    /// to end the loop rather than go round again.
    #[test]
    fn no_progress_is_an_error_rather_than_a_hang() {
        let mut out = [0u8; 8];
        assert_eq!(
            fill_from(|_| 0, &mut out).unwrap_err(),
            Error::EntropyUnavailable(0)
        );
        // Likewise a return no kernel would make.
        assert_eq!(
            fill_from(|_| isize::MIN, &mut out).unwrap_err(),
            Error::EntropyUnavailable(0)
        );
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
