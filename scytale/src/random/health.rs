//! Watching a raw entropy source for signs it has stopped working.
//!
//! A processor's generator reports a failure it has noticed, and
//! those reports are believed. What it cannot report is the failure
//! where it goes on answering confidently with bytes that are not
//! random: parts have been shipped that return all ones from `rdrand`
//! after a resume, with the carry flag set to say the answer is good.
//! Nothing in the instruction's own signalling catches that, so the
//! bytes themselves are examined here.
//!
//! The two tests are the ones SP 800-90B requires of an entropy
//! source, kept in the state of whoever owns the source:
//!
//! - **Repetition count** catches a source that has stuck fast, in
//!   the first handful of samples after it happens.
//! - **Adaptive proportion** catches one that still varies but has
//!   collapsed towards a favourite value, which no flag reports and
//!   which the repetition count would let through.
//!
//! Neither can prove a source is good. They catch the failures that
//! have actually been seen in the field, quickly, and cost a
//! comparison per sample.
//!
//! # Why sixteen bit samples
//!
//! The architectures disagree about how much they hand over at once:
//! sixty-four bits from `rdseed` and `rndr`, sixteen from the RISC-V
//! `seed` register. Sixteen is what they have in common, so a word is
//! treated as four samples and one set of cutoffs serves all of them.

use crate::Error;

/// Min-entropy credited to each sixteen bit sample, in bits.
///
/// Half of what the sample could hold. The vendors claim their raw
/// sources do better, and this does not take their word for it: the
/// cutoffs below are derived from this figure, and crediting a source
/// with less than it deserves makes the tests stricter rather than
/// weaker. The surplus is conditioned away by the derivation function
/// in the generator, so the caution costs samples and nothing else.
const CREDITED: u32 = 8;

/// Identical samples in a row that mean the source has stuck.
///
/// SP 800-90B gives `1 + ceil(-log2(alpha) / H)` for a false alarm
/// rate `alpha` of 2^-40 and `H` bits of min-entropy per sample:
/// `1 + ceil(40 / 8)` is six. A working source reaches six in a row
/// about once in 2^80 samples, which is never.
const REPETITION: u32 = 1 + 40_u32.div_ceil(CREDITED);

/// Samples in one adaptive proportion window.
///
/// The figure SP 800-90B gives for a source with more than one bit
/// per sample.
const WINDOW: u32 = 512;

/// Times one value may appear in a window before the source is called
/// broken.
///
/// The count of a value that turns up with probability 2^-8 in 512
/// draws follows a binomial distribution with a mean of two. Nineteen
/// is the smallest cutoff whose tail is under the same 2^-40 false
/// alarm rate; `the_cutoff_matches_its_derivation` below recomputes
/// it rather than trusting this comment.
const PROPORTION: u32 = 19;

// The repetition cutoff has to be the smallest one whose false alarm
// rate is within the budget: a run of C identical samples happens with
// probability 2^(-H(C-1)), which must be no more than 2^-40. Checked
// here rather than in a test, so that changing the credited entropy
// cannot leave a stale cutoff behind in a build nobody tested.
const _: () = assert!(CREDITED * (REPETITION - 1) >= 40);
const _: () = assert!(CREDITED * (REPETITION - 2) < 40);

/// Samples examined at startup before a source is used at all.
///
/// SP 800-90B asks for a thousand or so consecutive samples before
/// any output is relied on. This is the whole reason a source is a
/// thing a caller holds rather than a function it calls: paid once,
/// it is nothing; paid per call, it is unaffordable.
pub(crate) const STARTUP: usize = 1024;

/// The number a system uses for a device that is not working.
const BROKEN: i32 = 5;

/// Refuses a source that has failed a test.
fn broken() -> Error {
    Error::EntropyUnavailable(BROKEN)
}

/// The running state of both tests over one source's samples.
#[derive(Clone, Debug)]
pub(crate) struct Health {
    /// The last sample seen, and how many times running it has come
    /// up. A run of zero means nothing has been seen yet.
    last: u16,
    run: u32,
    /// The value this window is counting, how often it has appeared,
    /// and how far through the window we are.
    reference: u16,
    count: u32,
    seen: u32,
}

impl Health {
    /// A source that has not been looked at yet.
    pub(crate) fn new() -> Self {
        Health {
            last: 0,
            run: 0,
            reference: 0,
            count: 0,
            // A full window, so the first sample starts a fresh one.
            seen: WINDOW,
        }
    }

    /// Examines one word as four samples, having first refused the
    /// two words that mean the source has died with its output line
    /// stuck high or low.
    ///
    /// Those two are worth naming separately because they are the
    /// observed hardware failure, and because a working source offers
    /// either of them about once in 2^63 words.
    pub(crate) fn word(&mut self, word: u64) -> Result<(), Error> {
        if word == 0 || word == u64::MAX {
            return Err(broken());
        }
        for half in 0..4 {
            self.sample((word >> (16 * half)) as u16)?;
        }
        Ok(())
    }

    /// Examines one sample.
    fn sample(&mut self, sample: u16) -> Result<(), Error> {
        if self.run != 0 && sample == self.last {
            self.run += 1;
            if self.run >= REPETITION {
                return Err(broken());
            }
        } else {
            self.last = sample;
            self.run = 1;
        }

        if self.seen == WINDOW {
            // This sample is the value the new window counts.
            self.reference = sample;
            self.count = 1;
            self.seen = 1;
        } else {
            if sample == self.reference {
                self.count += 1;
            }
            self.seen += 1;
            // Judged only once the window is complete, which is what
            // makes the cutoff mean what it says.
            if self.seen == WINDOW && self.count >= PROPORTION {
                return Err(broken());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds a stream of samples, reporting where it was refused.
    fn feed(samples: impl IntoIterator<Item = u16>) -> Result<(), usize> {
        let mut health = Health::new();
        for (at, sample) in samples.into_iter().enumerate() {
            health.sample(sample).map_err(|_| at)?;
        }
        Ok(())
    }

    /// A counter is a poor generator but an unimpeachable one by
    /// these two measures: nothing ever repeats and nothing is
    /// favoured. Neither test may fire on it, or every real source
    /// would be refused too.
    #[test]
    fn a_stream_that_never_repeats_passes() {
        assert_eq!(feed((0..40_000).map(|n| n as u16)), Ok(()));
    }

    /// The failure this exists for: the source sticks, and says
    /// nothing about it. It must be caught within a handful of
    /// samples rather than eventually.
    #[test]
    fn a_stuck_source_is_caught_at_the_cutoff() {
        assert_eq!(feed([7u16; 100]), Err(REPETITION as usize - 1));
        assert_eq!(feed([0u16; 100]), Err(REPETITION as usize - 1));
    }

    /// Just short of the cutoff is not a failure. A run of five
    /// happens by chance, and refusing it would refuse working
    /// hardware.
    #[test]
    fn a_short_run_is_not_a_failure() {
        let short = (0..1000).map(|n| (n / (REPETITION - 1)) as u16);
        assert_eq!(feed(short), Ok(()));
    }

    /// A source that still varies, so the repetition count never
    /// fires, but which returns to one value far too often. This is
    /// the degradation no flag reports.
    #[test]
    fn a_favoured_value_is_caught_at_the_window_end() {
        // Alternates a fixed value with a changing one, so the fixed
        // one takes half the window and no two samples in a row
        // match.
        let biased = (0..WINDOW).map(|n| if n % 2 == 0 { 0 } else { n as u16 });
        assert_eq!(feed(biased), Err(WINDOW as usize - 1));
    }

    /// A value appearing a few times in a window is ordinary: with a
    /// mean of two, refusing that would refuse everything.
    #[test]
    fn a_value_recurring_a_few_times_is_not_a_failure() {
        // The reference value returns four times in the window,
        // spread out, and the rest are distinct.
        let occasional =
            (0..WINDOW).map(|n| if n % 128 == 0 { 0 } else { n as u16 });
        assert_eq!(feed(occasional), Ok(()));
    }

    /// The stuck output line, which is the shipped hardware bug.
    #[test]
    fn all_ones_and_all_zeros_words_are_refused() {
        let mut health = Health::new();
        assert!(health.word(0).is_err());
        assert!(health.word(u64::MAX).is_err());
    }

    /// An ordinary word must pass, and must be counted as four
    /// samples rather than one, or the window would run four times
    /// too slowly.
    #[test]
    fn an_ordinary_word_passes_as_four_samples() {
        let mut health = Health::new();
        assert!(health.word(0x0123_4567_89ab_cdef).is_ok());
        assert_eq!(health.seen, 4);
    }

    /// Four equal halves inside one word are still four samples in a
    /// row, and must be counted as such.
    #[test]
    fn a_word_of_one_repeated_sample_counts_towards_the_run() {
        let mut health = Health::new();
        assert!(health.word(0x0007_0007_0007_0007).is_ok());
        assert_eq!(health.run, 4);
        // Two more halves take the run to six.
        assert!(health.word(0x1234_5678_0007_0007).is_err());
    }

    /// The cutoff is a number with a derivation, not a number
    /// somebody liked. This recomputes the binomial tail it comes
    /// from, so a change to the credited entropy cannot silently
    /// leave a stale cutoff behind.
    #[test]
    fn the_cutoff_matches_its_derivation() {
        // Probability of any one value, given the entropy credited.
        let p = 1.0 / f64::from(1u32 << CREDITED);
        let n = f64::from(WINDOW);
        // P(X = k) for the binomial, built up term by term, and the
        // upper tail P(X >= k) alongside it.
        let mut term = (1.0 - p).powf(n);
        let mut tail = 1.0;
        let mut cutoff = 0;
        for k in 0..WINDOW {
            if tail <= f64::exp2(-40.0) {
                cutoff = k;
                break;
            }
            tail -= term;
            term *= (n - f64::from(k)) / f64::from(k + 1) * (p / (1.0 - p));
        }
        assert_eq!(cutoff, PROPORTION, "cutoff for {CREDITED} bits");
    }
}
