//! Asking the processor what it can do, once.
//!
//! Every implementation in the crate is chosen at run time from what
//! the processor reports, and asking is not cheap: `cpuid` serialises
//! the pipeline, and the RISC-V answer is a system call. Neither can
//! change while the program runs, so the answer is asked for once and
//! kept.
//!
//! Two shapes cover everything here: whether the processor has some
//! one thing, and which of a list of implementations it has. Both are
//! one relaxed atomic load once the first caller has been and gone.
//!
//! # Why a race is harmless
//!
//! Nothing locks. Two threads arriving together may both ask the
//! processor and both store the answer, but the question has one true
//! answer, so they store the same thing. That is worth more than the
//! lock it saves: it means a probe can be reached from anywhere,
//! including code with no allocator and no threads at all.

use core::sync::atomic::{AtomicU8, Ordering};

/// An answer about the processor, asked once and kept.
///
/// Zero means not yet asked, so a probe starts out as [`Probe::new`]
/// and needs no initialiser to run.
pub(crate) struct Probe(AtomicU8);

/// The largest list [`Probe::first`] can choose from. A `u8` holds
/// the answer, one value going to "asked, and none of them".
const LIMIT: usize = 254;

impl Probe {
    /// A probe that has not asked yet.
    pub(crate) const fn new() -> Self {
        Probe(AtomicU8::new(0))
    }

    /// Whether the processor has it, asking `ask` the first time.
    pub(crate) fn yes(&self, ask: impl Fn() -> bool) -> bool {
        match self.0.load(Ordering::Relaxed) {
            0 => {
                let yes = ask();
                self.0.store(1 + u8::from(yes), Ordering::Relaxed);
                yes
            }
            n => n == 2,
        }
    }

    /// The first of `choices` the processor has, asking `ask` about
    /// each in turn the first time.
    ///
    /// `choices` must be the same list on every call, since what is
    /// kept is a position in it. In practice it is a `const` in the
    /// module that owns the probe.
    pub(crate) fn first<T: Copy>(
        &self,
        choices: &[T],
        ask: impl Fn(T) -> bool,
    ) -> Option<T> {
        debug_assert!(choices.len() <= LIMIT);
        match self.0.load(Ordering::Relaxed) {
            0 => {
                let at = choices.iter().position(|&c| ask(c));
                // Two plus the position, so that one can mean the
                // processor has none of them and zero can go on
                // meaning the question has not been put yet.
                let kept = match at {
                    Some(at) if at < LIMIT => 2 + at as u8,
                    Some(_) => 0,
                    None => 1,
                };
                self.0.store(kept, Ordering::Relaxed);
                at.map(|at| choices[at])
            }
            1 => None,
            n => choices.get(usize::from(n) - 2).copied(),
        }
    }

    /// Whether the question has been put to the processor yet, for a
    /// test that wants to know the answer was kept rather than worked
    /// out afresh.
    #[cfg(test)]
    pub(crate) fn asked(&self) -> bool {
        self.0.load(Ordering::Relaxed) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn a_yes_is_asked_once_and_then_remembered() {
        for answer in [false, true] {
            let asked = Cell::new(0);
            let probe = Probe::new();
            for _ in 0..3 {
                assert_eq!(
                    probe.yes(|| {
                        asked.set(asked.get() + 1);
                        answer
                    }),
                    answer
                );
            }
            assert_eq!(asked.get(), 1, "answer {answer}");
            assert!(probe.asked());
        }
    }

    #[test]
    fn the_first_choice_the_processor_has_is_the_one_kept() {
        const CHOICES: [char; 3] = ['a', 'b', 'c'];
        for (has, want) in [
            (['a', 'b', 'c'].as_slice(), Some('a')),
            (['b', 'c'].as_slice(), Some('b')),
            (['c'].as_slice(), Some('c')),
            ([].as_slice(), None),
        ] {
            let asked = Cell::new(0);
            let probe = Probe::new();
            for _ in 0..3 {
                let got = probe.first(&CHOICES, |c| {
                    asked.set(asked.get() + 1);
                    has.contains(&c)
                });
                assert_eq!(got, want, "has {has:?}");
            }
            // Asked once, and only as far down the list as it had to
            // go to find one.
            let expected = match want {
                Some(c) => CHOICES.iter().position(|&x| x == c).unwrap() + 1,
                None => CHOICES.len(),
            };
            assert_eq!(asked.get(), expected, "has {has:?}");
        }
    }

    /// The last position a `u8` can hold, so that the arithmetic is
    /// exercised somewhere other than the first two entries.
    #[test]
    fn a_long_list_still_answers() {
        let choices: [u8; LIMIT] = core::array::from_fn(|i| i as u8);
        let probe = Probe::new();
        let last = choices[LIMIT - 1];
        for _ in 0..3 {
            assert_eq!(probe.first(&choices, |c| c == last), Some(last));
        }
    }
}
