//! Nonces that cannot repeat (NIST SP 800-38D, section 8.2.1).
//!
//! GCM and GCM-SIV need a nonce that has never been used before under
//! the same key. Drawing one at random gets that wrong eventually:
//! ninety-six bits sound like plenty, but two random nonces collide
//! with even chances after about 2^48 messages, and the standard caps
//! a random nonce at 2^32 messages for that reason.
//!
//! Counting instead makes repetition impossible rather than unlikely.
//! The standard's construction splits the nonce into a fixed part
//! naming the device and a counter that advances once per message.
//! Here that is sixty-four bits of prefix and thirty-two of counter,
//! so one sequence yields four thousand million nonces, which is also
//! about where GCM wants a fresh key anyway.
//!
//! # Using it safely
//!
//! - **The counter must never go backwards.** That is the whole
//!   guarantee, and it is the caller's to keep. Starting again from
//!   zero under a key that has already used those numbers repeats
//!   every nonce.
//! - Three ways to be safe, in order of preference: use a fresh key
//!   each run, so counting from zero is always right; or give every
//!   device a prefix of its own and never share a key between them;
//!   or write [`count`](Nonces::count) down before you use it, not
//!   after.
//! - **Restoring a virtual machine snapshot brings the counter back
//!   with it.** A restored machine must take a new key, since it is
//!   about to reissue nonces the original already sent.
//! - [`random`](Nonces::random) sidesteps the problem by drawing a
//!   new prefix each time, which is right for a program that cannot
//!   store anything. It trades certainty for a collision chance of
//!   about one in 2^64 between runs.
//! - If none of that can be guaranteed, use GCM-SIV, which survives a
//!   repeat rather than collapsing.
//!
//! # Example
//!
//! ```
//! use scytale::random::{Rng, System};
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::{Gcm, Nonces};
//! use scytale::symmetric::BlockCipher;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let gcm = Gcm::try_new(Aes::try_new(&[0u8; 16])?)?;
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let mut nonces = Nonces::random(&mut rng)?;
//!
//! let mut message = *b"hello";
//! let mut tag = [0u8; 16];
//! let nonce = nonces.take()?;
//! gcm.encrypt(&nonce, b"", &mut message, &mut tag)?;
//!
//! gcm.decrypt(&nonce, b"", &mut message, &tag)?;
//! assert_eq!(&message, b"hello");
//! # Ok(())
//! # }
//! ```

use crate::random::Random;
use crate::Error;

/// The nonce length this builds, in bytes.
const NONCE: usize = 12;

/// A sequence of ninety-six bit nonces that cannot repeat.
///
/// Suitable for [`Gcm`](super::Gcm) and [`GcmSiv`](super::GcmSiv).
/// Read the warnings above before using it across restarts.
#[derive(Clone, Debug)]
pub struct Nonces {
    /// Names this sequence, and separates it from every other one.
    prefix: u64,
    /// The number the next nonce carries, or nothing once every
    /// number has been handed out.
    next: Option<u32>,
}

impl Nonces {
    /// A sequence under a prefix drawn from `source`, counting from
    /// zero.
    ///
    /// For programs that cannot store a counter between runs. Each
    /// run gets a prefix of its own, so the sequences do not overlap
    /// unless two runs draw the same sixty-four bits.
    pub fn random(source: &mut impl Random) -> Result<Self, Error> {
        let mut prefix = [0u8; 8];
        source.fill(&mut prefix)?;
        Ok(Nonces::new(u64::from_be_bytes(prefix), 0))
    }

    /// A sequence under a prefix of your own, starting at `first`.
    ///
    /// Use this where the prefix identifies the device, as the
    /// standard intends, or to carry on from a counter that was
    /// stored.
    pub fn new(prefix: u64, first: u32) -> Self {
        Nonces {
            prefix,
            next: Some(first),
        }
    }

    /// The next nonce.
    ///
    /// Returns [`Error::SequenceExhausted`] once every number under
    /// this prefix has been issued. It never starts over: that would
    /// repeat a nonce, which is the one thing this exists to stop.
    pub fn take(&mut self) -> Result<[u8; NONCE], Error> {
        let count = self.next.ok_or(Error::SequenceExhausted)?;
        let mut nonce = [0u8; NONCE];
        nonce[..8].copy_from_slice(&self.prefix.to_be_bytes());
        nonce[8..].copy_from_slice(&count.to_be_bytes());
        self.next = count.checked_add(1);
        Ok(nonce)
    }

    /// The number the next nonce will carry, or nothing if the
    /// sequence is spent and the key must be changed.
    ///
    /// This is the value to store if the counter has to outlive the
    /// program. Store it before the nonce is used, not after: a crash
    /// in between must lose a nonce rather than repeat one.
    pub fn count(&self) -> Option<u32> {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::random::{Rng, MIN_SEED};

    /// The layout the standard describes: the prefix unchanged in
    /// every nonce, the counter advancing by one, most significant
    /// byte first.
    #[test]
    fn counts_up_without_repeating() {
        let mut nonces = Nonces::new(0x0102_0304_0506_0708, 0);
        let first = nonces.take().expect("first");
        assert_eq!(first, [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0]);
        let second = nonces.take().expect("second");
        assert_eq!(second, [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 1]);

        let mut seen = first;
        for want in 2..1000u32 {
            let nonce = nonces.take().expect("nonce");
            assert_ne!(nonce, seen, "repeated a nonce");
            assert_eq!(nonce[..8], first[..8], "prefix moved");
            assert_eq!(nonce[8..], want.to_be_bytes(), "wrong count");
            seen = nonce;
        }
    }

    /// The last nonce is still handed out, and everything after it is
    /// refused. Starting `first` at the end is what makes this
    /// reachable without counting to four thousand million.
    #[test]
    fn refuses_to_start_over() {
        let mut nonces = Nonces::new(9, u32::MAX);
        assert_eq!(nonces.take().expect("last")[8..], u32::MAX.to_be_bytes());
        assert_eq!(nonces.count(), None);
        // Exhaustion sticks; it does not clear itself.
        for _ in 0..3 {
            assert_eq!(nonces.take().unwrap_err(), Error::SequenceExhausted);
        }
    }

    /// A stored count must carry on rather than repeat, which is the
    /// whole point of being able to read it.
    #[test]
    fn resumes_where_it_stopped() {
        let mut nonces = Nonces::new(4, 0);
        for _ in 0..3 {
            nonces.take().expect("nonce");
        }
        let stored = nonces.count().expect("not spent");
        assert_eq!(stored, 3);

        let mut resumed = Nonces::new(4, stored);
        assert_eq!(resumed.take().expect("nonce"), nonces.take().unwrap());
    }

    /// Two sequences that cannot store anything must still not
    /// overlap, which rests entirely on the prefix differing.
    #[test]
    fn separate_runs_get_separate_prefixes() {
        let mut rng = Rng::from_seed(&[0x5au8; MIN_SEED]).expect("seed");
        let one = Nonces::random(&mut rng).expect("random");
        let two = Nonces::random(&mut rng).expect("random");
        assert_ne!(one.prefix, two.prefix);
    }
}
