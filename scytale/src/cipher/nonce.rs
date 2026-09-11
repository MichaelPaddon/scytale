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
//!
//! # Choosing the split
//!
//! The counter takes whatever the fixed part leaves, so supplying the
//! fixed part chooses the split. Both halves are worth something and
//! they trade against each other: a wide fixed part names more
//! devices, a wide counter sends more messages from each. A nonce is
//! only as unique as the fixed part is distinct, so a prefix that two
//! devices might both pick is no prefix at all.
//!
//! Sixty-four bits of prefix over ninety-six leaves a thirty-two bit
//! counter, which is four thousand million nonces from one sequence,
//! and about where GCM wants a fresh key anyway. MACsec goes the
//! other way: a thirty-two bit channel identifier and a sixty-four
//! bit packet number, which is what [`Xpn`](crate::aead::Xpn) calls a
//! frame identifier.
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
//! - [`try_random`](Nonces::try_random) sidesteps the problem by
//!   drawing a new prefix each time, which is right for a program
//!   that cannot store anything. It trades certainty for a collision
//!   chance that depends on how wide the prefix is: one in 2^64
//!   between runs, for the split in the example below.
//! - If none of that can be guaranteed, use GCM-SIV, which survives a
//!   repeat rather than collapsing.
//!
//! # Example
//!
//! ```
//! use scytale::Key;
//! use scytale::random::CtrDrbg;
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::Nonces;
//! use scytale::aead::{Aead, Gcm};
//! use scytale::cipher::BlockCipher;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let gcm = Gcm::<Aes128>::new(&Key::from([0u8; 16]));
//! let mut rng = CtrDrbg::from_system()?;
//!
//! // A ninety-six bit nonce counting in its last four bytes.
//! let mut nonces = Nonces::<[u8; 12]>::try_random(&mut rng, 4)?;
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

use crate::Error;
use crate::Random;
use crate::traits::ByteArray;

/// The widest counter field there is, in bytes, since the counter is
/// a `u64`. Eight bytes is 2^64 messages under one key, which no key
/// lives long enough to need.
const COUNTER: usize = 8;

/// A sequence of nonces that cannot repeat.
///
/// `B` is the nonce, so its width is a type: `Nonces<[u8; 12]>` is
/// the ninety-six bit nonce [`Gcm`](crate::aead::Gcm),
/// [`GcmSiv`](crate::aead::GcmSiv) and
/// [`ChaCha20`](super::chacha20) all take. Read the warnings above
/// before using one across restarts.
#[derive(Clone, Debug)]
pub struct Nonces<B: ByteArray> {
    /// The nonce with its counter field zeroed.
    fixed: B,
    /// Where the counter field starts, which is the length of the
    /// fixed part.
    at: usize,
    /// The number the next nonce carries, or nothing once every
    /// number the field holds has been handed out.
    next: Option<u64>,
}

impl<B: ByteArray> Nonces<B> {
    /// A sequence under a fixed part of your own, starting at
    /// `first`.
    ///
    /// The counter takes the bytes `fixed` leaves, which must be one
    /// to eight of them; anything else is
    /// [`Error::InvalidNonceLength`]. A `first` the counter field
    /// cannot hold is [`Error::SequenceExhausted`], since a sequence
    /// starting past the end of its field has nothing to give.
    ///
    /// Use this where the fixed part identifies the device, as the
    /// standard intends, or to carry on from a counter that was
    /// stored.
    pub fn try_new(fixed: &[u8], first: u64) -> Result<Self, Error> {
        let mut nonce = B::zeroed();
        let at = fixed.len();
        // Saturating, so a fixed part longer than the nonce fails the
        // range test rather than the subtraction.
        let width = nonce.as_ref().len().saturating_sub(at);
        if !(1..=COUNTER).contains(&width) {
            return Err(Error::InvalidNonceLength(at));
        }
        nonce.as_mut()[..at].copy_from_slice(fixed);

        let nonces = Nonces {
            fixed: nonce,
            at,
            next: Some(first),
        };
        if first > nonces.last() {
            return Err(Error::SequenceExhausted);
        }
        Ok(nonces)
    }

    /// A sequence under a fixed part drawn from `source`, counting
    /// from zero in the last `counter` bytes.
    ///
    /// For programs that cannot store a counter between runs. Each
    /// run gets a fixed part of its own, so the sequences do not
    /// overlap unless two runs draw the same bytes.
    pub fn try_random(
        source: &mut impl Random,
        counter: usize,
    ) -> Result<Self, Error> {
        let mut fixed = B::zeroed();
        if !(1..=COUNTER).contains(&counter) {
            return Err(Error::InvalidNonceLength(counter));
        }
        let at = fixed
            .as_ref()
            .len()
            .checked_sub(counter)
            .ok_or(Error::InvalidNonceLength(counter))?;
        source.fill(&mut fixed.as_mut()[..at])?;
        Self::try_new(&fixed.as_ref()[..at], 0)
    }

    /// The next nonce.
    ///
    /// Returns [`Error::SequenceExhausted`] once every number the
    /// counter field holds has been issued. It never starts over:
    /// that would repeat a nonce, which is the one thing this exists
    /// to stop.
    pub fn take(&mut self) -> Result<B, Error> {
        let count = self.next.ok_or(Error::SequenceExhausted)?;
        let mut nonce = self.fixed;
        let bytes = count.to_be_bytes();
        let field = &mut nonce.as_mut()[self.at..];
        // The low bytes of the count, most significant first, which
        // is the order both SP 800-38D and MACsec number in.
        field.copy_from_slice(&bytes[COUNTER - field.len()..]);

        self.next = (count < self.last()).then(|| count + 1);
        Ok(nonce)
    }

    /// The number the next nonce will carry, or nothing if the
    /// sequence is spent and the key must be changed.
    ///
    /// This is the value to store if the counter has to outlive the
    /// program. Store it before the nonce is used, not after: a crash
    /// in between must lose a nonce rather than repeat one.
    pub fn count(&self) -> Option<u64> {
        self.next
    }

    /// The largest number the counter field holds.
    fn last(&self) -> u64 {
        match self.fixed.as_ref().len() - self.at {
            COUNTER => u64::MAX,
            width => (1u64 << (8 * width)) - 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::random::{CtrDrbg, MIN_SEED};

    /// The layout the standard describes: the fixed part unchanged in
    /// every nonce, the counter advancing by one, most significant
    /// byte first.
    #[test]
    fn counts_up_without_repeating() {
        let prefix = 0x0102_0304_0506_0708u64.to_be_bytes();
        let mut nonces =
            Nonces::<[u8; 12]>::try_new(&prefix, 0).expect("sequence");
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

    /// The counter takes whatever the fixed part leaves, so the same
    /// width of nonce counts in different places.
    #[test]
    fn the_fixed_part_chooses_the_split() {
        let mut narrow =
            Nonces::<[u8; 12]>::try_new(&[0xaa; 8], 7).expect("sequence");
        assert_eq!(
            narrow.take().expect("nonce"),
            [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0, 0, 0, 7]
        );

        let mut wide =
            Nonces::<[u8; 12]>::try_new(&[0xaa; 4], 7).expect("sequence");
        assert_eq!(
            wide.take().expect("nonce"),
            [0xaa, 0xaa, 0xaa, 0xaa, 0, 0, 0, 0, 0, 0, 0, 7]
        );
    }

    /// The whole of a narrow field is walked, which the wider ones
    /// are too large to check.
    #[test]
    fn a_one_byte_field_holds_exactly_its_range() {
        let mut nonces =
            Nonces::<[u8; 12]>::try_new(&[1; 11], 0).expect("sequence");
        for want in 0..=u8::MAX {
            assert_eq!(nonces.take().expect("nonce")[11], want);
        }
        assert_eq!(nonces.count(), None);
        assert_eq!(nonces.take().unwrap_err(), Error::SequenceExhausted);
    }

    /// The nonce's width is the caller's, not this module's.
    #[test]
    fn any_width_of_nonce_counts() {
        let mut short =
            Nonces::<[u8; 8]>::try_new(&[9; 4], 1).expect("sequence");
        assert_eq!(short.take().expect("nonce"), [9, 9, 9, 9, 0, 0, 0, 1]);

        let mut long =
            Nonces::<[u8; 16]>::try_new(&[9; 12], 1).expect("sequence");
        assert_eq!(
            long.take().expect("nonce"),
            [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0, 0, 0, 1]
        );
    }

    /// A split that leaves no counter, or one too wide to count in a
    /// `u64`, is refused rather than quietly adjusted.
    #[test]
    fn an_impossible_split_is_refused() {
        for fixed in [12, 13] {
            assert_eq!(
                Nonces::<[u8; 12]>::try_new(&[0; 13][..fixed], 0).unwrap_err(),
                Error::InvalidNonceLength(fixed),
                "fixed part of {fixed}"
            );
        }
        // Four bytes of sixteen leaves a twelve byte counter.
        assert_eq!(
            Nonces::<[u8; 16]>::try_new(&[0; 4], 0).unwrap_err(),
            Error::InvalidNonceLength(4)
        );
        for counter in [0, 9] {
            let seed = [0x5au8; MIN_SEED];
            let mut rng = CtrDrbg::from_seed(&seed).expect("seed");
            assert_eq!(
                Nonces::<[u8; 12]>::try_random(&mut rng, counter).unwrap_err(),
                Error::InvalidNonceLength(counter),
                "counter of {counter}"
            );
        }
    }

    /// The last number is still handed out, and a start beyond the
    /// field is refused outright.
    #[test]
    fn refuses_to_start_over_or_past_the_end() {
        let mut nonces = Nonces::<[u8; 12]>::try_new(&[9; 8], u32::MAX.into())
            .expect("sequence");
        assert_eq!(nonces.take().expect("last")[8..], u32::MAX.to_be_bytes());
        assert_eq!(nonces.count(), None);
        // Exhaustion sticks; it does not clear itself.
        for _ in 0..3 {
            assert_eq!(nonces.take().unwrap_err(), Error::SequenceExhausted);
        }

        let past = u64::from(u32::MAX) + 1;
        assert_eq!(
            Nonces::<[u8; 12]>::try_new(&[9; 8], past).unwrap_err(),
            Error::SequenceExhausted
        );
        // The widest field has no number it cannot hold.
        assert!(Nonces::<[u8; 12]>::try_new(&[9; 4], u64::MAX).is_ok());
    }

    /// A stored count must carry on rather than repeat, which is the
    /// whole point of being able to read it.
    #[test]
    fn resumes_where_it_stopped() {
        let mut nonces =
            Nonces::<[u8; 12]>::try_new(&[4; 8], 0).expect("sequence");
        for _ in 0..3 {
            nonces.take().expect("nonce");
        }
        let stored = nonces.count().expect("not spent");
        assert_eq!(stored, 3);

        let mut resumed =
            Nonces::<[u8; 12]>::try_new(&[4; 8], stored).expect("sequence");
        assert_eq!(resumed.take().expect("nonce"), nonces.take().unwrap());
    }

    /// Two sequences that cannot store anything must still not
    /// overlap, which rests entirely on the fixed part differing.
    /// Every byte of it comes from the source, and the counter field
    /// starts at zero.
    #[test]
    fn separate_runs_get_separate_prefixes() {
        let mut rng = CtrDrbg::from_seed(&[0x5au8; MIN_SEED]).expect("seed");
        let mut one = Nonces::<[u8; 12]>::try_random(&mut rng, 4).expect("one");
        let mut two = Nonces::<[u8; 12]>::try_random(&mut rng, 4).expect("two");
        let one = one.take().expect("nonce");
        let two = two.take().expect("nonce");
        assert_ne!(one[..8], two[..8]);
        assert_eq!(one[8..], [0; 4], "counter did not start at zero");
        assert_ne!(one[..8], [0; 8], "prefix was not drawn");
    }

    /// MACsec's frame identifier is this construction at a different
    /// split, so the bytes must match the ones
    /// [`Xpn`](crate::aead::Xpn) documents assembling by
    /// hand.
    #[test]
    fn builds_an_xpn_frame_identifier() {
        let channel = 1u32.to_be_bytes();
        let mut by_hand = [0u8; 12];
        by_hand[..4].copy_from_slice(&channel);
        by_hand[4..].copy_from_slice(&7u64.to_be_bytes());

        let mut frames =
            Nonces::<[u8; 12]>::try_new(&channel, 7).expect("sequence");
        assert_eq!(frames.take().expect("frame"), by_hand);
    }
}
