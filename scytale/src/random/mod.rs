//! Random numbers, from a generator you hold.
//!
//! # What this is
//!
//! An [`Rng`] is seeded once from a source of entropy and then
//! produces random bytes from that seeding, in the shape SP 800-90A
//! calls CTR_DRBG: AES-256 driven by a counter, its key and counter
//! replaced after every request so that nothing already handed out
//! can be worked backwards from what comes next.
//!
//! ```
//! use scytale::random::{Random, Rng, System};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//!
//! let mut key = [0u8; 32];
//! rng.fill(&mut key)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Why you hold it, and what that costs you
//!
//! This used to be a function with no state at all, which asked the
//! operating system afresh every call. That refused a real problem by
//! having nothing to duplicate: `fork` gives both processes the same
//! next bytes, and restoring a virtual machine snapshot gives every
//! restored copy the same. Either repeats a nonce, and a repeated
//! nonce is enough to lose the key.
//!
//! It also had nowhere to put the things a generator needs. A raw
//! entropy source has to be watched for failure, and the tests that
//! do the watching span more samples than any single call draws. Raw
//! entropy has to be conditioned before use, and a function with no
//! state has nothing to condition it with. So the state exists now,
//! and it belongs to you:
//!
//! - **After `fork`, the child must not keep using the parent's
//!   generator.** Drop it and build another, or call
//!   [`reseed`](Rng::reseed).
//! - **After a virtual machine is restored from a snapshot, the same
//!   applies.** Nothing here can see that it happened.
//! - **The state is wiped when the object is dropped**, so the window
//!   is as short as you make it.
//!
//! Whoever forked is the one who knows they forked. Nothing in this
//! module can find that out without asking the kernel on every call,
//! which is most of the reason to hold a generator in the first
//! place.
//!
//! # Where the seed comes from
//!
//! | Source | What it asks |
//! | --- | --- |
//! | [`System`] | the operating system, or the processor if there is none |
//! | [`Processor`] | the processor's own generator, health tested |
//! | [`External`] | nothing; you supply the entropy yourself |
//!
//! A board with a generator of its own on a bus, or a ring
//! oscillator, or a chip on I2C, implements [`Entropy`] over it and
//! is served exactly as well as a machine with an instruction for it.
//! That is the ordinary way such a board works, not a fallback.
//!
//! Where there is no operating system and the processor has no
//! instruction either, construction fails with
//! [`Error::NotSupported`] and the program does not start. Nothing
//! weaker is quietly substituted: randomness invented from a clock or
//! a process number is worse than none, because it looks as though it
//! worked.
//!
//! # Running out
//!
//! One seeding does not last forever, and both limits refuse rather
//! than quietly carrying on:
//!
//! - A single request may ask for at most [`MAX_REQUEST`] bytes.
//! - After [`RESEED_INTERVAL`] requests the generator must be
//!   reseeded. Where it has a source of its own it does that itself
//!   and you never see it. Where it does not, because you seeded it
//!   yourself, [`fill`](Random::fill) fails with
//!   [`Error::ReseedRequired`] until you supply fresh entropy through
//!   [`reseed_from`](Rng::reseed_from).
//!
//! You may reseed at any time, and doing so mixes the new material
//! into what is already there rather than replacing it, so fresh
//! entropy can never make a generator worse.
//!
//! # Assurance
//!
//! The generator is checked against NIST's ACVP vectors for CTR_DRBG,
//! alongside the rest of the library. The entropy sources are not:
//! there is nothing deterministic in a noise source to check. What is
//! tested there is the health testing, against sample streams with
//! known faults in them.

pub(crate) mod health;
mod source;

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher::aes::{Aes, BLOCK_SIZE};
use crate::Error;

pub use source::{External, Processor, System};

/// AES-256: the key length the generator uses, in bytes.
const KEY: usize = 32;

/// The generator's internal seed, a key and a counter block.
const SEED: usize = KEY + BLOCK_SIZE;

/// The least entropy a generator can be built or reseeded from, in
/// bytes.
///
/// Three hundred and eighty four bits: two hundred and fifty six for
/// the security strength, and a further hundred and twenty eight for
/// the instantiation nonce SP 800-90A requires alongside it.
///
/// Material shorter than this is refused rather than stretched. The
/// derivation function will condition whatever it is given, but it
/// cannot create what is not there. What it also cannot check is
/// whether the bytes you supply are *full* entropy over their whole
/// length, which is required and is your side of the bargain.
pub const MIN_SEED: usize = SEED;

/// How much raw material is drawn from a source for each seeding.
///
/// Twice what is needed, because a noise source is credited with less
/// entropy than it has bits and the surplus costs nothing: the
/// derivation function condenses it. A source that is already full
/// entropy, such as an operating system, is no worse off for being
/// asked twice over.
const OVERSAMPLE: usize = 2;

/// Bytes one request may ask for.
///
/// The 2^19 bits of SP 800-90A. Ask for more and the call is refused;
/// ask twice instead.
pub const MAX_REQUEST: usize = 1 << 16;

/// Requests one seeding covers.
///
/// The 2^48 of SP 800-90A. At a request a nanosecond this is nine
/// years, so it is a bound that exists to be correct rather than one
/// anything reaches.
pub const RESEED_INTERVAL: u64 = 1 << 48;

/// A source of seed material.
///
/// Deliberately not the same trait as [`Random`]. What a noise source
/// hands over is raw: unconditioned, and holding fewer bits of
/// entropy than it has bits. It becomes random bytes by going through
/// a generator, and keeping the two traits apart is what stops raw
/// entropy reaching a caller by mistake.
///
/// Implement this to seed an [`Rng`] from hardware of your own.
pub trait Entropy {
    /// Fills the whole of `out` with raw entropy, or fails without
    /// leaving anything worth relying on.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;
}

/// A source of random bytes fit to use.
///
/// [`Rng`] is the one that matters. The trait exists so that work
/// which consumes randomness can be handed a fixed sequence instead
/// and tested for an exact answer.
pub trait Random {
    /// Fills the whole of `out`, or fails without leaving anything
    /// worth relying on.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;
}

/// A generator, seeded from `S`.
///
/// See the [module documentation](self) for what holding one commits
/// you to across `fork` and virtual machine snapshots.
///
/// Deliberately not `Clone`: two generators with one state hand out
/// the same bytes twice, which is the same failure a `fork` causes and
/// the one thing this type is careful about. Two generators are made
/// by seeding two.
#[derive(ZeroizeOnDrop)]
pub struct Rng<S: Entropy = System> {
    /// Where a reseeding gets its material. [`External`] means there
    /// is nowhere, and the caller must bring it.
    #[zeroize(skip)]
    source: S,
    /// The key and counter block that are the generator's whole
    /// secret.
    key: [u8; KEY],
    v: [u8; BLOCK_SIZE],
    /// Requests made since the last seeding, counted from one as
    /// SP 800-90A counts it.
    #[zeroize(skip)]
    counter: u64,
}

impl<S: Entropy> Rng<S> {
    /// A generator seeded from `source`.
    ///
    /// # Errors
    ///
    /// Whatever the source refuses with. A source with nothing to
    /// give yields no generator rather than one that cannot work.
    pub fn try_new(mut source: S) -> Result<Self, Error> {
        let mut raw = [0u8; MIN_SEED * OVERSAMPLE];
        let drawn = source.fill(&mut raw);
        let built = drawn.and_then(|()| Self::instantiate(&raw, source));
        raw.zeroize();
        built
    }

    /// Reseeds from the generator's own source.
    ///
    /// Called automatically once [`RESEED_INTERVAL`] requests have
    /// been made, so there is rarely a reason to call it. After a
    /// `fork` or a restored snapshot there is: it is the cheaper
    /// alternative to dropping the generator and building another.
    ///
    /// # Errors
    ///
    /// [`Error::ReseedRequired`] where the generator has no source of
    /// its own, and whatever the source refuses with otherwise.
    pub fn reseed(&mut self) -> Result<(), Error> {
        let mut raw = [0u8; MIN_SEED * OVERSAMPLE];
        let drawn = self.source.fill(&mut raw);
        let done = drawn.and_then(|()| self.reseed_from(&raw));
        raw.zeroize();
        done
    }

    /// Mixes `entropy` into the generator and starts the count again.
    ///
    /// The new material is combined with what is already there rather
    /// than replacing it, so this can only improve a generator, never
    /// weaken one.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSeedLength`] if `entropy` is shorter than
    /// [`MIN_SEED`]. The generator is left exactly as it was.
    pub fn reseed_from(&mut self, entropy: &[u8]) -> Result<(), Error> {
        if entropy.len() < MIN_SEED {
            return Err(Error::InvalidSeedLength(entropy.len()));
        }
        let mut seed = [0u8; SEED];
        let derived = derive(entropy, &mut seed);
        let done = derived.and_then(|()| self.update(&seed));
        seed.zeroize();
        if done.is_ok() {
            self.counter = 1;
        }
        done
    }

    /// Builds a generator from material that has already been
    /// gathered.
    fn instantiate(material: &[u8], source: S) -> Result<Self, Error> {
        let mut seed = [0u8; SEED];
        let derived = derive(material, &mut seed);
        let mut rng = Rng {
            source,
            key: [0u8; KEY],
            v: [0u8; BLOCK_SIZE],
            counter: 1,
        };
        let done = derived.and_then(|()| rng.update(&seed));
        seed.zeroize();
        done.map(|()| rng)
    }

    /// The CTR_DRBG update: runs the generator forward far enough to
    /// replace both the key and the counter block, mixing `provided`
    /// in as it goes.
    fn update(&mut self, provided: &[u8; SEED]) -> Result<(), Error> {
        let aes = Aes::try_new(&self.key)?;
        let mut temp = [0u8; SEED];
        for (chunk, extra) in
            temp.chunks_mut(BLOCK_SIZE).zip(provided.chunks(BLOCK_SIZE))
        {
            increment(&mut self.v);
            let mut block = self.v;
            aes.encrypt_block(&mut block);
            for (out, (b, p)) in chunk.iter_mut().zip(block.iter().zip(extra)) {
                *out = b ^ p;
            }
            block.zeroize();
        }
        self.key.copy_from_slice(&temp[..KEY]);
        self.v.copy_from_slice(&temp[KEY..]);
        temp.zeroize();
        Ok(())
    }
}

impl Rng<External> {
    /// A generator seeded from entropy you supply, with no source of
    /// its own to go back to.
    ///
    /// For a board whose hardware generator is read some other way,
    /// and for tests that need a generator that cannot reach for
    /// anything.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSeedLength`] if `seed` is shorter than
    /// [`MIN_SEED`]. It must be full entropy over its whole length.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        if seed.len() < MIN_SEED {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        Self::instantiate(seed, External)
    }
}

impl<S: Entropy> Random for Rng<S> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() > MAX_REQUEST {
            return Err(Error::RequestTooLarge(out.len()));
        }
        if self.counter > RESEED_INTERVAL {
            self.reseed()?;
        }
        let aes = Aes::try_new(&self.key)?;
        for chunk in out.chunks_mut(BLOCK_SIZE) {
            increment(&mut self.v);
            let mut block = self.v;
            aes.encrypt_block(&mut block);
            chunk.copy_from_slice(&block[..chunk.len()]);
            block.zeroize();
        }
        // Moves the generator past what was just handed out, so that
        // nothing already given away can be worked forward again.
        self.update(&[0u8; SEED])?;
        self.counter += 1;
        Ok(())
    }
}

impl<S: Entropy> fmt::Debug for Rng<S> {
    /// Deliberately omits the state, which is key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rng")
            .field("requests_since_seeding", &(self.counter - 1))
            .finish()
    }
}

/// Adds one to a counter block, as a single big-endian number.
fn increment(v: &mut [u8; BLOCK_SIZE]) {
    for byte in v.iter_mut().rev() {
        let (sum, carried) = byte.overflowing_add(1);
        *byte = sum;
        if !carried {
            break;
        }
    }
}

/// The SP 800-90A block cipher derivation function: condenses
/// material of any length, holding entropy at any density, into
/// exactly a seed's worth.
///
/// This is what lets a caller hand over a hundred bytes from a ring
/// oscillator, or two hundred rate-limited samples from `rdseed`, and
/// get a seed that is worth its full length.
fn derive(input: &[u8], out: &mut [u8; SEED]) -> Result<(), Error> {
    // The length goes into the input as a thirty-two bit number, so
    // it has to fit in one.
    let Ok(length) = u32::try_from(input.len()) else {
        return Err(Error::InvalidLength(input.len()));
    };

    // The fixed key the standard names for this first pass: the bytes
    // 0x00 to 0x1f in order. It is written down in the standard, so
    // there is nothing here to keep.
    let mut fixed = [0u8; KEY];
    for (i, byte) in fixed.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let aes = Aes::try_new(&fixed)?;

    // Each pass differs only in the counter its chain starts from,
    // which is what makes the three blocks differ.
    let mut temp = [0u8; SEED];
    for (i, chunk) in temp.chunks_mut(BLOCK_SIZE).enumerate() {
        let mut start = [0u8; BLOCK_SIZE];
        start[..4].copy_from_slice(&(i as u32).to_be_bytes());
        let mut chain = Chain::new(&aes);
        chain.update(&start);
        chain.update(&length.to_be_bytes());
        chain.update(&(SEED as u32).to_be_bytes());
        chain.update(input);
        // The standard's padding: a set bit, then zeros.
        chain.update(&[0x80]);
        chunk.copy_from_slice(&chain.finish());
    }

    // The second pass runs the block cipher forward under a key made
    // from the first.
    let aes = Aes::try_new(&temp[..KEY])?;
    let mut block = [0u8; BLOCK_SIZE];
    block.copy_from_slice(&temp[KEY..]);
    temp.zeroize();
    for chunk in out.chunks_mut(BLOCK_SIZE) {
        aes.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    block.zeroize();
    Ok(())
}

/// A CBC-MAC taken over material that arrives in pieces.
///
/// The derivation function's input is several runs of bytes with a
/// pad on the end, and building the whole of it somewhere would mean
/// a buffer as long as the caller's entropy. Chaining it a block at a
/// time needs sixteen bytes and no assumptions about length.
struct Chain<'a> {
    aes: &'a Aes,
    chain: [u8; BLOCK_SIZE],
    block: [u8; BLOCK_SIZE],
    used: usize,
}

impl<'a> Chain<'a> {
    fn new(aes: &'a Aes) -> Self {
        Chain {
            aes,
            chain: [0u8; BLOCK_SIZE],
            block: [0u8; BLOCK_SIZE],
            used: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (BLOCK_SIZE - self.used).min(data.len());
            self.block[self.used..self.used + take]
                .copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used == BLOCK_SIZE {
                self.absorb();
            }
        }
    }

    fn absorb(&mut self) {
        for (c, b) in self.chain.iter_mut().zip(&self.block) {
            *c ^= b;
        }
        self.aes.encrypt_block(&mut self.chain);
        self.used = 0;
    }

    /// Zero fills whatever is left of the last block and returns the
    /// chaining value.
    fn finish(mut self) -> [u8; BLOCK_SIZE] {
        if self.used != 0 {
            self.block[self.used..].fill(0);
            self.absorb();
        }
        self.chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A seed of the least acceptable length, filled with something
    /// that is not all one byte.
    fn seed() -> [u8; MIN_SEED] {
        let mut seed = [0u8; MIN_SEED];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        seed
    }

    /// The same seed must give the same stream, or the ACVP vectors
    /// could not check anything.
    #[test]
    fn one_seed_gives_one_stream() {
        let mut first = Rng::from_seed(&seed()).expect("seed");
        let mut second = Rng::from_seed(&seed()).expect("seed");
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        first.fill(&mut a).expect("fill");
        second.fill(&mut b).expect("fill");
        assert_eq!(a, b);
    }

    /// Two requests from one generator must not repeat: the state is
    /// moved on after every one.
    #[test]
    fn successive_requests_differ() {
        let mut rng = Rng::from_seed(&seed()).expect("seed");
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        rng.fill(&mut first).expect("first");
        rng.fill(&mut second).expect("second");
        assert_ne!(first, second);
    }

    /// Different seeds must give different streams.
    #[test]
    fn different_seeds_give_different_streams() {
        let mut other = seed();
        other[0] ^= 1;
        let mut first = Rng::from_seed(&seed()).expect("seed");
        let mut second = Rng::from_seed(&other).expect("seed");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        first.fill(&mut a).expect("fill");
        second.fill(&mut b).expect("fill");
        assert_ne!(a, b);
    }

    /// Guard bytes either side catch a length slip, and lengths that
    /// are not a whole number of blocks must still be filled exactly.
    #[test]
    fn requests_stay_inside_the_buffer() {
        let mut rng = Rng::from_seed(&seed()).expect("seed");
        const PAD: usize = 32;
        let mut buf = [0xaau8; PAD + 1000 + PAD];
        for len in [0, 1, 15, 16, 17, 31, 100, 1000] {
            buf.fill(0xaa);
            rng.fill(&mut buf[PAD..PAD + len]).expect("fill");
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

    /// Too little entropy is refused rather than stretched, at
    /// construction and at reseeding alike.
    #[test]
    fn a_short_seed_is_refused() {
        let short = [0x5au8; MIN_SEED - 1];
        assert_eq!(
            Rng::from_seed(&short).err(),
            Some(Error::InvalidSeedLength(MIN_SEED - 1))
        );
        let mut rng = Rng::from_seed(&seed()).expect("seed");
        assert_eq!(
            rng.reseed_from(&short).err(),
            Some(Error::InvalidSeedLength(MIN_SEED - 1))
        );
    }

    /// A refused reseeding must leave the generator exactly as it
    /// was, still producing the stream it was going to produce.
    #[test]
    fn a_refused_reseed_changes_nothing() {
        let mut rng = Rng::from_seed(&seed()).expect("seed");
        let mut untouched = Rng::from_seed(&seed()).expect("seed");
        assert!(rng.reseed_from(&[0u8; MIN_SEED - 1]).is_err());
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill(&mut a).expect("fill");
        untouched.fill(&mut b).expect("fill");
        assert_eq!(a, b);
    }

    /// Reseeding must change the stream, and must count from the
    /// start again.
    #[test]
    fn reseeding_moves_the_generator_on() {
        let mut rng = Rng::from_seed(&seed()).expect("seed");
        let mut untouched = Rng::from_seed(&seed()).expect("seed");
        rng.reseed_from(&[0x11u8; MIN_SEED]).expect("reseed");
        assert_eq!(rng.counter, 1);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill(&mut a).expect("fill");
        untouched.fill(&mut b).expect("fill");
        assert_ne!(a, b);
    }

    /// A request larger than the standard allows is refused, and the
    /// largest allowed one is not.
    #[test]
    fn an_oversized_request_is_refused() {
        let mut rng = Rng::from_seed(&seed()).expect("seed");
        let mut buf = [0u8; MAX_REQUEST + 1];
        assert_eq!(
            rng.fill(&mut buf).err(),
            Some(Error::RequestTooLarge(MAX_REQUEST + 1))
        );
        rng.fill(&mut buf[..MAX_REQUEST]).expect("largest allowed");
    }

    /// At the reseed interval a generator with no source of its own
    /// must stop, and must start again once it is given entropy.
    /// Reaching the interval by counting to it would take years, so
    /// the count is moved.
    #[test]
    fn running_out_stops_a_generator_until_it_is_fed() {
        let mut rng = Rng::from_seed(&seed()).expect("seed");
        rng.counter = RESEED_INTERVAL + 1;
        let mut buf = [0u8; 16];
        assert_eq!(rng.fill(&mut buf).err(), Some(Error::ReseedRequired));
        rng.reseed_from(&[0x22u8; MIN_SEED]).expect("reseed");
        rng.fill(&mut buf).expect("fill after reseeding");
    }

    /// A generator with a source of its own reseeds itself, and the
    /// caller never sees it happen.
    #[test]
    fn a_generator_with_a_source_reseeds_itself() {
        let Ok(system) = System::try_new() else {
            return;
        };
        let mut rng = Rng::try_new(system).expect("rng");
        rng.counter = RESEED_INTERVAL + 1;
        let mut buf = [0u8; 16];
        rng.fill(&mut buf).expect("fill");
        assert_eq!(rng.counter, 2, "reseeded and then counted one request");
    }

    /// The state must not survive the object.
    #[test]
    fn the_generator_wipes_itself() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Rng<External>>();
    }

    /// Output that is technically written but obviously not random
    /// would fail this. The band is about nine standard deviations
    /// wide.
    #[test]
    fn bits_are_not_wildly_skewed() {
        let mut rng = Rng::from_seed(&seed()).expect("seed");
        let mut buf = [0u8; 4096];
        rng.fill(&mut buf).expect("fill");
        let set: u32 = buf.iter().map(|b| b.count_ones()).sum();
        assert!((15600..17200).contains(&set), "{set} bits set of 32768");
    }

    /// The derivation function must condense rather than truncate:
    /// changing any byte of a long input must change the whole seed.
    #[test]
    fn the_derivation_function_uses_all_of_its_input() {
        let long = [0x33u8; 500];
        let mut spoiled = long;
        spoiled[499] ^= 1;
        let mut first = [0u8; SEED];
        let mut second = [0u8; SEED];
        derive(&long, &mut first).expect("derive");
        derive(&spoiled, &mut second).expect("derive");
        assert_ne!(first, second);
    }

    /// The counter block is one big-endian number, and must carry
    /// across every byte of it.
    #[test]
    fn the_counter_carries() {
        let mut v = [0u8; BLOCK_SIZE];
        increment(&mut v);
        assert_eq!(v[BLOCK_SIZE - 1], 1);

        let mut v = [0xffu8; BLOCK_SIZE];
        increment(&mut v);
        assert_eq!(v, [0u8; BLOCK_SIZE], "wraps around");

        let mut v = [0u8; BLOCK_SIZE];
        v[BLOCK_SIZE - 1] = 0xff;
        increment(&mut v);
        assert_eq!(v[BLOCK_SIZE - 2], 1);
        assert_eq!(v[BLOCK_SIZE - 1], 0);
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

    /// And a source of entropy of one's own, which is how a board
    /// with its own hardware is served.
    #[test]
    fn an_entropy_source_of_ones_own_can_seed_a_generator() {
        struct Board(u8);
        impl Entropy for Board {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
                for byte in out.iter_mut() {
                    self.0 = self.0.wrapping_mul(31).wrapping_add(17);
                    *byte = self.0;
                }
                Ok(())
            }
        }
        let mut rng = Rng::try_new(Board(1)).expect("board");
        let mut buf = [0u8; 32];
        rng.fill(&mut buf).expect("fill");
        assert_ne!(buf, [0u8; 32]);
        // And it can go back to the board for more.
        rng.reseed().expect("reseed");
    }
}
