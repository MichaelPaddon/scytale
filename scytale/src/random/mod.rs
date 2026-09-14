//! Random numbers, from a generator you hold.
//!
//! # What this is
//!
//! [`CtrDrbg`] is the generator to reach for. It is seeded once from
//! a source of entropy and then produces random bytes from that
//! seeding, in the shape SP 800-90A calls CTR_DRBG: AES-256 driven
//! by a counter, its key and counter replaced after every request so
//! that nothing already handed out can be worked backwards from what
//! comes next. It is named for the construction rather than for its
//! category, so that the next generator can sit beside it under its
//! own name; what code takes is the [`Random`] trait, not either of
//! them.
//!
//! ```
//! use scytale::Random;
//! use scytale::random::CtrDrbg;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//!
//! let mut key = [0u8; 32];
//! rng.fill(&mut key)?;
//! # Ok(())
//! # }
//! ```
//!
//! [`from_system`](CtrDrbg::from_system) asks this machine for the
//! seed. To choose the source yourself, name it:
//! [`CtrDrbg::try_new(entropy::Processor::try_new()?)`](CtrDrbg::try_new).
//! For entropy you gather some other way, implement [`Entropy`] over
//! it and hand that to [`try_new`](CtrDrbg::try_new); there is no
//! way to build a generator from a seed you hold, on purpose, and the
//! [rule below](#fork-snapshots-and-clones-the-rule) is why.
//!
//! # Fork, snapshots and clones: the rule
//!
//! **A copy of this process holds a copy of this generator, and both
//! copies will hand out the same bytes. The library cannot see the
//! copy being made. Whoever makes it must reseed or rebuild the
//! generator in the copy before it is used again. That is your
//! responsibility, and nothing here does it for you.**
//!
//! What makes a copy: `fork`, and everything built on it, which is
//! most process spawning in most languages; `clone` and `vfork`;
//! restoring a virtual machine from a snapshot; restoring a container
//! from a checkpoint; live migration that leaves the original
//! running; cloning a disk image with a warm process on it. In every
//! one of these the state is duplicated exactly, and the next request
//! on each side returns the same bytes.
//!
//! What that costs, primitive by primitive:
//!
//! - **AEADs.** A random nonce comes out twice. A repeated nonce under
//!   GCM or ChaCha20-Poly1305 loses the authentication key and the
//!   XOR of the two plaintexts. This is the worst case and the most
//!   common one.
//! - **Key generation.** RSA and ML-KEM keys come out twice, and so
//!   do ML-KEM shared secrets on encapsulation: two parties who each
//!   believed they held a fresh secret hold the same one.
//! - **Randomised signing and encryption.** RSA-PSS salts, OAEP seeds,
//!   and the hedge in ML-DSA and SLH-DSA fall back to the
//!   deterministic security of the scheme, which is still sound.
//! - **Deterministic signing.** Ed25519, RFC 6979 ECDSA, and ML-DSA
//!   and SLH-DSA in their deterministic modes draw nothing when they
//!   sign, and are unaffected.
//!
//! What to do, in the copy, before it uses the generator for
//! anything:
//!
//! - Call [`reseed`](CtrDrbg::reseed). The generator draws fresh
//!   material from its source and the two copies part ways from
//!   there. Or drop it and build another; the difference is only
//!   cost.
//! - Do it where the copy is made: the child side of a
//!   `pthread_atfork` handler, the first thing a worker does after
//!   it is spawned, the resume hook of whatever restores the
//!   snapshot. Do not do it lazily on first use, because the first
//!   use is the nonce.
//! - After a snapshot restore, the operating system's own generator
//!   is the source that knows a clone happened: it is told through
//!   `vmgenid` and virtio-rng where the hypervisor supports them,
//!   and nothing in user space is. A generator on
//!   [`entropy::System`] reseeded after restore is sound; one built
//!   before the snapshot and not reseeded is not.
//! - Better still, do not share a generator across the copy at all:
//!   build one per worker after the worker exists.
//!
//! Why the library does not detect it: the only hook is
//! `pthread_atfork`, which a raw `clone` or `vfork` never runs, which
//! does not exist on a build with no C library, and which knows
//! nothing about snapshots, since no operating system tells user
//! space that a machine was cloned. A check that is silently wrong
//! on some platforms is worse than a rule that is true on all of
//! them, so the rule is stated instead, here and on every
//! constructor.
//!
//! What the library does guarantee, so that the boundary is sharp:
//! the generator is not `Clone`, so a second copy in one process is
//! not something that happens by accident; it is wiped when dropped;
//! it fails loudly rather than carrying on when it runs out; and a
//! refused call leaves its state exactly as it was.
//!
//! # Why you hold it, and what that costs you
//!
//! This used to be a function with no state at all, which asked the
//! operating system afresh every call. That refused the problem above
//! by having nothing to duplicate. It also had nowhere to put the
//! things a generator needs. A raw entropy source has to be watched
//! for failure, and the tests that do the watching span more samples
//! than any single call draws. Raw entropy has to be conditioned
//! before use, and a function with no state has nothing to condition
//! it with. So the state exists now, and it belongs to you, with the
//! rule above as the price.
//!
//! Whoever forked is the one who knows they forked. Nothing in this
//! module can find that out without asking the kernel on every call,
//! which is most of the reason to hold a generator in the first
//! place.
//!
//! # Where the seed comes from
//!
//! The sources live in [`entropy`], and are sources of raw material
//! rather than of random bytes: what they hand back is conditioned
//! by the generator before any of it reaches a caller. That is why
//! they implement [`Entropy`] and not [`Random`].
//!
//! | Source | What it asks |
//! | --- | --- |
//! | [`entropy::System`] | the system, or the processor if there is none |
//! | [`entropy::Processor`] | the processor's own, health tested |
//! | yours | whatever you implement [`Entropy`] over |
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
//! # Seeding, and what is deliberately not offered
//!
//! Every seeding runs the material through the standard's derivation
//! function, which is what lets a source of any length and any
//! density be accepted. SP 800-90A also defines the generator without
//! it, for material that is already full entropy and exactly a seed
//! long. That construction is implemented, so that the vectors for it
//! can be run and the arithmetic checked in both shapes, but it is
//! not offered: a source the generator draws from is oversampled
//! precisely because it is not trusted to be full entropy, and a
//! constructor that trusts a caller's bytes as full entropy is a
//! constructor that will be handed something weaker.
//!
//! Nor is there a way to build a generator from a seed you hold. A
//! generator built that way has no source to go back to, so it cannot
//! obey the rule above and cannot reseed itself when it runs out; and
//! a seed that is a constant, a hash of something guessable, or a
//! test value looks exactly like a good one until it is too late.
//! Implement [`Entropy`] over what you have instead. A fixed sequence
//! for a test implements [`Random`] directly.
//!
//! What the generator does take is additional input: caller bytes
//! mixed into the state at a reseeding through
//! [`reseed_with`](CtrDrbg::reseed_with), or at a single request
//! through [`fill_with`](CtrDrbg::fill_with). They are not entropy
//! and are not counted as any; they bind the output to something the
//! caller knows, such as a request number or a time.
//!
//! # Running out
//!
//! One seeding does not last forever, and both limits refuse rather
//! than quietly carrying on:
//!
//! - A single request may ask for at most [`MAX_REQUEST`] bytes.
//! - After [`RESEED_INTERVAL`] requests the generator reseeds itself
//!   from its source, and you never see it. If the source refuses,
//!   [`fill`](Random::fill) fails with the source's error and keeps
//!   failing until a reseeding succeeds, through
//!   [`reseed`](CtrDrbg::reseed) or fresh entropy handed to
//!   [`reseed_from`](CtrDrbg::reseed_from).
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

pub mod entropy;
pub(crate) mod health;

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher::OneBlock;
use crate::cipher::aes::{Aes256, BLOCK_SIZE};
use crate::{Error, Key, Random};

/// AES-256: the key length the generator uses, in bytes.
const KEY: usize = 32;

/// The generator's internal seed, a key and a counter block, in bytes.
///
/// Also the exact length the construction without the derivation
/// function takes, and the most additional input it accepts.
pub(crate) const SEED: usize = KEY + BLOCK_SIZE;

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
/// Implement this to seed an [`CtrDrbg`] from hardware of your own.
pub trait Entropy {
    /// Fills the whole of `out` with raw entropy, or fails without
    /// leaving anything worth relying on.
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
pub struct CtrDrbg<S: Entropy = entropy::System> {
    /// Where a reseeding gets its material. The crate's own tests
    /// use a source that has nowhere, and so refuses.
    #[zeroize(skip)]
    source: S,
    /// The key and counter block that are the generator's whole
    /// secret.
    key: Key<[u8; KEY]>,
    v: [u8; BLOCK_SIZE],
    /// Requests made since the last seeding, counted from one as
    /// SP 800-90A counts it.
    #[zeroize(skip)]
    counter: u64,
    /// Whether seed material and additional input go through the
    /// derivation function, or straight in at a fixed width.
    #[zeroize(skip)]
    derivation: bool,
}

impl<S: Entropy> CtrDrbg<S> {
    /// A generator seeded from `source`.
    ///
    /// The source is kept, and is where every later reseeding
    /// comes from. This is the way to seed from hardware of your
    /// own, or from entropy gathered some other way: implement
    /// [`Entropy`] over it.
    ///
    /// # Fork and snapshots
    ///
    /// A copy of this process holds a copy of this generator, and
    /// both will hand out the same bytes. Call
    /// [`reseed`](CtrDrbg::reseed) in the copy before it is used, or
    /// build a fresh one there. See
    /// [the rule](self#fork-snapshots-and-clones-the-rule).
    ///
    /// # Errors
    ///
    /// Whatever the source refuses with. A source with nothing to
    /// give yields no generator rather than one that cannot work.
    pub fn try_new(mut source: S) -> Result<Self, Error> {
        let mut raw = [0u8; MIN_SEED * OVERSAMPLE];
        let drawn = source.fill(&mut raw);
        let built =
            drawn.and_then(|()| Self::instantiate(&raw, &[], source, true));
        raw.zeroize();
        built
    }

    /// Reseeds from the generator's own source.
    ///
    /// Called automatically once [`RESEED_INTERVAL`] requests have
    /// been made, so in ordinary running there is no reason to call
    /// it. After a `fork`, a restored snapshot, or anything else that
    /// copies the process there is every reason: this is the call
    /// [the rule](self#fork-snapshots-and-clones-the-rule) asks for,
    /// in the copy, before the generator is used again. It is the
    /// cheaper alternative to dropping the generator and building
    /// another, and does the same thing.
    ///
    /// # Errors
    ///
    /// Whatever the source refuses with. The generator is left
    /// exactly as it was, which after a copy is still unsafe to use.
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
    /// weaken one. It is for entropy that arrives from somewhere other
    /// than the generator's source: a second device, material handed
    /// over by a protocol. It also satisfies
    /// [the rule](self#fork-snapshots-and-clones-the-rule) after a
    /// copy, provided the entropy is fresh on the copy's side;
    /// [`reseed`](CtrDrbg::reseed) is the simpler way to do that.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSeedLength`] if `entropy` is shorter than
    /// [`MIN_SEED`]. The generator is left exactly as it was.
    pub fn reseed_from(&mut self, entropy: &[u8]) -> Result<(), Error> {
        self.reseed_with(entropy, &[])
    }

    /// [`reseed_from`](CtrDrbg::reseed_from), with additional input
    /// mixed in alongside the entropy.
    ///
    /// Additional input is whatever the caller wants the new state
    /// bound to: a counter, a time, a name. It is not credited as
    /// entropy, and `entropy` must be enough on its own.
    ///
    /// # Errors
    ///
    /// As `reseed_from`. The generator is left exactly as it was.
    pub fn reseed_with(
        &mut self,
        entropy: &[u8],
        additional: &[u8],
    ) -> Result<(), Error> {
        let mut seed = [0u8; SEED];
        let mixed = self.seed_block(entropy, additional, &mut seed);
        let done = mixed.and_then(|()| self.update(&seed));
        seed.zeroize();
        if done.is_ok() {
            self.counter = 1;
        }
        done
    }

    /// Fills `out` with random bytes, with additional input mixed
    /// into the state before they are made.
    ///
    /// This is [`fill`](Random::fill) with the request bound to
    /// something the caller knows. The input is not entropy and does
    /// not count as a reseeding; with nothing in it this is exactly
    /// `fill`. It does not repair a generator duplicated by a copy of
    /// the process: two copies given the same input still agree.
    ///
    /// # Errors
    ///
    /// As `fill`. A refused request leaves the generator exactly as
    /// it was.
    pub fn fill_with(
        &mut self,
        out: &mut [u8],
        additional: &[u8],
    ) -> Result<(), Error> {
        if out.len() > MAX_REQUEST {
            return Err(Error::RequestTooLarge(out.len()));
        }
        // Prepared before anything moves, so that a refused input
        // refuses the whole request. Empty input leaves the zero
        // block the standard uses in its place.
        let mut seed = [0u8; SEED];
        let done = if additional.is_empty() {
            self.generate(out, None)
        } else {
            self.extra_block(additional, &mut seed)
                .and_then(|()| self.generate(out, Some(&seed)))
        };
        seed.zeroize();
        done
    }

    /// The request itself: mixes `extra` in, runs the counter over
    /// `out`, and mixes `extra` in again to move the generator past
    /// what was handed out. With no extra the second mixing is of
    /// a zero block, as the standard has it.
    fn generate(
        &mut self,
        out: &mut [u8],
        extra: Option<&[u8; SEED]>,
    ) -> Result<(), Error> {
        // The standard folds the additional input into this reseeding
        // and then requests with none. Here the source is drawn alone
        // and the input still goes in afterwards, which mixes more,
        // never less.
        if self.counter > RESEED_INTERVAL {
            self.reseed()?;
        }
        if let Some(extra) = extra {
            self.update(extra)?;
        }
        let extra = extra.unwrap_or(&[0u8; SEED]);
        let aes = Aes256::new(&self.key);
        for chunk in out.chunks_mut(BLOCK_SIZE) {
            increment(&mut self.v);
            let mut block = self.v;
            aes.encrypt_one(&mut block);
            chunk.copy_from_slice(&block[..chunk.len()]);
            block.zeroize();
        }
        // Moves the generator past what was just handed out, so that
        // nothing already given away can be worked forward again.
        self.update(extra)?;
        self.counter += 1;
        Ok(())
    }

    /// Builds a generator from material that has already been
    /// gathered, with or without the derivation function in the way.
    fn instantiate(
        entropy: &[u8],
        personalization: &[u8],
        source: S,
        derivation: bool,
    ) -> Result<Self, Error> {
        let mut rng = CtrDrbg {
            source,
            key: Key::zeroed(),
            v: [0u8; BLOCK_SIZE],
            counter: 1,
            derivation,
        };
        let mut seed = [0u8; SEED];
        let mixed = rng.seed_block(entropy, personalization, &mut seed);
        let done = mixed.and_then(|()| rng.update(&seed));
        seed.zeroize();
        done.map(|()| rng)
    }

    /// Turns entropy and whatever accompanies it into one seed's
    /// worth, the way this generator was built to.
    ///
    /// With the derivation function that is a condensation of both
    /// runs together. Without it the entropy is the seed, and the
    /// extra is padded out and XORed over it, as the standard says.
    fn seed_block(
        &self,
        entropy: &[u8],
        extra: &[u8],
        out: &mut [u8; SEED],
    ) -> Result<(), Error> {
        if self.derivation {
            if entropy.len() < MIN_SEED {
                return Err(Error::InvalidSeedLength(entropy.len()));
            }
            return derive(&[entropy, extra], out);
        }
        if entropy.len() != SEED {
            return Err(Error::InvalidSeedLength(entropy.len()));
        }
        if extra.len() > SEED {
            return Err(Error::InvalidLength(extra.len()));
        }
        out.copy_from_slice(entropy);
        for (o, e) in out.iter_mut().zip(extra) {
            *o ^= e;
        }
        Ok(())
    }

    /// Turns additional input on its own into one seed's worth, the
    /// way this generator was built to: derived, or padded with zeros.
    fn extra_block(
        &self,
        additional: &[u8],
        out: &mut [u8; SEED],
    ) -> Result<(), Error> {
        if self.derivation {
            return derive(&[additional], out);
        }
        if additional.len() > SEED {
            return Err(Error::InvalidLength(additional.len()));
        }
        let (head, tail) = out.split_at_mut(additional.len());
        head.copy_from_slice(additional);
        tail.fill(0);
        Ok(())
    }

    /// The CTR_DRBG update: runs the generator forward far enough to
    /// replace both the key and the counter block, mixing `provided`
    /// in as it goes.
    fn update(&mut self, provided: &[u8; SEED]) -> Result<(), Error> {
        let aes = Aes256::new(&self.key);
        let mut temp = [0u8; SEED];
        for (chunk, extra) in
            temp.chunks_mut(BLOCK_SIZE).zip(provided.chunks(BLOCK_SIZE))
        {
            increment(&mut self.v);
            let mut block = self.v;
            aes.encrypt_one(&mut block);
            for (out, (b, p)) in chunk.iter_mut().zip(block.iter().zip(extra)) {
                *out = b ^ p;
            }
            block.zeroize();
        }
        self.key.as_mut().copy_from_slice(&temp[..KEY]);
        self.v.copy_from_slice(&temp[KEY..]);
        temp.zeroize();
        Ok(())
    }
}

impl CtrDrbg<entropy::System> {
    /// A generator seeded from this machine's own source: the
    /// operating system where there is one, the processor's
    /// generator where there is not.
    ///
    /// This is the one to reach for. [`try_new`](CtrDrbg::try_new)
    /// exists for a processor source chosen deliberately, or for
    /// entropy the caller gathers.
    ///
    /// # Fork and snapshots
    ///
    /// A copy of this process holds a copy of this generator, and
    /// both will hand out the same bytes. Call
    /// [`reseed`](CtrDrbg::reseed) in the copy before it is used, or
    /// build a fresh one there. The system source is the one that is
    /// told about virtual machine clones, so a reseeding after a
    /// restore is sound. See
    /// [the rule](self#fork-snapshots-and-clones-the-rule).
    ///
    /// # Errors
    ///
    /// Whatever [`entropy::System`] refuses to be built with, and
    /// whatever it then refuses to hand over. On a target with an
    /// operating system that is the system's own error; on one
    /// without, [`Error::NotSupported`] where the processor has no
    /// generator and [`Error::EntropyUnavailable`] where the one it
    /// has does not pass its startup test.
    pub fn from_system() -> Result<Self, Error> {
        Self::try_new(entropy::System::try_new()?)
    }
}

/// The generators the vector suites and the unit tests are built on:
/// seeded from bytes the test holds, with no source to go back to.
///
/// Neither constructor is public, on purpose, and neither exists
/// outside the test build. A generator with no source cannot obey
/// the fork rule and cannot reseed itself when it runs out, and a
/// seed that is a constant or a test value behaves exactly like a
/// good one. A caller with entropy of their own implements
/// [`Entropy`]; a caller wanting a fixed sequence implements
/// [`Random`].
#[cfg(test)]
impl CtrDrbg<entropy::External> {
    /// A generator seeded through the derivation function from
    /// `seed`, which must be at least [`MIN_SEED`] bytes.
    pub(crate) fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        Self::instantiate(seed, &[], entropy::External, true)
    }

    /// A generator seeded without the derivation function: the
    /// standard's construction for material that is already full
    /// entropy and exactly a seed long, with the personalization
    /// padded and XORed over it. Exists so that the vectors for that
    /// construction can be run; reseeding one takes exactly `SEED`
    /// bytes, and additional input to one is at most `SEED` bytes,
    /// refused with [`Error::InvalidLength`] otherwise.
    pub(crate) fn from_full_entropy(
        entropy: &[u8; SEED],
        personalization: &[u8],
    ) -> Result<Self, Error> {
        Self::instantiate(entropy, personalization, entropy::External, false)
    }
}

impl<S: Entropy> Random for CtrDrbg<S> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.fill_with(out, &[])
    }
}

impl<S: Entropy> fmt::Debug for CtrDrbg<S> {
    /// Deliberately omits the state, which is key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtrDrbg")
            .field("requests_since_seeding", &(self.counter - 1))
            .field("derivation_function", &self.derivation)
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
///
/// The input is the concatenation of `parts`. They arrive separately
/// because entropy and additional input come from different places
/// and there is no allocator to join them with; the chaining absorbs
/// them as though they were one run.
fn derive(parts: &[&[u8]], out: &mut [u8; SEED]) -> Result<(), Error> {
    // The length goes into the input as a thirty-two bit number, so
    // it has to fit in one.
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let Ok(length) = u32::try_from(total) else {
        return Err(Error::InvalidLength(total));
    };

    // The fixed key the standard names for this first pass: the bytes
    // 0x00 to 0x1f in order. It is written down in the standard, so
    // there is nothing here to keep.
    let mut fixed = Key::<[u8; KEY]>::zeroed();
    for (i, byte) in fixed.as_mut().iter_mut().enumerate() {
        *byte = i as u8;
    }
    let aes = Aes256::new(&fixed);

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
        for part in parts {
            chain.update(part);
        }
        // The standard's padding: a set bit, then zeros.
        chain.update(&[0x80]);
        chunk.copy_from_slice(&chain.finish());
    }

    // The second pass runs the block cipher forward under a key made
    // from the first.
    let (key, counter) = temp.split_at(KEY);
    let key = Key::<[u8; KEY]>::try_from(key)?;
    let aes = Aes256::new(&key);
    let mut block = [0u8; BLOCK_SIZE];
    block.copy_from_slice(counter);
    temp.zeroize();
    for chunk in out.chunks_mut(BLOCK_SIZE) {
        aes.encrypt_one(&mut block);
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
    aes: &'a Aes256,
    chain: [u8; BLOCK_SIZE],
    block: [u8; BLOCK_SIZE],
    used: usize,
}

impl<'a> Chain<'a> {
    fn new(aes: &'a Aes256) -> Self {
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
        self.aes.encrypt_one(&mut self.chain);
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
        let mut first = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut second = CtrDrbg::from_seed(&seed()).expect("seed");
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
        let mut rng = CtrDrbg::from_seed(&seed()).expect("seed");
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
        let mut first = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut second = CtrDrbg::from_seed(&other).expect("seed");
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
        let mut rng = CtrDrbg::from_seed(&seed()).expect("seed");
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
            CtrDrbg::from_seed(&short).err(),
            Some(Error::InvalidSeedLength(MIN_SEED - 1))
        );
        let mut rng = CtrDrbg::from_seed(&seed()).expect("seed");
        assert_eq!(
            rng.reseed_from(&short).err(),
            Some(Error::InvalidSeedLength(MIN_SEED - 1))
        );
    }

    /// A refused reseeding must leave the generator exactly as it
    /// was, still producing the stream it was going to produce.
    #[test]
    fn a_refused_reseed_changes_nothing() {
        let mut rng = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut untouched = CtrDrbg::from_seed(&seed()).expect("seed");
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
        let mut rng = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut untouched = CtrDrbg::from_seed(&seed()).expect("seed");
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
        let mut rng = CtrDrbg::from_seed(&seed()).expect("seed");
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
        let mut rng = CtrDrbg::from_seed(&seed()).expect("seed");
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
        let Ok(system) = entropy::System::try_new() else {
            return;
        };
        let mut rng = CtrDrbg::try_new(system).expect("rng");
        rng.counter = RESEED_INTERVAL + 1;
        let mut buf = [0u8; 16];
        rng.fill(&mut buf).expect("fill");
        assert_eq!(rng.counter, 2, "reseeded and then counted one request");
    }

    /// The state must not survive the object.
    #[test]
    fn the_generator_wipes_itself() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<CtrDrbg<entropy::External>>();
    }

    /// Output that is technically written but obviously not random
    /// would fail this. The band is about nine standard deviations
    /// wide.
    #[test]
    fn bits_are_not_wildly_skewed() {
        let mut rng = CtrDrbg::from_seed(&seed()).expect("seed");
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
        derive(&[&long], &mut first).expect("derive");
        derive(&[&spoiled], &mut second).expect("derive");
        assert_ne!(first, second);
    }

    /// Material in pieces must derive to the same seed as the same
    /// bytes in one run, or the pieces would not be a concatenation.
    #[test]
    fn the_derivation_function_joins_its_parts() {
        let whole = [0x44u8; 70];
        let mut joined = [0u8; SEED];
        let mut split = [0u8; SEED];
        derive(&[&whole], &mut joined).expect("derive");
        derive(&[&whole[..17], &whole[17..], &[]], &mut split).expect("derive");
        assert_eq!(joined, split);
    }

    /// With nothing to add, a request with additional input is the
    /// plain request, byte for byte.
    #[test]
    fn empty_additional_input_is_a_plain_request() {
        let mut plain = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut with = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut a = [0u8; 40];
        let mut b = [0u8; 40];
        plain.fill(&mut a).expect("fill");
        with.fill_with(&mut b, &[]).expect("fill_with");
        assert_eq!(a, b);
        plain.fill(&mut a).expect("fill");
        with.fill_with(&mut b, &[]).expect("fill_with");
        assert_eq!(a, b, "and the state moved on the same way");
    }

    /// Additional input must change the output, the same input from
    /// the same state must repeat it, and it counts as a request, not
    /// a reseeding.
    #[test]
    fn additional_input_binds_the_request() {
        let mut plain = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut first = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut again = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut other = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        let mut d = [0u8; 32];
        plain.fill(&mut a).expect("fill");
        first.fill_with(&mut b, b"request 1").expect("fill_with");
        again.fill_with(&mut c, b"request 1").expect("fill_with");
        other.fill_with(&mut d, b"request 2").expect("fill_with");
        assert_ne!(a, b);
        assert_eq!(b, c);
        assert_ne!(b, d);
        assert_eq!(first.counter, 2);
    }

    /// Reseeding with additional input alongside the entropy is, with
    /// the derivation function, the same as reseeding from the two
    /// joined: the derivation function sees one run either way.
    #[test]
    fn reseed_with_is_reseed_from_the_concatenation() {
        let mut split = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut joined = CtrDrbg::from_seed(&seed()).expect("seed");
        let entropy = [0x66u8; MIN_SEED];
        let additional = [0x77u8; 20];
        let mut both = [0u8; MIN_SEED + 20];
        both[..MIN_SEED].copy_from_slice(&entropy);
        both[MIN_SEED..].copy_from_slice(&additional);
        split.reseed_with(&entropy, &additional).expect("reseed");
        joined.reseed_from(&both).expect("reseed");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        split.fill(&mut a).expect("fill");
        joined.fill(&mut b).expect("fill");
        assert_eq!(a, b);
    }

    /// The construction without the derivation function takes its
    /// seed as it is, so the personalization must show in the output
    /// and must be no longer than a seed.
    #[test]
    fn full_entropy_takes_a_personalization_up_to_a_seed() {
        let mut bare = CtrDrbg::from_full_entropy(&seed(), &[]).expect("no df");
        let mut named =
            CtrDrbg::from_full_entropy(&seed(), b"instance").expect("no df");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        bare.fill(&mut a).expect("fill");
        named.fill(&mut b).expect("fill");
        assert_ne!(a, b);
        assert_eq!(
            CtrDrbg::from_full_entropy(&seed(), &[0u8; SEED + 1]).err(),
            Some(Error::InvalidLength(SEED + 1))
        );
        CtrDrbg::from_full_entropy(&seed(), &[0u8; SEED])
            .expect("a whole seed of personalization");
    }

    /// The two constructions must not agree: a seed the derivation
    /// function has been over is not the seed itself.
    #[test]
    fn the_two_constructions_differ() {
        let mut derived = CtrDrbg::from_seed(&seed()).expect("seed");
        let mut direct =
            CtrDrbg::from_full_entropy(&seed(), &[]).expect("no df");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        derived.fill(&mut a).expect("fill");
        direct.fill(&mut b).expect("fill");
        assert_ne!(a, b);
    }

    /// Without the derivation function the lengths are fixed, and
    /// anything else is refused with the generator left as it was.
    #[test]
    fn full_entropy_refuses_the_wrong_lengths() {
        let mut rng = CtrDrbg::from_full_entropy(&seed(), &[]).expect("no df");
        let mut untouched =
            CtrDrbg::from_full_entropy(&seed(), &[]).expect("no df");
        assert_eq!(
            rng.reseed_from(&[0u8; SEED - 1]).err(),
            Some(Error::InvalidSeedLength(SEED - 1))
        );
        assert_eq!(
            rng.reseed_from(&[0u8; SEED + 1]).err(),
            Some(Error::InvalidSeedLength(SEED + 1))
        );
        assert_eq!(
            rng.reseed_with(&[0u8; SEED], &[0u8; SEED + 1]).err(),
            Some(Error::InvalidLength(SEED + 1))
        );
        let mut a = [0u8; 32];
        assert_eq!(
            rng.fill_with(&mut a, &[0u8; SEED + 1]).err(),
            Some(Error::InvalidLength(SEED + 1))
        );
        let mut b = [0u8; 32];
        rng.fill(&mut a).expect("fill");
        untouched.fill(&mut b).expect("fill");
        assert_eq!(a, b, "nothing refused touched the state");
        // And the fixed lengths themselves are taken.
        rng.reseed_with(&[0x88u8; SEED], &[0x99u8; SEED])
            .expect("reseed");
        rng.fill_with(&mut a, &[0xaau8; SEED]).expect("fill_with");
    }

    /// Additional input to that construction is padded, not derived,
    /// so all-zero input is still input: it must be mixed in rather
    /// than mistaken for none.
    #[test]
    fn zero_additional_input_is_still_input_without_the_df() {
        let mut none = CtrDrbg::from_full_entropy(&seed(), &[]).expect("no df");
        let mut zeros =
            CtrDrbg::from_full_entropy(&seed(), &[]).expect("no df");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        none.fill(&mut a).expect("fill");
        zeros.fill_with(&mut b, &[0u8; 8]).expect("fill_with");
        assert_ne!(a, b);
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
        let mut rng = CtrDrbg::try_new(Board(1)).expect("board");
        let mut buf = [0u8; 32];
        rng.fill(&mut buf).expect("fill");
        assert_ne!(buf, [0u8; 32]);
        // And it can go back to the board for more.
        rng.reseed().expect("reseed");
    }
}
