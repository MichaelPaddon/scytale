//! Galois/Counter Mode (NIST SP 800-38D).
//!
//! The default here, and a mode of operation in its own right: it
//! encrypts with counter mode and authenticates with GHASH, a hash
//! built on multiplication in a finite field, so a receiver learns
//! not just what the message says but that nobody altered it. Data
//! sent alongside in the clear, such as a header that must be
//! readable but must not be tampered with, can be authenticated too.
//!
//! # Speed
//!
//! GHASH, not the cipher, is what makes GCM slower than counter mode
//! alone, so what matters is how much of it can be got for nothing.
//!
//! Where the processor has both the AES instructions and the
//! carry-less multiply, this mode is one loop rather than two: the
//! counter blocks go through the rounds while the multiplications for
//! the message blocks are issued between them, on a port the cipher
//! is not using. Which of these the processor has is settled once,
//! when the mode is built, so no call pays to find out.
//!
//! Failing that, the counter loop and the hash run in turn, the hash
//! still taking whole groups of blocks at once where the architecture
//! offers a way. Failing even a carry-less multiply, it walks 128
//! bits per block, which leaks nothing but is slow enough to dominate
//! everything else here; on such a processor
//! [`ChaCha20Poly1305`](super::ChaCha20Poly1305) is the faster
//! choice.
//!
//! # Using it safely
//!
//! - **Never reuse a nonce with the same key.** For GCM this is worse
//!   than for the unauthenticated stream modes: as well as revealing
//!   the relationship between the two messages, it lets an attacker
//!   recover the hash key and then forge tags for any message at all.
//!   If nonces cannot be guaranteed unique, use a mode built to
//!   survive repeats.
//! - **Counting beats drawing.** [`Nonces`](crate::cipher::Nonces) makes a
//!   repeat impossible. A nonce drawn at random is allowed, but then
//!   the standard caps one key at 2^32 messages, and counting those
//!   messages is the caller's job.
//! - A 96-bit nonce is the usual choice and the one the standard
//!   treats specially. Any other length is allowed and supported, but
//!   is hashed down to a counter block first, which costs a little
//!   and gains nothing.
//! - Do not use a decrypted message before the tag has been checked.
//!   The one-shot [`decrypt`](Gcm::decrypt) checks first and wipes the
//!   buffer on failure. The incremental form cannot: see
//!   [`Decryptor`].
//! - A shorter tag is a weaker one. Every method here takes the full
//!   sixteen bytes; a protocol that has decided to carry fewer keeps a
//!   prefix and checks it with [`Decryptor::verify_truncated`], so
//!   that the decision is visible where it is made.
//!
//! # Example
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::aes::Aes128;
//! use scytale::aead::{Aead, Gcm};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let gcm = Gcm::<Aes128>::new(&Key::from([0u8; 16]));
//! let nonce = [0u8; 12];
//! let header = b"to: alice";
//!
//! let mut message = *b"hello";
//! let mut tag = [0u8; 16];
//! gcm.encrypt(&nonce, header, &mut message, &mut tag)?;
//!
//! gcm.decrypt(&nonce, header, &mut message, &tag)?;
//! assert_eq!(&message, b"hello");
//! # Ok(())
//! # }
//! ```

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64;
#[cfg(target_arch = "riscv64")]
pub(crate) mod riscv64;
#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;

// The loops written out for this processor, whichever it is. Each
// architecture's module offers the same entry points for GCM itself,
// so the code below needs no conditionals beyond whether there is one
// at all. POLYVAL and GCM-SIV reach further into the x86-64 one and
// name it directly.
#[cfg(target_arch = "aarch64")]
pub(crate) use self::aarch64 as native;
#[cfg(target_arch = "riscv64")]
pub(crate) use self::riscv64 as native;
#[cfg(target_arch = "x86_64")]
pub(crate) use self::x86_64 as native;

use core::fmt;

use super::ghash::{BLOCK, Ghash};
use crate::aead::Aead;
use crate::cipher::mode::{ByteOrder, counter_blocks, xor};
use crate::cipher::{BlockCipher, OneBlock};
use crate::util;
use crate::{Error, KeyType};

/// The most message bytes GCM may protect under one key and nonce:
/// 2^39 - 256 bits, the limit at which counter mode would repeat.
const MAX_MESSAGE: u64 = (1 << 36) - 32;

/// The shortest tag SP 800-38D allows, in bytes. Four and eight are
/// for applications the standard names, and are weaker than the rest.
const MIN_TAG: usize = 4;

/// The nonce length the standard singles out, in bytes.
pub(crate) const SHORT_NONCE: usize = 12;

/// The tag length, in bytes.
pub(crate) const TAG: usize = BLOCK;

/// Which way round the hash and the keystream go.
///
/// GHASH covers the ciphertext either way; the two directions differ
/// only in whether that is what arrived or what is about to be
/// produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Hash what the keystream produces.
    Encrypt,
    /// Hash what arrived, then apply the keystream to it.
    Decrypt,
}

/// What the mode keeps for the key: how the bulk work will be done,
/// and whatever that way of doing it works out once.
///
/// Which arm this is is settled when the mode is built, because it is
/// the processor that decides and the processor does not change. On
/// one that has the AES instructions and the carry-less multiply,
/// [`x86_64::Engine`] is a single loop running the cipher and the
/// hash at once. On any other, the counter loop and the hash are
/// called in turn, each still as fast as that processor allows on its
/// own.
// The first arm is much the larger, since it carries the powers of
// the subkey for both of the widths it works in; there is no heap to
// put them on.
#[allow(clippy::large_enum_variant)]
enum Engine<C: BlockCipher<Block = [u8; BLOCK]>> {
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    ))]
    Native(native::Engine<C>),
    /// The counter loop over the cipher's own bulk encrypt, with the
    /// hash run separately.
    Generic,
}

/// By hand rather than derived: an engine holds no cipher, only a
/// pointer to the loop written for one, so it clones whatever `C` is.
impl<C: BlockCipher<Block = [u8; BLOCK]>> Clone for Engine<C> {
    fn clone(&self) -> Self {
        match self {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "riscv64",
                target_arch = "x86_64"
            ))]
            Engine::Native(engine) => Engine::Native(engine.clone()),
            Engine::Generic => Engine::Generic,
        }
    }
}

/// Which implementation to use.
///
/// A caller never names one: the mode takes the best the processor
/// has. The tests and the vector suites do name them, so that every
/// implementation is validated and not only the one this machine
/// would pick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Choice {
    /// The one loop, two blocks to a register.
    Wide,
    /// The one loop, one block to a register.
    Narrow,
    /// The counter loop and the hash, called in turn.
    Generic,
}

/// Every implementation, best first.
pub(crate) const CHOICES: [Choice; 3] =
    [Choice::Wide, Choice::Narrow, Choice::Generic];

impl<C: BlockCipher<Block = [u8; BLOCK]>> Engine<C> {
    /// The best engine for this cipher on this processor, under hash
    /// subkey `h`.
    fn new(h: &[u8; BLOCK]) -> Self {
        for choice in CHOICES {
            if let Some(engine) = Self::with(h, choice) {
                return engine;
            }
        }
        Engine::Generic
    }

    /// The engine `choice` names, or `None` where this processor or
    /// this cipher has no such thing.
    fn with(h: &[u8; BLOCK], choice: Choice) -> Option<Self> {
        let _ = h;
        match choice {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "riscv64",
                target_arch = "x86_64"
            ))]
            Choice::Wide => {
                native::Engine::at_width(h, true).map(Engine::Native)
            }
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "riscv64",
                target_arch = "x86_64"
            ))]
            Choice::Narrow => {
                native::Engine::at_width(h, false).map(Engine::Native)
            }
            Choice::Generic => Some(Engine::Generic),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

/// What one message keeps: the running hash, and whatever else
/// changes as the message goes by.
///
/// Everything settled by the key it borrows from the engine, so
/// starting a message copies nothing that the key already worked out.
enum Hash<'a, C: BlockCipher<Block = [u8; BLOCK]>> {
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    ))]
    Native(native::Hasher<'a, C>),
    Generic {
        hash: Ghash,
        /// What the other arm borrows from the engine. On an
        /// architecture with no such arm nothing is borrowed, and the
        /// lifetime would otherwise go unused.
        engine: core::marker::PhantomData<&'a C>,
    },
}

impl<'a, C: BlockCipher<Block = [u8; BLOCK]>> Hash<'a, C> {
    /// A hash at the start of a message.
    fn new(gcm: &'a Gcm<C>) -> Self {
        match &gcm.engine {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "riscv64",
                target_arch = "x86_64"
            ))]
            Engine::Native(engine) => Hash::Native(native::Hasher::new(engine)),
            Engine::Generic => Hash::Generic {
                hash: Ghash::new(&gcm.h),
                engine: core::marker::PhantomData,
            },
        }
    }

    /// Adds more of the current field to the hash.
    fn hash(&mut self, data: &[u8]) {
        match self {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "riscv64",
                target_arch = "x86_64"
            ))]
            Hash::Native(hasher) => hasher.hash(data),
            Hash::Generic { hash, .. } => hash.update(data),
        }
    }

    /// Ends the current field, padding it with zeros to a block.
    fn pad(&mut self) {
        match self {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "riscv64",
                target_arch = "x86_64"
            ))]
            Hash::Native(hasher) => hasher.pad(),
            Hash::Generic { hash, .. } => hash.pad(),
        }
    }

    /// The hash so far. Every field must have been padded first.
    fn finish(&self) -> [u8; BLOCK] {
        match self {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "riscv64",
                target_arch = "x86_64"
            ))]
            Hash::Native(hasher) => hasher.finish(),
            Hash::Generic { hash, .. } => hash.finish(),
        }
    }

    /// The counter over `data`, which is a whole number of blocks,
    /// and the hash of it.
    fn bulk(
        &mut self,
        cipher: &C,
        counter: &mut [u8; BLOCK],
        direction: Direction,
        data: &mut [u8],
    ) {
        match self {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "riscv64",
                target_arch = "x86_64"
            ))]
            Hash::Native(hasher) => {
                hasher.bulk(cipher, counter, direction, data)
            }
            Hash::Generic { hash, .. } => {
                if direction == Direction::Decrypt {
                    hash.update(data);
                }
                // GCM counts in the last four bytes of the block and
                // wraps inside them, which is what the counter loop
                // does, so there is no boundary to split the run at.
                counter_blocks(cipher, counter, ByteOrder::Big, data);
                if direction == Direction::Encrypt {
                    hash.update(data);
                }
            }
        }
    }
}

/// GCM over a block cipher.
#[derive(Clone)]
pub struct Gcm<C: BlockCipher<Block = [u8; BLOCK]>> {
    cipher: C,
    /// The hash subkey, the cipher applied to a block of zeros.
    h: [u8; BLOCK],
    /// How the bulk work will be done, settled when the mode is
    /// built, along with whatever that way of doing it works out once
    /// for the key.
    engine: Engine<C>,
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> fmt::Debug for Gcm<C> {
    /// Deliberately omits the hash subkey, which is enough to forge
    /// tags, and the cipher.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gcm").finish_non_exhaustive()
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Gcm<C> {
    /// Takes the key the cipher runs under.
    pub fn new(key: &C::Key) -> Self {
        let cipher = C::new(key);
        let mut h = [0u8; BLOCK];
        cipher.encrypt_one(&mut h);
        Gcm {
            engine: Engine::<C>::new(&h),
            cipher,
            h,
        }
    }

    /// The mode over the implementation `choice` names, or `None`
    /// where this processor or this cipher has no such thing.
    ///
    /// For the tests and the vector suites, which run every
    /// implementation rather than only the one [`new`](Self::new)
    /// would take.
    #[cfg(test)]
    pub(crate) fn with_choice(key: &C::Key, choice: Choice) -> Option<Self> {
        let cipher = C::new(key);
        let mut h = [0u8; BLOCK];
        cipher.encrypt_one(&mut h);
        Some(Gcm {
            engine: Engine::<C>::with(&h, choice)?,
            cipher,
            h,
        })
    }

    /// Starts encrypting a message that arrives in pieces.
    ///
    /// The nonce is a slice here, not the fixed
    /// [`Nonce`](Aead::Nonce) the one-shot calls take: GCM accepts one
    /// of any length, and this is the way to use one. Ninety-six bits
    /// is what the standard recommends and what everything else here
    /// assumes, so reach for another length only when a protocol
    /// dictates it.
    pub fn encryptor(&self, nonce: &[u8]) -> Result<Encryptor<'_, C>, Error> {
        Ok(Encryptor {
            core: Core::new(self, nonce)?,
        })
    }

    /// Starts decrypting a message that arrives in pieces.
    ///
    /// Takes a nonce of any length, as
    /// [`encryptor`](Self::encryptor) explains.
    pub fn decryptor(&self, nonce: &[u8]) -> Result<Decryptor<'_, C>, Error> {
        Ok(Decryptor {
            core: Core::new(self, nonce)?,
        })
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> KeyType for Gcm<C> {
    type Key = C::Key;

    fn zero_key() -> Self::Key {
        C::zero_key()
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Aead for Gcm<C> {
    type Nonce = [u8; SHORT_NONCE];
    type Tag = [u8; TAG];

    fn try_new(key: &Self::Key) -> Result<Self, Error> {
        Ok(Gcm::new(key))
    }

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    ) -> Result<(), Error> {
        let mut state = self.encryptor(nonce)?;
        state.aad(aad)?;
        state.update(data)?;
        *tag = state.finalize()?;
        Ok(())
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), Error> {
        let mut state = self.decryptor(nonce)?;
        state.aad(aad)?;
        state.update(data)?;
        match state.verify(tag) {
            Ok(()) => Ok(()),
            Err(e) => {
                data.fill(0);
                Err(e)
            }
        }
    }
}

/// The first counter block, from which everything else follows.
///
/// A 96-bit nonce becomes the counter directly, with a one in the
/// counter field. Any other length is hashed down to a block, which
/// is why that case costs more. An empty nonce is refused: the
/// standard allows it, and it makes every message share a counter.
fn counter_start<C: BlockCipher<Block = [u8; BLOCK]>>(
    gcm: &Gcm<C>,
    nonce: &[u8],
) -> Result<[u8; BLOCK], Error> {
    if nonce.is_empty() {
        return Err(Error::InvalidNonceLength(0));
    }
    if nonce.len() == SHORT_NONCE {
        let mut start = [0u8; BLOCK];
        start[..SHORT_NONCE].copy_from_slice(nonce);
        start[BLOCK - 1] = 1;
        return Ok(start);
    }
    let mut hash = Hash::new(gcm);
    hash.hash(nonce);
    hash.pad();
    let bits = (nonce.len() as u64)
        .checked_mul(8)
        .ok_or(Error::MessageTooLong)?;
    let mut lengths = [0u8; BLOCK];
    lengths[8..].copy_from_slice(&bits.to_be_bytes());
    hash.hash(&lengths);
    Ok(hash.finish())
}

/// Adds one to the last four bytes of the counter, wrapping within
/// them. GCM increments only that field, not the whole block.
fn increment32(counter: &mut [u8; BLOCK]) {
    for byte in counter[BLOCK - 4..].iter_mut().rev() {
        let (sum, carried) = byte.overflowing_add(1);
        *byte = sum;
        if !carried {
            break;
        }
    }
}

/// What both directions share: the counter, the hash, and the lengths
/// that go into the tag.
struct Core<'a, C: BlockCipher<Block = [u8; BLOCK]>> {
    cipher: &'a C,
    /// The hash and the bulk loop, for this message.
    engine: Hash<'a, C>,
    counter: [u8; BLOCK],
    /// The keystream block a previous piece ended inside.
    keystream: [u8; BLOCK],
    used: usize,
    /// The cipher applied to the first counter block, which the tag
    /// is combined with at the end.
    mask: [u8; BLOCK],
    aad_bits: u64,
    message_bytes: u64,
    /// Whether the additional data is finished. It must all arrive
    /// before any of the message.
    started: bool,
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Core<'_, C> {
    /// Debug for whichever direction owns this core: the counts, and
    /// nothing derived from the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
        f.debug_struct(name)
            .field("aad_bits", &self.aad_bits)
            .field("message_bytes", &self.message_bytes)
            .finish_non_exhaustive()
    }
}

impl<'a, C: BlockCipher<Block = [u8; BLOCK]>> Core<'a, C> {
    fn new(gcm: &'a Gcm<C>, nonce: &[u8]) -> Result<Self, Error> {
        let cipher = &gcm.cipher;
        let start = counter_start(gcm, nonce)?;
        let mut mask = start;
        cipher.encrypt_one(&mut mask);
        let mut counter = start;
        increment32(&mut counter);
        Ok(Core {
            cipher,
            engine: Hash::new(gcm),
            counter,
            keystream: [0; BLOCK],
            used: BLOCK,
            mask,
            aad_bits: 0,
            message_bytes: 0,
            started: false,
        })
    }

    fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        // All additional data must come before any of the message.
        if self.started {
            return Err(Error::OutOfOrder);
        }
        let bits = (data.len() as u64)
            .checked_mul(8)
            .and_then(|b| self.aad_bits.checked_add(b))
            .ok_or(Error::MessageTooLong)?;
        self.aad_bits = bits;
        self.engine.hash(data);
        Ok(())
    }

    /// Ends the additional data and counts the message.
    fn begin(&mut self, len: usize) -> Result<(), Error> {
        if !self.started {
            self.engine.pad();
            self.started = true;
        }
        let total = (len as u64)
            .checked_add(self.message_bytes)
            .ok_or(Error::MessageTooLong)?;
        if total > MAX_MESSAGE {
            return Err(Error::MessageTooLong);
        }
        self.message_bytes = total;
        Ok(())
    }

    /// Applies the counter-mode keystream to `data` and hashes the
    /// ciphertext.
    ///
    /// Both are done here rather than by the caller because on a
    /// processor that has an engine for the pair they are one loop
    /// and not two; see [`Engine`].
    fn apply(
        &mut self,
        mut data: &mut [u8],
        direction: Direction,
    ) -> Result<(), Error> {
        // Finish the block a previous piece stopped inside. The bulk
        // loop starts on a block boundary, so this comes first.
        if self.used < BLOCK {
            let take = data.len().min(BLOCK - self.used);
            let (now, rest) = data.split_at_mut(take);
            if direction == Direction::Decrypt {
                self.engine.hash(now);
            }
            xor(now, &self.keystream[self.used..self.used + take]);
            if direction == Direction::Encrypt {
                self.engine.hash(now);
            }
            self.used += take;
            data = rest;
        }

        let (whole, tail) = data.as_chunks_mut::<BLOCK>();
        self.engine.bulk(
            self.cipher,
            &mut self.counter,
            direction,
            whole.as_flattened_mut(),
        );

        if !tail.is_empty() {
            self.keystream = self.counter;
            increment32(&mut self.counter);
            self.cipher.encrypt_one(&mut self.keystream);
            if direction == Direction::Decrypt {
                self.engine.hash(tail);
            }
            xor(tail, &self.keystream);
            if direction == Direction::Encrypt {
                self.engine.hash(tail);
            }
            self.used = tail.len();
        }
        Ok(())
    }

    /// The full-length tag.
    fn tag(&mut self) -> Result<[u8; BLOCK], Error> {
        if !self.started {
            self.engine.pad();
            self.started = true;
        }
        self.engine.pad();

        let mut lengths = [0u8; BLOCK];
        lengths[..8].copy_from_slice(&self.aad_bits.to_be_bytes());
        let message_bits = self
            .message_bytes
            .checked_mul(8)
            .ok_or(Error::MessageTooLong)?;
        lengths[8..].copy_from_slice(&message_bits.to_be_bytes());
        self.engine.hash(&lengths);

        let mut tag = self.engine.finish();
        xor(&mut tag, &self.mask);
        Ok(tag)
    }
}

/// Encrypts one message, a piece at a time.
///
/// All additional data must be given before any of the message.
pub struct Encryptor<'a, C: BlockCipher<Block = [u8; BLOCK]>> {
    core: Core<'a, C>,
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> fmt::Debug for Encryptor<'_, C> {
    /// Says how far along it is and nothing else.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.core.fmt(f, "Encryptor")
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Encryptor<'_, C> {
    /// Adds data that is authenticated but not encrypted.
    ///
    /// Returns [`Error::OutOfOrder`] if called after
    /// [`update`](Self::update): all of it must come first.
    pub fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        self.core.aad(data)
    }

    /// Encrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.core.begin(data.len())?;
        self.core.apply(data, Direction::Encrypt)
    }

    /// Finishes, returning the tag. A protocol that carries a shorter
    /// tag keeps the first bytes of this one; the receiver then checks
    /// it with [`Decryptor::verify_truncated`].
    pub fn finalize(mut self) -> Result<[u8; TAG], Error> {
        self.core.tag()
    }
}

/// Decrypts one message, a piece at a time.
///
/// **The pieces this hands back are not yet authenticated.** Nothing
/// can vouch for any of the message until [`verify`](Self::verify)
/// has checked the tag, so a caller must not act on the plaintext, or
/// let anyone else see it, before that succeeds. Where the whole
/// message fits in memory, use [`Gcm::decrypt`], which checks first.
pub struct Decryptor<'a, C: BlockCipher<Block = [u8; BLOCK]>> {
    core: Core<'a, C>,
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> fmt::Debug for Decryptor<'_, C> {
    /// Says how far along it is and nothing else.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.core.fmt(f, "Decryptor")
    }
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Decryptor<'_, C> {
    /// Adds data that is authenticated but not encrypted.
    ///
    /// Returns [`Error::OutOfOrder`] if called after
    /// [`update`](Self::update): all of it must come first.
    pub fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        self.core.aad(data)
    }

    /// Decrypts the next piece of the message in place, yielding
    /// plaintext that is not yet authenticated.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.core.begin(data.len())?;
        self.core.apply(data, Direction::Decrypt)
    }

    /// Checks `tag`, in time that depends on nothing secret.
    ///
    /// Returns [`Error::AuthenticationFailed`] if it is not the tag
    /// of what was given, and never says more than that.
    pub fn verify(self, tag: &[u8; TAG]) -> Result<(), Error> {
        self.verify_truncated(tag)
    }

    /// Checks a tag that a protocol has cut to between four and
    /// sixteen bytes, the range SP 800-38D allows.
    ///
    /// A shorter tag is a weaker one: an attacker's chance of forging
    /// a message is one in 2^(8n), and the standard limits how many
    /// messages a key may protect under the short ones. That is a
    /// decision for a protocol to make, which is why this method is
    /// named for it rather than reached by handing
    /// [`verify`](Decryptor::verify) a shorter slice. Returns
    /// [`Error::InvalidTagLength`]
    /// outside the range and [`Error::AuthenticationFailed`] for a
    /// wrong tag.
    pub fn verify_truncated(mut self, tag: &[u8]) -> Result<(), Error> {
        if !(MIN_TAG..=TAG).contains(&tag.len()) {
            return Err(Error::InvalidTagLength(tag.len()));
        }
        let full = self.core.tag()?;
        if util::equal(&full[..tag.len()], tag) {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::Key;
    use crate::cipher::aes::{Aes, Aes128, portable};
    use std::vec::Vec;

    /// Buffers big enough for every case below.
    const MAX: usize = 64;

    fn unhex<'a>(text: &str, buffer: &'a mut [u8]) -> &'a [u8] {
        let n = text.len() / 2;
        for i in 0..n {
            buffer[i] =
                u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        &buffer[..n]
    }

    /// The published GCM test cases: key, nonce, additional data,
    /// plaintext, ciphertext, tag.
    const CASES: [[&str; 6]; 7] = [
        // A nonce that is not 96 bits, so it is hashed first.
        [
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbad",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a\
             721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c74\
             2373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
            "3612d2e79e3b0785561be14aaca2fccb",
        ],
        // Empty message and no additional data.
        [
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        ],
        // One block, still nothing to authenticate alongside.
        [
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        ],
        // Four whole blocks.
        [
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a\
             721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aaf\
             d255",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca1\
             2e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f\
             5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        ],
        // Additional data, and a message that is not whole blocks.
        [
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a\
             721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca1\
             2e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47",
        ],
        // AES-192.
        [
            "feffe9928665731c6d6a8f9467308308feffe9928665731c",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a\
             721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e1\
             9c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
            "2519498e80f1478f37ba55bd6d27618c",
        ],
        // AES-256.
        [
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f94673083\
             08",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a\
             721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1\
             aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        ],
    ];

    #[test]
    fn published_test_cases() {
        for (i, case) in CASES.iter().enumerate() {
            let (mut kb, mut nb) = ([0u8; 32], [0u8; 32]);
            let (mut ab, mut pb) = ([0u8; MAX], [0u8; MAX]);
            let (mut cb, mut tb) = ([0u8; MAX], [0u8; 16]);
            let key = unhex(case[0], &mut kb);
            let nonce = unhex(case[1], &mut nb);
            let aad = unhex(case[2], &mut ab);
            let plain = unhex(case[3], &mut pb);
            let cipher = unhex(case[4], &mut cb);
            unhex(case[5], &mut tb);
            let tag = &tb;

            match key.len() {
                16 => run_case::<16>(i, key, nonce, aad, plain, cipher, tag),
                24 => run_case::<24>(i, key, nonce, aad, plain, cipher, tag),
                _ => run_case::<32>(i, key, nonce, aad, plain, cipher, tag),
            }
        }
    }

    fn run_case<const K: usize>(
        i: usize,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plain: &[u8],
        cipher: &[u8],
        tag: &[u8; 16],
    ) {
        let key: &[u8; K] = key.try_into().unwrap();
        let gcm = Gcm::<Aes<K>>::new(&Key::from(*key));
        let mut data = [0u8; MAX];
        let data = &mut data[..plain.len()];
        data.copy_from_slice(plain);
        let mut got = [0u8; 16];

        // The vectors carry nonces of several lengths. The one-shot
        // calls take the standard twelve bytes, so the others go
        // through the incremental form, which is where GCM's general
        // nonce lives.
        match <&[u8; SHORT_NONCE]>::try_from(nonce) {
            Ok(nonce) => gcm.encrypt(nonce, aad, data, &mut got).unwrap(),
            Err(_) => {
                let mut state = gcm.encryptor(nonce).unwrap();
                state.aad(aad).unwrap();
                state.update(data).unwrap();
                got = state.finalize().unwrap();
            }
        }
        assert_eq!(data, cipher, "case {i} ciphertext");
        assert_eq!(&got, tag, "case {i} tag");

        match <&[u8; SHORT_NONCE]>::try_from(nonce) {
            Ok(nonce) => gcm.decrypt(nonce, aad, data, tag).unwrap(),
            Err(_) => {
                let mut state = gcm.decryptor(nonce).unwrap();
                state.aad(aad).unwrap();
                state.update(data).unwrap();
                state.verify(tag).unwrap();
            }
        }
        assert_eq!(data, plain, "case {i} plaintext");
    }

    fn gcm() -> Gcm<Aes128> {
        Gcm::new(&Key::from([0x42u8; 16]))
    }

    /// Anything altered must be rejected, and the buffer wiped rather
    /// than left holding plaintext that was never authenticated.
    #[test]
    fn rejects_an_empty_nonce() {
        let gcm = gcm();
        assert_eq!(
            gcm.encryptor(&[]).err(),
            Some(Error::InvalidNonceLength(0))
        );
    }

    #[test]
    fn rejects_and_wipes() {
        let gcm = gcm();
        let nonce = [7u8; 12];
        let aad = [1u8, 2, 3];
        let plain = [9u8; 20];

        let mut sealed = plain;
        let mut tag = [0u8; 16];
        gcm.encrypt(&nonce, &aad, &mut sealed, &mut tag).unwrap();

        // A wrong tag.
        let mut wrong = tag;
        wrong[0] ^= 1;
        let mut data = sealed;
        assert_eq!(
            gcm.decrypt(&nonce, &aad, &mut data, &wrong).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(data, [0u8; 20], "buffer wiped");

        // Altered ciphertext.
        let mut data = sealed;
        data[0] ^= 1;
        assert_eq!(
            gcm.decrypt(&nonce, &aad, &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );

        // Altered additional data.
        let mut data = sealed;
        assert_eq!(
            gcm.decrypt(&nonce, &[1, 2, 4], &mut data, &tag)
                .unwrap_err(),
            Error::AuthenticationFailed
        );

        // A different nonce.
        let mut data = sealed;
        assert_eq!(
            gcm.decrypt(&[8u8; 12], &aad, &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    /// A truncated tag is a prefix of the full one, and only the
    /// lengths the standard allows are accepted.
    #[test]
    fn truncated_tags() {
        let gcm = gcm();
        let nonce = [3u8; 12];
        let mut full = [0u8; 16];
        gcm.encrypt(&nonce, b"", &mut [], &mut full).unwrap();

        for n in [4, 8, 12, 13, 14, 15, 16] {
            let d = gcm.decryptor(&nonce).unwrap();
            d.verify_truncated(&full[..n]).unwrap();
            let mut wrong = full;
            wrong[n - 1] ^= 1;
            let d = gcm.decryptor(&nonce).unwrap();
            assert_eq!(
                d.verify_truncated(&wrong[..n]).unwrap_err(),
                Error::AuthenticationFailed,
                "{n}-byte tag"
            );
        }
        let long = [0u8; 32];
        for n in [0, 1, 2, 3, 17, 32] {
            let d = gcm.decryptor(&nonce).unwrap();
            assert_eq!(
                d.verify_truncated(&long[..n]).unwrap_err(),
                Error::InvalidTagLength(n)
            );
        }
    }

    #[test]
    fn debug_shows_no_secrets() {
        struct Buffer([u8; 128], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let gcm = gcm();
        let mut buffer = Buffer([0; 128], 0);
        core::fmt::write(&mut buffer, format_args!("{gcm:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert_eq!(text, "Gcm { .. }");
        let e = gcm.encryptor(&[0; 12]).unwrap();
        let mut buffer = Buffer([0; 128], 0);
        core::fmt::write(&mut buffer, format_args!("{e:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(text.starts_with("Encryptor {"));
        assert!(!text.contains("42"), "{text}");
    }

    /// Pieces must match one call, including additional data given in
    /// several parts and a message split inside a block.
    #[test]
    fn pieces_match_one_call() {
        let gcm = gcm();
        let nonce = [5u8; 12];
        let aad = [1u8; 25];
        let mut plain = [0u8; 50];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }

        let mut whole = plain;
        let mut tag = [0u8; 16];
        gcm.encrypt(&nonce, &aad, &mut whole, &mut tag).unwrap();

        for split in [1, 7, 16, 17, 32, 49] {
            let mut pieces = plain;
            let mut e = gcm.encryptor(&nonce).unwrap();
            e.aad(&aad[..10]).unwrap();
            e.aad(&aad[10..]).unwrap();
            let (a, b) = pieces.split_at_mut(split);
            e.update(a).unwrap();
            e.update(b).unwrap();
            assert_eq!(
                e.finalize().unwrap(),
                tag,
                "encrypt tag, split {split}"
            );
            assert_eq!(pieces, whole, "encrypt, split {split}");

            let mut d = gcm.decryptor(&nonce).unwrap();
            d.aad(&aad).unwrap();
            let (a, b) = pieces.split_at_mut(split);
            d.update(a).unwrap();
            d.update(b).unwrap();
            d.verify(&tag).unwrap();
            assert_eq!(pieces, plain, "decrypt, split {split}");
        }

        // A byte at a time, which leaves both the keystream and the
        // hash part way through a block at every step.
        let mut pieces = plain;
        let mut e = gcm.encryptor(&nonce).unwrap();
        for byte in aad.iter() {
            e.aad(core::slice::from_ref(byte)).unwrap();
        }
        for byte in pieces.iter_mut() {
            e.update(core::slice::from_mut(byte)).unwrap();
        }
        assert_eq!(e.finalize().unwrap(), tag, "encrypt tag, byte at a time");
        assert_eq!(pieces, whole, "encrypt, byte at a time");
    }

    /// The engine that runs the cipher and the hash together must
    /// agree with the two run in turn, at every length around the
    /// group boundaries it works in and with the pieces landing
    /// anywhere.
    ///
    /// The other side of the comparison is GCM over the portable
    /// cipher, whose key schedule the AES instructions cannot read,
    /// so it always gets the generic engine. AES is AES, so the two
    /// must produce the same ciphertext and the same tag.
    #[test]
    fn the_engines_agree() {
        const MAX: usize = 9 * 16 * BLOCK + 3;
        let key = [0x9du8; 16];
        let generic = Gcm::<portable::bitsliced::Aes<16>>::new(&Key::from(key));
        // Every implementation this processor has, not only the one
        // the mode would pick.
        let all: Vec<Gcm<Aes128>> = CHOICES
            .iter()
            .filter_map(|&c| Gcm::<Aes128>::with_choice(&Key::from(key), c))
            .collect();
        assert!(!all.is_empty(), "no implementation to test");
        let nonce = [0x33u8; 12];
        let aad = [0x77u8; 21];

        let mut message = [0u8; MAX];
        for (i, b) in message.iter_mut().enumerate() {
            *b = (i * 5 + 1) as u8;
        }

        // Every length either side of the first few group boundaries,
        // then a spread of longer ones.
        // Either side of both group widths, and well past both.
        let edges = [
            255, 256, 257, 383, 384, 385, 511, 512, 513, 639, 640, 641, 767,
            768, 1024, 1279, 1280, 2047, MAX,
        ];
        for len in (0..300).chain(edges) {
            let (mut a, mut b) = ([0u8; MAX], [0u8; MAX]);
            a[..len].copy_from_slice(&message[..len]);
            b[..len].copy_from_slice(&message[..len]);
            let (mut ta, mut tb) = ([0u8; TAG], [0u8; TAG]);
            generic
                .encrypt(&nonce, &aad, &mut b[..len], &mut tb)
                .unwrap();
            for (i, native) in all.iter().enumerate() {
                a[..len].copy_from_slice(&message[..len]);
                native
                    .encrypt(&nonce, &aad, &mut a[..len], &mut ta)
                    .unwrap();
                assert_eq!(a[..len], b[..len], "ciphertext, {len}, {i}");
                assert_eq!(ta, tb, "tag, {len} bytes, {i}");
                native.decrypt(&nonce, &aad, &mut a[..len], &ta).unwrap();
                assert_eq!(a[..len], message[..len], "plaintext, {len}, {i}");
            }

            // The same message in pieces, which leaves the hash and
            // the keystream part way through a block, where the bulk
            // loop cannot start and has to give way.
            for (piece, native) in
                [1, 17, 128, 129].into_iter().zip(all.iter().cycle())
            {
                let mut c = [0u8; MAX];
                c[..len].copy_from_slice(&message[..len]);
                let mut e = native.encryptor(&nonce).unwrap();
                e.aad(&aad).unwrap();
                for part in c[..len].chunks_mut(piece) {
                    e.update(part).unwrap();
                }
                assert_eq!(e.finalize().unwrap(), tb, "tag, {len} in {piece}");
                assert_eq!(c[..len], b[..len], "{len} bytes in {piece}");

                let mut d = native.decryptor(&nonce).unwrap();
                d.aad(&aad).unwrap();
                for part in c[..len].chunks_mut(piece) {
                    d.update(part).unwrap();
                }
                d.verify(&tb).unwrap();
                assert_eq!(c[..len], message[..len], "{len} in {piece}");
            }
        }
    }

    /// Encrypts through the incremental form, which is what takes a
    /// nonce of any length.
    fn seal<C: BlockCipher<Block = [u8; BLOCK]>>(
        gcm: &Gcm<C>,
        nonce: &[u8],
        data: &mut [u8],
        tag: &mut [u8; TAG],
    ) {
        let mut state = gcm.encryptor(nonce).unwrap();
        state.aad(b"x").unwrap();
        state.update(data).unwrap();
        *tag = state.finalize().unwrap();
    }

    /// A nonce that is not ninety-six bits is hashed down to a
    /// counter block, which the engine does with its own hash. Both
    /// engines must reach the same block.
    #[test]
    fn the_engines_agree_on_a_long_nonce() {
        let key = [0x11u8; 16];
        let native = Gcm::<Aes128>::new(&Key::from(key));
        let generic = Gcm::<portable::bitsliced::Aes<16>>::new(&Key::from(key));
        for len in [1, 8, 15, 16, 17, 128, 129] {
            let nonce = std::vec![0xa5u8; len];
            let mut a = [7u8; 40];
            let mut b = a;
            let (mut ta, mut tb) = ([0u8; TAG], [0u8; TAG]);
            seal(&native, &nonce, &mut a, &mut ta);
            seal(&generic, &nonce, &mut b, &mut tb);
            assert_eq!(a, b, "{len}-byte nonce");
            assert_eq!(ta, tb, "{len}-byte nonce tag");
        }
    }

    /// The engine written for the pair is not merely present but
    /// chosen: on a processor that has one, our own AES must get it.
    #[test]
    fn the_native_engine_is_chosen_where_there_is_one() {
        #[cfg(target_arch = "x86_64")]
        {
            if !x86_64::supported() {
                // Nothing to check on a processor without them.
                return;
            }
            let key = Key::from([0u8; 16]);
            let gcm = Gcm::<Aes128>::new(&key);
            assert!(matches!(gcm.engine, Engine::Native(_)));
            // And the portable cipher, whose schedule those
            // instructions cannot read, does not.
            let other = Gcm::<portable::bitsliced::Aes<16>>::new(&key);
            assert!(matches!(other.engine, Engine::Generic));

            // The generic one is always to be had, and the narrower
            // of the two written out is too wherever this test runs
            // at all, so both are validated and not just the one this
            // machine would take.
            assert!(Gcm::<Aes128>::with_choice(&key, Choice::Narrow).is_some());
            assert!(
                Gcm::<Aes128>::with_choice(&key, Choice::Generic).is_some()
            );
        }
    }

    #[test]
    fn additional_data_after_the_message_is_refused() {
        let gcm = gcm();
        let mut e = gcm.encryptor(&[0; 12]).unwrap();
        e.update(&mut [0; 4]).unwrap();
        assert_eq!(e.aad(b"too late").unwrap_err(), Error::OutOfOrder);
        let mut d = gcm.decryptor(&[0; 12]).unwrap();
        d.update(&mut [0; 4]).unwrap();
        assert_eq!(d.aad(b"too late").unwrap_err(), Error::OutOfOrder);
    }
}
