//! ChaCha20 (RFC 8439): a stream cipher.
//!
//! ChaCha20 turns a 256-bit key, a 96-bit nonce and a 32-bit block
//! counter into a keystream, sixty-four bytes a block, and a message
//! is xored with it. There is no block cipher underneath: the block
//! function is twenty rounds of additions, rotations and xors on
//! sixteen 32-bit words, which run at full speed on any processor
//! without special instructions and never touch memory in a way
//! that depends on the key.
//!
//! ```
//! use scytale::cipher::chacha20::ChaCha20;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let cipher = ChaCha20::try_new(&[0x42; 32])?;
//! let nonce = [0u8; 12];
//! let mut message = *b"attack at dawn";
//! cipher.encrypt(&nonce, 1, &mut message)?;
//! cipher.decrypt(&nonce, 1, &mut message)?;
//! assert_eq!(&message, b"attack at dawn");
//! # Ok(())
//! # }
//! ```
//!
//! # Using it safely
//!
//! - **Never reuse a nonce with the same key.** Two messages under
//!   the same key and nonce are xored with the same keystream, and
//!   the xor of the two messages falls straight out. Count nonces,
//!   or draw them from a source that cannot repeat.
//! - **This authenticates nothing.** Anyone can flip bits of the
//!   ciphertext and flip the same bits of the message. Use
//!   [`ChaCha20Poly1305`](crate::cipher::mode::ChaCha20Poly1305),
//!   which is this cipher under a MAC, unless a protocol supplies
//!   its own authentication.
//! - The counter is 32 bits, so one nonce carries at most 256 GiB;
//!   [`Error::MessageTooLong`] is returned rather than wrapping.
//!   RFC 8439 starts the counter at one when a Poly1305 key has been
//!   taken from block zero; on its own the cipher accepts any start.
//!
//! # Speed
//!
//! Every block is independent, so the processor's vector unit can
//! compute several at once: eight with AVX2 on x86-64, four with
//! NEON on AArch64, and as many as the registers hold with the
//! RISC-V vector extension and Zvbb's rotates. Each is reachable by
//! name in the module for its architecture; [`ChaCha20`] picks the
//! best the processor has. The portable code works four blocks at a
//! time in a form the compiler vectorises where it can.

#![allow(unsafe_code)]

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
pub mod portable;
#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

/// The key length, in bytes.
pub const KEY_SIZE: usize = 32;

/// The nonce length, in bytes.
pub const NONCE_SIZE: usize = 12;

/// Bytes of keystream per block.
pub const BLOCK_SIZE: usize = 64;

/// The first four words of every state: "expand 32-byte k".
pub(crate) const CONSTANTS: [u32; 4] =
    [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// Keeps the backend trait to this crate's own implementations.
mod sealed {
    pub trait Sealed {}
}
pub(crate) use sealed::Sealed;

/// A keystream generator. Sealed.
pub trait Backend: Sealed {
    /// Whether this processor can run it.
    fn supported() -> bool;

    /// Xors the keystream for consecutive blocks from `counter` into
    /// `data`, whose length is a whole number of blocks.
    ///
    /// # Safety
    /// [`supported`](Backend::supported) must have returned true on
    /// this processor.
    unsafe fn xor(
        key: &[u32; 8],
        nonce: &[u32; 3],
        counter: u32,
        data: &mut [u8],
    );
}

/// The key as the words the block function takes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Key([u32; 8]);

impl Key {
    fn try_new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KEY_SIZE {
            return Err(Error::InvalidKeyLength(key.len()));
        }
        let mut words = [0u32; 8];
        for (w, bytes) in words.iter_mut().zip(key.chunks_exact(4)) {
            *w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        Ok(Key(words))
    }
}

/// The nonce as words.
fn nonce_words(nonce: &[u8; NONCE_SIZE]) -> [u32; 3] {
    let mut words = [0u32; 3];
    for (w, bytes) in words.iter_mut().zip(nonce.chunks_exact(4)) {
        *w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    words
}

/// ChaCha20 over the keystream generator `B`. The type for callers
/// is [`ChaCha20`], which picks `B`; the per-architecture modules
/// name the others.
pub struct Cipher<B: Backend> {
    key: Key,
    _marker: PhantomData<B>,
}

impl<B: Backend> Cipher<B> {
    /// Takes `key`, which must be 32 bytes.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        if !B::supported() {
            return Err(Error::NotSupported);
        }
        // SAFETY: just confirmed.
        unsafe { Self::new_unchecked(key) }
    }

    /// Takes `key` without asking the processor.
    ///
    /// # Safety
    /// The caller must have confirmed `B::supported()`.
    pub(crate) unsafe fn new_unchecked(key: &[u8]) -> Result<Self, Error> {
        Ok(Cipher {
            key: Key::try_new(key)?,
            _marker: PhantomData,
        })
    }

    /// Encrypts `data` in place, its first byte at the start of
    /// block `counter`.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.stream(nonce, counter).update(data)
    }

    /// Decrypts `data` in place, its first byte at the start of
    /// block `counter`.
    ///
    /// This is the same operation as [`encrypt`](Self::encrypt): the
    /// keystream does not depend on the message. Both names exist so
    /// that calling code reads the way it means.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.stream(nonce, counter).update(data)
    }

    /// Starts a message that arrives in pieces.
    pub fn stream(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> Stream<'_, B> {
        Stream {
            cipher: self,
            nonce: nonce_words(nonce),
            counter: u64::from(counter),
            keystream: [0; BLOCK_SIZE],
            used: BLOCK_SIZE,
        }
    }

    /// One block of keystream, as the AEAD takes its Poly1305 key.
    pub(crate) fn keystream_block(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        // SAFETY: the cipher only exists once support was confirmed.
        unsafe { B::xor(&self.key.0, &nonce_words(nonce), counter, &mut block) }
        block
    }
}

impl<B: Backend> Clone for Cipher<B> {
    fn clone(&self) -> Self {
        Cipher {
            key: self.key.clone(),
            _marker: PhantomData,
        }
    }
}

// The key wipes itself; this only says so.
impl<B: Backend> ZeroizeOnDrop for Cipher<B> {}

impl<B: Backend> fmt::Debug for Cipher<B> {
    /// Deliberately omits the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChaCha20").finish_non_exhaustive()
    }
}

/// A message in progress: the keystream position, and any of the
/// current block not yet used.
pub struct Stream<'a, B: Backend> {
    cipher: &'a Cipher<B>,
    nonce: [u32; 3],
    /// The block the next fresh keystream comes from. Wider than the
    /// counter so that using the last block is recorded rather than
    /// wrapped round.
    counter: u64,
    keystream: [u8; BLOCK_SIZE],
    used: usize,
}

impl<B: Backend> Stream<'_, B> {
    /// Encrypts or decrypts the next piece of the message in place.
    ///
    /// Returns [`Error::MessageTooLong`] if the piece would take the
    /// block counter past 2^32, leaving `data` untouched.
    pub fn update(&mut self, mut data: &mut [u8]) -> Result<(), Error> {
        let fresh = data.len().saturating_sub(BLOCK_SIZE - self.used);
        let blocks = fresh.div_ceil(BLOCK_SIZE) as u64;
        if self.counter + blocks > 1 << 32 {
            return Err(Error::MessageTooLong);
        }

        // What is left of the current block first.
        if self.used < BLOCK_SIZE {
            let take = (BLOCK_SIZE - self.used).min(data.len());
            let (now, rest) = data.split_at_mut(take);
            for (d, k) in now.iter_mut().zip(&self.keystream[self.used..]) {
                *d ^= k;
            }
            self.used += take;
            data = rest;
        }

        // Whole blocks straight through the backend.
        let whole = data.len() - data.len() % BLOCK_SIZE;
        let (now, rest) = data.split_at_mut(whole);
        if !now.is_empty() {
            // SAFETY: the cipher only exists once support was
            // confirmed.
            unsafe {
                B::xor(
                    &self.cipher.key.0,
                    &self.nonce,
                    self.counter as u32,
                    now,
                )
            }
            self.counter += (whole / BLOCK_SIZE) as u64;
        }

        // A last partial block, keeping the rest of its keystream.
        if !rest.is_empty() {
            self.keystream = [0; BLOCK_SIZE];
            // SAFETY: as above.
            unsafe {
                B::xor(
                    &self.cipher.key.0,
                    &self.nonce,
                    self.counter as u32,
                    &mut self.keystream,
                )
            }
            self.counter += 1;
            for (d, k) in rest.iter_mut().zip(&self.keystream) {
                *d ^= k;
            }
            self.used = rest.len();
        }
        Ok(())
    }
}

impl<B: Backend> Drop for Stream<'_, B> {
    /// The keystream is as secret as the key.
    fn drop(&mut self) {
        self.keystream.zeroize();
        self.nonce.zeroize();
        self.counter.zeroize();
        self.used.zeroize();
    }
}

impl<B: Backend> ZeroizeOnDrop for Stream<'_, B> {}

impl<B: Backend> fmt::Debug for Stream<'_, B> {
    /// Deliberately omits the keystream.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

/// The implementation the processor gets, chosen once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Choice {
    Avx2,
    Neon,
    Zvbb,
    Portable,
}

/// Candidates in order of preference; the portable code is last so
/// the search always ends.
const CHOICES: [Choice; 4] =
    [Choice::Avx2, Choice::Neon, Choice::Zvbb, Choice::Portable];

/// The probe result: 0 until probed, then one plus the index into
/// `CHOICES`. Probing is idempotent, so a race between two first
/// callers is harmless.
static PROBED: AtomicU8 = AtomicU8::new(0);

/// Asks the processor once; afterwards a single atomic load.
fn probe() -> Choice {
    match PROBED.load(Ordering::Relaxed) {
        0 => {
            let found = CHOICES
                .into_iter()
                .enumerate()
                .find(|&(_, c)| supported(c))
                .unwrap_or((3, Choice::Portable));
            PROBED.store(found.0 as u8 + 1, Ordering::Relaxed);
            found.1
        }
        n => CHOICES
            .get(usize::from(n) - 1)
            .copied()
            .unwrap_or(Choice::Portable),
    }
}

/// Whether the processor can run `choice`.
fn supported(choice: Choice) -> bool {
    match choice {
        #[cfg(target_arch = "x86_64")]
        Choice::Avx2 => <x86_64::Avx2 as Backend>::supported(),
        #[cfg(target_arch = "aarch64")]
        Choice::Neon => <aarch64::Neon as Backend>::supported(),
        #[cfg(target_arch = "riscv64")]
        Choice::Zvbb => <riscv64::Zvbb as Backend>::supported(),
        Choice::Portable => true,
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

/// Applies a method to whichever implementation is in use.
macro_rules! dispatch {
    ($value:expr, $inner:ident, $x:ident => $body:expr) => {
        match $value {
            #[cfg(target_arch = "x86_64")]
            $inner::Avx2($x) => $body,
            #[cfg(target_arch = "aarch64")]
            $inner::Neon($x) => $body,
            #[cfg(target_arch = "riscv64")]
            $inner::Zvbb($x) => $body,
            $inner::Portable($x) => $body,
        }
    };
}

/// ChaCha20 using the best implementation the processor supports.
///
/// The processor is probed once, the first time a key is taken;
/// every later [`ChaCha20::try_new`] reads the cached answer, and
/// each call then dispatches with a single predictable branch.
#[derive(Clone)]
pub struct ChaCha20(Inner);

#[derive(Clone)]
enum Inner {
    #[cfg(target_arch = "x86_64")]
    Avx2(Cipher<x86_64::Avx2>),
    #[cfg(target_arch = "aarch64")]
    Neon(Cipher<aarch64::Neon>),
    #[cfg(target_arch = "riscv64")]
    Zvbb(Cipher<riscv64::Zvbb>),
    Portable(Cipher<portable::Portable>),
}

/// A message in progress under [`ChaCha20`].
pub struct AutoStream<'a>(InnerStream<'a>);

enum InnerStream<'a> {
    #[cfg(target_arch = "x86_64")]
    Avx2(Stream<'a, x86_64::Avx2>),
    #[cfg(target_arch = "aarch64")]
    Neon(Stream<'a, aarch64::Neon>),
    #[cfg(target_arch = "riscv64")]
    Zvbb(Stream<'a, riscv64::Zvbb>),
    Portable(Stream<'a, portable::Portable>),
}

impl ChaCha20 {
    /// Takes `key`, which must be 32 bytes, with the best
    /// implementation the processor supports.
    // The hardware constructors skip their own processor check
    // because the probe has already made it.
    #[allow(unsafe_code)]
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        // SAFETY: `probe` only names hardware after confirming the
        // processor supports it.
        let inner = unsafe {
            match probe() {
                #[cfg(target_arch = "x86_64")]
                Choice::Avx2 => Inner::Avx2(Cipher::new_unchecked(key)?),
                #[cfg(target_arch = "aarch64")]
                Choice::Neon => Inner::Neon(Cipher::new_unchecked(key)?),
                #[cfg(target_arch = "riscv64")]
                Choice::Zvbb => Inner::Zvbb(Cipher::new_unchecked(key)?),
                _ => Inner::Portable(Cipher::new_unchecked(key)?),
            }
        };
        Ok(ChaCha20(inner))
    }

    /// Encrypts `data` in place, its first byte at the start of
    /// block `counter`.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        dispatch!(&self.0, Inner, c => c.encrypt(nonce, counter, data))
    }

    /// Decrypts `data` in place; the same operation as
    /// [`encrypt`](Self::encrypt).
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        dispatch!(&self.0, Inner, c => c.decrypt(nonce, counter, data))
    }

    /// Starts a message that arrives in pieces.
    pub fn stream(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> AutoStream<'_> {
        AutoStream(match &self.0 {
            #[cfg(target_arch = "x86_64")]
            Inner::Avx2(c) => InnerStream::Avx2(c.stream(nonce, counter)),
            #[cfg(target_arch = "aarch64")]
            Inner::Neon(c) => InnerStream::Neon(c.stream(nonce, counter)),
            #[cfg(target_arch = "riscv64")]
            Inner::Zvbb(c) => InnerStream::Zvbb(c.stream(nonce, counter)),
            Inner::Portable(c) => {
                InnerStream::Portable(c.stream(nonce, counter))
            }
        })
    }

    /// One block of keystream, as the AEAD takes its Poly1305 key.
    pub(crate) fn keystream_block(
        &self,
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> [u8; BLOCK_SIZE] {
        dispatch!(&self.0, Inner, c => c.keystream_block(nonce, counter))
    }
}

impl AutoStream<'_> {
    /// Encrypts or decrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        dispatch!(&mut self.0, InnerStream, s => s.update(data))
    }
}

impl fmt::Debug for ChaCha20 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dispatch!(&self.0, Inner, c => c.fmt(f))
    }
}

impl fmt::Debug for AutoStream<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dispatch!(&self.0, InnerStream, s => s.fmt(f))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(s.len(), 2 * N);
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    /// RFC 8439 section 2.4.2: the sunscreen message.
    pub(crate) const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    const NONCE: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    const PLAIN: &[u8; 114] = b"Ladies and Gentlemen of the class of '99: \
        If I could offer you only one tip for the future, sunscreen would \
        be it.";
    const CIPHER: &str = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a\
        27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c\
        359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7\
        7937365af90bbf74a35be6b40b8eedf2785e42874d";

    /// Checks one implementation against the RFC's worked examples.
    pub(crate) fn check_known_answers<B: Backend>() {
        let cipher = Cipher::<B>::try_new(&KEY).unwrap();
        let mut data = *PLAIN;
        cipher.encrypt(&NONCE, 1, &mut data).unwrap();
        assert_eq!(data, hex::<114>(CIPHER));
        cipher.decrypt(&NONCE, 1, &mut data).unwrap();
        assert_eq!(&data, PLAIN);

        // Section 2.3.2: the block function on its own.
        let cipher = Cipher::<B>::try_new(&KEY).unwrap();
        let nonce = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let block = cipher.keystream_block(&nonce, 1);
        assert_eq!(block[..16], hex::<16>("10f1e7e4d13b5915500fdd1fa32071c4"));
        assert_eq!(block[48..], hex::<16>("b5129cd1de164eb9cbd083e8a2503c4e"));

        // Section 2.6.2: the Poly1305 key generation block.
        let key = hex::<32>(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e\
             9f",
        );
        let cipher = Cipher::<B>::try_new(&key).unwrap();
        let nonce = hex::<12>("000000000001020304050607");
        assert_eq!(
            cipher.keystream_block(&nonce, 0)[..32],
            hex::<32>(
                "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1\
                 a646"
            )
        );
    }

    /// Checks one implementation against the portable one over many
    /// lengths, counters and chunkings.
    pub(crate) fn check_matches_portable<B: Backend>() {
        let cipher = Cipher::<B>::try_new(&KEY).unwrap();
        let reference = Cipher::<portable::Portable>::try_new(&KEY).unwrap();
        let data: [u8; 1100] = core::array::from_fn(|i| (i * 13 + 7) as u8);
        for len in [
            0usize, 1, 63, 64, 65, 127, 128, 255, 256, 257, 511, 512, 513,
            1024, 1100,
        ] {
            for counter in [0u32, 1, 7, u32::MAX - 20] {
                let mut want = data;
                let mut got = data;
                let want_result =
                    reference.encrypt(&NONCE, counter, &mut want[..len]);
                let got_result =
                    cipher.encrypt(&NONCE, counter, &mut got[..len]);
                assert_eq!(
                    want_result, got_result,
                    "len {len} counter {counter}"
                );
                assert_eq!(
                    want[..len],
                    got[..len],
                    "len {len} counter {counter}"
                );
                // The same message in pieces.
                let mut pieces = data;
                let mut stream = cipher.stream(&NONCE, counter);
                let mut ok = Ok(());
                for chunk in pieces[..len].chunks_mut(37) {
                    ok = ok.and(stream.update(chunk));
                }
                assert_eq!(
                    ok, got_result,
                    "len {len} counter {counter} pieces"
                );
                if ok.is_ok() {
                    assert_eq!(pieces[..len], want[..len], "len {len} pieces");
                }
            }
        }
    }

    #[test]
    fn known_answers() {
        let cipher = ChaCha20::try_new(&KEY).unwrap();
        let mut data = *PLAIN;
        cipher.encrypt(&NONCE, 1, &mut data).unwrap();
        assert_eq!(data, hex::<114>(CIPHER));
    }

    #[test]
    fn matches_portable() {
        let cipher = ChaCha20::try_new(&KEY).unwrap();
        let reference = Cipher::<portable::Portable>::try_new(&KEY).unwrap();
        let mut a = [0x5au8; 1000];
        let mut b = a;
        cipher.encrypt(&NONCE, 3, &mut a).unwrap();
        reference.encrypt(&NONCE, 3, &mut b).unwrap();
        assert_eq!(a[..], b[..]);
    }

    #[test]
    fn pieces_match_whole() {
        let cipher = ChaCha20::try_new(&KEY).unwrap();
        let data: [u8; 517] = core::array::from_fn(|i| (i * 31) as u8);
        let mut whole = data;
        cipher.encrypt(&NONCE, 5, &mut whole).unwrap();
        for chunk in [1, 3, 63, 64, 65, 100, 517] {
            let mut pieces = data;
            let mut stream = cipher.stream(&NONCE, 5);
            for piece in pieces.chunks_mut(chunk) {
                stream.update(piece).unwrap();
            }
            assert_eq!(pieces[..], whole[..], "chunk {chunk}");
        }
    }

    #[test]
    fn rejects_wrong_key_length() {
        for n in [0, 16, 31, 33, 64] {
            assert_eq!(
                ChaCha20::try_new(&[0u8; 64][..n]).err(),
                Some(Error::InvalidKeyLength(n))
            );
        }
    }

    #[test]
    fn refuses_to_wrap_the_counter() {
        let cipher = ChaCha20::try_new(&KEY).unwrap();
        let mut data = [0u8; 129];
        // Two blocks and a byte from the last block: the third block
        // does not exist.
        assert_eq!(
            cipher.encrypt(&NONCE, u32::MAX - 1, &mut data),
            Err(Error::MessageTooLong)
        );
        assert_eq!(data, [0u8; 129]);
        // Exactly the last two blocks is fine.
        assert_eq!(
            cipher.encrypt(&NONCE, u32::MAX - 1, &mut data[..128]),
            Ok(())
        );
        // And a stream that has consumed the last block cannot go on.
        let mut stream = cipher.stream(&NONCE, u32::MAX);
        assert_eq!(stream.update(&mut data[..10]), Ok(()));
        assert_eq!(stream.update(&mut data[..54]), Ok(()));
        assert_eq!(stream.update(&mut data[..1]), Err(Error::MessageTooLong));
    }

    #[test]
    fn every_implementation_zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Cipher<portable::Portable>>();
        wipes::<Stream<'static, portable::Portable>>();
        #[cfg(target_arch = "x86_64")]
        wipes::<Cipher<x86_64::Avx2>>();
        #[cfg(target_arch = "aarch64")]
        wipes::<Cipher<aarch64::Neon>>();
        #[cfg(target_arch = "riscv64")]
        wipes::<Cipher<riscv64::Zvbb>>();
    }

    #[test]
    fn picks_best_supported() {
        let choice = probe();
        for c in CHOICES {
            if supported(c) {
                assert_eq!(choice, c);
                break;
            }
        }
        assert_eq!(probe(), choice);
    }

    #[test]
    fn debug_omits_the_key() {
        struct Buffer([u8; 128], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let cipher = ChaCha20::try_new(&[0x5a; 32]).unwrap();
        let mut buffer = Buffer([0; 128], 0);
        core::fmt::write(&mut buffer, format_args!("{cipher:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("5a"), "{text}");
    }
}
