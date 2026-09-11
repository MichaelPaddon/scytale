//! Cipher block chaining (NIST SP 800-38A).
//!
//! Each block is combined with the one before it before encryption,
//! starting from an initialisation vector, so identical plaintext
//! blocks do not produce identical ciphertext.
//!
//! # Using it safely
//!
//! - The IV must be unpredictable to an attacker who can influence
//!   the plaintext, so draw it with [`random`](crate::random) for
//!   each message. It
//!   need not be secret and is normally sent alongside the
//!   ciphertext.
//! - CBC provides no authentication. On its own it does not detect a
//!   modified message, and decrypting attacker-controlled ciphertext
//!   has historically been the source of padding-oracle attacks.
//!   Prefer an authenticated mode.
//! - The message must be a whole number of blocks. Padding is the
//!   caller's business; this mode adds none.
//!
//! # Example
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::mode::Cbc;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let cbc = Cbc::<Aes128>::new(&Key::from([0u8; 16]));
//! let iv = [0u8; 16];
//!
//! let mut data = [0u8; 32];
//! cbc.encrypt(&iv, &mut data)?;
//! cbc.decrypt(&iv, &mut data)?;
//! assert_eq!(data, [0u8; 32]);
//! # Ok(())
//! # }
//! ```

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

// The loops written out for this processor, whichever it is. Each
// architecture's module offers the same few entry points, so the code
// below needs no conditionals beyond whether there is one at all.
#[cfg(target_arch = "aarch64")]
use self::aarch64 as native;
#[cfg(target_arch = "x86_64")]
use self::x86_64 as native;

use core::fmt;

use super::{LANES, xor};
use crate::KeyType;
use crate::cipher::{BlockCipher, OneBlock};
use crate::implementation::Implementation;
use crate::{ByteArray, Error};

/// Every implementation, best first.
///
/// A caller never names one: the mode takes the best the processor
/// has. The tests and the vector suites do name them, so that every
/// implementation is validated and not only the one this machine
/// would pick.
pub(crate) const CHOICES: &[Implementation] = &[
    #[cfg(target_arch = "x86_64")]
    Implementation::Vaes,
    #[cfg(target_arch = "x86_64")]
    Implementation::Aesni,
    #[cfg(target_arch = "aarch64")]
    Implementation::Armv8,
    Implementation::Portable,
];

/// What does the work, settled when the mode is built.
enum Engine<C: BlockCipher> {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    Native(native::Engine<C>),
    /// What the other arm is written for. On an architecture with no
    /// such arm nothing here names `C`, and the parameter would
    /// otherwise go unused.
    Generic(core::marker::PhantomData<C>),
}

/// By hand rather than derived: an engine holds no cipher, only a
/// pointer to the loop written for one, so it clones whatever `C` is.
impl<C: BlockCipher> Clone for Engine<C> {
    fn clone(&self) -> Self {
        match self {
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            Engine::Native(engine) => Engine::Native(engine.clone()),
            Engine::Generic(_) => Engine::Generic(core::marker::PhantomData),
        }
    }
}

impl<C: BlockCipher> Engine<C> {
    /// The best engine for this cipher on this processor.
    fn new() -> Self {
        for &implementation in CHOICES {
            if let Some(engine) = Self::with(implementation) {
                return engine;
            }
        }
        Engine::Generic(core::marker::PhantomData)
    }

    /// The engine `implementation` names, or `None` where this processor or
    /// this cipher has no such thing.
    fn with(implementation: Implementation) -> Option<Self> {
        match implementation {
            Implementation::Portable => {
                Some(Engine::Generic(core::marker::PhantomData))
            }
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            hardware => native::Engine::of(hardware).map(Engine::Native),
            #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

/// The key is the cipher's own, so generic code can draw one
/// without naming the cipher.
impl<C: BlockCipher> KeyType for Cbc<C> {
    type Key = C::Key;

    fn zero_key() -> Self::Key {
        C::zero_key()
    }
}

/// CBC over a block cipher.
#[derive(Clone)]
pub struct Cbc<C: BlockCipher> {
    cipher: C,
    /// What does the work, settled when the mode is built.
    engine: Engine<C>,
}

impl<C: BlockCipher> Cbc<C>
where
    C::Block: ByteArray,
{
    /// Takes the key the cipher runs under.
    /// The mode over the implementation `implementation` names, or `None`
    /// where this processor or this cipher has no such thing.
    ///
    /// For the tests and the vector suites, which run every
    /// implementation rather than only the one [`new`](Self::new)
    /// would take.
    #[cfg(test)]
    pub(crate) fn with_implementation(
        key: &C::Key,
        implementation: Implementation,
    ) -> Option<Self> {
        Some(Cbc {
            cipher: C::new(key),
            engine: Engine::with(implementation)?,
        })
    }

    /// Takes the key the cipher runs under.
    pub fn new(key: &C::Key) -> Self {
        Cbc {
            cipher: C::new(key),
            engine: Engine::new(),
        }
    }

    /// Encrypts `data` in place under `iv`.
    ///
    /// `data` must be a whole number of blocks.
    pub fn encrypt(&self, iv: &C::Block, data: &mut [u8]) -> Result<(), Error> {
        self.encryptor(iv).update(data)
    }

    /// Decrypts `data` in place under `iv`.
    ///
    /// `data` must be a whole number of blocks.
    pub fn decrypt(&self, iv: &C::Block, data: &mut [u8]) -> Result<(), Error> {
        self.decryptor(iv).update(data)
    }

    /// Starts encrypting a message that arrives in pieces.
    pub fn encryptor(&self, iv: &C::Block) -> Encryptor<'_, C> {
        Encryptor {
            cipher: &self.cipher,
            engine: self.engine.clone(),
            chain: *iv,
        }
    }

    /// Starts decrypting a message that arrives in pieces.
    pub fn decryptor(&self, iv: &C::Block) -> Decryptor<'_, C> {
        Decryptor {
            cipher: &self.cipher,
            engine: self.engine.clone(),
            chain: *iv,
        }
    }
}

/// Encrypts one message, a piece at a time.
///
/// Every piece must be a whole number of blocks, since a block cannot
/// be encrypted until all of it has arrived. There is nothing to
/// finish: the state can simply be dropped when the message ends.
pub struct Encryptor<'a, C: BlockCipher> {
    cipher: &'a C,
    /// Read only where there is a loop written out to reach.
    #[cfg_attr(
        not(any(target_arch = "aarch64", target_arch = "x86_64")),
        allow(dead_code)
    )]
    engine: Engine<C>,
    chain: C::Block,
}

impl<C: BlockCipher> Encryptor<'_, C>
where
    C::Block: ByteArray,
{
    /// Encrypts the next piece of the message in place.
    ///
    /// Encryption chains, so this runs one block at a time and cannot
    /// use the cipher's bulk path.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let (blocks, rest) = <C::Block as ByteArray>::split_mut(data);
        if !rest.is_empty() {
            return Err(Error::NotBlockAligned(data.len()));
        }
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if let (Engine::Native(engine), Ok(chain)) =
            (&self.engine, <&mut [u8; 16]>::try_from(self.chain.as_mut()))
        {
            {
                engine.encrypt(
                    self.cipher,
                    chain,
                    <C::Block as ByteArray>::flatten_mut(blocks),
                );
                return Ok(());
            }
        }
        for block in blocks {
            xor(block.as_mut(), self.chain.as_ref());
            self.cipher.encrypt_one(block);
            self.chain = *block;
        }
        Ok(())
    }
}

/// Decrypts one message, a piece at a time.
///
/// Every piece must be a whole number of blocks. There is nothing to
/// finish.
pub struct Decryptor<'a, C: BlockCipher> {
    cipher: &'a C,
    /// Read only where there is a loop written out to reach.
    #[cfg_attr(
        not(any(target_arch = "aarch64", target_arch = "x86_64")),
        allow(dead_code)
    )]
    engine: Engine<C>,
    chain: C::Block,
}

impl<C: BlockCipher> Decryptor<'_, C>
where
    C::Block: ByteArray,
{
    /// Decrypts the next piece of the message in place.
    ///
    /// Decryption does not chain through the cipher, so blocks go
    /// through the bulk path in groups. Each group's ciphertext is
    /// kept first, because decrypting in place overwrites the very
    /// bytes the next block needs.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let (blocks, rest) = <C::Block as ByteArray>::split_mut(data);
        if !rest.is_empty() {
            return Err(Error::NotBlockAligned(data.len()));
        }
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if let (Engine::Native(engine), Ok(chain)) =
            (&self.engine, <&mut [u8; 16]>::try_from(self.chain.as_mut()))
        {
            {
                engine.decrypt(
                    self.cipher,
                    chain,
                    <C::Block as ByteArray>::flatten_mut(blocks),
                );
                return Ok(());
            }
        }
        let mut seen = [C::zero_block(); LANES];
        for group in blocks.chunks_mut(LANES) {
            let seen = &mut seen[..group.len()];
            seen.copy_from_slice(group);
            self.cipher.decrypt(group);

            let mut previous = &self.chain;
            for (block, ciphertext) in group.iter_mut().zip(&*seen) {
                xor(block.as_mut(), previous.as_ref());
                previous = ciphertext;
            }
            self.chain = seen[seen.len() - 1];
        }
        Ok(())
    }
}

// Debug output omits the state: it is all derived from the key.
impl<C: BlockCipher> fmt::Debug for Cbc<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cbc").finish_non_exhaustive()
    }
}

impl<C: BlockCipher> fmt::Debug for Encryptor<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor").finish_non_exhaustive()
    }
}

impl<C: BlockCipher> fmt::Debug for Decryptor<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryptor").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::Key;
    use crate::cipher::aes::{Aes, Aes128};
    use std::vec::Vec;

    /// Largest buffer any test here uses.
    const MAX: usize = 24 * 16;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            let hex = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(hex, 16).unwrap();
        }
        out
    }

    fn cbc<const K: usize>(key: &[u8; K]) -> Cbc<Aes<K>> {
        Cbc::new(&Key::from(*key))
    }

    /// Fills `buf` with something that is not all one byte.
    fn fill(buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
    }

    /// NIST SP 800-38A F.2.1 and F.2.2, AES-128.
    #[test]
    fn sp800_38a_aes128() {
        let key: [u8; 16] = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
        let plain: [u8; 64] = unhex(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let cipher: [u8; 64] = unhex(
            "7649abac8119b246cee98e9b12e9197d\
             5086cb9b507219ee95db113a917678b2\
             73bed6b8e3c1743b7116e69e22229516\
             3ff1caa1681fac09120eca307586e1a7",
        );
        let cbc = cbc(&key);

        let mut data = plain;
        cbc.encrypt(&iv, &mut data).unwrap();
        assert_eq!(data, cipher, "encrypt");
        cbc.decrypt(&iv, &mut data).unwrap();
        assert_eq!(data, plain, "decrypt");
    }

    /// Chaining must actually happen: equal plaintext blocks must not
    /// give equal ciphertext blocks, which is the point of CBC over
    /// ECB.
    #[test]
    fn equal_blocks_differ() {
        let cbc = cbc(&[0x11; 16]);
        let mut data = [0u8; 32];
        cbc.encrypt(&[0x22; 16], &mut data).unwrap();
        assert_ne!(data[..16], data[16..]);
    }

    /// Every implementation this processor has must agree, at every
    /// length around the group boundaries of both widths and with the
    /// pieces landing anywhere.
    #[test]
    fn the_engines_agree() {
        const MAX: usize = 5 * 16 * 16;
        let key = Key::from([0x31u8; 16]);
        let iv = [0x9au8; 16];
        let mut message = [0u8; MAX];
        for (i, b) in message.iter_mut().enumerate() {
            *b = (i * 7 + 2) as u8;
        }

        let all: Vec<Cbc<Aes128>> = CHOICES
            .iter()
            .filter_map(|&c| Cbc::<Aes128>::with_implementation(&key, c))
            .collect();
        assert!(!all.is_empty(), "no implementation to test");
        // The generic one is always to be had.
        assert!(
            Cbc::<Aes128>::with_implementation(&key, Implementation::Portable)
                .is_some()
        );

        for len in (0..MAX).step_by(16) {
            let mut want = [0u8; MAX];
            want[..len].copy_from_slice(&message[..len]);
            all[all.len() - 1].encrypt(&iv, &mut want[..len]).unwrap();

            for (i, cbc) in all.iter().enumerate() {
                let mut got = [0u8; MAX];
                got[..len].copy_from_slice(&message[..len]);
                cbc.encrypt(&iv, &mut got[..len]).unwrap();
                assert_eq!(got[..len], want[..len], "encrypt {len}, {i}");
                cbc.decrypt(&iv, &mut got[..len]).unwrap();
                assert_eq!(got[..len], message[..len], "decrypt {len}, {i}");

                // In pieces, which starts a run part way along.
                for piece in [16, 128, 256, 272] {
                    let mut got = [0u8; MAX];
                    got[..len].copy_from_slice(&message[..len]);
                    let mut e = cbc.encryptor(&iv);
                    for part in got[..len].chunks_mut(piece) {
                        e.update(part).unwrap();
                    }
                    assert_eq!(got[..len], want[..len], "{len}, {piece}");
                    let mut d = cbc.decryptor(&iv);
                    for part in got[..len].chunks_mut(piece) {
                        d.update(part).unwrap();
                    }
                    assert_eq!(got[..len], message[..len], "{len}, {piece}");
                }
            }
        }
    }

    #[test]
    fn round_trips_at_many_lengths() {
        let cbc = cbc(&[0x5a; 32]);
        let iv = [0x77u8; 16];
        let mut plain = [0u8; MAX];
        fill(&mut plain);
        // Zero, one, and enough blocks to cross the group the
        // decryption path works in.
        for blocks in [0, 1, 2, 7, 8, 9, 16, 17, 24] {
            let n = blocks * 16;
            let mut data = [0u8; MAX];
            data[..n].copy_from_slice(&plain[..n]);

            cbc.encrypt(&iv, &mut data[..n]).unwrap();
            if blocks > 0 {
                assert_ne!(data[..n], plain[..n], "{blocks} blocks");
            }
            cbc.decrypt(&iv, &mut data[..n]).unwrap();
            assert_eq!(data[..n], plain[..n], "{blocks} blocks");
        }
    }

    /// Feeding the message in pieces must match one call, in both
    /// directions.
    #[test]
    fn pieces_match_one_call() {
        let cbc = cbc(&[0x33; 24]);
        let iv = [1u8; 16];
        let mut plain = [0u8; MAX];
        fill(&mut plain);

        for split in [1, 2, 7, 8, 15] {
            let mut whole = plain;
            cbc.encrypt(&iv, &mut whole).unwrap();

            let mut pieces = plain;
            let mut e = cbc.encryptor(&iv);
            let (a, b) = pieces.split_at_mut(split * 16);
            e.update(a).unwrap();
            e.update(b).unwrap();
            assert_eq!(pieces, whole, "encrypt split at {split}");

            let mut d = cbc.decryptor(&iv);
            let (a, b) = pieces.split_at_mut(split * 16);
            d.update(a).unwrap();
            d.update(b).unwrap();
            assert_eq!(pieces, plain, "decrypt split at {split}");
        }
    }

    #[test]
    fn rejects_partial_block() {
        let cbc = cbc(&[0; 16]);
        let iv = [0u8; 16];
        for n in [1, 15, 17, 31, 33] {
            let mut data = [0x44u8; 33];
            let data = &mut data[..n];
            assert_eq!(
                cbc.encrypt(&iv, data).unwrap_err(),
                Error::NotBlockAligned(n)
            );
            assert_eq!(
                cbc.decrypt(&iv, data).unwrap_err(),
                Error::NotBlockAligned(n)
            );
            assert!(data.iter().all(|&b| b == 0x44), "data untouched");
        }
    }

    /// The state derives from the key, so its debug output must not
    /// show it.
    #[test]
    fn debug_omits_the_state() {
        struct Buffer([u8; 256], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let mode = cbc(&[0x5a; 16]);
        let iv = [0x5a; 16];
        let state = mode.encryptor(&iv);
        let mut buffer = Buffer([0; 256], 0);
        core::fmt::write(&mut buffer, format_args!("{mode:?} {state:?}"))
            .unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        // 0x5a prints as 90 in decimal.
        assert!(!text.contains("90"), "{text}");
    }
}
