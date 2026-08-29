//! ChaCha20-Poly1305 (RFC 8439): authenticated encryption from the
//! stream cipher and the one-time MAC.
//!
//! The first block of ChaCha20 keystream under the message's nonce
//! becomes a Poly1305 key, the message is encrypted from the second
//! block on, and Poly1305 under that key tags the additional data,
//! the ciphertext, and both their lengths. Each message gets a fresh
//! Poly1305 key because the nonce is fresh, which is exactly why the
//! nonce must be.
//!
//! ```
//! use scytale::symmetric::mode::ChaCha20Poly1305;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let aead = ChaCha20Poly1305::try_new(&[0x42; 32])?;
//! let nonce = [7u8; 12];
//! let header = b"to: bob";
//! let mut message = *b"attack at dawn";
//! let mut tag = [0u8; 16];
//! aead.encrypt(&nonce, header, &mut message, &mut tag)?;
//! aead.decrypt(&nonce, header, &mut message, &tag)?;
//! assert_eq!(&message, b"attack at dawn");
//! # Ok(())
//! # }
//! ```
//!
//! # Using it safely
//!
//! - **Never reuse a nonce with the same key.** Both halves fail at
//!   once: the keystream repeats, so the xor of the two messages
//!   falls out, and the Poly1305 key repeats, which gives away the
//!   key and with it forgeries. Count nonces, with
//!   [`Nonces`](super::Nonces) or otherwise.
//! - Do not use a decrypted message before the tag has been checked.
//!   The one-shot [`decrypt`](ChaCha20Poly1305::decrypt) checks first
//!   and wipes the buffer on failure; the incremental form cannot,
//!   see [`Decryptor`].
//! - A message is at most 256 GiB, the reach of ChaCha20's counter;
//!   [`Error::MessageTooLong`] is returned rather than wrapping.
//!
//! # Compared with GCM
//!
//! The same job, and as strong. Without AES instructions this is
//! several times the speed of GCM and, unlike a table-driven AES,
//! leaks nothing through the cache, which is why it is the usual
//! choice on processors without them. With those instructions GCM
//! is the faster.

use core::fmt;

use zeroize::Zeroize;

use crate::mac::poly1305::Poly1305;
use crate::mac::Mac;
use crate::symmetric::chacha20::{AutoStream, ChaCha20, NONCE_SIZE};
use crate::Error;

/// The tag length, in bytes.
const TAG: usize = 16;

/// ChaCha20-Poly1305 under one key.
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    cipher: ChaCha20,
}

impl ChaCha20Poly1305 {
    /// Takes `key`, which must be 32 bytes.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        Ok(ChaCha20Poly1305 {
            cipher: ChaCha20::try_new(key)?,
        })
    }

    /// Encrypts `data` in place and writes its tag.
    ///
    /// `aad` is authenticated but not encrypted.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8; TAG],
    ) -> Result<(), Error> {
        let mut state = self.encryptor(nonce)?;
        state.aad(aad)?;
        state.update(data)?;
        *tag = state.finalize()?;
        Ok(())
    }

    /// Checks `tag` and, if it is right, decrypts `data` in place.
    ///
    /// On failure the buffer is wiped and
    /// [`Error::AuthenticationFailed`] returned, so a caller cannot
    /// use plaintext that was never authenticated.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG],
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

    /// Starts encrypting a message that arrives in pieces.
    pub fn encryptor(
        &self,
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Encryptor<'_>, Error> {
        Ok(Encryptor {
            core: Core::new(&self.cipher, nonce)?,
        })
    }

    /// Starts decrypting a message that arrives in pieces.
    pub fn decryptor(
        &self,
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Decryptor<'_>, Error> {
        Ok(Decryptor {
            core: Core::new(&self.cipher, nonce)?,
        })
    }
}

impl fmt::Debug for ChaCha20Poly1305 {
    /// Deliberately omits the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChaCha20Poly1305").finish_non_exhaustive()
    }
}

/// What encryption and decryption share: the keystream from block
/// one, the MAC keyed from block zero, and the lengths for the end.
struct Core<'a> {
    stream: AutoStream<'a>,
    mac: Poly1305,
    aad_bytes: u64,
    message_bytes: u64,
    /// Whether any of the message has been seen, after which no more
    /// additional data may be.
    started: bool,
}

impl<'a> Core<'a> {
    fn new(
        cipher: &'a ChaCha20,
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Self, Error> {
        let mut block = cipher.keystream_block(nonce, 0);
        let mac = Poly1305::try_new(&block[..32]);
        block.zeroize();
        Ok(Core {
            stream: cipher.stream(nonce, 1),
            mac: mac?,
            aad_bytes: 0,
            message_bytes: 0,
            started: false,
        })
    }

    fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.started {
            return Err(Error::OutOfOrder);
        }
        self.mac.update(data);
        self.aad_bytes += data.len() as u64;
        Ok(())
    }

    /// Ends the additional data, padding it to a whole block, before
    /// the first piece of message.
    fn start(&mut self) {
        if !self.started {
            self.started = true;
            self.pad(self.aad_bytes);
        }
    }

    /// Zeros up to the next sixteen-byte boundary after `bytes`.
    fn pad(&mut self, bytes: u64) {
        let over = (bytes % TAG as u64) as usize;
        if over != 0 {
            self.mac.update(&[0u8; TAG][..TAG - over]);
        }
    }

    /// Feeds ciphertext to the MAC.
    fn absorb(&mut self, ciphertext: &[u8]) {
        self.mac.update(ciphertext);
        self.message_bytes += ciphertext.len() as u64;
    }

    fn tag(mut self) -> [u8; TAG] {
        self.start();
        self.pad(self.message_bytes);
        let mut lengths = [0u8; TAG];
        lengths[..8].copy_from_slice(&self.aad_bytes.to_le_bytes());
        lengths[8..].copy_from_slice(&self.message_bytes.to_le_bytes());
        self.mac.update(&lengths);
        self.mac.finalize()
    }
}

/// Encryption of a message that arrives in pieces.
///
/// Additional data first, then the message, then the tag; the
/// ciphertext is in place as each piece is given.
pub struct Encryptor<'a> {
    core: Core<'a>,
}

impl Encryptor<'_> {
    /// Authenticates `data` without encrypting it. All of it must
    /// come before any of the message, or
    /// [`Error::OutOfOrder`] is returned.
    pub fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        self.core.aad(data)
    }

    /// Encrypts the next piece of the message in place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.core.start();
        self.core.stream.update(data)?;
        self.core.absorb(data);
        Ok(())
    }

    /// Finishes, returning the tag.
    pub fn finalize(self) -> Result<[u8; TAG], Error> {
        Ok(self.core.tag())
    }
}

/// Decryption of a message that arrives in pieces.
///
/// **The pieces this hands back are not yet authenticated.** Nothing
/// can vouch for any of the message until [`verify`](Self::verify)
/// has passed, so a caller must hold every piece back from use until
/// then, or use the one-shot
/// [`decrypt`](ChaCha20Poly1305::decrypt), which does that itself.
pub struct Decryptor<'a> {
    core: Core<'a>,
}

impl Decryptor<'_> {
    /// Authenticates `data`. All of it must come before any of the
    /// message, or [`Error::OutOfOrder`] is returned.
    pub fn aad(&mut self, data: &[u8]) -> Result<(), Error> {
        self.core.aad(data)
    }

    /// Decrypts the next piece of the message in place. The result
    /// is not authenticated until [`verify`](Self::verify) passes.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.core.start();
        self.core.absorb(data);
        self.core.stream.update(data)
    }

    /// Checks `tag` against the message, in constant time.
    pub fn verify(self, tag: &[u8; TAG]) -> Result<(), Error> {
        let expected = self.core.tag();
        if crate::util::equal(&expected, tag) {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}

impl fmt::Debug for Encryptor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("message_bytes", &self.core.message_bytes)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Decryptor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryptor")
            .field("message_bytes", &self.core.message_bytes)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
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

    /// RFC 8439 section 2.8.2.
    const KEY: &str =
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const NONCE: &str = "070000004041424344454647";
    const AAD: &str = "50515253c0c1c2c3c4c5c6c7";
    const PLAIN: &[u8; 114] = b"Ladies and Gentlemen of the class of '99: \
        If I could offer you only one tip for the future, sunscreen would \
        be it.";
    const CIPHER: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9\
        e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6\
        a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808\
        b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    const TAG_HEX: &str = "1ae10b594f09e26a7e902ecbd0600691";

    fn aead() -> ChaCha20Poly1305 {
        ChaCha20Poly1305::try_new(&hex::<32>(KEY)).unwrap()
    }

    #[test]
    fn rfc8439() {
        let aead = aead();
        let nonce = hex::<12>(NONCE);
        let aad = hex::<12>(AAD);
        let mut data = *PLAIN;
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, &aad, &mut data, &mut tag).unwrap();
        assert_eq!(data, hex::<114>(CIPHER));
        assert_eq!(tag, hex::<16>(TAG_HEX));
        aead.decrypt(&nonce, &aad, &mut data, &tag).unwrap();
        assert_eq!(&data, PLAIN);
    }

    #[test]
    fn rejects_and_wipes() {
        let aead = aead();
        let nonce = hex::<12>(NONCE);
        let aad = hex::<12>(AAD);
        let mut data = *PLAIN;
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, &aad, &mut data, &mut tag).unwrap();
        let sealed = data;

        let mut wrong = tag;
        wrong[0] ^= 1;
        assert_eq!(
            aead.decrypt(&nonce, &aad, &mut data, &wrong).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(data, [0u8; 114]);

        data = sealed;
        assert_eq!(
            aead.decrypt(&nonce, b"other", &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(data, [0u8; 114]);

        data = sealed;
        data[50] ^= 0x80;
        assert_eq!(
            aead.decrypt(&nonce, &aad, &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn pieces_match_whole() {
        let aead = aead();
        let nonce = hex::<12>(NONCE);
        let aad = hex::<12>(AAD);
        let mut whole = *PLAIN;
        let mut tag = [0u8; 16];
        aead.encrypt(&nonce, &aad, &mut whole, &mut tag).unwrap();
        for chunk in [1, 7, 16, 63, 64, 65, 114] {
            let mut data = *PLAIN;
            let mut e = aead.encryptor(&nonce).unwrap();
            e.aad(&aad[..5]).unwrap();
            e.aad(&aad[5..]).unwrap();
            for piece in data.chunks_mut(chunk) {
                e.update(piece).unwrap();
            }
            assert_eq!(data, whole, "chunk {chunk}");
            assert_eq!(e.finalize().unwrap(), tag, "chunk {chunk}");

            let mut d = aead.decryptor(&nonce).unwrap();
            d.aad(&aad).unwrap();
            for piece in data.chunks_mut(chunk) {
                d.update(piece).unwrap();
            }
            d.verify(&tag).unwrap();
            assert_eq!(&data, PLAIN, "chunk {chunk}");
        }
    }

    #[test]
    fn aad_after_message_is_out_of_order() {
        let aead = aead();
        let mut e = aead.encryptor(&[0u8; 12]).unwrap();
        e.update(&mut [0u8; 3]).unwrap();
        assert_eq!(e.aad(b"late"), Err(Error::OutOfOrder));
    }

    #[test]
    fn empty_message_and_aad() {
        let aead = aead();
        let mut tag = [0u8; 16];
        aead.encrypt(&[0u8; 12], &[], &mut [], &mut tag).unwrap();
        aead.decrypt(&[0u8; 12], &[], &mut [], &tag).unwrap();
        let mut wrong = tag;
        wrong[15] ^= 1;
        assert_eq!(
            aead.decrypt(&[0u8; 12], &[], &mut [], &wrong),
            Err(Error::AuthenticationFailed)
        );
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
        let aead = ChaCha20Poly1305::try_new(&[0x5a; 32]).unwrap();
        let mut buffer = Buffer([0; 128], 0);
        core::fmt::write(&mut buffer, format_args!("{aead:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("5a"), "{text}");
    }
}
