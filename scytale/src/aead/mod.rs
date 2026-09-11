//! Authenticated encryption with associated data.
//!
//! An AEAD encrypts a message and authenticates it in one pass, and
//! refuses to hand back a message whose tag does not check. That last
//! part is what separates these from the modes in
//! [`cipher::mode`](crate::cipher::mode): a plain mode will happily
//! decrypt anything, including what an attacker wrote, and pairing it
//! with a MAC correctly is work these constructions have already done.
//! Unless there is a reason not to, encrypt with one of these.
//!
//! "Associated data" is the part of a message that must be
//! authenticated without being encrypted: a header that has to stay
//! readable on the wire. It is covered by the tag, so changing it
//! fails the check.
//!
//! Three of these are modes of operation of a block cipher and name
//! their cipher as a type parameter: `Gcm::<Aes128>::new(&key)`. The
//! fourth is not built that way at all, which is the reason this
//! module groups by what a construction does rather than by how it is
//! made. [`Aead`] is that contract written down, and the one-shot
//! calls live on it: a caller imports the trait and then does not care
//! which construction it has.
//!
//! # Which one
//!
//! | Need | Use |
//! | --- | --- |
//! | Encrypt and authenticate a message | [`Gcm`], with [`Nonces`] |
//! | The same, without AES instructions | [`ChaCha20Poly1305`] |
//! | The same, when a nonce might repeat | [`GcmSiv`] |
//! | MACsec frames | [`Xpn`] |
//!
//! [`Gcm`] is the default. It is fast, standard, and every protocol
//! that matters speaks it. Its one hazard is a repeated nonce, which
//! [`Nonces`] rules out; where uniqueness cannot be promised,
//! [`GcmSiv`] survives a repeat at the cost of a second pass over the
//! message. [`ChaCha20Poly1305`] is as strong as [`Gcm`] and, on a
//! processor without AES instructions, several times faster while
//! leaking nothing through the cache; with them, [`Gcm`] is the
//! faster. [`Xpn`] is [`Gcm`] with the nonce assembled from a secret
//! salt and a frame number, as MACsec does it.
//!
//! # Nonces
//!
//! All four need a nonce that has never been used before under the
//! same key, and for [`Gcm`], [`Xpn`] and [`ChaCha20Poly1305`] a
//! repeat is fatal rather than merely revealing: it gives up the hash
//! key, and with it the ability to forge tags. Count nonces with
//! [`Nonces`] rather than drawing them.
//!
//! # Example
//!
//! ```
//! use scytale::Key;
//! use scytale::aead::{Aead, Gcm};
//! use scytale::cipher::Nonces;
//! use scytale::cipher::aes::Aes128;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let gcm = Gcm::<Aes128>::new(&Key::from([0u8; 16]));
//! let mut nonces = Nonces::<[u8; 12]>::try_new(&[0x5a; 8], 0)?;
//!
//! let nonce = nonces.take()?;
//! let mut message = *b"attack at dawn";
//! let mut tag = [0u8; 16];
//! gcm.encrypt(&nonce, b"header", &mut message, &mut tag)?;
//!
//! // The header is authenticated but not encrypted, so it must be
//! // handed back unchanged for the tag to check.
//! gcm.decrypt(&nonce, b"header", &mut message, &tag)?;
//! assert_eq!(&message, b"attack at dawn");
//! # Ok(())
//! # }
//! ```
//!
//! [`Nonces`]: crate::cipher::Nonces

pub mod chacha20_poly1305;
pub mod gcm;
pub mod gcm_siv;
pub(crate) mod ghash;
pub(crate) mod polyval;
pub mod xpn;

pub use chacha20_poly1305::ChaCha20Poly1305;
pub use gcm::Gcm;
pub use gcm_siv::{GcmSiv, SivKey};
pub use xpn::Xpn;

use crate::traits::ByteArray;
use crate::{Error, KeyType};

/// Authenticated encryption under one key.
///
/// [`Gcm`], [`GcmSiv`] and [`ChaCha20Poly1305`] implement this, so a
/// caller that does not care which one it got -- a protocol that
/// negotiated it, or a format that records it -- can hold any of them.
/// The nonce, the key and the tag are types, so the trait is usable as
/// an object once they are named:
/// `&dyn Aead<Key = Key<[u8; 16]>, Nonce = [u8; 12], Tag = [u8; 16]>`
/// takes AES-128-GCM and AES-128-GCM-SIV alike. Only
/// [`try_new`](Aead::try_new) needs the concrete type.
///
/// [`Xpn`] deliberately does not implement it. Its nonce is two
/// separate halves, a secret salt and a frame identifier, and pushing
/// that through one `Nonce` would mean pretending the salt is part of
/// the nonce a caller supplies.
///
/// Nothing here is incremental. The one-shot calls check the tag
/// before they return any plaintext, which is the property worth
/// having in generic code; where a message is too large to hold, the
/// concrete types that can stream say so themselves, and they do not
/// all agree on whether that is possible.
pub trait Aead: KeyType {
    /// The nonce; `[u8; 12]` for all three of these.
    ///
    /// It must never repeat under one key. Count nonces with
    /// [`Nonces`](crate::cipher::Nonces) rather than drawing them.
    type Nonce: ByteArray;

    /// The tag; `[u8; 16]` for all three of these.
    type Tag: Copy + AsRef<[u8]> + AsMut<[u8]>;

    /// Takes the key.
    fn try_new(key: &Self::Key) -> Result<Self, Error>
    where
        Self: Sized;

    /// Encrypts `data` in place and writes its tag.
    ///
    /// `aad` is authenticated but not encrypted: it is the part of a
    /// message that must stay readable and must not be tampered with.
    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut Self::Tag,
    ) -> Result<(), Error>;

    /// Checks `tag` and, if it is right, decrypts `data` in place.
    ///
    /// On failure the buffer is wiped and
    /// [`Error::AuthenticationFailed`] returned, so a caller cannot
    /// reach plaintext that was never authenticated.
    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key;
    use crate::cipher::aes::Aes128;

    /// Fed through an object, each one encrypts what its own type
    /// encrypts, and the object form checks tags as the concrete one
    /// does.
    #[test]
    fn as_an_object() {
        /// What a protocol that negotiated its AEAD would hold.
        type Any =
            dyn Aead<Key = Key<[u8; 16]>, Nonce = [u8; 12], Tag = [u8; 16]>;

        fn round_trip(aead: &Any) -> ([u8; 5], [u8; 16]) {
            let nonce = [7u8; 12];
            let mut data = *b"hello";
            let mut tag = [0u8; 16];
            aead.encrypt(&nonce, b"head", &mut data, &mut tag)
                .expect("encrypt");
            let sealed = data;

            aead.decrypt(&nonce, b"head", &mut data, &tag)
                .expect("decrypt");
            assert_eq!(&data, b"hello");

            // A tag that does not belong to the message is refused,
            // and the buffer is not left holding plaintext.
            let mut other = sealed;
            let mut wrong = tag;
            wrong[0] ^= 1;
            assert_eq!(
                aead.decrypt(&nonce, b"head", &mut other, &wrong),
                Err(Error::AuthenticationFailed)
            );
            assert_eq!(other, [0u8; 5]);

            (sealed, tag)
        }

        let key = Key::from([0x42u8; 16]);
        let gcm = Gcm::<Aes128>::new(&key);
        let siv = GcmSiv::<Aes128>::new(&key);
        assert_ne!(round_trip(&gcm), round_trip(&siv));
    }

    /// Generic code can draw a key and take an AEAD under it without
    /// naming the construction, which is what [`KeyType`] is for.
    #[test]
    fn keyed_generically() {
        fn seal<A: Aead<Tag = [u8; 16]>>(
            key: &A::Key,
            nonce: &A::Nonce,
        ) -> [u8; 16] {
            let aead = A::try_new(key).expect("key");
            let mut tag = [0u8; 16];
            aead.encrypt(nonce, b"", &mut [], &mut tag)
                .expect("encrypt");
            tag
        }
        let nonce = [0u8; 12];
        let gcm = seal::<Gcm<Aes128>>(&Gcm::<Aes128>::zero_key(), &nonce);
        let cc20 =
            seal::<ChaCha20Poly1305>(&ChaCha20Poly1305::zero_key(), &nonce);
        assert_ne!(gcm, cc20);
        assert_ne!(gcm, [0u8; 16]);
    }
}
