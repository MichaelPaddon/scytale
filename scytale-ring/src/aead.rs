//! Authenticated encryption: AES-GCM and ChaCha20-Poly1305.
//!
//! Everything is in place. A message is sealed where it lies and its
//! tag handed back or appended; it is opened where it lies, and the
//! plaintext is what the returned slice covers.

use core::fmt;
use core::ops::RangeFrom;

use scytale::Key;
use scytale::aead::{Aead, ChaCha20Poly1305, Gcm};
use scytale::cipher::aes::{Aes128, Aes256};
use zeroize::Zeroize;

use crate::{error, hkdf};

pub mod quic;

/// The length of every nonce here.
pub const NONCE_LEN: usize = 96 / 8;

/// The length of every tag here.
pub const MAX_TAG_LEN: usize = TAG_LEN;

const TAG_LEN: usize = 16;

/// The longest key of any algorithm here.
const MAX_KEY_LEN: usize = 32;

/// Which AEAD an [`Algorithm`] is, and what [`Debug`] prints.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Id {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}

/// An AEAD algorithm. The only values are the `static`s in this
/// module.
pub struct Algorithm {
    id: Id,
    key_len: usize,
}

impl Algorithm {
    /// The length of a key, in bytes.
    #[inline]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The length of a tag, in bytes.
    #[inline]
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// The length of a nonce, in bytes.
    #[inline]
    pub fn nonce_len(&self) -> usize {
        NONCE_LEN
    }
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.id, f)
    }
}

impl hkdf::KeyType for &'static Algorithm {
    #[inline]
    fn len(&self) -> usize {
        self.key_len()
    }
}

/// AES-128 in GCM.
pub static AES_128_GCM: Algorithm = Algorithm {
    id: Id::AES_128_GCM,
    key_len: 16,
};

/// AES-256 in GCM.
pub static AES_256_GCM: Algorithm = Algorithm {
    id: Id::AES_256_GCM,
    key_len: 32,
};

/// ChaCha20-Poly1305 (RFC 8439).
pub static CHACHA20_POLY1305: Algorithm = Algorithm {
    id: Id::CHACHA20_POLY1305,
    key_len: 32,
};

/// A nonce. The caller promises it is used once under a key: nothing
/// here can check that.
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// A nonce from bytes, which must be [`NONCE_LEN`] long.
    #[inline]
    pub fn try_assume_unique_for_key(
        value: &[u8],
    ) -> Result<Self, error::Unspecified> {
        let value: &[u8; NONCE_LEN] = value.try_into()?;
        Ok(Self::assume_unique_for_key(*value))
    }

    /// A nonce from an array.
    #[inline]
    pub fn assume_unique_for_key(value: [u8; NONCE_LEN]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; NONCE_LEN]> for Nonce {
    fn as_ref(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

/// Data that is authenticated and not encrypted.
#[derive(Clone, Copy)]
pub struct Aad<A>(A);

impl<A: AsRef<[u8]>> Aad<A> {
    /// Wraps `aad`.
    #[inline]
    pub fn from(aad: A) -> Self {
        Self(aad)
    }
}

impl<A> AsRef<[u8]> for Aad<A>
where
    A: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Aad<[u8; 0]> {
    /// No data.
    pub fn empty() -> Self {
        Self::from([])
    }
}

impl<A> fmt::Debug for Aad<A>
where
    A: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Aad").field(&self.0).finish()
    }
}

impl<A> PartialEq for Aad<A>
where
    A: PartialEq,
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<A> Eq for Aad<A> where A: Eq {}

/// An authentication tag.
#[must_use]
#[derive(Clone, Copy)]
pub struct Tag([u8; TAG_LEN]);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for Tag {
    type Error = error::Unspecified;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; TAG_LEN] = value.try_into()?;
        Ok(Self::from(raw))
    }
}

impl From<[u8; TAG_LEN]> for Tag {
    #[inline]
    fn from(value: [u8; TAG_LEN]) -> Self {
        Self(value)
    }
}

/// The keyed cipher, one arm per algorithm.
#[derive(Clone)]
enum Inner {
    Aes128Gcm(Gcm<Aes128>),
    Aes256Gcm(Gcm<Aes256>),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

/// A key of the wrong length is the only way to fail.
fn key<B: scytale::ByteArray>(
    bytes: &[u8],
) -> Result<Key<B>, error::Unspecified> {
    Key::try_from(bytes).map_err(error::erase)
}

impl Inner {
    fn new(
        algorithm: &'static Algorithm,
        bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        Ok(match algorithm.id {
            Id::AES_128_GCM => Inner::Aes128Gcm(Gcm::new(&key(bytes)?)),
            Id::AES_256_GCM => Inner::Aes256Gcm(Gcm::new(&key(bytes)?)),
            Id::CHACHA20_POLY1305 => {
                Inner::ChaCha20Poly1305(ChaCha20Poly1305::new(&key(bytes)?))
            }
        })
    }

    fn seal(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, error::Unspecified> {
        fn with<A>(
            a: &A,
            nonce: &Nonce,
            aad: &[u8],
            in_out: &mut [u8],
        ) -> Result<Tag, error::Unspecified>
        where
            A: Aead<Nonce = [u8; NONCE_LEN], Tag = [u8; TAG_LEN]>,
        {
            let mut tag = [0u8; TAG_LEN];
            a.encrypt(&nonce.0, aad, in_out, &mut tag)
                .map_err(error::erase)?;
            Ok(Tag(tag))
        }
        match self {
            Inner::Aes128Gcm(a) => with(a, nonce, aad, in_out),
            Inner::Aes256Gcm(a) => with(a, nonce, aad, in_out),
            Inner::ChaCha20Poly1305(a) => with(a, nonce, aad, in_out),
        }
    }

    /// Opens `data` in place. On failure scytale has already wiped it.
    fn open(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        data: &mut [u8],
        tag: &Tag,
    ) -> Result<(), error::Unspecified> {
        fn with<A>(
            a: &A,
            nonce: &Nonce,
            aad: &[u8],
            data: &mut [u8],
            tag: &Tag,
        ) -> Result<(), error::Unspecified>
        where
            A: Aead<Nonce = [u8; NONCE_LEN], Tag = [u8; TAG_LEN]>,
        {
            a.decrypt(&nonce.0, aad, data, &tag.0).map_err(error::erase)
        }
        match self {
            Inner::Aes128Gcm(a) => with(a, nonce, aad, data, tag),
            Inner::Aes256Gcm(a) => with(a, nonce, aad, data, tag),
            Inner::ChaCha20Poly1305(a) => with(a, nonce, aad, data, tag),
        }
    }
}

/// A key not yet tied to a way of choosing nonces.
pub struct UnboundKey {
    inner: LessSafeKey,
}

impl UnboundKey {
    /// A key for `algorithm`. Fails only if `key_bytes` is the wrong
    /// length.
    #[inline]
    pub fn new(
        algorithm: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        Ok(Self {
            inner: LessSafeKey::new_(algorithm, key_bytes)?,
        })
    }

    /// The algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.inner.algorithm()
    }

    fn into_inner(self) -> LessSafeKey {
        self.inner
    }
}

impl fmt::Debug for UnboundKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt_debug("UnboundKey", f)
    }
}

impl From<hkdf::Okm<'_, &'static Algorithm>> for UnboundKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let algorithm = *okm.len();
        let mut bytes = [0u8; MAX_KEY_LEN];
        let bytes = &mut bytes[..algorithm.key_len()];
        // A key is far below HKDF's limit, and the buffer is exactly
        // the key's length, so neither step can fail.
        okm.fill(bytes).unwrap_or_else(|error::Unspecified| {
            unreachable!("one key exceeded HKDF's limit")
        });
        let key =
            Self::new(algorithm, bytes).unwrap_or_else(|error::Unspecified| {
                unreachable!("a key of its own length")
            });
        bytes.zeroize();
        key
    }
}

/// A key the caller supplies each nonce for.
///
/// "Less safe" because nothing stops a nonce being used twice, which
/// under either algorithm gives away the plaintexts and the key's
/// authentication.
#[derive(Clone)]
pub struct LessSafeKey {
    inner: Inner,
    algorithm: &'static Algorithm,
}

impl LessSafeKey {
    /// Takes the key.
    #[inline]
    pub fn new(key: UnboundKey) -> Self {
        key.into_inner()
    }

    fn new_(
        algorithm: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        Ok(Self {
            inner: Inner::new(algorithm, key_bytes)?,
            algorithm,
        })
    }

    /// Opens the ciphertext at `in_out[ciphertext..]` against `tag`,
    /// leaving the plaintext at the front of `in_out`. The returned
    /// slice is the plaintext. On failure the region is zeroed.
    pub fn open_in_place_separate_tag<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        tag: Tag,
        in_out: &'in_out mut [u8],
        ciphertext: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        let start = ciphertext.start;
        let len = in_out.len().checked_sub(start).ok_or(error::Unspecified)?;
        // scytale opens in place, so the plaintext is moved to the
        // front once it is known to be genuine.
        match self
            .inner
            .open(&nonce, aad.as_ref(), &mut in_out[start..], &tag)
        {
            Ok(()) => {
                in_out.copy_within(start.., 0);
                Ok(&mut in_out[..len])
            }
            Err(e) => {
                in_out[..len].fill(0);
                Err(e)
            }
        }
    }

    /// Opens `in_out`, which is ciphertext then tag. The returned slice
    /// is the plaintext.
    #[inline]
    pub fn open_in_place<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.open_within(nonce, aad, in_out, 0..)
    }

    /// Opens the ciphertext and tag at `in_out[ciphertext_and_tag..]`,
    /// leaving the plaintext at the front of `in_out`.
    pub fn open_within<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        let tag_offset = in_out
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(error::Unspecified)?;
        let (in_out, received) = in_out.split_at_mut(tag_offset);
        let tag = Tag::try_from(&*received)?;
        self.open_in_place_separate_tag(
            nonce,
            aad,
            tag,
            in_out,
            ciphertext_and_tag,
        )
    }

    /// Seals `in_out` and appends the tag to it.
    #[inline]
    pub fn seal_in_place_append_tag<A, InOut>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), error::Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.seal_in_place_separate_tag(nonce, aad, in_out.as_mut())
            .map(|tag| in_out.extend(tag.as_ref()))
    }

    /// Seals `in_out` and returns the tag.
    #[inline]
    pub fn seal_in_place_separate_tag<A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.inner.seal(&nonce, aad.as_ref(), in_out)
    }

    /// The algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    fn fmt_debug(
        &self,
        type_name: &'static str,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        f.debug_struct(type_name)
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

impl fmt::Debug for LessSafeKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_debug("LessSafeKey", f)
    }
}

/// Where a bound key's nonces come from. Each call must return a
/// nonce never returned before under the same key.
pub trait NonceSequence {
    /// The next nonce, or an error once there are no more.
    fn advance(&mut self) -> Result<Nonce, error::Unspecified>;
}

/// A key bound to a [`NonceSequence`].
pub trait BoundKey<N: NonceSequence>: fmt::Debug {
    /// Binds `key` to `nonce_sequence`.
    fn new(key: UnboundKey, nonce_sequence: N) -> Self;

    /// The algorithm.
    fn algorithm(&self) -> &'static Algorithm;
}

/// A key that seals, taking each nonce from its sequence.
pub struct SealingKey<N: NonceSequence> {
    key: LessSafeKey,
    nonce_sequence: N,
}

impl<N: NonceSequence> BoundKey<N> for SealingKey<N> {
    fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key: key.into_inner(),
            nonce_sequence,
        }
    }

    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm()
    }
}

impl<N: NonceSequence> fmt::Debug for SealingKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.key.fmt_debug("SealingKey", f)
    }
}

impl<N: NonceSequence> SealingKey<N> {
    /// As [`LessSafeKey::seal_in_place_append_tag`], with the next
    /// nonce.
    #[inline]
    pub fn seal_in_place_append_tag<A, InOut>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), error::Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        let nonce = self.nonce_sequence.advance()?;
        self.key.seal_in_place_append_tag(nonce, aad, in_out)
    }

    /// As [`LessSafeKey::seal_in_place_separate_tag`], with the next
    /// nonce.
    #[inline]
    pub fn seal_in_place_separate_tag<A>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        let nonce = self.nonce_sequence.advance()?;
        self.key.seal_in_place_separate_tag(nonce, aad, in_out)
    }
}

/// A key that opens, taking each nonce from its sequence.
pub struct OpeningKey<N: NonceSequence> {
    key: LessSafeKey,
    nonce_sequence: N,
}

impl<N: NonceSequence> BoundKey<N> for OpeningKey<N> {
    fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key: key.into_inner(),
            nonce_sequence,
        }
    }

    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm()
    }
}

impl<N: NonceSequence> fmt::Debug for OpeningKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.key.fmt_debug("OpeningKey", f)
    }
}

impl<N: NonceSequence> OpeningKey<N> {
    /// As [`LessSafeKey::open_in_place`], with the next nonce.
    #[inline]
    pub fn open_in_place<'in_out, A>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        let nonce = self.nonce_sequence.advance()?;
        self.key.open_in_place(nonce, aad, in_out)
    }

    /// As [`LessSafeKey::open_within`], with the next nonce.
    #[inline]
    pub fn open_within<'in_out, A>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        let nonce = self.nonce_sequence.advance()?;
        self.key.open_within(nonce, aad, in_out, ciphertext_and_tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    // RFC 8439 section 2.8.2.
    #[test]
    fn chacha20_poly1305_gives_the_published_output() {
        let key = hex("808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f");
        let nonce = hex("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
        let key = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &key).expect("key"),
        );
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::try_assume_unique_for_key(&nonce).expect("nonce"),
            Aad::from(&aad),
            &mut in_out,
        )
        .expect("seal");
        assert_eq!(
            &in_out[in_out.len() - 16..],
            &hex("1ae10b594f09e26a7e902ecbd0600691")[..]
        );
        assert_eq!(&in_out[..4], &hex("d31a8d34")[..]);
        let opened = key
            .open_in_place(
                Nonce::try_assume_unique_for_key(&nonce).expect("nonce"),
                Aad::from(&aad),
                &mut in_out,
            )
            .expect("open");
        assert_eq!(opened, &plaintext[..]);
    }

    fn round_trip(algorithm: &'static Algorithm) {
        let key_bytes = [0x11u8; 32];
        let key = LessSafeKey::new(
            UnboundKey::new(algorithm, &key_bytes[..algorithm.key_len()])
                .expect("key"),
        );
        let n = || Nonce::assume_unique_for_key([7u8; NONCE_LEN]);
        let message = *b"a message of no particular length";

        // Sealed with the tag apart, then opened from an offset, as a
        // TLS 1.2 record with an explicit nonce is.
        let mut buf = [0u8; 8 + 33 + 16];
        buf[8..41].copy_from_slice(&message);
        let tag = key
            .seal_in_place_separate_tag(n(), Aad::empty(), &mut buf[8..41])
            .expect("seal");
        buf[41..].copy_from_slice(tag.as_ref());
        let opened = key
            .open_within(n(), Aad::empty(), &mut buf, 8..)
            .expect("open");
        assert_eq!(opened, &message[..]);

        // A flipped bit is refused and the region zeroed.
        let mut sealed = message.to_vec();
        key.seal_in_place_append_tag(n(), Aad::from(b"hdr"), &mut sealed)
            .expect("seal");
        sealed[3] ^= 1;
        assert!(
            key.open_in_place(n(), Aad::from(b"hdr"), &mut sealed)
                .is_err()
        );
        assert!(sealed[..33].iter().all(|&b| b == 0));
    }

    #[test]
    fn every_algorithm_round_trips_and_refuses_forgery() {
        round_trip(&AES_128_GCM);
        round_trip(&AES_256_GCM);
        round_trip(&CHACHA20_POLY1305);
    }

    #[test]
    fn short_input_and_wrong_lengths_are_refused() {
        assert!(UnboundKey::new(&AES_128_GCM, &[0u8; 32]).is_err());
        assert!(Nonce::try_assume_unique_for_key(&[0u8; 11]).is_err());
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &[0u8; 32]).expect("key"),
        );
        let n = Nonce::assume_unique_for_key([0u8; NONCE_LEN]);
        assert!(key.open_in_place(n, Aad::empty(), &mut [0u8; 15]).is_err());
        let n = Nonce::assume_unique_for_key([0u8; NONCE_LEN]);
        assert!(
            key.open_within(n, Aad::empty(), &mut [0u8; 20], 5..)
                .is_err()
        );
    }

    #[test]
    fn algorithms_print_by_name() {
        extern crate std;
        assert_eq!(std::format!("{:?}", AES_128_GCM), "AES_128_GCM");
        let key = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &[0u8; 32]).expect("key"),
        );
        assert_eq!(
            std::format!("{key:?}"),
            "LessSafeKey { algorithm: CHACHA20_POLY1305 }"
        );
    }
}
