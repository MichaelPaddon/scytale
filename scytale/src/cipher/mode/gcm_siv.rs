//! AES-GCM-SIV (RFC 8452), which survives a repeated nonce.
//!
//! Every mode before this one fails catastrophically if a nonce is
//! used twice: the keystream repeats and the messages leak into each
//! other, and for GCM an attacker can go on to forge tags at will.
//! GCM-SIV is built so that repeating a nonce reveals only whether
//! two messages were identical, and nothing else.
//!
//! It achieves that by deriving the tag from the message itself and
//! then using the tag as the starting counter, so the keystream
//! depends on what is being encrypted. Fresh keys are also derived
//! for every nonce, from the key given here.
//!
//! # One-shot only
//!
//! There is no incremental form, and there cannot be one for
//! encryption: the counter is the tag, the tag covers the whole
//! message, so nothing can be encrypted until every byte has been
//! seen. Decryption is kept one-shot to match, and because releasing
//! plaintext before the tag has been checked would give away the
//! property this mode exists for.
//!
//! # Using it safely
//!
//! - A repeated nonce is survivable here, not free: an observer still
//!   learns that two messages were the same. Fresh nonces remain
//!   worth having.
//! - The key is 16 or 32 bytes. RFC 8452 defines no 24-byte variant,
//!   so one is refused rather than quietly reinterpreted.
//! - The nonce is always 12 bytes and the tag always 16.
//!
//! # Example
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::mode::GcmSiv;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let siv = GcmSiv::<Aes128>::new(&Key::from([0u8; 16]));
//! let nonce = [0u8; 12];
//!
//! let mut message = *b"hello";
//! let mut tag = [0u8; 16];
//! siv.encrypt(&nonce, b"header", &mut message, &mut tag)?;
//!
//! siv.decrypt(&nonce, b"header", &mut message, &tag)?;
//! assert_eq!(&message, b"hello");
//! # Ok(())
//! # }
//! ```

use core::fmt;

#[cfg(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
))]
use super::gcm;
use super::ghash::BLOCK;
use super::polyval::Polyval;
use super::{ByteOrder, counter_blocks, xor};
use crate::cipher::{BlockCipher, OneBlock};
use crate::util;
use crate::{Error, Key};
use zeroize::Zeroize;

/// The nonce length, fixed by the standard.
const NONCE: usize = 12;

/// The tag length, fixed by the standard.
const TAG: usize = BLOCK;

/// The most bytes of message or additional data allowed: 2^36.
const MAX_FIELD: u64 = 1 << 36;

/// A key width GCM-SIV's key derivation is defined for: 16 or 32
/// bytes. Sealed.
///
/// RFC 8452 derives a 16-byte hashing key and an encrypting key of
/// the cipher's own width from successive counter blocks, and it
/// spells that out for those two widths only. A 24-byte key has no
/// derivation to follow, so AES-192 is not a GCM-SIV cipher and
/// `GcmSiv<Aes192>` does not compile.
/// ```
/// use scytale::Key;
/// use scytale::cipher::aes::{Aes128, Aes256};
/// use scytale::cipher::mode::GcmSiv;
/// let _ = GcmSiv::<Aes128>::new(&Key::from([0u8; 16]));
/// let _ = GcmSiv::<Aes256>::new(&Key::from([0u8; 32]));
/// ```
///
/// ```compile_fail
/// use scytale::Key;
/// use scytale::cipher::aes::Aes192;
/// use scytale::cipher::mode::GcmSiv;
/// // AES-192 is a cipher, but not one GCM-SIV is defined over.
/// let _ = GcmSiv::<Aes192>::new(&Key::from([0u8; 24]));
/// ```
pub trait SivKey: sealed::Sealed {}

impl SivKey for Key<[u8; 16]> {}
impl SivKey for Key<[u8; 32]> {}

mod sealed {
    use crate::Key;

    pub trait Sealed {}
    impl Sealed for Key<[u8; 16]> {}
    impl Sealed for Key<[u8; 32]> {}
}

/// GCM-SIV over a block cipher.
///
/// RFC 8452 defines the construction over AES-128 and AES-256, which
/// is what [`Aes128`](crate::cipher::aes::Aes128) and
/// [`Aes256`](crate::cipher::aes::Aes256) give. Any other 128-bit
/// block cipher taking a key of one of those widths satisfies the
/// construction and is allowed here, but it is outside the standard
/// and there are no vectors for it; that choice is the caller's.
///
/// Every nonce gets its own pair of keys derived from the key here,
/// so the cipher this holds encrypts nothing but those derivations.
#[derive(Clone)]
pub struct GcmSiv<C: BlockCipher<Block = [u8; BLOCK], Key: SivKey>> {
    cipher: C,
    key_len: usize,
    /// How to reach the round keys of a cipher derived from this key,
    /// where this processor has the loops that want them.
    ///
    /// Encrypting, the counter runs on its own: the tag covers the
    /// plaintext and the counter comes from the tag, so the hash must
    /// finish before the cipher starts. Decrypting, the counter comes
    /// from the tag that arrived, so the cipher runs first and the
    /// hash covers what it produces, which is the one case here where
    /// the two can be the same loop.
    #[cfg_attr(
        not(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "x86_64"
        )),
        allow(dead_code)
    )]
    native: Option<Keys<C>>,
}

/// How to reach a cipher's round keys; see [`GcmSiv::native`].
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
))]
type Keys<C> = gcm::native::Keys<C>;

/// Nothing reaches them on an architecture with no loop to feed.
#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
)))]
type Keys<C> = core::marker::PhantomData<C>;

impl<C: BlockCipher<Block = [u8; BLOCK], Key: SivKey>> fmt::Debug
    for GcmSiv<C>
{
    /// Deliberately omits the cipher, which holds the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcmSiv").finish_non_exhaustive()
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
    /// The counter written out, and when decrypting the hash run
    /// beside it.
    Native,
    /// The construction over the cipher's own counter loop, with the
    /// hash run separately.
    Generic,
}

/// Every implementation, best first.
pub(crate) const CHOICES: [Choice; 2] = [Choice::Native, Choice::Generic];

impl<C: BlockCipher<Block = [u8; BLOCK], Key: SivKey>> GcmSiv<C> {
    /// Takes the key that all others are derived from.
    pub fn new(key: &C::Key) -> Self {
        for choice in CHOICES {
            if let Some(mode) = Self::with_choice(key, choice) {
                return mode;
            }
        }
        Self::generic(key)
    }

    /// The mode over the implementation `choice` names, or `None`
    /// where this processor or this cipher has no such thing.
    pub(crate) fn with_choice(key: &C::Key, choice: Choice) -> Option<Self> {
        match choice {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "riscv64",
                target_arch = "x86_64"
            ))]
            Choice::Native => {
                let keys = gcm::native::keys::<C>()?;
                Some(GcmSiv {
                    native: Some(keys),
                    ..Self::generic(key)
                })
            }
            Choice::Generic => Some(Self::generic(key)),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// The mode over the cipher's own calls, which every processor
    /// has.
    fn generic(key: &C::Key) -> Self {
        GcmSiv {
            cipher: C::new(key),
            key_len: key.as_ref().len(),
            native: None,
        }
    }

    /// Encrypts `data` in place and writes its 16-byte tag.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8; TAG],
    ) -> Result<(), Error> {
        check(aad, data.len())?;
        let (hash_key, cipher) = self.derive(nonce);

        // The tag covers the plaintext, so it is computed first.
        let full = authenticate(&hash_key, &cipher, nonce, aad, data)?;
        let mut counter = full;
        counter[BLOCK - 1] |= 0x80;
        self.apply(&cipher, &mut counter, data);

        tag.copy_from_slice(&full);
        Ok(())
    }

    /// Checks `tag` and, if it is right, decrypts `data` in place.
    ///
    /// On failure the buffer is wiped and
    /// [`Error::AuthenticationFailed`] returned.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG],
    ) -> Result<(), Error> {
        check(aad, data.len())?;
        let (hash_key, cipher) = self.derive(nonce);

        // The counter comes from the tag, so the message can be
        // decrypted before the tag is known to be right; then the tag
        // is recomputed over the plaintext and compared.
        let mut counter = *tag;
        counter[BLOCK - 1] |= 0x80;
        let full = self.decrypt_and_authenticate(
            &hash_key,
            &cipher,
            nonce,
            aad,
            &mut counter,
            data,
        )?;
        if util::equal(&full, tag) {
            Ok(())
        } else {
            data.fill(0);
            Err(Error::AuthenticationFailed)
        }
    }

    /// The counter over `data`, with nothing hashed beside it.
    fn apply(&self, cipher: &C, counter: &mut [u8; BLOCK], data: &mut [u8]) {
        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "x86_64"
        ))]
        if let Some(schedule) = self.native.and_then(|keys| keys(cipher)) {
            let (whole, tail) = data.as_chunks_mut::<BLOCK>();
            gcm::native::siv_counter(
                schedule,
                counter,
                whole.as_flattened_mut(),
            );
            steal(cipher, counter, tail);
            return;
        }
        apply(cipher, counter, data);
    }

    /// Decrypts `data` and hashes the plaintext it produces, which
    /// here is one pass: the counter comes from the tag that arrived,
    /// so the cipher does not wait on the hash.
    #[allow(clippy::too_many_arguments)]
    fn decrypt_and_authenticate(
        &self,
        hash_key: &[u8; BLOCK],
        cipher: &C,
        nonce: &[u8; NONCE],
        aad: &[u8],
        counter: &mut [u8; BLOCK],
        data: &mut [u8],
    ) -> Result<[u8; BLOCK], Error> {
        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "x86_64"
        ))]
        if let Some(schedule) = self.native.and_then(|keys| keys(cipher)) {
            {
                let len = data.len();
                let mut hash = Polyval::new(hash_key, aad.len() + len);
                // The additional data comes first, as it does in the
                // tag's definition, and is a field of its own.
                hash.update(aad);
                hash.pad();
                let (whole, tail) = data.as_chunks_mut::<BLOCK>();
                let whole = whole.as_flattened_mut();
                // One pass where there is a loop that decrypts and
                // hashes together, which so far is x86-64 alone.
                #[allow(unused_mut)]
                let mut fused = false;
                #[cfg(target_arch = "x86_64")]
                if let Some(native) = hash.native() {
                    native.bulk(schedule, counter, whole);
                    fused = true;
                }
                if !fused {
                    // In turn: the counter written out, and then the
                    // hash over what it produced.
                    gcm::native::siv_counter(schedule, counter, whole);
                    hash.update(whole);
                }
                steal(cipher, counter, tail);
                hash.update(tail);
                hash.pad();
                hash.update(&lengths(aad.len(), len));
                return Ok(seal(hash.finish(), cipher, nonce));
            }
        }
        apply(cipher, counter, data);
        authenticate(hash_key, cipher, nonce, aad, data)
    }

    /// Derives the hashing key and the encrypting cipher for one
    /// nonce, as RFC 8452 section 4 does: successive counters with
    /// the nonce, keeping the first half of each result.
    fn derive(&self, nonce: &[u8; NONCE]) -> ([u8; BLOCK], C) {
        let mut material = [0u8; 48];
        let blocks = 2 + self.key_len / 8;
        for i in 0..blocks {
            let mut block = [0u8; BLOCK];
            block[..4].copy_from_slice(&(i as u32).to_le_bytes());
            block[4..BLOCK].copy_from_slice(nonce);
            self.cipher.encrypt_one(&mut block);
            material[i * 8..(i + 1) * 8].copy_from_slice(&block[..8]);
        }
        let mut hash_key = [0u8; BLOCK];
        hash_key.copy_from_slice(&material[..BLOCK]);
        let mut key = C::zero_key();
        key.as_mut()
            .copy_from_slice(&material[BLOCK..BLOCK + self.key_len]);
        let cipher = C::new(&key);
        key.as_mut().zeroize();
        material.zeroize();
        (hash_key, cipher)
    }
}

/// Checks the size limits.
fn check(aad: &[u8], message: usize) -> Result<(), Error> {
    if aad.len() as u64 > MAX_FIELD || message as u64 > MAX_FIELD {
        return Err(Error::MessageTooLong);
    }
    Ok(())
}

/// The tag for a plaintext: POLYVAL over the additional data, the
/// message and their lengths, combined with the nonce and encrypted.
fn authenticate<C: BlockCipher<Block = [u8; BLOCK]>>(
    hash_key: &[u8; BLOCK],
    cipher: &C,
    nonce: &[u8; NONCE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<[u8; BLOCK], Error> {
    let mut hash = Polyval::new(hash_key, aad.len() + plaintext.len());
    hash.update(aad);
    hash.pad();
    hash.update(plaintext);
    hash.pad();

    hash.update(&lengths(aad.len(), plaintext.len()));
    Ok(seal(hash.finish(), cipher, nonce))
}

/// The length block the hash ends with: the two lengths in bits, the
/// little-endian way round.
fn lengths(aad: usize, message: usize) -> [u8; BLOCK] {
    let mut lengths = [0u8; BLOCK];
    lengths[..8].copy_from_slice(&((aad as u64) * 8).to_le_bytes());
    lengths[8..].copy_from_slice(&((message as u64) * 8).to_le_bytes());
    lengths
}

/// The tag from a finished hash: combined with the nonce and
/// encrypted.
fn seal<C: BlockCipher<Block = [u8; BLOCK]>>(
    mut tag: [u8; BLOCK],
    cipher: &C,
    nonce: &[u8; NONCE],
) -> [u8; BLOCK] {
    for (byte, n) in tag.iter_mut().zip(nonce) {
        *byte ^= n;
    }
    // The top bit is cleared here and set again in the counter, which
    // keeps the tag out of the counter's own range.
    tag[BLOCK - 1] &= 0x7f;
    cipher.encrypt_one(&mut tag);
    tag
}

/// The counter over the last part block, which no bulk loop covers.
///
/// The construction over the cipher's own calls does its own, so this
/// is for the loops written out.
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
))]
fn steal<C: BlockCipher<Block = [u8; BLOCK]>>(
    cipher: &C,
    counter: &mut [u8; BLOCK],
    tail: &mut [u8],
) {
    if !tail.is_empty() {
        let mut keystream = *counter;
        increment(counter);
        cipher.encrypt_one(&mut keystream);
        xor(tail, &keystream);
    }
}

/// Counter mode as GCM-SIV defines it: the counter is the first four
/// bytes, read the little-endian way round.
fn apply<C: BlockCipher<Block = [u8; BLOCK]>>(
    cipher: &C,
    counter: &mut [u8; BLOCK],
    data: &mut [u8],
) {
    // Whole blocks in one run: the four bytes this mode counts in wrap
    // inside themselves, which is what the counter loop does, so there
    // is no boundary to split at.
    let (whole, tail) = data.as_chunks_mut::<BLOCK>();
    counter_blocks(
        cipher,
        counter,
        ByteOrder::Little,
        whole.as_flattened_mut(),
    );
    if !tail.is_empty() {
        let mut keystream = *counter;
        increment(counter);
        cipher.encrypt_one(&mut keystream);
        xor(tail, &keystream);
    }
}

/// Adds one to the first four bytes, least significant first.
fn increment(counter: &mut [u8; BLOCK]) {
    for byte in counter[..4].iter_mut() {
        let (sum, carried) = byte.overflowing_add(1);
        *byte = sum;
        if !carried {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::{Aes, Aes128, Aes256};

    /// Buffers big enough for every case below.
    const MAX: usize = 32;

    fn unhex<'a>(text: &str, buffer: &'a mut [u8]) -> &'a [u8] {
        let n = text.len() / 2;
        for i in 0..n {
            buffer[i] =
                u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        &buffer[..n]
    }

    /// RFC 8452 appendix C: key, nonce, additional data, plaintext,
    /// ciphertext, tag.
    const CASES: [[&str; 6]; 6] = [
        [
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "0100000000000000",
            "b5d839330ac7b786",
            "578782fff6013b815b287c22493a364c",
        ],
        [
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "010000000000000000000000",
            "7323ea61d05932260047d942",
            "a4978db357391a0bc4fdec8b0d106639",
        ],
        [
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            "0200000000000000",
            "1e6daba35669f427",
            "3b0a1a2560969cdf790d99759abd1508",
        ],
        [
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "010000000000000000000000",
            "02000000000000000000000000000000",
            "daf46cabd2e1ee43d52942c0f99a3309",
            "b4abb466c906a2777c93bdae563831e1",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000\
             000000",
            "030000000000000000000000",
            "",
            "0100000000000000",
            "c2ef328e5c71c83b",
            "843122130f7364b761e0b97427e3df28",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000\
             000000",
            "030000000000000000000000",
            "010000000000000000000000",
            "02000000000000000000000000000000",
            "a463fcad737f8a3069d2b7575e79c6b7",
            "feae1d0f24321df9ccf01f22033a0b30",
        ],
    ];

    #[test]
    fn rfc8452_test_cases() {
        for (i, case) in CASES.iter().enumerate() {
            let (mut kb, mut nb) = ([0u8; 32], [0u8; 12]);
            let (mut ab, mut pb) = ([0u8; MAX], [0u8; MAX]);
            let (mut cb, mut tb) = ([0u8; MAX], [0u8; 16]);
            let key = unhex(case[0], &mut kb);
            unhex(case[1], &mut nb);
            let nonce = &nb;
            let aad = unhex(case[2], &mut ab);
            let plain = unhex(case[3], &mut pb);
            let cipher = unhex(case[4], &mut cb);
            unhex(case[5], &mut tb);
            let want = &tb;

            match key.len() {
                16 => run_case::<16>(i, key, nonce, aad, plain, cipher, want),
                _ => run_case::<32>(i, key, nonce, aad, plain, cipher, want),
            }
        }
    }

    fn run_case<const K: usize>(
        i: usize,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plain: &[u8],
        cipher: &[u8],
        want: &[u8; 16],
    ) where
        Key<[u8; K]>: SivKey,
    {
        let key: &[u8; K] = key.try_into().unwrap();
        let siv = GcmSiv::<Aes<K>>::new(&Key::from(*key));
        let mut data = [0u8; MAX];
        let data = &mut data[..plain.len()];
        data.copy_from_slice(plain);
        let mut tag = [0u8; 16];

        siv.encrypt(nonce, aad, data, &mut tag).unwrap();
        assert_eq!(data, cipher, "case {i} ciphertext");
        assert_eq!(&tag, want, "case {i} tag");

        siv.decrypt(nonce, aad, data, want).unwrap();
        assert_eq!(data, plain, "case {i} plaintext");
    }

    fn siv() -> GcmSiv<Aes128> {
        GcmSiv::<Aes128>::new(&Key::from([0x42; 16]))
    }

    /// The point of the mode: a repeated nonce must not be a
    /// catastrophe. Two different messages under one nonce must not
    /// share a keystream, which is what would happen in GCM.
    #[test]
    fn a_repeated_nonce_is_survivable() {
        let siv = siv();
        let nonce = [1u8; 12];

        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        second[0] = 1; // differs in one byte only
        let original = second;
        let mut tag_a = [0u8; 16];
        let mut tag_b = [0u8; 16];
        siv.encrypt(&nonce, b"", &mut first, &mut tag_a).unwrap();
        siv.encrypt(&nonce, b"", &mut second, &mut tag_b).unwrap();

        // Under a shared keystream the two ciphertexts would differ
        // in exactly the byte the plaintexts differ in. Here they
        // differ throughout.
        let same: usize =
            first.iter().zip(&second).filter(|(a, b)| a == b).count();
        assert!(same < 8, "{same} bytes matched; keystream was reused");
        assert_ne!(tag_a, tag_b);

        // What it does reveal is that two identical messages are
        // identical.
        let mut third = original;
        let mut tag_c = [0u8; 16];
        siv.encrypt(&nonce, b"", &mut third, &mut tag_c).unwrap();
        assert_eq!(third, second);
        assert_eq!(tag_c, tag_b);
    }

    #[test]
    fn rejects_and_wipes() {
        let siv = siv();
        let nonce = [7u8; 12];
        let plain = [9u8; 20];
        let mut sealed = plain;
        let mut tag = [0u8; 16];
        siv.encrypt(&nonce, b"head", &mut sealed, &mut tag).unwrap();

        let mut wrong = tag;
        wrong[0] ^= 1;
        let mut data = sealed;
        assert_eq!(
            siv.decrypt(&nonce, b"head", &mut data, &wrong).unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(data, [0u8; 20], "buffer wiped");

        let mut data = sealed;
        assert_eq!(
            siv.decrypt(&nonce, b"HEAD", &mut data, &tag).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    /// Every implementation this processor has must agree, at every
    /// length around the group boundaries the loops work in.
    #[test]
    fn the_engines_agree() {
        // Past the length at which the hash starts working out the
        // powers of its key, so that the loop which runs the cipher
        // and the hash together is reached as well.
        const MAX: usize = 2 * 1024 + 5;
        let key = Key::from([0x21u8; 16]);
        let nonce = [0x37u8; NONCE];
        let aad = [0x5au8; 13];
        let mut message = [0u8; MAX];
        for (i, b) in message.iter_mut().enumerate() {
            *b = (i * 9 + 4) as u8;
        }

        let generic =
            GcmSiv::<Aes128>::with_choice(&key, Choice::Generic).unwrap();
        for len in 0..MAX {
            let mut want = [0u8; MAX];
            want[..len].copy_from_slice(&message[..len]);
            let mut wanted_tag = [0u8; TAG];
            generic
                .encrypt(&nonce, &aad, &mut want[..len], &mut wanted_tag)
                .unwrap();

            for choice in CHOICES {
                let Some(siv) = GcmSiv::<Aes128>::with_choice(&key, choice)
                else {
                    continue;
                };
                let mut got = [0u8; MAX];
                got[..len].copy_from_slice(&message[..len]);
                let mut tag = [0u8; TAG];
                siv.encrypt(&nonce, &aad, &mut got[..len], &mut tag)
                    .unwrap();
                assert_eq!(got[..len], want[..len], "{len}, {choice:?}");
                assert_eq!(tag, wanted_tag, "tag {len}, {choice:?}");

                siv.decrypt(&nonce, &aad, &mut got[..len], &tag)
                    .unwrap_or_else(|e| panic!("{len}, {choice:?}: {e:?}"));
                assert_eq!(got[..len], message[..len], "{len}, {choice:?}");
            }
        }
    }

    #[test]
    fn round_trips_at_many_lengths() {
        let siv = GcmSiv::<Aes256>::new(&Key::from([0x5a; 32]));
        let nonce = [0x77u8; 12];
        let mut plain = [0u8; 70];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        for n in [0, 1, 15, 16, 17, 31, 32, 33, 70] {
            let mut data = [0u8; 70];
            data[..n].copy_from_slice(&plain[..n]);
            let mut tag = [0u8; 16];
            siv.encrypt(&nonce, &plain[..n], &mut data[..n], &mut tag)
                .unwrap();
            siv.decrypt(&nonce, &plain[..n], &mut data[..n], &tag)
                .unwrap();
            assert_eq!(data[..n], plain[..n], "{n} bytes");
        }
    }

    /// Formatting the state must not print the key.
    #[test]
    fn debug_omits_the_key() {
        struct Buffer([u8; 256], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let mut buffer = Buffer([0; 256], 0);
        core::fmt::write(
            &mut buffer,
            format_args!("{:?}", GcmSiv::<Aes256>::new(&Key::from([0x5a; 32]))),
        )
        .unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("5a, 5a"), "{text}");
        assert!(text.starts_with("GcmSiv"));
    }
}
