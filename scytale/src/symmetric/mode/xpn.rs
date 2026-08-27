//! AES-GCM with extended packet numbering, as MACsec uses it.
//!
//! This is [`Gcm`] with the nonce assembled differently.
//! A link protocol numbers its frames, and the number is what keeps
//! nonces from repeating; extending that number to 64 bits lets a
//! fast link run far longer before the key must be changed. To keep
//! the number itself off the wire in full, it is combined with a
//! secret salt agreed for the session, and the result is the nonce
//! GCM sees.
//!
//! # The two halves
//!
//! Both are 96 bits. The salt is fixed for the session and secret.
//! The other half identifies the frame: in MACsec it is a 32-bit
//! channel identifier followed by the 64-bit packet number, most
//! significant byte first.
//!
//! # Using it safely
//!
//! - **The frame identifier must never repeat under one salt and
//!   key.** That is the whole basis of the scheme, and repeating it
//!   breaks GCM completely, as described in [`Gcm`].
//! - A shorter tag is a weaker one, and link protocols often choose
//!   eight bytes for the sake of overhead. That is a deliberate
//!   trade, not a free saving.
//!
//! There is no incremental form: this exists for network frames,
//! which are small and arrive whole.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::Aes;
//! use scytale::symmetric::mode::Xpn;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let xpn = Xpn::try_new(Aes::try_new(&[0u8; 16])?)?;
//! let salt = [0x5a; 12];
//!
//! // Channel 1, packet 7.
//! let mut frame_id = [0u8; 12];
//! frame_id[..4].copy_from_slice(&1u32.to_be_bytes());
//! frame_id[4..].copy_from_slice(&7u64.to_be_bytes());
//!
//! let mut frame = *b"payload";
//! let mut tag = [0u8; 16];
//! xpn.encrypt(&salt, &frame_id, b"header", &mut frame, &mut tag)?;
//!
//! xpn.decrypt(&salt, &frame_id, b"header", &mut frame, &tag)?;
//! assert_eq!(&frame, b"payload");
//! # Ok(())
//! # }
//! ```

use super::gcm::Gcm;
use super::ghash::BLOCK;
use crate::symmetric::BlockCipher;
use crate::Error;

/// The length of both the salt and the frame identifier.
const HALF: usize = 12;

/// GCM with extended packet numbering, over a block cipher.
#[derive(Clone, Debug)]
pub struct Xpn<C> {
    gcm: Gcm<C>,
}

impl<C: BlockCipher<Block = [u8; BLOCK]>> Xpn<C> {
    /// Wraps `cipher`.
    pub fn try_new(cipher: C) -> Result<Self, Error> {
        Ok(Xpn {
            gcm: Gcm::try_new(cipher)?,
        })
    }

    /// Encrypts `data` in place and writes its tag.
    ///
    /// `salt` and `frame` are each 12 bytes; together they make the
    /// nonce. `aad` is authenticated but not encrypted, which for a
    /// link protocol is the part of the header that must stay
    /// readable.
    pub fn encrypt(
        &self,
        salt: &[u8],
        frame: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), Error> {
        let nonce = nonce(salt, frame)?;
        self.gcm.encrypt(&nonce, aad, data, tag)
    }

    /// Checks `tag` and, if it is right, decrypts `data` in place.
    ///
    /// On failure the buffer is wiped and
    /// [`Error::AuthenticationFailed`] returned.
    pub fn decrypt(
        &self,
        salt: &[u8],
        frame: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let nonce = nonce(salt, frame)?;
        self.gcm.decrypt(&nonce, aad, data, tag)
    }
}

/// Combines the session salt with the frame identifier.
fn nonce(salt: &[u8], frame: &[u8]) -> Result<[u8; HALF], Error> {
    if salt.len() != HALF {
        return Err(Error::InvalidNonceLength(salt.len()));
    }
    if frame.len() != HALF {
        return Err(Error::InvalidNonceLength(frame.len()));
    }
    let mut nonce = [0u8; HALF];
    for ((slot, a), b) in nonce.iter_mut().zip(salt).zip(frame) {
        *slot = a ^ b;
    }
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::Aes;
    use crate::symmetric::mode::Gcm;

    fn xpn() -> Xpn<Aes> {
        Xpn::try_new(Aes::try_new(&[0x42; 16]).unwrap()).unwrap()
    }

    /// It must agree with plain GCM under the combined nonce, which
    /// is the whole of what it adds.
    #[test]
    fn matches_gcm_under_the_combined_nonce() {
        let salt = [0x5au8; 12];
        let frame = [0x31u8; 12];
        let mut combined = [0u8; 12];
        for ((s, a), b) in combined.iter_mut().zip(&salt).zip(&frame) {
            *s = a ^ b;
        }

        let plain = [7u8; 24];
        let mut by_xpn = plain;
        let mut xpn_tag = [0u8; 16];
        xpn()
            .encrypt(&salt, &frame, b"head", &mut by_xpn, &mut xpn_tag)
            .unwrap();

        let gcm = Gcm::try_new(Aes::try_new(&[0x42; 16]).unwrap()).unwrap();
        let mut by_gcm = plain;
        let mut gcm_tag = [0u8; 16];
        gcm.encrypt(&combined, b"head", &mut by_gcm, &mut gcm_tag)
            .unwrap();

        assert_eq!(by_xpn, by_gcm);
        assert_eq!(xpn_tag, gcm_tag);
    }

    /// Changing either half must change the answer: neither may be
    /// ignored.
    #[test]
    fn both_halves_matter() {
        let xpn = xpn();
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        let mut third = [0u8; 16];
        let mut tag = [0u8; 16];
        xpn.encrypt(&[1; 12], &[2; 12], b"", &mut first, &mut tag)
            .unwrap();
        xpn.encrypt(&[9; 12], &[2; 12], b"", &mut second, &mut tag)
            .unwrap();
        xpn.encrypt(&[1; 12], &[9; 12], b"", &mut third, &mut tag)
            .unwrap();
        assert_ne!(first, second, "the salt matters");
        assert_ne!(first, third, "the frame identifier matters");
    }

    #[test]
    fn rejects_and_wipes() {
        let xpn = xpn();
        let plain = [3u8; 20];
        let mut sealed = plain;
        let mut tag = [0u8; 16];
        xpn.encrypt(&[1; 12], &[2; 12], b"h", &mut sealed, &mut tag)
            .unwrap();

        let mut wrong = tag;
        wrong[0] ^= 1;
        let mut data = sealed;
        assert_eq!(
            xpn.decrypt(&[1; 12], &[2; 12], b"h", &mut data, &wrong)
                .unwrap_err(),
            Error::AuthenticationFailed
        );
        assert_eq!(data, [0u8; 20], "buffer wiped");

        // The right tag but the wrong frame.
        let mut data = sealed;
        assert_eq!(
            xpn.decrypt(&[1; 12], &[3; 12], b"h", &mut data, &tag)
                .unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn rejects_bad_lengths() {
        let xpn = xpn();
        let source = [0u8; 16];
        for n in [0, 11, 13, 16] {
            assert_eq!(
                xpn.encrypt(&source[..n], &[0; 12], b"", &mut [], &mut [0; 16])
                    .unwrap_err(),
                Error::InvalidNonceLength(n)
            );
            assert_eq!(
                xpn.encrypt(&[0; 12], &source[..n], b"", &mut [], &mut [0; 16])
                    .unwrap_err(),
                Error::InvalidNonceLength(n)
            );
        }
    }
}
