//! The `chacha20-poly1305@openssh.com` transport cipher.
//!
//! A packet is a four-byte length and then the payload. The length is
//! encrypted with one key, so that a receiver can read it before the
//! rest arrives, and the payload with another; the tag covers both
//! as sent. The nonce is the packet's sequence number, and every
//! key's counter starts at zero for the Poly1305 key and one for the
//! payload, as ChaCha20-Poly1305 has it.

use scytale::Key;
use scytale::cipher::chacha20::ChaCha20;
use scytale::mac::Mac;
use scytale::mac::poly1305::Poly1305;
use zeroize::Zeroize;

use crate::error;

/// The length of the key material: two ChaCha20 keys.
pub const KEY_LEN: usize = 2 * 32;

/// The length of the packet length field.
pub const PACKET_LENGTH_LEN: usize = 4;

/// The length of a tag.
pub const TAG_LEN: usize = super::TAG_LEN;

/// The two keys: `k_1` for the length, `k_2` for the payload.
struct Keys {
    k_1: ChaCha20,
    k_2: ChaCha20,
}

impl Keys {
    fn new(key_material: &[u8; KEY_LEN]) -> Self {
        let (k_2, k_1) = key_material.split_at(32);
        let key = |bytes: &[u8]| {
            let mut key = Key::from([0u8; 32]);
            key.as_mut().copy_from_slice(bytes);
            ChaCha20::new(&key)
        };
        Keys {
            k_1: key(k_1),
            k_2: key(k_2),
        }
    }

    /// Encrypts or decrypts the length field: the first block of
    /// `k_1`'s keystream, counter zero.
    fn length(&self, nonce: &[u8; 12], len: &mut [u8; PACKET_LENGTH_LEN]) {
        self.k_1
            .encrypt(nonce, 0, len)
            .unwrap_or_else(|_| unreachable!("four bytes at counter zero"));
    }

    /// The Poly1305 key for this packet: the first 32 bytes of
    /// `k_2`'s keystream at counter zero.
    fn poly_key(&self, nonce: &[u8; 12]) -> Key<[u8; 32]> {
        let mut key = Key::from([0u8; 32]);
        self.k_2
            .encrypt(nonce, 0, key.as_mut())
            .unwrap_or_else(|_| unreachable!("one block at counter zero"));
        key
    }

    /// Encrypts or decrypts the payload with `k_2` from counter one.
    fn payload(
        &self,
        nonce: &[u8; 12],
        data: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        self.k_2.encrypt(nonce, 1, data).map_err(error::erase)
    }
}

fn nonce(sequence_number: u32) -> [u8; 12] {
    let [s0, s1, s2, s3] = sequence_number.to_be_bytes();
    [0, 0, 0, 0, 0, 0, 0, 0, s0, s1, s2, s3]
}

fn tag(poly_key: &Key<[u8; 32]>, packet: &[u8]) -> [u8; TAG_LEN] {
    let mut mac = Poly1305::new(poly_key);
    mac.update(packet);
    mac.finalize()
}

/// A key that seals packets.
pub struct SealingKey {
    keys: Keys,
}

impl SealingKey {
    /// A key from its material.
    pub fn new(key_material: &[u8; KEY_LEN]) -> Self {
        SealingKey {
            keys: Keys::new(key_material),
        }
    }

    /// Encrypts the packet in place, length and payload, and writes
    /// the tag.
    ///
    /// # Panics
    ///
    /// If the packet is shorter than its length field.
    pub fn seal_in_place(
        &self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8; TAG_LEN],
    ) {
        let nonce = nonce(sequence_number);
        let Some((len, payload)) = plaintext_in_ciphertext_out
            .split_first_chunk_mut::<PACKET_LENGTH_LEN>()
        else {
            panic!("a packet is at least its length field");
        };
        self.keys.length(&nonce, len);
        self.keys
            .payload(&nonce, payload)
            .unwrap_or_else(|_| unreachable!("a packet is under 256 GiB"));
        let mut poly_key = self.keys.poly_key(&nonce);
        *tag_out = tag(&poly_key, plaintext_in_ciphertext_out);
        poly_key.zeroize();
    }
}

/// A key that opens packets.
pub struct OpeningKey {
    keys: Keys,
}

impl OpeningKey {
    /// A key from its material.
    pub fn new(key_material: &[u8; KEY_LEN]) -> Self {
        OpeningKey {
            keys: Keys::new(key_material),
        }
    }

    /// The packet length, decrypted, so the rest can be read.
    pub fn decrypt_packet_length(
        &self,
        sequence_number: u32,
        encrypted_packet_length: [u8; PACKET_LENGTH_LEN],
    ) -> [u8; PACKET_LENGTH_LEN] {
        let mut len = encrypted_packet_length;
        self.keys.length(&nonce(sequence_number), &mut len);
        len
    }

    /// Checks the tag over the packet as received, then decrypts the
    /// payload in place and returns it. The length field is left as
    /// it came.
    pub fn open_in_place<'a>(
        &self,
        sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<&'a [u8], error::Unspecified> {
        if ciphertext_in_plaintext_out.len() < PACKET_LENGTH_LEN {
            return Err(error::Unspecified);
        }
        let nonce = nonce(sequence_number);
        let mut poly_key = self.keys.poly_key(&nonce);
        let expected = self::tag(&poly_key, ciphertext_in_plaintext_out);
        poly_key.zeroize();
        if !scytale::constant_time::equal(&expected, tag) {
            return Err(error::Unspecified);
        }
        let payload = &mut ciphertext_in_plaintext_out[PACKET_LENGTH_LEN..];
        self.keys.payload(&nonce, payload)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_round_trips_and_a_forgery_is_refused() {
        let material = [0x42u8; KEY_LEN];
        let sealer = SealingKey::new(&material);
        let opener = OpeningKey::new(&material);
        let mut packet = *b"\x00\x00\x00\x0cpayload data";
        let plain = packet;
        let mut tag = [0u8; TAG_LEN];
        sealer.seal_in_place(7, &mut packet, &mut tag);
        assert_ne!(packet, plain);
        let len: [u8; 4] = packet[..4].try_into().expect("four");
        assert_eq!(opener.decrypt_packet_length(7, len), plain[..4]);

        let mut forged = packet;
        forged[5] ^= 1;
        assert!(opener.open_in_place(7, &mut forged, &tag).is_err());
        assert!(opener.open_in_place(8, &mut packet, &tag).is_err());
        let opened = opener.open_in_place(7, &mut packet, &tag).expect("open");
        assert_eq!(opened, &plain[4..]);
    }
}
