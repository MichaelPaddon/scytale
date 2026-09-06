//! SHA-1 (FIPS 180-4), for the protocols and formats that still name
//! it.
//!
//! # Do not choose this
//!
//! SHA-1 is broken as a collision-resistant hash: two distinct
//! inputs with the same digest have been public since 2017, and a
//! chosen-prefix collision, the kind that forges a certificate or a
//! signed document, costs tens of thousands of dollars of computing.
//! Nothing new should sign, certify or fingerprint with it, and the
//! standards that once allowed it have withdrawn it for those uses.
//!
//! It is here because deployed protocols still speak it where a
//! collision does not matter: HMAC-SHA-1 in older TLS and IPsec
//! suites, whose security rests on the key rather than on collision
//! resistance; HKDF and PBKDF2 over it in older key schedules; and
//! RSA-OAEP with SHA-1 as the mask generation function, which is
//! still PKCS#1's default. Every one of those has a SHA-2 form that
//! is the right choice for anything new; this module exists so the
//! old form can be read.
//!
//! One implementation, portable, with no hardware path: the speed of
//! a hash nothing should adopt is not worth pursuing.
//!
//! ```
//! use scytale::hash::sha1::Sha1;
//! use scytale::hash::Hash;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let digest = Sha1::digest(b"abc")?;
//! assert_eq!(digest[..4], [0xa9, 0x99, 0x3e, 0x36]);
//! # Ok(())
//! # }
//! ```

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash::{BitHash, Hash};
use crate::{BlockType, Error};

/// A SHA-1 computation in progress.
pub struct Sha1 {
    state: [u32; 5],
    /// Bytes of a block not yet complete.
    block: [u8; 64],
    used: usize,
    /// Whole bytes taken so far; wraps at the length the padding
    /// cannot express, which no real message reaches.
    bytes: u64,
}

const IV: [u32; 5] =
    [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// The compression function, FIPS 180-4 section 6.1.2, over whole
/// blocks. The message schedule is kept as a rolling window of
/// sixteen words rather than eighty.
fn compress(state: &mut [u32; 5], blocks: &[[u8; 64]]) {
    for block in blocks {
        let mut w = [0u32; 16];
        for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
            *word =
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for t in 0..80 {
            let wt = if t < 16 {
                w[t]
            } else {
                let next = (w[(t + 13) & 15]
                    ^ w[(t + 8) & 15]
                    ^ w[(t + 2) & 15]
                    ^ w[t & 15])
                    .rotate_left(1);
                w[t & 15] = next;
                next
            };
            let (f, k) = match t {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wt);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
}

impl Sha1 {
    /// Starts a new hash; the same as [`Hash::try_new`], which
    /// cannot fail here.
    pub fn new() -> Self {
        Sha1 {
            state: IV,
            block: [0; 64],
            used: 0,
            bytes: 0,
        }
    }

    /// Pads with `trailer`, the leading one bit and any last bits of
    /// message, plus `extra` bits beyond whole bytes, and folds the
    /// last block or two in.
    fn pad(&mut self, trailer: u8, extra: u64) {
        self.block[self.used] = trailer;
        self.used += 1;
        if self.used > 56 {
            self.block[self.used..].fill(0);
            let block = self.block;
            compress(&mut self.state, &[block]);
            self.used = 0;
        }
        self.block[self.used..56].fill(0);
        let bits = (self.bytes << 3) | extra;
        self.block[56..].copy_from_slice(&bits.to_be_bytes());
        let block = self.block;
        compress(&mut self.state, &[block]);
    }

    fn output(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        for (chunk, word) in out.chunks_exact_mut(4).zip(&self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Sha1 {
    fn clone(&self) -> Self {
        Sha1 {
            state: self.state,
            block: self.block,
            used: self.used,
            bytes: self.bytes,
        }
    }
}

impl BlockType for Sha1 {
    type Block = [u8; 64];

    fn zero_block() -> Self::Block {
        [0; 64]
    }
}

impl Hash for Sha1 {
    type Output = [u8; 20];

    fn try_new() -> Result<Self, Error> {
        Ok(Self::new())
    }

    fn reset(&mut self) {
        self.state = IV;
        self.block.zeroize();
        self.used = 0;
        self.bytes = 0;
    }

    fn update(&mut self, mut data: &[u8]) {
        self.bytes = self.bytes.wrapping_add(data.len() as u64);
        if self.used > 0 {
            let take = (64 - self.used).min(data.len());
            self.block[self.used..self.used + take]
                .copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used < 64 {
                return;
            }
            let block = self.block;
            compress(&mut self.state, &[block]);
            self.used = 0;
        }
        let (blocks, rest) = data.as_chunks::<64>();
        compress(&mut self.state, blocks);
        self.block[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
    }

    fn finalize(&mut self) -> Self::Output {
        self.pad(0x80, 0);
        let out = self.output();
        self.reset();
        out
    }
}

impl BitHash for Sha1 {
    fn finalize_bits(
        &mut self,
        last: u8,
        bits: u32,
    ) -> Result<Self::Output, Error> {
        if !(1..=7).contains(&bits) {
            return Err(Error::InvalidBitCount(bits));
        }
        // The kept bits are the top ones, and the padding's one bit
        // follows them; the same convention as the rest of FIPS 180.
        let keep = 0xffu8 << (8 - bits);
        let trailer = (last & keep) | (0x80 >> bits);
        self.pad(trailer, u64::from(bits));
        let out = self.output();
        self.reset();
        Ok(out)
    }
}

impl Drop for Sha1 {
    /// The buffer holds message, and the state is a function of it.
    fn drop(&mut self) {
        self.state.zeroize();
        self.block.zeroize();
        self.used.zeroize();
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for Sha1 {}

impl fmt::Debug for Sha1 {
    /// Deliberately omits the state and buffer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sha1").field("bytes", &self.bytes).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(hex: &str) -> [u8; 20] {
        let mut out = [0u8; 20];
        for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    /// FIPS 180-4's examples and the NIST CAVP one-million-`a` case.
    #[test]
    fn known_answers() {
        assert_eq!(
            Sha1::digest(b"").unwrap(),
            unhex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(
            Sha1::digest(b"abc").unwrap(),
            unhex("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            Sha1::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )
            .unwrap(),
            unhex("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        );
        let mut hash = Sha1::new();
        for _ in 0..1000 {
            hash.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hash.finalize(),
            unhex("34aa973cd4c4daa4f61eeb2bdbad27316534016f")
        );
    }

    /// Pieces of any size give the digest of the whole, including
    /// the block-boundary cases the padding has two paths for.
    #[test]
    fn pieces_agree_with_one_call() {
        let data: [u8; 200] = core::array::from_fn(|i| (i * 7) as u8);
        for len in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 200] {
            let whole = Sha1::digest(&data[..len]).unwrap();
            for piece in [1usize, 3, 16, 63, 64, 65] {
                let mut hash = Sha1::new();
                for chunk in data[..len].chunks(piece) {
                    hash.update(chunk);
                }
                assert_eq!(hash.finalize(), whole, "len {len} piece {piece}");
            }
        }
    }

    /// The five bits 01100, checked against an independent SHA-1
    /// over bit strings.
    #[test]
    fn bit_string() {
        let digest = Sha1::new().finalize_bits(0b0110_0000, 5).unwrap();
        assert_eq!(digest, unhex("80c0e3041a384f9edd3a4b03cc351af075b9069e"));
        assert_eq!(
            Sha1::new().finalize_bits(0, 8),
            Err(Error::InvalidBitCount(8))
        );
    }

    #[test]
    fn reset_and_debug() {
        let mut hash = Sha1::new();
        hash.update(b"garbage");
        hash.reset();
        hash.update(b"abc");
        assert_eq!(hash.clone().finalize(), Sha1::digest(b"abc").unwrap());
        extern crate std;
        assert_eq!(std::format!("{hash:?}"), "Sha1 { bytes: 3 }");
    }
}
