//! Poly1305 (RFC 8439 section 2.5): a one-time authenticator.
//!
//! The message is read as coefficients of a polynomial, evaluated
//! at a secret point `r` modulo the prime `2^130 - 5`, and the
//! result is masked with a second secret `s`. The bound on forgery
//! is information-theoretic: it does not rest on any problem being
//! hard, only on `r` and `s` being uniform and unknown.
//!
//! # One key, one message
//!
//! That bound holds for a single message. Two tags under the same
//! key give away `r` through a little algebra, and every later tag
//! can then be forged. So a Poly1305 key is never reused, which is
//! why it is nearly always derived afresh per message from a stream
//! cipher, as ChaCha20-Poly1305 does; reach it that way unless a
//! protocol says otherwise. [`reset`](Mac::reset) exists for that
//! caller, not for a second message.
//!
//! # Constant time
//!
//! The arithmetic is plain multiplication and addition on limbs,
//! with no branch or table lookup that depends on the key or the
//! message; the final reduction chooses with a mask.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Mac;
use crate::Error;

/// The key length in bytes: `r` then `s`.
pub const KEY_SIZE: usize = 32;

/// The block, and tag, length in bytes.
const BLOCK: usize = 16;

/// A 44-bit limb's worth of ones.
const MASK44: u64 = (1 << 44) - 1;

/// A 42-bit limb's worth: the top limb holds 130 - 88 bits.
const MASK42: u64 = (1 << 42) - 1;

/// Poly1305 under a one-time key.
///
/// The accumulator and `r` are kept as three limbs of 44, 44 and 42
/// bits, so that a product of two fits a 128-bit word with room for
/// the sums of three, and reduction modulo `2^130 - 5` is a
/// multiplication by five folded into the limb arithmetic.
pub struct Poly1305 {
    /// `r`, clamped as the standard requires.
    r: [u64; 3],
    /// `r[1]` and `r[2]` times twenty: `2^132 = 4 * 2^130 = 20`
    /// modulo the prime, which is what a limb carried past the top
    /// is worth.
    r20: [u64; 2],
    /// `s`, as the two little-endian words it is added as.
    s: [u64; 2],
    /// The running polynomial value.
    h: [u64; 3],
    /// Bytes of a block not yet complete.
    block: [u8; BLOCK],
    used: usize,
}

impl Poly1305 {
    /// Starts an authenticator under `key`, which must be 32 bytes:
    /// `r` then `s`.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KEY_SIZE {
            return Err(Error::InvalidKeyLength(key.len()));
        }
        let word = |at: usize| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&key[at..at + 8]);
            u64::from_le_bytes(bytes)
        };
        // Clamping clears the top four bits of every four-byte word
        // of `r` and the low two bits of all but the first, so that
        // the limb products cannot carry too far.
        let t0 = word(0) & 0x0ffffffc0fffffff;
        let t1 = word(8) & 0x0ffffffc0ffffffc;
        let r = [
            t0 & MASK44,
            ((t0 >> 44) | (t1 << 20)) & MASK44,
            (t1 >> 24) & MASK42,
        ];
        Ok(Poly1305 {
            r,
            r20: [r[1] * 20, r[2] * 20],
            s: [word(16), word(24)],
            h: [0; 3],
            block: [0; BLOCK],
            used: 0,
        })
    }

    /// Adds one block, with `high` as the bit above its top byte,
    /// and multiplies by `r`.
    ///
    /// The bit is `2^128` for a whole block. A final short block has
    /// its one written as a byte in the buffer instead, and passes
    /// zero here.
    fn absorb(&mut self, block: &[u8; BLOCK], high: u64) {
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&block[..8]);
        hi.copy_from_slice(&block[8..]);
        let t0 = u64::from_le_bytes(lo);
        let t1 = u64::from_le_bytes(hi);
        let [mut h0, mut h1, mut h2] = self.h;
        h0 += t0 & MASK44;
        h1 += ((t0 >> 44) | (t1 << 20)) & MASK44;
        h2 += ((t1 >> 24) & MASK42) | (high << 40);

        let [r0, r1, r2] = self.r;
        let [s1, s2] = self.r20;
        let wide = |a: u64, b: u64| u128::from(a) * u128::from(b);
        // Schoolbook product, with the limbs that pass 2^132 wrapped
        // round through the twenty-fold values.
        let d0 = wide(h0, r0) + wide(h1, s2) + wide(h2, s1);
        let d1 = wide(h0, r1) + wide(h1, r0) + wide(h2, s2);
        let d2 = wide(h0, r2) + wide(h1, r1) + wide(h2, r0);

        // Partial carry: enough to keep every limb small for the
        // next block, without a full reduction.
        let c = (d0 >> 44) as u64;
        h0 = (d0 as u64) & MASK44;
        let d1 = d1 + u128::from(c);
        let c = (d1 >> 44) as u64;
        h1 = (d1 as u64) & MASK44;
        let d2 = d2 + u128::from(c);
        let c = (d2 >> 42) as u64;
        h2 = (d2 as u64) & MASK42;
        h0 += c * 5;
        let c = h0 >> 44;
        h0 &= MASK44;
        h1 += c;
        self.h = [h0, h1, h2];
    }

    /// Fully reduces the accumulator, adds `s`, and returns the tag.
    fn tag(&self) -> [u8; BLOCK] {
        let [mut h0, mut h1, mut h2] = self.h;
        // Carry through twice, so that only the top limb can be at
        // most one above the prime.
        for _ in 0..2 {
            let c = h1 >> 44;
            h1 &= MASK44;
            h2 += c;
            let c = h2 >> 42;
            h2 &= MASK42;
            h0 += c * 5;
            let c = h0 >> 44;
            h0 &= MASK44;
            h1 += c;
        }

        // Compute h - p and keep it if there was no borrow, choosing
        // with a mask rather than a branch.
        let mut g0 = h0 + 5;
        let c = g0 >> 44;
        g0 &= MASK44;
        let mut g1 = h1 + c;
        let c = g1 >> 44;
        g1 &= MASK44;
        let g2 = h2.wrapping_add(c).wrapping_sub(1 << 42);
        let keep = (g2 >> 63).wrapping_sub(1);
        h0 = (h0 & !keep) | (g0 & keep);
        h1 = (h1 & !keep) | (g1 & keep);
        h2 = (h2 & !keep) | (g2 & keep);

        // The low 128 bits as two words, plus s, dropping the carry.
        let lo = h0 | (h1 << 44);
        let hi = (h1 >> 20) | (h2 << 24);
        let (lo, carry) = lo.overflowing_add(self.s[0]);
        let hi = hi.wrapping_add(self.s[1]).wrapping_add(u64::from(carry));
        let mut tag = [0u8; BLOCK];
        tag[..8].copy_from_slice(&lo.to_le_bytes());
        tag[8..].copy_from_slice(&hi.to_le_bytes());
        tag
    }
}

impl Mac for Poly1305 {
    type Tag = [u8; BLOCK];

    fn try_new(key: &[u8]) -> Result<Self, Error> {
        Poly1305::try_new(key)
    }

    fn reset(&mut self) {
        self.h = [0; 3];
        self.block.zeroize();
        self.used = 0;
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.used > 0 {
            let take = (BLOCK - self.used).min(data.len());
            self.block[self.used..self.used + take]
                .copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used < BLOCK {
                return;
            }
            let block = self.block;
            self.absorb(&block, 1);
            self.used = 0;
        }
        let (blocks, rest) = data.as_chunks::<BLOCK>();
        for block in blocks {
            self.absorb(block, 1);
        }
        self.block[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
    }

    fn finalize(mut self) -> Self::Tag {
        if self.used > 0 {
            // The one that marks the end goes just past the message;
            // the standard's 2^128 for a whole block is the same rule.
            let mut block = self.block;
            block[self.used] = 1;
            block[self.used + 1..].fill(0);
            self.absorb(&block, 0);
        }
        self.tag()
    }
}

impl Clone for Poly1305 {
    fn clone(&self) -> Self {
        Poly1305 {
            r: self.r,
            r20: self.r20,
            s: self.s,
            h: self.h,
            block: self.block,
            used: self.used,
        }
    }
}

impl Drop for Poly1305 {
    /// Every field is the key, or a function of it and the message.
    fn drop(&mut self) {
        self.r.zeroize();
        self.r20.zeroize();
        self.s.zeroize();
        self.h.zeroize();
        self.block.zeroize();
        self.used.zeroize();
    }
}

impl ZeroizeOnDrop for Poly1305 {}

impl fmt::Debug for Poly1305 {
    /// Deliberately omits everything but how far the message has got.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Poly1305")
            .field("buffered", &self.used)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes hex into a fixed buffer, returning the used prefix.
    fn hex(s: &str) -> ([u8; 512], usize) {
        let mut out = [0u8; 512];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        (out, s.len() / 2)
    }

    fn tag_of(key: &[u8], message: &[u8]) -> [u8; 16] {
        let mut mac = Poly1305::try_new(key).unwrap();
        mac.update(message);
        mac.finalize()
    }

    fn check(key: &str, message: &[u8], expected: &str) {
        let (k, _) = hex(key);
        let (t, _) = hex(expected);
        assert_eq!(tag_of(&k[..32], message), t[..16]);
    }

    /// RFC 8439 section 2.5.2.
    #[test]
    fn rfc8439_example() {
        check(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f5\
             1b",
            b"Cryptographic Forum Research Group",
            "a8061dc1305136c6c22b8baf0c0127a9",
        );
    }

    /// The text of RFC 8439 appendix A.3, tests 2 and 3.
    const IETF: &str =
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e\
         6465642062792074686520436f6e7472696275746f7220666f72207075626c69\
         636174696f6e20617320616c6c206f722070617274206f6620616e2049455446\
         20496e7465726e65742d4472616674206f722052464320616e6420616e792073\
         746174656d656e74206d6164652077697468696e2074686520636f6e74657874\
         206f6620616e204945544620616374697669747920697320636f6e7369646572\
         656420616e20224945544620436f6e747269627574696f6e222e205375636820\
         73746174656d656e747320696e636c756465206f72616c2073746174656d656e\
         747320696e20494554462073657373696f6e732c2061732077656c6c20617320\
         7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361\
         74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c\
         207768696368206172652061646472657373656420746f";

    /// A 32-byte key from `r` and `s` given as 16-byte arrays.
    fn key(r: [u8; 16], s: [u8; 16]) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&r);
        key[16..].copy_from_slice(&s);
        key
    }

    /// Sixteen bytes: `first`, then `rest` repeated.
    fn block(first: u8, rest: u8) -> [u8; 16] {
        let mut b = [rest; 16];
        b[0] = first;
        b
    }

    /// RFC 8439 appendix A.3, tests 1 to 4.
    #[test]
    fn rfc8439_a3_ordinary() {
        assert_eq!(tag_of(&[0u8; 32], &[0u8; 64]), [0u8; 16]);
        let (text, n) = hex(IETF);
        let text = &text[..n];
        assert_eq!(n, 375);
        let (s, _) = hex("36e5f6b5c5e06070f0efca96227a863e");
        let s: [u8; 16] = s[..16].try_into().unwrap();
        // r = 0: the tag is s, whatever the message.
        assert_eq!(tag_of(&key([0; 16], s), text), s);
        // s = 0.
        let (expected, _) = hex("f3477e7cd95417af89a6b8794c310cf0");
        assert_eq!(tag_of(&key(s, [0; 16]), text), expected[..16]);
        check(
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075\
             c0",
            b"'Twas brillig, and the slithy toves\nDid gyre and gimble in \
              the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths \
              outgrabe.",
            "4541669a7eaaee61e708dc7cbcc5eb62",
        );
    }

    /// RFC 8439 appendix A.3, tests 5 to 11: values chosen to make
    /// the accumulator overflow, borrow, and need every reduction.
    /// The tags were also recomputed from the standard's definition
    /// with big integers, which agreed.
    #[test]
    fn rfc8439_a3_edge_cases() {
        let r1 = block(1, 0);
        let r2 = block(2, 0);
        let ones = [0xff; 16];
        let zero = [0; 16];

        // 5: r = 2, s = 0, message of ones: the product wraps past
        // 2^130 and reduces to three.
        assert_eq!(tag_of(&key(r2, zero), &ones), block(3, 0));
        // 6: r = 2, s all ones, message 2: the final addition wraps.
        assert_eq!(tag_of(&key(r2, ones), &r2), block(3, 0));
        // 7: r = 1, carries through every limb.
        let mut m = [0u8; 48];
        m[..16].copy_from_slice(&ones);
        m[16..32].copy_from_slice(&block(0xf0, 0xff));
        m[32..].copy_from_slice(&block(0x11, 0));
        assert_eq!(tag_of(&key(r1, zero), &m), block(5, 0));
        // 8: r = 1, a borrow.
        m[16..32].copy_from_slice(&block(0xfb, 0xff));
        m[17] = 0xfe;
        m[32..].copy_from_slice(&block(1, 0));
        assert_eq!(tag_of(&key(r1, zero), &m), block(0, 0xff));
        // 9: r = 2, the accumulator lands just under the prime.
        assert_eq!(
            tag_of(&key(r2, zero), &block(0xfd, 0xff)),
            block(0xfa, 0xff)
        );
        // 10 and 11: r with a bit in its second word, and messages
        // built to cancel.
        let mut r = block(1, 0);
        r[8] = 4;
        let (m, n) = hex(
            "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000\
             0000000000000000000000000000000000010000000000000000000000000000\
             00",
        );
        assert_eq!(n, 64);
        let mut expected = block(0x14, 0);
        expected[8] = 0x55;
        assert_eq!(tag_of(&key(r, zero), &m[..64]), expected);
        assert_eq!(tag_of(&key(r, zero), &m[..48]), block(0x13, 0));
    }

    #[test]
    fn pieces_make_the_same_tag() {
        let (key, _) = hex(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f5\
             1b",
        );
        let key = &key[..32];
        let message: [u8; 101] = core::array::from_fn(|i| (i * 13) as u8);
        let expected = tag_of(key, &message);
        for chunk in [1, 3, 15, 16, 17, 40] {
            let mut mac = Poly1305::try_new(key).unwrap();
            for piece in message.chunks(chunk) {
                mac.update(piece);
            }
            assert_eq!(mac.finalize(), expected, "chunk {chunk}");
        }
        let mut mac = Poly1305::try_new(key).unwrap();
        mac.update(b"not this");
        mac.reset();
        mac.update(&message);
        assert_eq!(mac.finalize(), expected);
    }

    #[test]
    fn verify_accepts_and_rejects() {
        let key = [7u8; 32];
        let tag = tag_of(&key, b"message");
        let mut mac = Poly1305::try_new(&key).unwrap();
        mac.update(b"message");
        assert_eq!(mac.clone().verify(&tag), Ok(()));
        let mut wrong = tag;
        wrong[0] ^= 1;
        assert_eq!(
            mac.clone().verify(&wrong),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(mac.verify(&tag[..15]), Err(Error::AuthenticationFailed));
    }

    #[test]
    fn key_length_is_checked() {
        assert_eq!(
            Poly1305::try_new(&[0u8; 31]).err(),
            Some(Error::InvalidKeyLength(31))
        );
    }

    #[test]
    fn debug_omits_the_key() {
        struct Buffer([u8; 128], usize);
        impl fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let key = [0x5a; 32];
        let mut mac = Poly1305::try_new(&key).unwrap();
        mac.update(b"abc");
        let mut buffer = Buffer([0; 128], 0);
        fmt::write(&mut buffer, format_args!("{mac:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("5a") && !text.contains("90"));
        assert!(text.contains("buffered: 3"));
    }

    #[test]
    fn zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<Poly1305>();
    }
}
