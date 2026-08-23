//! GHASH, the universal hash that GCM authenticates with.
//!
//! GHASH works in the field GF(2^128) with the polynomial
//! `x^128 + x^7 + x^2 + x + 1`. Its bit order is the reverse of the
//! usual one: the most significant bit of the first byte is the
//! coefficient of `x^0`. The hash of a sequence of blocks is
//! `Y_i = (Y_{i-1} + X_i) * H`, starting from zero, where `H` is a
//! key derived from the block cipher key.
//!
//! # Speed
//!
//! The multiplication here walks all 128 bits with masks rather than
//! branches, and uses no lookup tables, so it takes the same time
//! whatever the key and leaks nothing through the cache. It is also
//! slow: this is the part of GCM that hardware carry-less multiply
//! instructions exist to replace.

/// GHASH works only on 128-bit blocks, whatever the cipher's block.
pub(crate) const BLOCK: usize = 16;

/// The reduction constant: the polynomial's low terms, in GHASH's
/// reversed bit order.
const REDUCE: u64 = 0xe100_0000_0000_0000;

/// A GHASH computation in progress.
#[derive(Clone)]
pub(crate) struct Ghash {
    /// The hash subkey.
    h: [u64; 2],
    /// The running hash.
    y: [u64; 2],
    /// Bytes of a block not yet complete.
    block: [u8; BLOCK],
    used: usize,
}

impl Ghash {
    /// Starts a hash under subkey `h`, which is one block.
    pub(crate) fn new(h: &[u8]) -> Self {
        debug_assert_eq!(h.len(), BLOCK);
        Ghash {
            h: [halve(&h[..8]), halve(&h[8..])],
            y: [0, 0],
            block: [0; BLOCK],
            used: 0,
        }
    }

    /// Adds more of the current field.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        // Finish a block a previous call left part way through.
        if self.used > 0 {
            let take = data.len().min(BLOCK - self.used);
            self.block[self.used..self.used + take]
                .copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used < BLOCK {
                // Still not a whole block. Keep what we have: the
                // code below would otherwise reset the count and
                // throw these bytes away.
                return;
            }
            let block = self.block;
            self.absorb(&block);
            self.used = 0;
        }
        let mut blocks = data.chunks_exact(BLOCK);
        for block in &mut blocks {
            self.absorb(block);
        }
        let rest = blocks.remainder();
        self.block[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
    }

    /// Ends the current field, padding it with zeros to a block.
    ///
    /// GCM hashes the additional data and the ciphertext as separate
    /// fields, each padded, so this is called between them.
    pub(crate) fn pad(&mut self) {
        if self.used > 0 {
            let mut block = self.block;
            block[self.used..].fill(0);
            self.absorb(&block);
            self.used = 0;
        }
    }

    /// The hash so far. Every field must have been padded first.
    pub(crate) fn finish(&self) -> [u8; BLOCK] {
        debug_assert_eq!(self.used, 0);
        let mut out = [0u8; BLOCK];
        out[..8].copy_from_slice(&self.y[0].to_be_bytes());
        out[8..BLOCK].copy_from_slice(&self.y[1].to_be_bytes());
        out
    }

    /// Adds one whole block: `y = (y + block) * h`.
    fn absorb(&mut self, block: &[u8]) {
        self.y[0] ^= halve(&block[..8]);
        self.y[1] ^= halve(&block[8..BLOCK]);
        multiply(&mut self.y, &self.h);
    }
}

/// Reads eight bytes as a big-endian word, which is how GHASH's bit
/// order maps onto integers.
fn halve(bytes: &[u8]) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    u64::from_be_bytes(word)
}

/// Multiplies `value` by `h` in the field, in place.
///
/// This is the schoolbook method of SP 800-38D: walk the bits of one
/// operand, adding a running double of the other wherever a bit is
/// set. The choice of whether to add is made with a mask rather than
/// a branch, and the whole 128 iterations always run, so the time
/// taken does not depend on either operand.
fn multiply(value: &mut [u64; 2], h: &[u64; 2]) {
    let (mut zh, mut zl) = (0u64, 0u64);
    let (mut vh, mut vl) = (h[0], h[1]);

    for i in 0..128 {
        // Bit i of `value`, counting from the most significant bit of
        // its first byte, as GHASH numbers bits.
        let bit = if i < 64 {
            (value[0] >> (63 - i)) & 1
        } else {
            (value[1] >> (127 - i)) & 1
        };
        let add = 0u64.wrapping_sub(bit);
        zh ^= vh & add;
        zl ^= vl & add;

        // Double `v`, reducing when it overflows the field.
        let overflow = 0u64.wrapping_sub(vl & 1);
        vl = (vl >> 1) | (vh << 63);
        vh = (vh >> 1) ^ (REDUCE & overflow);
    }

    value[0] = zh;
    value[1] = zl;
}
