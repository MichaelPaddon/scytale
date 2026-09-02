//! POLYVAL, the universal hash that GCM-SIV authenticates with.
//!
//! POLYVAL does the same job as [GHASH](super::ghash) but reads its
//! blocks the other way round, which suits machines that are
//! little-endian. RFC 8452 defines it in terms of GHASH, and that is
//! how it is built here: reverse the bytes of each block, hash with
//! GHASH under a converted key, and reverse the result. Reusing the
//! tested multiplication is worth more than the few operations saved
//! by writing the field arithmetic out again.

use super::ghash::{multiply_by_x, Ghash, BLOCK};

/// A POLYVAL computation in progress.
#[derive(Clone)]
pub(crate) struct Polyval {
    inner: Ghash,
    block: [u8; BLOCK],
    used: usize,
}

/// Reverses a block, which is all that separates the two hashes'
/// conventions.
fn reverse(block: &[u8]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    out.copy_from_slice(block);
    out.reverse();
    out
}

impl Polyval {
    /// Starts a hash under subkey `h`, which is one block.
    pub(crate) fn new(h: &[u8]) -> Self {
        debug_assert_eq!(h.len(), BLOCK);
        let mut key = reverse(h);
        multiply_by_x(&mut key);
        Polyval {
            inner: Ghash::new(&key),
            block: [0; BLOCK],
            used: 0,
        }
    }

    /// Adds more of the current field.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        if self.used > 0 {
            let take = data.len().min(BLOCK - self.used);
            self.block[self.used..self.used + take]
                .copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used < BLOCK {
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
        reverse(&self.inner.finish())
    }

    fn absorb(&mut self, block: &[u8]) {
        self.inner.update(&reverse(block));
    }
}
