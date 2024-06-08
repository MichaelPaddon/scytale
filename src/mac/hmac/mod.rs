//! HMAC is a keyed-hash message authentication code,
//! constructed from an underlying hash function.
//!
//! HMAC was first published in 1996 by
//! [Bellare, Cannetti and Krawczyk](https://cseweb.ucsd.edu/~mihir/papers/hmac-cb.pdf).
//! It is standardized in
//! [RFC 2104](https://www.ietf.org/rfc/rfc2104.txt) and
//! [FIPS-198](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.198-1.pdf).

use core::cmp::min;
use smallvec::SmallVec;
use std::io::{Result, Write};
use crate::hash::Hash;
use crate::mac::Mac;

type Key = SmallVec<[u8; 64]>;

#[derive(Clone, Debug)]
pub struct Hmac<H: Hash> {
    inner_key: Key,
    outer_key: Key,
    hash: H
}

impl<H: Hash> Hmac<H> {
    fn generate_keys(key: &[u8]) -> (Key, Key) {
        let block_size = H::block_size();

        let mut inner_key = if key.len() <= block_size {
            Key::from_slice(key)
        }
        else {
            let mut hash = H::new_with_prefix(key);
            let digest = hash.finalize();
            let n = min(digest.len(), block_size);
            Key::from_slice(&digest[..n])
        };
        for _ in inner_key.len()..block_size {
            inner_key.push(0);
        }

        let mut outer_key = inner_key.clone();

        for i in 0..block_size {
            inner_key[i] ^= 0x36;
            outer_key[i] ^= 0x5c;
        }

       (inner_key, outer_key)
    }
}

impl<H: Hash> Mac for Hmac<H> {
    fn new(key: &[u8]) -> Self {
        let (inner_key, outer_key) = Self::generate_keys(key);
        let hash = H::new_with_prefix(&inner_key);
        Self {
            inner_key,
            outer_key,
            hash
        }
    }

    #[inline(always)]
    fn reset(&mut self) {
        self.hash.reset();
        self.hash.update(&self.inner_key);
    }

    fn rekey(&mut self, key: &[u8]) {
        (self.inner_key, self.outer_key) = Self::generate_keys(key);
        self.reset();
    }

    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
    }

    fn finalize<'a>(&'a mut self) -> &'a [u8] {
        let digest = Key::from_slice(self.hash.finalize());
        self.hash.reset();
        self.hash.update(&self.outer_key);
        self.hash.update(&digest);
        self.hash.finalize()
    }
}

impl<H: Hash> Write for Hmac<H> {
    #[inline]
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.update(data);
        Ok(data.len())
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod test;
