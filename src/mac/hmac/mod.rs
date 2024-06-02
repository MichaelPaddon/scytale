//! HMAC is a keyed-hash message authentication code,
//! constructed from an underlying hash function.
//!
//! HMAC was first published in 1996 by
//! [Bellare, Cannetti and Krawczyk](https://cseweb.ucsd.edu/~mihir/papers/hmac-cb.pdf).
//! It is standardized in
//! [RFC 2104](https://www.ietf.org/rfc/rfc2104.txt) and
//! [FIPS-198](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.198-1.pdf).

use smallvec::SmallVec;
use crate::hash::Hash;
use crate::mac::Mac;

const MAX_BLOCK_SIZE: usize = 64;

#[derive(Clone, Debug)]
pub struct Hmac<H: Hash> {
    initial_state: (H, H),
    inner_hash: H,
    outer_hash: H
}

impl<H> Hmac<H>
where
    H: Clone + Hash,
{
    fn keyed_hashes(key: &[u8]) -> (H, H) {
        let block_size = H::block_size();
        let mut block = SmallVec::<[u8; MAX_BLOCK_SIZE]>::new();
        if key.len() <= block_size {
            block.extend_from_slice(key);
            for _ in key.len()..block_size {
                block.push(0);
            }
        }
        else {
            let mut hash = H::new_with_prefix(key);
            let digest = hash.finalize();
            block.extend_from_slice(digest);
            for _ in digest.len()..block_size {
                block.push(0);
            }
        };

        let mut inner_key = block.clone();
        let mut outer_key = block;
        for i in 0..inner_key.len() {
            inner_key[i] ^= 0x36;
            outer_key[i] ^= 0x5c;
        }

       let inner_hash = H::new_with_prefix(&inner_key);
       let outer_hash = H::new_with_prefix(&outer_key);

       (inner_hash, outer_hash)
    }
}

impl<H> Mac for Hmac<H>
where
    H: Clone + Hash,
{
    fn new(key: &[u8]) -> Self
    where
        Self: Sized
    {
        let initial_state = Self::keyed_hashes(key.as_ref());
        let inner_hash = initial_state.0.clone();
        let outer_hash = initial_state.1.clone();
        Self {
            initial_state,
            inner_hash,
            outer_hash
        }
    }

    fn rekey(&mut self, key: &[u8])
    {
        self.initial_state = Self::keyed_hashes(key.as_ref());
        self.inner_hash = self.initial_state.0.clone();
        self.outer_hash = self.initial_state.1.clone();
    }

    fn reset(&mut self) {
        self.inner_hash = self.initial_state.0.clone();
        self.outer_hash = self.initial_state.1.clone();
    }

    fn update(&mut self, data: &[u8]) {
        self.inner_hash.update(data);
    }

    fn finalize<'a>(&'a mut self) -> &'a [u8] {
        let digest = self.inner_hash.finalize();
        self.outer_hash.update(digest);
        self.outer_hash.finalize()
    }
}

#[cfg(test)]
mod test;
