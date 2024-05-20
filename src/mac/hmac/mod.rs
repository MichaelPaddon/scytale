use core::cmp::min;
use crate::hash::Hash;
use crate::hash::internal::BlockHash;
use crate::mac::Mac;

#[derive(Clone, Debug)]
pub struct Hmac<H: Hash> {
    initial_state: (H, H),
    inner_hash: H
}

impl<H> Hmac<H>
where
    H: Clone + BlockHash,
    H::Block: Clone + Default
{
    fn keyed_hashes(key: &[u8]) -> (H, H) {
        let mut block = H::Block::default();
        if key.len() <= block.len() {
            let n = min(key.len(), block.len());
            block[..n].copy_from_slice(&key[..n]);
            block[n..].fill(0);
        }
        else {
            let digest = H::hash(key);
            let n = min(digest.len(), block.len());
            block[..n].copy_from_slice(&digest[..n]);
            block[n..].fill(0);
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

    fn zzz(&mut self) -> H::Digest {
        // TODO: get rid of reset
        let digest = self.inner_hash.finalize_and_reset();
        let mut outer_hash = self.initial_state.1.clone();
        outer_hash.update(&digest);
        outer_hash.finalize()
    }
}

impl<H> Mac for Hmac<H>
where
    H: Clone + BlockHash,
    H::Block: Clone + Default
{
    type Tag = H::Digest;

    fn new<T: AsRef<[u8]>>(key: T) -> Self {
        let initial_state = Self::keyed_hashes(key.as_ref());
        let inner_hash = initial_state.0.clone();
        Self {
            initial_state,
            inner_hash
        }
    }

    fn rekey<T: AsRef<[u8]>>(&mut self, key: T) {
        self.initial_state = Self::keyed_hashes(key.as_ref());
        self.inner_hash = self.initial_state.0.clone();
    }

    fn reset(&mut self) {
        self.inner_hash = self.initial_state.0.clone();
    }

    fn update<T: AsRef<[u8]>>(&mut self, data: T){
        // TODO: remove as_ref()
        self.inner_hash.update(data.as_ref());
    }

    fn finalize(mut self) -> Self::Tag {
        self.zzz()
    }

    fn finalize_and_reset(&mut self) -> Self::Tag {
        let tag = self.zzz();
        self.reset();
        tag
    }
}

#[cfg(test)]
mod test;
