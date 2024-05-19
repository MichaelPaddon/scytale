use core::cmp::min;
use crate::hash::Hash;

#[derive(Clone, Debug)]
pub struct Hmac<H: Hash> {
    initial_state: (H, H),
    inner_hash: H
}

impl<H> Hmac<H>
where
    H: Clone + Hash,
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

    pub fn new(key: &[u8]) -> Self {
        let initial_state = Self::keyed_hashes(key);
        let inner_hash = initial_state.0.clone();
        Self {
            initial_state,
            inner_hash
        }
    }

    pub fn rekey(&mut self, key: &[u8]) {
        self.initial_state = Self::keyed_hashes(key);
        self.inner_hash = self.initial_state.0.clone();
    }

    pub fn reset(&mut self) {
        self.inner_hash = self.initial_state.0.clone();
    }

    pub fn update(&mut self, bytes: &[u8]){
        self.inner_hash.update(bytes);
    }

    pub fn finalize(self) -> H::Digest {
        let digest = self.inner_hash.finalize();
        let mut outer_hash = self.initial_state.1.clone();
        outer_hash.update(&digest);
        outer_hash.finalize()
    }
}
