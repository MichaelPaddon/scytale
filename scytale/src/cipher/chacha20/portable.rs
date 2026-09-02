//! ChaCha20 in plain Rust, for any processor.
//!
//! Four blocks are computed together, each word of the state held as
//! four lanes, so that every operation is the same one on four
//! independent values. Written that way, the compiler turns the
//! rounds into whatever vector instructions the target has, and on a
//! target with none it is still the plain arithmetic, four times.
//! Nothing here touches memory in a way that depends on the key.

// Only the trait impl is unsafe, and it calls safe code.
#![allow(unsafe_code)]

use super::{Backend, Cipher, Sealed, BLOCK_SIZE, CONSTANTS};

/// ChaCha20, portably.
pub type ChaCha20 = Cipher<Portable>;

/// Blocks computed together.
const LANES: usize = 4;

/// One word of the state across the blocks being computed.
type Word = [u32; LANES];

#[inline(always)]
fn add(a: Word, b: Word) -> Word {
    let mut r = [0; LANES];
    for i in 0..LANES {
        r[i] = a[i].wrapping_add(b[i]);
    }
    r
}

#[inline(always)]
fn xor_rotate(a: Word, b: Word, n: u32) -> Word {
    let mut r = [0; LANES];
    for i in 0..LANES {
        r[i] = (a[i] ^ b[i]).rotate_left(n);
    }
    r
}

/// The quarter round on four words of the state.
#[inline(always)]
fn quarter_round(s: &mut [Word; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = add(s[a], s[b]);
    s[d] = xor_rotate(s[d], s[a], 16);
    s[c] = add(s[c], s[d]);
    s[b] = xor_rotate(s[b], s[c], 12);
    s[a] = add(s[a], s[b]);
    s[d] = xor_rotate(s[d], s[a], 8);
    s[c] = add(s[c], s[d]);
    s[b] = xor_rotate(s[b], s[c], 7);
}

/// Twenty rounds on the state, then the input added back.
#[inline(always)]
fn block(state: &[Word; 16]) -> [Word; 16] {
    let mut s = *state;
    for _ in 0..10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }
    for (s, input) in s.iter_mut().zip(state) {
        *s = add(*s, *input);
    }
    s
}

/// Xors keystream from `counter` into `data`, a whole number of
/// blocks.
pub(crate) fn xor(
    key: &[u32; 8],
    nonce: &[u32; 3],
    counter: u32,
    data: &mut [u8],
) {
    debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
    let mut state = [[0u32; LANES]; 16];
    for (i, &c) in CONSTANTS.iter().enumerate() {
        state[i] = [c; LANES];
    }
    for (i, &k) in key.iter().enumerate() {
        state[4 + i] = [k; LANES];
    }
    for (i, &n) in nonce.iter().enumerate() {
        state[13 + i] = [n; LANES];
    }

    let mut counter = counter;
    for group in data.chunks_mut(BLOCK_SIZE * LANES) {
        for (lane, word) in state[12].iter_mut().enumerate() {
            *word = counter.wrapping_add(lane as u32);
        }
        let out = block(&state);
        for (lane, block) in group.chunks_mut(BLOCK_SIZE).enumerate() {
            for (word, bytes) in block.chunks_exact_mut(4).enumerate() {
                let k = out[word][lane].to_le_bytes();
                for (b, k) in bytes.iter_mut().zip(k) {
                    *b ^= k;
                }
            }
        }
        counter = counter.wrapping_add((group.len() / BLOCK_SIZE) as u32);
    }
}

/// The keystream generator in plain Rust.
pub struct Portable;

impl Sealed for Portable {}

impl Backend for Portable {
    fn supported() -> bool {
        true
    }

    unsafe fn xor(
        key: &[u32; 8],
        nonce: &[u32; 3],
        counter: u32,
        data: &mut [u8],
    ) {
        xor(key, nonce, counter, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::chacha20::tests::check_known_answers;

    #[test]
    fn known_answers() {
        check_known_answers::<Portable>();
    }

    /// RFC 8439 section 2.1.1: the quarter round on its own.
    #[test]
    fn quarter_round_example() {
        let mut s = [[0u32; LANES]; 16];
        s[0] = [0x11111111; LANES];
        s[1] = [0x01020304; LANES];
        s[2] = [0x9b8d6f43; LANES];
        s[3] = [0x01234567; LANES];
        quarter_round(&mut s, 0, 1, 2, 3);
        assert_eq!(s[0][0], 0xea2a92f4);
        assert_eq!(s[1][0], 0xcb1cf8ce);
        assert_eq!(s[2][0], 0x4581472e);
        assert_eq!(s[3][0], 0x5881c4bb);
    }
}
