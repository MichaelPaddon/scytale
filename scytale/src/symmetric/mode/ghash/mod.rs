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
//! The portable multiplication walks all 128 bits with masks rather
//! than branches, and uses no lookup tables, so it takes the same
//! time whatever the key and leaks nothing through the cache. It is
//! also slow, and it is nearly all of GCM's cost. Where the processor
//! has a carry-less multiply instruction, that is used instead.
//!
//! Each block's hash depends on the one before it, so the multiplies
//! cannot overlap and the cost is the whole latency of the chain.
//! Where an architecture offers it, whole groups of blocks are hashed
//! at once instead: the identity
//!
//! ```text
//! Y_8 = (Y_0 + X_1) H^8 + X_2 H^7 + ... + X_8 H
//! ```
//!
//! turns eight dependent multiplications into eight independent ones,
//! which the processor can run at once, and needs only one reduction
//! at the end rather than eight.

use core::sync::atomic::{AtomicU8, Ordering};

/// GHASH works only on 128-bit blocks, whatever the cipher's block.
pub(crate) const BLOCK: usize = 16;

/// The reduction constant: the polynomial's low terms, in GHASH's
/// reversed bit order.
const REDUCE: u64 = 0xe100_0000_0000_0000;

/// The most blocks any architecture here hashes in one group. It
/// fixes the size of the table of powers of the subkey.
const MAX_GROUP: usize = 8;

// The accelerated multiply for whichever architecture this is. Each
// offers the same set of items, so the code below needs no
// conditionals; `none` stands in where there is nothing to use.
#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
)))]
mod none;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
use self::aarch64 as arch;
#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
)))]
use self::none as arch;
#[cfg(target_arch = "riscv64")]
use self::riscv64 as arch;
#[cfg(target_arch = "x86_64")]
use self::x86_64 as arch;

/// Whether the processor's carry-less multiply is available. Probed
/// once: 0 unknown, 1 no, 2 yes.
static PROBED: AtomicU8 = AtomicU8::new(0);

/// The subkey ready for the processor's carry-less multiply, or
/// nothing if there is no such instruction here.
fn prepared(h: &[u64; 2]) -> Option<[u64; 2]> {
    let known = match PROBED.load(Ordering::Relaxed) {
        0 => {
            let yes = arch::has_carryless_multiply();
            PROBED.store(1 + u8::from(yes), Ordering::Relaxed);
            yes
        }
        n => n == 2,
    };
    known.then(|| arch::prepare(h))
}

/// Divides the subkey by `x` and puts its halves in the order a
/// vector register wants them, least significant first.
///
/// The multiplies built out of carry-less multiplication use this so
/// that no product needs shifting afterwards. Division by `x` is the
/// reverse of multiplication by it: the top bit says whether the
/// polynomial was folded in on the way, so it both selects the term
/// to undo and supplies the bit that comes back at the bottom.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn divide_by_x(h: &[u64; 2]) -> [u64; 2] {
    let bit = h[0] >> 63;
    // A mask rather than a branch: the subkey is secret.
    let mask = 0u64.wrapping_sub(bit);
    let high = h[0] ^ (mask & (0xe1 << 56));
    let low = h[1];
    [(low << 1) | bit, (high << 1) | (low >> 63)]
}

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
    /// The subkey prepared for the processor's carry-less multiply,
    /// present only when there is one to use. Decided when the hash
    /// starts rather than per block.
    fast: Option<[u64; 2]>,
    /// Prepared powers of the subkey, `H` first, for hashing a whole
    /// group of blocks at once. Built the first time a group turns
    /// up, so that short messages never pay for it.
    powers: Option<[[u64; 2]; MAX_GROUP]>,
}

impl Ghash {
    /// Starts a hash under subkey `h`, which is one block.
    pub(crate) fn new(h: &[u8]) -> Self {
        debug_assert_eq!(h.len(), BLOCK);
        let h = [halve(&h[..8]), halve(&h[8..])];
        Ghash {
            h,
            y: [0, 0],
            block: [0; BLOCK],
            used: 0,
            fast: prepared(&h),
            powers: None,
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
        let data = self.absorb_groups(data);
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

    /// Adds as many whole groups of blocks as `data` holds, and
    /// returns what is left over. Does nothing where the architecture
    /// has no group multiply.
    #[allow(unsafe_code)]
    fn absorb_groups<'a>(&mut self, data: &'a [u8]) -> &'a [u8] {
        let span = arch::GROUP * BLOCK;
        let Some(h) = self.fast else { return data };
        if arch::GROUP == 1 || data.len() < span {
            return data;
        }
        // A copy, so that the loop below can borrow the hash itself.
        let powers = match self.powers {
            Some(powers) => powers,
            None => *self.powers.insert(powers_of(&h)),
        };
        let mut groups = data.chunks_exact(span);
        for group in &mut groups {
            // SAFETY: the instructions were confirmed present when
            // this hash was started, and the group is the width the
            // multiply expects.
            unsafe { arch::multiply_group(&mut self.y, &powers, group) };
        }
        groups.remainder()
    }

    /// Adds one whole block: `y = (y + block) * h`.
    #[allow(unsafe_code)]
    fn absorb(&mut self, block: &[u8]) {
        self.y[0] ^= halve(&block[..8]);
        self.y[1] ^= halve(&block[8..BLOCK]);
        if let Some(h) = self.fast.as_ref() {
            // SAFETY: the instruction was confirmed present when this
            // hash was started.
            unsafe { arch::multiply(&mut self.y, h) };
            return;
        }
        multiply(&mut self.y, &self.h);
    }
}

/// The first [`MAX_GROUP`] powers of the subkey, each prepared for
/// the architecture's multiply, given the subkey already prepared.
#[allow(unsafe_code)]
fn powers_of(h: &[u64; 2]) -> [[u64; 2]; MAX_GROUP] {
    // The powers are built with the accelerated multiply rather than
    // the portable one: this runs once per hash that sees a whole
    // group, and the portable version would cost more than the group
    // it is about to speed up.
    let mut powers = [[0u64; 2]; MAX_GROUP];
    let mut power = [1u64 << 63, 0];
    for slot in powers.iter_mut() {
        // SAFETY: the caller has confirmed the instruction.
        unsafe { arch::multiply(&mut power, h) };
        *slot = arch::prepare(&power);
    }
    powers
}

/// Multiplies a block by `x` in the GHASH field, in place.
///
/// POLYVAL is defined in terms of GHASH and needs this to convert its
/// key; see [`polyval`](super::polyval).
pub(crate) fn multiply_by_x(block: &mut [u8; BLOCK]) {
    let mut high = halve(&block[..8]);
    let mut low = halve(&block[8..]);
    let overflow = 0u64.wrapping_sub(low & 1);
    low = (low >> 1) | (high << 63);
    high = (high >> 1) ^ (REDUCE & overflow);
    block[..8].copy_from_slice(&high.to_be_bytes());
    block[8..].copy_from_slice(&low.to_be_bytes());
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::eprintln;

    /// A cheap spread of test values. The multiply is linear in each
    /// operand, so agreement on a varied sample is strong evidence.
    fn values(seed: u64) -> [u64; 2] {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        [next(), next()]
    }

    #[test]
    #[allow(unsafe_code)]
    fn carryless_multiply_agrees_with_portable() {
        if !arch::has_carryless_multiply() {
            eprintln!("skipping: no carry-less multiply");
            return;
        }
        for seed in 0..500 {
            let h = values(seed);
            let start = values(seed ^ 0x5555_5555);
            let mut want = start;
            multiply(&mut want, &h);
            let mut got = start;
            let scaled = arch::prepare(&h);
            unsafe { arch::multiply(&mut got, &scaled) };
            assert_eq!(got, want, "seed {seed}");
        }
    }

    /// The hash of `data`, computed only with the portable multiply.
    fn portably(key: &[u8; BLOCK], data: &[u8]) -> [u8; BLOCK] {
        let h = [halve(&key[..8]), halve(&key[8..])];
        let mut y = [0u64; 2];
        for block in data.chunks(BLOCK) {
            let mut whole = [0u8; BLOCK];
            whole[..block.len()].copy_from_slice(block);
            y[0] ^= halve(&whole[..8]);
            y[1] ^= halve(&whole[8..]);
            multiply(&mut y, &h);
        }
        let mut out = [0u8; BLOCK];
        out[..8].copy_from_slice(&y[0].to_be_bytes());
        out[8..].copy_from_slice(&y[1].to_be_bytes());
        out
    }

    /// Whatever path the processor takes must agree with the portable
    /// one, at every length either side of a group boundary and
    /// whether the data arrives whole or in pieces.
    #[test]
    fn hashes_agree_with_portable_at_every_length() {
        let key: [u8; BLOCK] = core::array::from_fn(|i| (i as u8) | 1);
        let data: [u8; 40 * BLOCK] =
            core::array::from_fn(|i| (i * 7 + 3) as u8);

        for len in 0..data.len() {
            let want = portably(&key, &data[..len]);

            let mut hash = Ghash::new(&key);
            hash.update(&data[..len]);
            hash.pad();
            assert_eq!(hash.finish(), want, "one call, {len} bytes");

            // Pieces that do not line up with blocks or groups, so
            // the group path meets every kind of leftover.
            for piece in [1, 7, 16, 17, 63, 129] {
                let mut hash = Ghash::new(&key);
                for part in data[..len].chunks(piece) {
                    hash.update(part);
                }
                hash.pad();
                assert_eq!(
                    hash.finish(),
                    want,
                    "{len} bytes in pieces of {piece}"
                );
            }
        }
    }

    /// Zero and one are the cases the folding is most likely to get
    /// wrong, and the random sample is unlikely to hit them.
    #[test]
    #[allow(unsafe_code)]
    fn carryless_multiply_handles_edges() {
        if !arch::has_carryless_multiply() {
            eprintln!("skipping: no carry-less multiply");
            return;
        }
        // In this bit order the identity is the top bit of the first
        // word, and the all-ones value exercises every fold term.
        let edges = [[0, 0], [1 << 63, 0], [0, 1], [!0, !0]];
        for a in edges {
            for b in edges {
                let mut want = a;
                multiply(&mut want, &b);
                let mut got = a;
                let scaled = arch::prepare(&b);
                unsafe { arch::multiply(&mut got, &scaled) };
                assert_eq!(got, want, "{a:x?} * {b:x?}");
            }
        }
    }
}
