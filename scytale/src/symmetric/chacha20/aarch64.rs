//! ChaCha20 with NEON on AArch64.
//!
//! Four blocks at a time, each block's state as four rows of four
//! words in four vector registers, sixteen registers in all. A
//! column round is one quarter round on the four rows of a block; the
//! diagonal round is the same after rotating three rows by a word,
//! which `ext` does. The four blocks are independent, so their
//! instructions interleave and the processor overlaps them.
//!
//! The rotate by 16 is a halfword reverse; the others are a shift
//! left and a shift-right-insert. No memory access depends on the
//! key.

#![allow(unsafe_code)]

use super::{Backend, Cipher, Sealed, BLOCK_SIZE};

/// ChaCha20 with NEON.
pub type ChaCha20 = Cipher<Neon>;

/// The keystream generator with NEON, which every AArch64 processor
/// has.
pub struct Neon;

impl Sealed for Neon {}

impl Backend for Neon {
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

/// Blocks one pass of the assembly handles.
const GROUP: usize = 4;

/// The input states of a group, one per block, consecutive counters.
fn states(
    key: &[u32; 8],
    nonce: &[u32; 3],
    counter: u32,
) -> [[u32; 16]; GROUP] {
    let mut states = [[0u32; 16]; GROUP];
    for (i, state) in states.iter_mut().enumerate() {
        state[..4].copy_from_slice(&super::CONSTANTS);
        state[4..12].copy_from_slice(key);
        state[12] = counter.wrapping_add(i as u32);
        state[13..].copy_from_slice(nonce);
    }
    states
}

/// Xors keystream from `counter` into `data`, a whole number of
/// blocks.
///
/// # Safety
/// Requires NEON.
unsafe fn xor(key: &[u32; 8], nonce: &[u32; 3], counter: u32, data: &mut [u8]) {
    debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
    let mut counter = counter;
    let mut chunks = data.chunks_exact_mut(BLOCK_SIZE * GROUP);
    for group in &mut chunks {
        group4(&states(key, nonce, counter), group.as_mut_ptr());
        counter = counter.wrapping_add(GROUP as u32);
    }
    let rest = chunks.into_remainder();
    if !rest.is_empty() {
        // A short group: keystream into a scratch buffer, then only
        // as much of it as is wanted.
        let mut scratch = [0u8; BLOCK_SIZE * GROUP];
        group4(&states(key, nonce, counter), scratch.as_mut_ptr());
        for (d, k) in rest.iter_mut().zip(&scratch) {
            *d ^= k;
        }
    }
}

/// A quarter round on the four rows of one block, `$t` a temporary.
#[rustfmt::skip]
macro_rules! quarter {
    ($a:literal, $b:literal, $c:literal, $d:literal, $t:literal) => {
        concat!(
            "add ", $a, ".4s, ", $a, ".4s, ", $b, ".4s\n",
            "eor ", $d, ".16b, ", $d, ".16b, ", $a, ".16b\n",
            "rev32 ", $d, ".8h, ", $d, ".8h\n",
            "add ", $c, ".4s, ", $c, ".4s, ", $d, ".4s\n",
            "eor ", $t, ".16b, ", $b, ".16b, ", $c, ".16b\n",
            "shl ", $b, ".4s, ", $t, ".4s, #12\n",
            "sri ", $b, ".4s, ", $t, ".4s, #20\n",
            "add ", $a, ".4s, ", $a, ".4s, ", $b, ".4s\n",
            "eor ", $t, ".16b, ", $d, ".16b, ", $a, ".16b\n",
            "shl ", $d, ".4s, ", $t, ".4s, #8\n",
            "sri ", $d, ".4s, ", $t, ".4s, #24\n",
            "add ", $c, ".4s, ", $c, ".4s, ", $d, ".4s\n",
            "eor ", $t, ".16b, ", $b, ".16b, ", $c, ".16b\n",
            "shl ", $b, ".4s, ", $t, ".4s, #7\n",
            "sri ", $b, ".4s, ", $t, ".4s, #25\n",
        )
    };
}

/// Rotates three rows by a word so the diagonals line up as
/// columns (`4, 8, 12`), and back again (`12, 8, 4`).
#[rustfmt::skip]
macro_rules! diagonal {
    ($b:literal, $c:literal, $d:literal, $bi:literal, $di:literal) => {
        concat!(
            "ext ", $b, ".16b, ", $b, ".16b, ", $b, ".16b, #", $bi, "\n",
            "ext ", $c, ".16b, ", $c, ".16b, ", $c, ".16b, #8\n",
            "ext ", $d, ".16b, ", $d, ".16b, ", $d, ".16b, #", $di, "\n",
        )
    };
}

/// Adds a block's input back and xors the result into its 64 bytes
/// of `data` at the given offset, through the temporaries v16-v19.
#[rustfmt::skip]
macro_rules! output {
    ($a:literal, $b:literal, $c:literal, $d:literal, $off:literal) => {
        concat!(
            "ld1 {{v16.4s, v17.4s, v18.4s, v19.4s}}, [{state}], #64\n",
            "add ", $a, ".4s, ", $a, ".4s, v16.4s\n",
            "add ", $b, ".4s, ", $b, ".4s, v17.4s\n",
            "add ", $c, ".4s, ", $c, ".4s, v18.4s\n",
            "add ", $d, ".4s, ", $d, ".4s, v19.4s\n",
            "ld1 {{v16.16b, v17.16b, v18.16b, v19.16b}}, [{data}]\n",
            "eor v16.16b, v16.16b, ", $a, ".16b\n",
            "eor v17.16b, v17.16b, ", $b, ".16b\n",
            "eor v18.16b, v18.16b, ", $c, ".16b\n",
            "eor v19.16b, v19.16b, ", $d, ".16b\n",
            "st1 {{v16.16b, v17.16b, v18.16b, v19.16b}}, [{data}], #64\n",
        )
    };
}

/// Four blocks from `states`, xored into the 256 bytes at `data`.
///
/// Block k has its rows in v4k to v4k+3; v16 to v19 are temporaries.
///
/// # Safety
/// Requires NEON; `data` must point at 256 writable bytes.
#[target_feature(enable = "neon")]
unsafe fn group4(states: &[[u32; 16]; GROUP], data: *mut u8) {
    core::arch::asm!(
        "mov {p}, {state}",
        "ld1 {{v0.4s, v1.4s, v2.4s, v3.4s}}, [{p}], #64",
        "ld1 {{v4.4s, v5.4s, v6.4s, v7.4s}}, [{p}], #64",
        "ld1 {{v8.4s, v9.4s, v10.4s, v11.4s}}, [{p}], #64",
        "ld1 {{v12.4s, v13.4s, v14.4s, v15.4s}}, [{p}]",
        "mov {n}, #10",
        "2:",
        quarter!("v0", "v1", "v2", "v3", "v16"),
        quarter!("v4", "v5", "v6", "v7", "v17"),
        quarter!("v8", "v9", "v10", "v11", "v18"),
        quarter!("v12", "v13", "v14", "v15", "v19"),
        diagonal!("v1", "v2", "v3", "4", "12"),
        diagonal!("v5", "v6", "v7", "4", "12"),
        diagonal!("v9", "v10", "v11", "4", "12"),
        diagonal!("v13", "v14", "v15", "4", "12"),
        quarter!("v0", "v1", "v2", "v3", "v16"),
        quarter!("v4", "v5", "v6", "v7", "v17"),
        quarter!("v8", "v9", "v10", "v11", "v18"),
        quarter!("v12", "v13", "v14", "v15", "v19"),
        diagonal!("v1", "v2", "v3", "12", "4"),
        diagonal!("v5", "v6", "v7", "12", "4"),
        diagonal!("v9", "v10", "v11", "12", "4"),
        diagonal!("v13", "v14", "v15", "12", "4"),
        "subs {n}, {n}, #1",
        "b.ne 2b",
        output!("v0", "v1", "v2", "v3", 0),
        output!("v4", "v5", "v6", "v7", 64),
        output!("v8", "v9", "v10", "v11", 128),
        output!("v12", "v13", "v14", "v15", 192),
        state = inout(reg) states.as_ptr() => _,
        data = inout(reg) data => _,
        p = out(reg) _,
        n = out(reg) _,
        out("v0") _, out("v1") _, out("v2") _, out("v3") _,
        out("v4") _, out("v5") _, out("v6") _, out("v7") _,
        out("v8") _, out("v9") _, out("v10") _, out("v11") _,
        out("v12") _, out("v13") _, out("v14") _, out("v15") _,
        out("v16") _, out("v17") _, out("v18") _, out("v19") _,
        options(nostack),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::chacha20::tests::{
        check_known_answers, check_matches_portable,
    };

    #[test]
    fn known_answers() {
        check_known_answers::<Neon>();
    }

    #[test]
    fn matches_portable() {
        check_matches_portable::<Neon>();
    }

    #[test]
    fn probe_agrees_with_constructor() {
        assert!(ChaCha20::try_new(&[0u8; 32]).is_ok());
    }
}
