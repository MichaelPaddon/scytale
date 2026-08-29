//! ChaCha20 with the RISC-V vector extension and Zvbb.
//!
//! Each of the sixteen state words is a vector register whose lanes
//! are consecutive blocks, so one pass computes as many blocks as a
//! register holds 32-bit lanes: four at a vector length of 128 bits,
//! more on wider hardware, and the code does not change. Zvbb's
//! `vror.vi` is the rotate; without it a rotate is three
//! instructions and the vector unit gains little, so the portable
//! code is used instead.
//!
//! Loads and stores are strided: lane `j` of word `i` is at byte
//! `64 j + 4 i` of the data, which is where the block's word lies,
//! so the blocks need no transposing. No memory access depends on
//! the key.

#![allow(unsafe_code)]

use super::{Backend, Cipher, Sealed, BLOCK_SIZE};
use crate::arch::riscv64::{hwprobe_ima_ext_0, vlenb, EXT_ZVBB, IMA_V};

/// ChaCha20 with the vector extension and Zvbb.
pub type ChaCha20 = Cipher<Zvbb>;

/// Whether the vector extension with Zvbb is available, with
/// registers of at least 128 bits.
pub(crate) fn has_zvbb() -> bool {
    let present = cfg!(all(target_feature = "v", target_feature = "zvbb")) || {
        let want = IMA_V | EXT_ZVBB;
        hwprobe_ima_ext_0().is_some_and(|ext| ext & want == want)
    };
    present && vlenb() >= 16
}

/// The keystream generator with the vector extension and Zvbb.
pub struct Zvbb;

impl Sealed for Zvbb {}

impl Backend for Zvbb {
    fn supported() -> bool {
        has_zvbb()
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

/// Xors keystream from `counter` into `data`, a whole number of
/// blocks.
///
/// # Safety
/// Requires the vector extension and Zvbb.
unsafe fn xor(key: &[u32; 8], nonce: &[u32; 3], counter: u32, data: &mut [u8]) {
    debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&super::CONSTANTS);
    state[4..12].copy_from_slice(key);
    state[13..].copy_from_slice(nonce);
    let mut counter = counter;
    let mut data = data;
    while !data.is_empty() {
        state[12] = counter;
        let blocks = data.len() / BLOCK_SIZE;
        let done = group(&state, data.as_mut_ptr(), blocks);
        counter = counter.wrapping_add(done as u32);
        data = &mut data[done * BLOCK_SIZE..];
    }
}

/// A quarter round on the state words `$a` to `$d` (vector register
/// numbers). Zvbb rotates right, so left by n is right by 32 - n.
#[rustfmt::skip]
macro_rules! quarter {
    ($a:literal, $b:literal, $c:literal, $d:literal) => {
        concat!(
            "vadd.vv v", $a, ", v", $a, ", v", $b, "\n",
            "vxor.vv v", $d, ", v", $d, ", v", $a, "\n",
            "vror.vi v", $d, ", v", $d, ", 16\n",
            "vadd.vv v", $c, ", v", $c, ", v", $d, "\n",
            "vxor.vv v", $b, ", v", $b, ", v", $c, "\n",
            "vror.vi v", $b, ", v", $b, ", 20\n",
            "vadd.vv v", $a, ", v", $a, ", v", $b, "\n",
            "vxor.vv v", $d, ", v", $d, ", v", $a, "\n",
            "vror.vi v", $d, ", v", $d, ", 24\n",
            "vadd.vv v", $c, ", v", $c, ", v", $d, "\n",
            "vxor.vv v", $b, ", v", $b, ", v", $c, "\n",
            "vror.vi v", $b, ", v", $b, ", 25\n",
        )
    };
}

/// Loads state word `$i` into every lane of vector `$i`, from the
/// scalar at its offset.
#[rustfmt::skip]
macro_rules! load {
    ($i:literal) => {
        concat!(
            "lw {t}, ", $i, " * 4({state})\n",
            "vmv.v.x v", $i, ", {t}\n",
        )
    };
}

/// Adds the input word back to vector `$i` and xors it into the
/// data with a stride of one block between lanes.
#[rustfmt::skip]
macro_rules! output {
    ($i:literal) => {
        concat!(
            "lw {t}, ", $i, " * 4({state})\n",
            "vadd.vx v", $i, ", v", $i, ", {t}\n",
            "addi {t}, {data}, ", $i, " * 4\n",
            "vlse32.v v17, ({t}), {stride}\n",
            "vxor.vv v17, v17, v", $i, "\n",
            "vsse32.v v17, ({t}), {stride}\n",
        )
    };
}

/// As many of `blocks` blocks as one vector register holds lanes,
/// from `state` with the counter in word 12 as the first lane's,
/// xored into `data`. Returns how many blocks were done.
///
/// # Safety
/// Requires the vector extension and Zvbb; `data` must point at
/// `blocks` whole blocks.
unsafe fn group(state: &[u32; 16], data: *mut u8, blocks: usize) -> usize {
    let done: usize;
    core::arch::asm!(
        ".option push",
        ".option arch, +v,+zvbb",
        "vsetvli {done}, {blocks}, e32, m1, ta, ma",
        load!(0), load!(1), load!(2), load!(3),
        load!(4), load!(5), load!(6), load!(7),
        load!(8), load!(9), load!(10), load!(11),
        load!(13), load!(14), load!(15),
        // Lane j's counter is the base plus j.
        "lw {t}, 12 * 4({state})",
        "vid.v v12",
        "vadd.vx v12, v12, {t}",
        "li {n}, 10",
        "2:",
        quarter!("0", "4", "8", "12"),
        quarter!("1", "5", "9", "13"),
        quarter!("2", "6", "10", "14"),
        quarter!("3", "7", "11", "15"),
        quarter!("0", "5", "10", "15"),
        quarter!("1", "6", "11", "12"),
        quarter!("2", "7", "8", "13"),
        quarter!("3", "4", "9", "14"),
        "addi {n}, {n}, -1",
        "bnez {n}, 2b",
        output!(0), output!(1), output!(2), output!(3),
        output!(4), output!(5), output!(6), output!(7),
        output!(8), output!(9), output!(10), output!(11),
        // The counter word adds back the per-lane counters.
        "lw {t}, 12 * 4({state})",
        "vid.v v16",
        "vadd.vx v16, v16, {t}",
        "vadd.vv v12, v12, v16",
        "addi {t}, {data}, 12 * 4",
        "vlse32.v v17, ({t}), {stride}",
        "vxor.vv v17, v17, v12",
        "vsse32.v v17, ({t}), {stride}",
        output!(13), output!(14), output!(15),
        ".option pop",
        state = in(reg) state.as_ptr(),
        data = in(reg) data,
        blocks = in(reg) blocks,
        stride = in(reg) BLOCK_SIZE,
        done = out(reg) done,
        t = out(reg) _,
        n = out(reg) _,
        out("v0") _, out("v1") _, out("v2") _, out("v3") _,
        out("v4") _, out("v5") _, out("v6") _, out("v7") _,
        out("v8") _, out("v9") _, out("v10") _, out("v11") _,
        out("v12") _, out("v13") _, out("v14") _, out("v15") _,
        out("v16") _, out("v17") _,
        options(nostack),
    );
    done
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::chacha20::tests::{
        check_known_answers, check_matches_portable,
    };

    #[test]
    fn known_answers() {
        if has_zvbb() {
            check_known_answers::<Zvbb>();
        }
    }

    #[test]
    fn matches_portable() {
        if has_zvbb() {
            check_matches_portable::<Zvbb>();
        }
    }

    #[test]
    fn probes_agree_with_constructors() {
        assert_eq!(ChaCha20::try_new(&[0u8; 32]).is_ok(), has_zvbb());
    }
}
