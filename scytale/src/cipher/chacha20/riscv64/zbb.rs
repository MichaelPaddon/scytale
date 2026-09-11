//! ChaCha20 on the general registers, with the rotate instruction of
//! Zbb (or Zbkb, which has the same one).
//!
//! ChaCha20 is almost nothing but rotates: twenty rounds of four
//! quarter rounds, each with four of them, is 320 a block. Without a
//! rotate instruction each one is a shift, a shift and an or, so a
//! third of the work is spent on something one instruction does.
//! `roriw` is that instruction, and it rotates right, so left by n is
//! right by 32 - n.
//!
//! The whole state fits in registers: sixteen words, and the rounds
//! never touch memory, so nothing here can depend on the key through
//! the cache. One block is computed at a time, because that is what
//! the registers hold; the vector backend beside this one does as
//! many at once as a vector register has lanes, and is the better
//! choice where there is a vector unit at all.
//!
//! The keystream goes to a buffer and the caller's data is xored with
//! it afterwards rather than in the assembly, because the data may
//! start at any byte and a word store wants an aligned address.

use super::super::{BLOCK_SIZE, Backend, CONSTANTS, Cipher, Sealed};
use crate::arch::riscv64::{EXT_ZBB, EXT_ZBKB, extensions};

/// ChaCha20 on the general registers.
pub type ChaCha20 = Cipher<Zbb>;

/// Whether the scalar rotate is available. Zbb and Zbkb both have it,
/// and either will do. RVA23 requires Zbb, so anything that conforms
/// to the profile has it.
pub(crate) fn has_zbb() -> bool {
    present(extensions())
}

/// Whether `ext` reports a scalar rotate.
fn present(ext: u64) -> bool {
    ext & (EXT_ZBB | EXT_ZBKB) != 0
}

/// The keystream generator on the general registers.
pub struct Zbb;

impl Sealed for Zbb {}

impl Backend for Zbb {
    fn supported() -> bool {
        has_zbb()
    }

    unsafe fn xor(
        key: &[u32; 8],
        nonce: &[u32; 3],
        counter: u32,
        data: &mut [u8],
    ) {
        unsafe { xor(key, nonce, counter, data) }
    }
}

/// Xors keystream from `counter` into `data`, a whole number of
/// blocks.
///
/// # Safety
/// Requires Zbb or Zbkb.
unsafe fn xor(key: &[u32; 8], nonce: &[u32; 3], counter: u32, data: &mut [u8]) {
    unsafe {
        debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&CONSTANTS);
        state[4..12].copy_from_slice(key);
        state[13..].copy_from_slice(nonce);

        let mut counter = counter;
        let mut keystream = [0u32; 16];
        for block in data.chunks_mut(BLOCK_SIZE) {
            state[12] = counter;
            keystream_block(&state, &mut keystream);
            for (bytes, word) in block.chunks_mut(4).zip(keystream) {
                for (b, k) in bytes.iter_mut().zip(word.to_le_bytes()) {
                    *b ^= k;
                }
            }
            counter = counter.wrapping_add(1);
        }
    }
}

/// A quarter round on the state words held in the named operands.
#[rustfmt::skip]
macro_rules! quarter {
    ($a:literal, $b:literal, $c:literal, $d:literal) => {
        concat!(
            "addw  {", $a, "}, {", $a, "}, {", $b, "}\n",
            "xor   {", $d, "}, {", $d, "}, {", $a, "}\n",
            "roriw {", $d, "}, {", $d, "}, 16\n",
            "addw  {", $c, "}, {", $c, "}, {", $d, "}\n",
            "xor   {", $b, "}, {", $b, "}, {", $c, "}\n",
            "roriw {", $b, "}, {", $b, "}, 20\n",
            "addw  {", $a, "}, {", $a, "}, {", $b, "}\n",
            "xor   {", $d, "}, {", $d, "}, {", $a, "}\n",
            "roriw {", $d, "}, {", $d, "}, 24\n",
            "addw  {", $c, "}, {", $c, "}, {", $d, "}\n",
            "xor   {", $b, "}, {", $b, "}, {", $c, "}\n",
            "roriw {", $b, "}, {", $b, "}, 25\n",
        )
    };
}

/// Loads state word `$i`, at its offset, into operand `$w`.
#[rustfmt::skip]
macro_rules! load {
    ($i:literal, $w:literal) => {
        concat!("lw {", $w, "}, ", $i, " * 4({state})\n")
    };
}

/// Adds the input word back to operand `$w` and stores it.
#[rustfmt::skip]
macro_rules! output {
    ($i:literal, $w:literal) => {
        concat!(
            "lw {t}, ", $i, " * 4({state})\n",
            "addw {", $w, "}, {", $w, "}, {t}\n",
            "sw {", $w, "}, ", $i, " * 4({out})\n",
        )
    };
}

/// One block of keystream from `state`, whose word 12 is the counter,
/// into `out`.
///
/// # Safety
/// Requires Zbb or Zbkb.
#[allow(unsafe_code)]
unsafe fn keystream_block(state: &[u32; 16], out: &mut [u32; 16]) {
    // SAFETY: the caller has confirmed the rotate; the assembly reads
    // sixteen words through `state` and writes sixteen through `out`,
    // which is the whole of each array.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +zbb",
            load!(0, "w0"), load!(1, "w1"), load!(2, "w2"),
            load!(3, "w3"), load!(4, "w4"), load!(5, "w5"),
            load!(6, "w6"), load!(7, "w7"), load!(8, "w8"),
            load!(9, "w9"), load!(10, "w10"), load!(11, "w11"),
            load!(12, "w12"), load!(13, "w13"), load!(14, "w14"),
            load!(15, "w15"),
            "li {n}, 10",
            "2:",
            quarter!("w0", "w4", "w8", "w12"),
            quarter!("w1", "w5", "w9", "w13"),
            quarter!("w2", "w6", "w10", "w14"),
            quarter!("w3", "w7", "w11", "w15"),
            quarter!("w0", "w5", "w10", "w15"),
            quarter!("w1", "w6", "w11", "w12"),
            quarter!("w2", "w7", "w8", "w13"),
            quarter!("w3", "w4", "w9", "w14"),
            "addi {n}, {n}, -1",
            "bnez {n}, 2b",
            output!(0, "w0"), output!(1, "w1"), output!(2, "w2"),
            output!(3, "w3"), output!(4, "w4"), output!(5, "w5"),
            output!(6, "w6"), output!(7, "w7"), output!(8, "w8"),
            output!(9, "w9"), output!(10, "w10"), output!(11, "w11"),
            output!(12, "w12"), output!(13, "w13"), output!(14, "w14"),
            output!(15, "w15"),
            ".option pop",
            state = in(reg) state.as_ptr(),
            out = in(reg) out.as_mut_ptr(),
            n = out(reg) _,
            t = out(reg) _,
            w0 = out(reg) _, w1 = out(reg) _, w2 = out(reg) _,
            w3 = out(reg) _, w4 = out(reg) _, w5 = out(reg) _,
            w6 = out(reg) _, w7 = out(reg) _, w8 = out(reg) _,
            w9 = out(reg) _, w10 = out(reg) _, w11 = out(reg) _,
            w12 = out(reg) _, w13 = out(reg) _, w14 = out(reg) _,
            w15 = out(reg) _,
            options(nostack),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::chacha20::tests::{
        check_known_answers, check_matches_portable,
    };

    #[test]
    fn known_answers() {
        if has_zbb() {
            check_known_answers::<Zbb>();
        }
    }

    #[test]
    fn matches_portable() {
        if has_zbb() {
            check_matches_portable::<Zbb>();
        }
    }

    #[test]
    fn probes_agree_with_constructors() {
        assert_eq!(
            ChaCha20::try_new(&crate::Key::from([0u8; 32])).is_ok(),
            has_zbb()
        );
    }

    /// `roriw` is in Zbb, which RVA23 requires, and in Zbkb, which
    /// comes with the scalar cryptography set. Either will do, and
    /// no vector unit is wanted.
    #[test]
    fn the_rotate_comes_from_either_extension() {
        use crate::arch::riscv64::profile;

        assert!(present(profile::RVA23));
        assert!(present(profile::ZKN));
        assert!(present(EXT_ZBB));
        assert!(present(EXT_ZBKB));
        assert!(!present(0));
    }
}
