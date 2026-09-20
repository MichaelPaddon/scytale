//! Keccak-f\[1600\] compiled for Zbb on RISC-V.
//!
//! There are no instructions for Keccak on this architecture. What
//! there is are `andn`, which is chi's `!b & c` in one instruction
//! where the baseline needs two, and `rori`, a rotation where the
//! baseline needs a shift, a shift and an or. Those are the two
//! things the permutation is made of: twenty-four rounds of twenty-five
//! lanes, each rotated and each taking a chi.
//!
//! This is the same arrangement as [`x86_64`](super::x86_64), where
//! the same two instructions under other names measured about a fifth
//! faster than the baseline build. The permutation itself is the
//! portable source and nothing else.

#![allow(unsafe_code)]

use super::engine::LANES;
use super::portable::keccak_f1600;
use crate::arch::riscv64::{EXT_ZBB, extensions};

/// Applies the permutation where the processor has Zbb, returning
/// whether it did.
pub(crate) fn permute(state: &mut [u64; LANES]) -> bool {
    if !has_zbb() {
        return false;
    }
    // SAFETY: the extension was just confirmed.
    unsafe { permute_zbb(state) };
    true
}

/// The portable permutation, inlined here and compiled for the
/// extension.
///
/// # Safety
/// Requires Zbb.
#[target_feature(enable = "zbb")]
unsafe fn permute_zbb(state: &mut [u64; LANES]) {
    keccak_f1600(state);
}

/// Whether the processor has Zbb, which the kernel answers for.
/// `extensions` keeps its answer, so asking for every permutation
/// costs a load.
fn has_zbb() -> bool {
    extensions() & EXT_ZBB != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The build for the extension permutes as the baseline one
    /// does, from the zero state and from states reached by
    /// permuting it.
    #[test]
    fn matches_the_baseline_build() {
        let mut expected = [0u64; LANES];
        for round in 0..4 {
            for (i, lane) in expected.iter_mut().enumerate() {
                *lane ^= (i as u64 + 1)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_mul(round);
            }
            let mut actual = expected;
            keccak_f1600(&mut expected);
            if !permute(&mut actual) {
                return;
            }
            assert_eq!(actual, expected, "round {round}");
        }
    }
}
