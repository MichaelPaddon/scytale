//! GHASH multiplication on RISC-V.
//!
//! Three different extensions can do this work, and a processor may
//! have any one of them without the others, so there is a backend for
//! each and the choice is made once, the first time a hash starts.
//!
//! * [`zvkg`] has `vgmul`, which performs the whole field
//!   multiplication, reduction included, in one instruction. It is
//!   the fastest and the first choice.
//! * [`zvbc`] has a vector carry-less multiply, which is the
//!   primitive x86 and ARM build this out of. Eight blocks are
//!   multiplied at once, one to a lane.
//! * [`zbc`] has the same primitive on the general registers, for a
//!   processor with no vector unit. Every processor with the scalar
//!   AES instructions has it, because Zkn pulls in Zbkc.
//!
//! The three are not alternatives a vendor picks between at whim:
//! `Zvkng` is `Zvkn` plus Zvkg, `Zvknc` is `Zvkn` plus Zvbc, and
//! `Zkn` includes Zbkc, so each of these is the only carry-less
//! multiply some real configuration has.
//!
//! # What is shared
//!
//! Both carry-less backends end the same way, and [`finish`] is that
//! ending: it corrects Karatsuba's middle product, folds it into the
//! outer thirds of the 256-bit result, and reduces. Only the multiply
//! itself differs, so each passes its own in.

#![allow(unsafe_code)]

use crate::arch::riscv64::{extensions, vector_bytes};
use crate::probe::Probe;

mod zbc;
mod zvbc;
pub(crate) mod zvkg;

/// The field polynomial `x^128 + x^7 + x^2 + x + 1` without its
/// leading term, written in GHASH's reversed bit order.
const POLYNOMIAL: u64 = 0xc200_0000_0000_0000;

/// Which multiply this processor has, named for the extension that
/// provides it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Choice {
    /// The whole field multiplication in one instruction.
    Zvkg,
    /// A vector carry-less multiply.
    Zvbc,
    /// A scalar carry-less multiply.
    Zbc,
}

/// The chosen multiply, asked for once; see [`crate::probe`].
static CHOSEN: Probe = Probe::new();

/// Every backend, best first.
const CHOICES: [Choice; 3] = [Choice::Zvkg, Choice::Zvbc, Choice::Zbc];

/// Whether `ext` reports `choice`, on a processor whose vector
/// registers are `bytes` wide.
fn present(choice: Choice, ext: u64, bytes: usize) -> bool {
    match choice {
        Choice::Zvkg => zvkg::present(ext, bytes),
        Choice::Zvbc => zvbc::present(ext, bytes),
        Choice::Zbc => zbc::present(ext, bytes),
    }
}

/// The best multiply the extensions in `ext` offer.
#[cfg(test)]
fn best_of(ext: u64, bytes: usize) -> Option<Choice> {
    CHOICES.into_iter().find(|&c| present(c, ext, bytes))
}

/// The chosen multiply, asked of the processor only once. The answer
/// cannot change while the program runs, and the probe is a system
/// call.
///
/// The extensions are read inside the closure rather than before it,
/// so that the system call happens only on the first call rather than
/// on every one. That first call may make it more than once, as it
/// works down the list, which is a cost paid once in the life of the
/// program.
fn choice() -> Option<Choice> {
    CHOSEN.first(&CHOICES, |choice| {
        let ext = extensions();
        present(choice, ext, vector_bytes(ext))
    })
}

/// How many blocks the group multiply takes at once.
pub(super) fn group() -> usize {
    match choice() {
        Some(Choice::Zvkg) => zvkg::GROUP,
        Some(Choice::Zvbc) => zvbc::GROUP,
        Some(Choice::Zbc) => zbc::GROUP,
        None => 1,
    }
}

/// Whether this processor can multiply in the field without walking
/// the bits.
pub(super) fn has_carryless_multiply() -> bool {
    choice().is_some()
}

/// Prepares the subkey for [`multiply`].
pub(super) fn prepare(h: &[u64; 2]) -> [u64; 2] {
    match choice() {
        Some(Choice::Zvkg) => zvkg::prepare(h),
        Some(Choice::Zvbc) => zvbc::prepare(h),
        Some(Choice::Zbc) => zbc::prepare(h),
        // Never reached: the subkey is only prepared once the probe
        // has found something to prepare it for.
        None => *h,
    }
}

/// Multiplies `value` by the prepared subkey `h`, in place.
///
/// # Safety
/// The subkey must have been prepared by [`prepare`], which is what
/// confirms the instructions.
pub(super) unsafe fn multiply(value: &mut [u64; 2], h: &[u64; 2]) {
    unsafe {
        match choice() {
            Some(Choice::Zvkg) => zvkg::multiply(value, h),
            Some(Choice::Zvbc) => zvbc::multiply(value, h),
            Some(Choice::Zbc) => zbc::multiply(value, h),
            None => unreachable!("no carry-less multiply on this processor"),
        }
    }
}

/// Multiplies in the whole of `blocks`, which is [`group`] blocks,
/// leaving the running hash in `value`.
///
/// # Safety
/// As [`multiply`], and `blocks` must be exactly [`group`] blocks
/// long. `powers` holds the prepared powers of the subkey, `H` first.
pub(super) unsafe fn multiply_group(
    value: &mut [u64; 2],
    powers: &[[u64; 2]; super::MAX_GROUP],
    blocks: &[u8],
) {
    unsafe {
        match choice() {
            Some(Choice::Zvkg) => zvkg::multiply_group(value, powers, blocks),
            Some(Choice::Zvbc) => zvbc::multiply_group(value, powers, blocks),
            Some(Choice::Zbc) => zbc::multiply_group(value, powers, blocks),
            None => unreachable!("no carry-less multiply on this processor"),
        }
    }
}

/// Whether the one-instruction multiply is the one this processor
/// would use.
///
/// GCM's own loop is written around it: it is the only one of the
/// three that fits in a register beside the cipher's round keys, so a
/// processor with one of the others runs GCM as the portable mode over
/// its own accelerated hash instead.
pub(crate) fn has_vector_ghash() -> bool {
    choice() == Some(Choice::Zvkg)
}

/// Finishes a field multiplication from its three Karatsuba pieces,
/// given a carry-less multiply.
///
/// `lo`, `m` and `hi` are the products of the operands' low halves,
/// of their halves added together, and of their high halves, each
/// least significant word first. `m` is the raw product, not yet
/// corrected; since every piece is a sum over however many blocks
/// went into it, and the correction is linear, it can be applied once
/// here rather than once a block.
///
/// The result is the field product in register order, least
/// significant word first.
fn finish(
    lo: [u64; 2],
    m: [u64; 2],
    hi: [u64; 2],
    wide: impl Fn(u64, u64) -> [u64; 2],
) -> [u64; 2] {
    // Karatsuba's middle term is the sum of the two cross products,
    // which this recovers from the product of the sums.
    let mid = [m[0] ^ lo[0] ^ hi[0], m[1] ^ lo[1] ^ hi[1]];
    // It belongs half in each end of the 256-bit result.
    let lo = [lo[0], lo[1] ^ mid[0]];
    let hi = [hi[0] ^ mid[1], hi[1]];

    // Fold the low half down in two steps. Each multiplication by
    // the polynomial moves one word's worth of excess up, and
    // exchanging the halves in between lets the same step do both.
    let p = wide(POLYNOMIAL, lo[0]);
    let s = [lo[1] ^ p[0], lo[0] ^ p[1]];
    let q = wide(POLYNOMIAL, s[0]);
    [hi[0] ^ s[1] ^ q[0], hi[1] ^ s[0] ^ q[1]]
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cipher::mode::ghash::{BLOCK, MAX_GROUP, halve};
    use std::eprintln;

    /// A cheap spread of test values; the multiply is linear in each
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

    /// Everything one backend has to offer, so that a test can drive
    /// each of them rather than only the one this processor would
    /// pick.
    struct Backend {
        name: &'static str,
        choice: Choice,
        group: usize,
        prepare: fn(&[u64; 2]) -> [u64; 2],
        multiply: unsafe fn(&mut [u64; 2], &[u64; 2]),
        multiply_group: unsafe fn(&mut [u64; 2], &[[u64; 2]; MAX_GROUP], &[u8]),
    }

    const BACKENDS: [Backend; 3] = [
        Backend {
            name: "zvkg",
            choice: Choice::Zvkg,
            group: zvkg::GROUP,
            prepare: zvkg::prepare,
            multiply: zvkg::multiply,
            multiply_group: zvkg::multiply_group,
        },
        Backend {
            name: "zvbc",
            choice: Choice::Zvbc,
            group: zvbc::GROUP,
            prepare: zvbc::prepare,
            multiply: zvbc::multiply,
            multiply_group: zvbc::multiply_group,
        },
        Backend {
            name: "zbc",
            choice: Choice::Zbc,
            group: zbc::GROUP,
            prepare: zbc::prepare,
            multiply: zbc::multiply,
            multiply_group: zbc::multiply_group,
        },
    ];

    /// Whether this processor has `choice`, which is what decides
    /// whether a test can run that backend's instructions at all.
    fn here(choice: Choice) -> bool {
        let ext = extensions();
        present(choice, ext, vector_bytes(ext))
    }

    /// The portable multiply is the reference; every backend has to
    /// agree with it, not just the one this processor chooses.
    #[test]
    #[allow(unsafe_code)]
    fn every_backend_agrees_with_portable() {
        for backend in &BACKENDS {
            if !here(backend.choice) {
                eprintln!("skipping: no {}", backend.name);
                continue;
            }
            // Zero and one are what the folding is most likely to get
            // wrong, and a random sample would not reach them.
            let edges = [[0, 0], [1 << 63, 0], [0, 1], [!0, !0]];
            let pairs = edges
                .iter()
                .flat_map(|&a| edges.iter().map(move |&b| (a, b)))
                .chain((0..200).map(|s| (values(s ^ 0x5555_5555), values(s))));
            for (start, h) in pairs {
                let mut want = start;
                super::super::multiply(&mut want, &h);
                let mut got = start;
                let scaled = (backend.prepare)(&h);
                unsafe { (backend.multiply)(&mut got, &scaled) };
                assert_eq!(got, want, "{}: {start:x?} * {h:x?}", backend.name);
            }
        }
    }

    /// A group multiply has to give what the same blocks give one at
    /// a time.
    #[test]
    #[allow(unsafe_code)]
    fn every_group_multiply_agrees_with_its_own_blocks() {
        for backend in &BACKENDS {
            if !here(backend.choice) || backend.group == 1 {
                eprintln!("skipping: no {} group multiply", backend.name);
                continue;
            }
            assert_eq!(backend.group, MAX_GROUP);
            for seed in 0..50 {
                let h = values(seed);
                let scaled = (backend.prepare)(&h);
                let mut powers = [[0u64; 2]; MAX_GROUP];
                let mut power = [1u64 << 63, 0];
                for slot in powers.iter_mut() {
                    unsafe { (backend.multiply)(&mut power, &scaled) };
                    *slot = (backend.prepare)(&power);
                }

                let blocks: [u8; MAX_GROUP * BLOCK] =
                    core::array::from_fn(|i| (i as u64 ^ seed) as u8);
                let start = values(seed ^ 0xaaaa_aaaa);

                let mut want = start;
                for block in blocks.chunks_exact(BLOCK) {
                    want[0] ^= halve(&block[..8]);
                    want[1] ^= halve(&block[8..]);
                    super::super::multiply(&mut want, &h);
                }

                let mut got = start;
                unsafe { (backend.multiply_group)(&mut got, &powers, &blocks) };
                assert_eq!(got, want, "{}: seed {seed}", backend.name);
            }
        }
    }

    /// Which backend each kind of real processor is given. The choice
    /// is a function of the extension bit set, so this is the whole of
    /// the dispatch rather than a sample of it, and it covers
    /// combinations no emulator offers.
    #[test]
    fn the_choice_follows_the_extensions() {
        use crate::arch::riscv64::profile;

        // The vector profiles that carry a multiply, and the ones
        // that carry none.
        assert_eq!(best_of(profile::ZVKNG, 16), Some(Choice::Zvkg));
        assert_eq!(best_of(profile::ZVKNC, 16), Some(Choice::Zvbc));
        assert_eq!(best_of(profile::ZVKN, 16), None);
        assert_eq!(best_of(profile::RVA23, 16), None);

        // Zkn has no vector unit and Zbkc with it, which is the whole
        // reason the scalar backend exists.
        assert_eq!(best_of(profile::ZKN, 0), Some(Choice::Zbc));

        // Zvkg wins wherever it is, whatever else is there.
        assert_eq!(
            best_of(profile::ZVKNG | profile::ZVKNC | profile::ZKN, 16),
            Some(Choice::Zvkg)
        );
        // The scalar multiply is taken over nothing, even beside a
        // vector unit that cannot help.
        assert_eq!(
            best_of(profile::RVA23 | profile::ZKN, 16),
            Some(Choice::Zbc)
        );

        // Registers too narrow for a 128-bit element group put the
        // vector backends out, and a vector profile has nothing else.
        assert_eq!(best_of(profile::ZVKNG, 8), None);
        assert_eq!(best_of(profile::ZVKNC, 8), None);
        // A processor with none of it has nothing.
        assert_eq!(best_of(0, 0), None);
    }

    /// The dispatch has to pick a backend that is really there, and
    /// report the group size of the one it picked.
    #[test]
    fn the_choice_is_one_the_processor_has() {
        match choice() {
            Some(chosen) => {
                assert!(here(chosen));
                assert!(has_carryless_multiply());
                let at = CHOICES.iter().position(|&c| c == chosen).unwrap();
                assert_eq!(group(), BACKENDS[at].group);
                // Asking twice must give the same answer, now that
                // the first call has cached it.
                assert_eq!(choice(), Some(chosen));
            }
            None => {
                assert!(!has_carryless_multiply());
                assert_eq!(group(), 1);
            }
        }
    }
}
