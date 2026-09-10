//! Poly1305 over four message blocks at a time, for processors with
//! AVX2.
//!
//! # Why four at once
//!
//! The definition is a chain: each block is added to the running value
//! and the sum multiplied by `r`, so a block cannot start until the
//! one before it has finished. Nothing about that is parallel.
//!
//! It becomes parallel the way GHASH does, by writing the polynomial
//! out. A message of `4K` blocks has
//!
//! ```text
//! P = sum over i of m_i r^(4K+1-i)
//! ```
//!
//! and splitting the blocks by their position within each group of
//! four gives four chains, each stepping by `r^4` and none waiting on
//! another:
//!
//! ```text
//! P = A_0 r^4 + A_1 r^3 + A_2 r^2 + A_3 r
//! where A_j = sum over k of m_(4k+j) (r^4)^(K-1-k)
//! ```
//!
//! The four chains are the four lanes of a 256-bit register, so the
//! loop below does one multiplication by `r^4` for every four blocks.
//!
//! # The limbs
//!
//! Five limbs of 26 bits, rather than the three of 44 the portable
//! code uses: `vpmuludq` multiplies the low 32 bits of each 64-bit
//! lane, so 26 is as wide as a limb can be and still leave room for
//! a product and the sum of five of them.
//!
//! # What is left to the caller
//!
//! The first group, the weights at the end, and the key's powers.
//! Each happens once for a message rather than once for a group, so
//! none of them is worth the assembly, and the arithmetic that is
//! easiest to get wrong stays where it can be read.

#![allow(unsafe_code)]

use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

use crate::probe::Probe;

/// Bytes in a block.
const BLOCK: usize = 16;

/// Blocks the loop takes at once: the lanes of a 256-bit register.
pub(super) const LANES: usize = 4;

/// Bytes in one group.
pub(super) const SPAN: usize = LANES * BLOCK;

/// A limb's worth of ones.
const MASK: u64 = (1 << 26) - 1;

/// Limbs in a value: 130 bits at 26 bits each.
const LIMBS: usize = 5;

/// The tables the loop reads, laid out as it wants them and aligned
/// so that a load of one is a single operation.
///
/// The first five are the limbs of `r^4`, each in every lane; then
/// the upper four of them times five, which is what a limb carried
/// past the top of the field is worth; then the limb mask; then the
/// bit that sits above a whole block.
#[repr(align(32))]
#[derive(Clone, Copy)]
struct Tables([[u64; LANES]; 11]);

/// Everything worked out from the key, once.
#[derive(Clone, Copy)]
pub(super) struct Powers {
    tables: Tables,
    /// The weight each lane's chain is multiplied by at the end:
    /// `r^4`, `r^3`, `r^2` and `r`, in the order the loads below
    /// leave the lanes.
    weights: [[u64; LIMBS]; LANES],
}

/// Whether the processor and operating system support AVX2.
pub(super) fn supported() -> bool {
    PROBED.yes(ask)
}

/// Asked once; see [`crate::probe`].
static PROBED: Probe = Probe::new();

fn ask() -> bool {
    let leaf1 = __cpuid(1);
    let wanted = (1 << 27) | (1 << 28);
    if leaf1.ecx & wanted != wanted {
        return false;
    }
    if __cpuid_count(7, 0).ebx & (1 << 5) == 0 {
        return false;
    }
    // SAFETY: OSXSAVE was just confirmed, so XGETBV is available.
    let xcr0 = unsafe { _xgetbv(0) };
    xcr0 & 0b110 == 0b110
}

/// Multiplies two values in the field, with the limbs carried far
/// enough that another multiplication cannot overflow.
///
/// Plain integer arithmetic: this runs a handful of times for a key
/// and never in the loop.
fn multiply(a: &[u64; LIMBS], b: &[u64; LIMBS]) -> [u64; LIMBS] {
    let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);
    // A limb carried past the top is worth five of the bottom, since
    // the field is the integers modulo 2^130 - 5.
    let five = |x: u64| 5 * x;
    let mut d = [0u128; LIMBS];
    for (k, d) in d.iter_mut().enumerate() {
        for (i, &a) in a.iter().enumerate() {
            let j = (k + LIMBS - i) % LIMBS;
            let term = if i + j == k { b[j] } else { five(b[j]) };
            *d += wide(a, term);
        }
    }
    carry(d)
}

/// Brings a row of products down to five limbs of 26 bits.
fn carry(d: [u128; LIMBS]) -> [u64; LIMBS] {
    let mut out = [0u64; LIMBS];
    let mut c = 0u128;
    for (out, d) in out.iter_mut().zip(d) {
        let v = d + c;
        *out = (v as u64) & MASK;
        c = v >> 26;
    }
    // What came off the top re-enters at the bottom, five times over.
    out[0] += 5 * (c as u64);
    let c = out[0] >> 26;
    out[0] &= MASK;
    out[1] += c;
    out
}

/// The limbs of one block, with the bit that sits above it.
fn block_limbs(block: &[u8; BLOCK], high: u64) -> [u64; LIMBS] {
    let word = |at: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&block[at..at + 8]);
        u64::from_le_bytes(bytes)
    };
    let (lo, hi) = (word(0), word(8));
    [
        lo & MASK,
        (lo >> 26) & MASK,
        ((lo >> 52) | (hi << 12)) & MASK,
        (hi >> 14) & MASK,
        (hi >> 40) | (high << 24),
    ]
}

impl Powers {
    /// The powers of `r`, which arrives as the three limbs the
    /// portable code clamped it into.
    pub(super) fn new(r: &[u64; 3]) -> Self {
        let r = &from_thirds(r);
        let r2 = multiply(r, r);
        let r3 = multiply(&r2, r);
        let r4 = multiply(&r2, &r2);

        let mut tables = Tables([[0u64; LANES]; 11]);
        for (k, &limb) in r4.iter().enumerate() {
            tables.0[k] = [limb; LANES];
        }
        for (k, &limb) in r4[1..].iter().enumerate() {
            tables.0[5 + k] = [5 * limb; LANES];
        }
        tables.0[9] = [MASK; LANES];
        tables.0[10] = [1 << 24; LANES];

        // The loads in the loop leave the group's blocks in the lane
        // order 0, 2, 1, 3, so the weights take that order too.
        Powers {
            tables,
            weights: [r4, r2, r3, *r],
        }
    }
}

/// Adds `data`, a whole number of groups, to the running value `h`.
///
/// `h` arrives and leaves as the three limbs of 44, 44 and 42 bits
/// the portable code keeps, so nothing outside this file has to know
/// about the five.
///
/// # Panics
/// If `data` is not a whole number of groups, or is empty.
pub(super) fn bulk(h: &mut [u64; 3], powers: &Powers, data: &[u8]) {
    assert!(!data.is_empty() && data.len().is_multiple_of(SPAN));
    let groups = data.len() / SPAN;

    // The first group is added here rather than in the loop, because
    // the running value joins the first block of it and a test for
    // that inside the loop would cost more than doing it outside.
    let (first, rest) = data.split_at(SPAN);
    let mut lanes = [[0u64; LANES]; LIMBS];
    for (lane, block) in ORDER.iter().enumerate() {
        let block: &[u8; BLOCK] =
            first[block * BLOCK..][..BLOCK].try_into().expect("block");
        let limbs = block_limbs(block, 1);
        for (limb, &value) in lanes.iter_mut().zip(&limbs) {
            limb[lane] = value;
        }
    }
    for (limb, value) in lanes.iter_mut().zip(from_thirds(h)) {
        limb[0] += value;
    }

    if groups > 1 {
        // SAFETY: `supported` was confirmed before these powers were
        // built, `lanes` is the five limbs the loop expects, the
        // tables are the ones built beside them, and `rest` is
        // `groups - 1` whole groups.
        unsafe {
            multiply_groups(
                lanes.as_mut_ptr().cast::<u64>(),
                powers.tables.0.as_ptr().cast::<u64>(),
                rest.as_ptr(),
                groups - 1,
            );
        }
    }

    // Each lane's chain carries the weight of its place in the group.
    let mut total = [0u128; LIMBS];
    for (lane, weight) in powers.weights.iter().enumerate() {
        let value: [u64; LIMBS] =
            core::array::from_fn(|limb| lanes[limb][lane]);
        for (total, limb) in total.iter_mut().zip(multiply(&value, weight)) {
            *total += u128::from(limb);
        }
    }
    *h = into_thirds(&carry(total));
}

/// The lanes in the order the loop's loads leave them.
const ORDER: [usize; LANES] = [0, 2, 1, 3];

/// The five limbs of a value kept as three.
fn from_thirds(h: &[u64; 3]) -> [u64; LIMBS] {
    let w0 = h[0] | (h[1] << 44);
    let w1 = (h[1] >> 20) | (h[2] << 24);
    let w2 = h[2] >> 40;
    [
        w0 & MASK,
        (w0 >> 26) & MASK,
        ((w0 >> 52) | (w1 << 12)) & MASK,
        (w1 >> 14) & MASK,
        ((w1 >> 40) | (w2 << 24)) & MASK,
    ]
}

/// The other way round.
fn into_thirds(limbs: &[u64; LIMBS]) -> [u64; 3] {
    let w0 = limbs[0] | (limbs[1] << 26) | (limbs[2] << 52);
    let w1 = (limbs[2] >> 12) | (limbs[3] << 14) | (limbs[4] << 40);
    let w2 = limbs[4] >> 24;
    [
        w0 & ((1 << 44) - 1),
        ((w0 >> 44) | (w1 << 20)) & ((1 << 44) - 1),
        ((w1 >> 24) | (w2 << 40)) & ((1 << 42) - 1),
    ]
}

/// One term of the product: limb `$k` of the result takes limb `$i`
/// of the running value times the table entry `$t`.
macro_rules! term {
    ($k:literal, $i:literal, $t:literal) => {
        concat!(
            "vpmuludq ymm15, ymm",
            $i,
            ", [{r} + ",
            $t,
            "*32]\n",
            "vpaddq ymm",
            $k,
            ", ymm",
            $k,
            ", ymm15\n",
        )
    };
}

/// The first term of a limb, which starts it rather than adding to it.
macro_rules! first {
    ($k:literal, $i:literal, $t:literal) => {
        concat!("vpmuludq ymm", $k, ", ymm", $i, ", [{r} + ", $t, "*32]\n")
    };
}

/// One limb's carry into the next.
macro_rules! step {
    ($from:literal, $to:literal, $into:literal) => {
        concat!(
            "vpsrlq ymm15, ymm",
            $from,
            ", 26\n",
            "vpand ymm",
            $into,
            ", ymm",
            $from,
            ", [{r} + 9*32]\n",
            "vpaddq ymm",
            $to,
            ", ymm",
            $to,
            ", ymm15\n",
        )
    };
}

/// Runs `groups` groups of four blocks through the loop.
///
/// # Safety
/// Requires AVX2. `a` must point at five lanes-wide limbs of the
/// running value, `r` at the tables, and `data` at `groups * 64`
/// bytes, with `groups >= 1`.
unsafe fn multiply_groups(
    a: *mut u64,
    r: *const u64,
    data: *const u8,
    groups: usize,
) {
    unsafe {
        core::arch::asm!(
            "vmovdqu ymm0, [{a} + 0*32]",
            "vmovdqu ymm1, [{a} + 1*32]",
            "vmovdqu ymm2, [{a} + 2*32]",
            "vmovdqu ymm3, [{a} + 3*32]",
            "vmovdqu ymm4, [{a} + 4*32]",

            "2:",
            // Four blocks. The unpacks put the four low words of the
            // blocks in one register and the four high words in
            // another, which leaves the lanes in the order 0, 2, 1, 3;
            // the weights at the end are in that order to match.
            "vmovdqu ymm5, [{data}]",
            "vmovdqu ymm6, [{data} + 32]",
            "vpunpcklqdq ymm7, ymm5, ymm6",
            "vpunpckhqdq ymm8, ymm5, ymm6",

            // Their five limbs, kept aside until after the multiply:
            // the running value is multiplied first and the blocks
            // added to the product, which is what the definition's
            // chain comes to when it is written out.
            "vpand ymm10, ymm7, [{r} + 9*32]",
            "vpsrlq ymm11, ymm7, 26",
            "vpand ymm11, ymm11, [{r} + 9*32]",
            "vpsrlq ymm12, ymm7, 52",
            "vpsllq ymm13, ymm8, 12",
            "vpor ymm12, ymm12, ymm13",
            "vpand ymm12, ymm12, [{r} + 9*32]",
            "vpsrlq ymm13, ymm8, 14",
            "vpand ymm13, ymm13, [{r} + 9*32]",
            "vpsrlq ymm14, ymm8, 40",
            // The bit that sits above a whole block.
            "vpor ymm14, ymm14, [{r} + 10*32]",

            // Multiply by r^4. Limbs that would pass the top of the
            // field come back at the bottom five times over, which is
            // what the second half of the table holds.
            first!(5, 0, 0),
            term!(5, 1, 8),
            term!(5, 2, 7),
            term!(5, 3, 6),
            term!(5, 4, 5),
            first!(6, 0, 1),
            term!(6, 1, 0),
            term!(6, 2, 8),
            term!(6, 3, 7),
            term!(6, 4, 6),
            first!(7, 0, 2),
            term!(7, 1, 1),
            term!(7, 2, 0),
            term!(7, 3, 8),
            term!(7, 4, 7),
            first!(8, 0, 3),
            term!(8, 1, 2),
            term!(8, 2, 1),
            term!(8, 3, 0),
            term!(8, 4, 8),
            first!(9, 0, 4),
            term!(9, 1, 3),
            term!(9, 2, 2),
            term!(9, 3, 1),
            term!(9, 4, 0),

            // Back down to 26 bits a limb.
            step!(5, 6, 0),
            step!(6, 7, 1),
            step!(7, 8, 2),
            step!(8, 9, 3),
            "vpsrlq ymm15, ymm9, 26",
            "vpand ymm4, ymm9, [{r} + 9*32]",
            // Five times what came off the top.
            "vpsllq ymm5, ymm15, 2",
            "vpaddq ymm15, ymm15, ymm5",
            "vpaddq ymm0, ymm0, ymm15",
            "vpsrlq ymm15, ymm0, 26",
            "vpand ymm0, ymm0, [{r} + 9*32]",
            "vpaddq ymm1, ymm1, ymm15",

            // And the blocks join the product.
            "vpaddq ymm0, ymm0, ymm10",
            "vpaddq ymm1, ymm1, ymm11",
            "vpaddq ymm2, ymm2, ymm12",
            "vpaddq ymm3, ymm3, ymm13",
            "vpaddq ymm4, ymm4, ymm14",

            "add {data}, 64",
            "dec {groups}",
            "jnz 2b",

            "vmovdqu [{a} + 0*32], ymm0",
            "vmovdqu [{a} + 1*32], ymm1",
            "vmovdqu [{a} + 2*32], ymm2",
            "vmovdqu [{a} + 3*32], ymm3",
            "vmovdqu [{a} + 4*32], ymm4",
            // Leaving the upper halves dirty would slow down whatever
            // plain SSE code runs next.
            "vzeroupper",
            a = in(reg) a,
            r = in(reg) r,
            data = inout(reg) data => _,
            groups = inout(reg) groups => _,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
            out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
            options(nostack),
        );
    }
}
