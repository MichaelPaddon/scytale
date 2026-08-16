//! AES tables, derived at compile time rather than transcribed.
//!
//! Every table here is computed from the GF(2^8) field definition by `const
//! fn`, so there are no hand-copied magic constants to mistype, and the
//! derivation itself is the documentation.

/// Multiply by x in GF(2^8) modulo the AES polynomial x^8+x^4+x^3+x+1.
const fn xtime(a: u8) -> u8 {
    // Branchless reduction: 0u8 - (a >> 7) is 0xff exactly when bit 7 is set.
    (a << 1) ^ (0x1b & 0u8.wrapping_sub(a >> 7))
}

/// Multiply two field elements in GF(2^8).
const fn gmul(a: u8, b: u8) -> u8 {
    let mut acc = 0u8;
    let mut a = a;
    let mut b = b;
    while b != 0 {
        if b & 1 != 0 {
            acc ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    acc
}

/// Multiplicative inverse in GF(2^8), with 0 mapping to 0 as AES defines.
const fn ginv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut b = 1u16;
    while b < 256 {
        if gmul(a, b as u8) == 1 {
            return b as u8;
        }
        b += 1;
    }
    0
}

/// The AES affine transform over GF(2), applied after inversion.
const fn affine(x: u8) -> u8 {
    x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3)
        ^ x.rotate_left(4) ^ 0x63
}

const fn build_sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        s[i] = affine(ginv(i as u8));
        i += 1;
    }
    s
}

const fn build_inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

/// One table entry: the four row bytes that a substituted byte contributes
/// to a column, least significant byte first.
///
/// A column holds its rows least significant byte first so that loading one
/// on a little endian machine is a plain load, with no byte swap anywhere in
/// the hot path.
const fn spread(coefficients: [u8; 4], x: u8) -> u32 {
    u32::from_le_bytes([
        gmul(coefficients[0], x),
        gmul(coefficients[1], x),
        gmul(coefficients[2], x),
        gmul(coefficients[3], x),
    ])
}

/// Build the four row tables. Rows 1 to 3 are row 0 rotated, which is what
/// lets a single derivation serve all four.
const fn build(sbox: &[u8; 256], coefficients: [u8; 4]) -> [[u32; 256]; 4] {
    let mut t = [[0u32; 256]; 4];
    let mut i = 0usize;
    while i < 256 {
        let row0 = spread(coefficients, sbox[i]);
        t[0][i] = row0;
        t[1][i] = row0.rotate_left(8);
        t[2][i] = row0.rotate_left(16);
        t[3][i] = row0.rotate_left(24);
        i += 1;
    }
    t
}

pub(super) const SBOX: [u8; 256] = build_sbox();
pub(super) const INV_SBOX: [u8; 256] = build_inv_sbox();

/// The MixColumns matrix column, and its inverse.
pub(super) static TE: [[u32; 256]; 4] = build(&SBOX, [2, 1, 1, 3]);
pub(super) static TD: [[u32; 256]; 4] = build(&INV_SBOX, [14, 9, 13, 11]);

/// Round constants, pre-shifted into the high byte of the word.
pub(super) const RCON: [u32; 11] = [
    0x0000_0000,
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1b00_0000,
    0x3600_0000,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbox_matches_fips_197_samples() {
        // Spot values from the FIPS-197 Figure 7 substitution table.
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x01], 0x7c);
        assert_eq!(SBOX[0x53], 0xed);
        assert_eq!(SBOX[0xff], 0x16);
    }

    #[test]
    fn inv_sbox_undoes_sbox() {
        for i in 0..256usize {
            assert_eq!(INV_SBOX[SBOX[i] as usize] as usize, i);
        }
    }

    #[test]
    fn field_inverse_is_self_consistent() {
        for a in 1..256usize {
            assert_eq!(gmul(a as u8, ginv(a as u8)), 1);
        }
    }
}
