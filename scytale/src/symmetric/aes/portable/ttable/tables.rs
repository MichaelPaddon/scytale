//! Lookup tables for the T-table AES implementation.
//!
//! Everything here is evaluated at compile time, so the tables live in
//! read-only data and cost nothing at runtime. The tables are derived
//! from first principles (the GF(2^8) inverse and the affine map) rather
//! than transcribed, which keeps the source auditable.

/// The AES S-box.
pub const SBOX: [u8; 256] = gen_sbox();

/// The inverse AES S-box.
pub const INV_SBOX: [u8; 256] = invert(&SBOX);

/// Encryption T-table: `TE[0][x] = (2s, s, s, 3s)` where `s = SBOX[x]`,
/// packed big-endian. `TE[i]` is `TE[0]` rotated right by `8 * i` bits,
/// so each table supplies one column of the combined SubBytes,
/// ShiftRows and MixColumns transform.
pub const TE: [[u32; 256]; 4] = gen_te();

/// Decryption T-table: `TD[0][x] = (14s, 9s, 13s, 11s)` where
/// `s = INV_SBOX[x]`, packed big-endian. `TD[i]` is `TD[0]` rotated
/// right by `8 * i` bits.
pub const TD: [[u32; 256]; 4] = gen_td();

/// Multiply by `x` in GF(2^8) modulo `x^8 + x^4 + x^3 + x + 1`.
const fn xtime(a: u8) -> u8 {
    (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 }
}

/// Multiply two elements of GF(2^8).
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

/// Walk the multiplicative group with generator 3 while tracking its
/// inverse (1/3 is a right shift by one in the field, expressed as the
/// xor chain below), so no division is needed. The affine map is then
/// applied to the inverse.
const fn gen_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    loop {
        p = p ^ xtime(p);
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if q & 0x80 != 0 { 0x09 } else { 0 };
        let x = q
            ^ q.rotate_left(1)
            ^ q.rotate_left(2)
            ^ q.rotate_left(3)
            ^ q.rotate_left(4);
        sbox[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    sbox[0] = 0x63;
    sbox
}

const fn invert(table: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[table[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

const fn pack(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | d as u32
}

const fn rotations(t0: [u32; 256]) -> [[u32; 256]; 4] {
    let mut t = [t0, [0; 256], [0; 256], [0; 256]];
    let mut i = 0;
    while i < 256 {
        t[1][i] = t0[i].rotate_right(8);
        t[2][i] = t0[i].rotate_right(16);
        t[3][i] = t0[i].rotate_right(24);
        i += 1;
    }
    t
}

const fn gen_te() -> [[u32; 256]; 4] {
    let mut t0 = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        t0[i] = pack(xtime(s), s, s, xtime(s) ^ s);
        i += 1;
    }
    rotations(t0)
}

const fn gen_td() -> [[u32; 256]; 4] {
    let mut t0 = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = INV_SBOX[i];
        t0[i] = pack(gf_mul(s, 14), gf_mul(s, 9), gf_mul(s, 13), gf_mul(s, 11));
        i += 1;
    }
    rotations(t0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbox_known_entries() {
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x01], 0x7c);
        assert_eq!(SBOX[0x53], 0xed);
        assert_eq!(SBOX[0xff], 0x16);
    }

    #[test]
    fn sbox_is_a_permutation() {
        let mut seen = [false; 256];
        for &s in SBOX.iter() {
            assert!(!seen[s as usize]);
            seen[s as usize] = true;
        }
    }

    #[test]
    fn inv_sbox_inverts_sbox() {
        for i in 0..256 {
            assert_eq!(INV_SBOX[SBOX[i] as usize], i as u8);
        }
    }

    #[test]
    fn te_known_entries() {
        assert_eq!(TE[0][0x00], 0xc66363a5);
        assert_eq!(TE[1][0x00], 0xa5c66363);
        assert_eq!(TE[2][0x00], 0x63a5c663);
        assert_eq!(TE[3][0x00], 0x6363a5c6);
        assert_eq!(TE[0][0xff], 0x2c16163a);
    }

    #[test]
    fn td_known_entries() {
        assert_eq!(TD[0][0x00], 0x51f4a750);
        assert_eq!(TD[1][0x00], 0x5051f4a7);
        assert_eq!(TD[0][0xff], 0xd0b85742);
    }
}
