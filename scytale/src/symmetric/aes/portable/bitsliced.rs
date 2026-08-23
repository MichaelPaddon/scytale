//! Portable bitsliced AES.
//!
//! Four blocks are processed together. Their 64 bytes are spread over
//! eight 64-bit words, one word per bit position of a byte, so every
//! step of AES becomes plain boolean and shift operations on whole
//! words. The S-box is the 113-gate circuit of Boyar and Peralta.
//!
//! There are no lookup tables and no data-dependent branches or
//! memory accesses, so unlike [`Aes`](super::Aes) this
//! implementation does not leak key material through cache timing. It
//! is several times slower.
//!
//! # Layout
//!
//! Within each word, bit `16 * row + 4 * column + block` holds the
//! chosen bit of that byte of that block. ShiftRows is then a rotation
//! within each 16-bit row group and MixColumns a rotation of the word
//! by multiples of 16.
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::portable::bitsliced::Aes;
//!
//! # fn main() -> Result<(), scytale::symmetric::Error> {
//! let aes = Aes::try_new(&[0u8; 16])?;
//! let mut block = [0u8; 16];
//! aes.encrypt_block(&mut block);
//! aes.decrypt_block(&mut block);
//! assert_eq!(block, [0u8; 16]);
//! # Ok(())
//! # }
//! ```

use core::fmt;

use crate::symmetric::aes::{expand_words, KeySize, BLOCK_SIZE};
use crate::symmetric::{BlockCipher, Error};
use zeroize::ZeroizeOnDrop;

/// Round keys for the largest key size (AES-256: 15 round keys).
const MAX_ROUND_KEYS: usize = 15;

/// Blocks held in one bitsliced state.
const LANES: usize = 4;

/// Bytes in one bitsliced state.
const GROUP: usize = LANES * BLOCK_SIZE;

/// Eight bit planes holding four blocks.
type State = [u64; 8];

/// A bitsliced AES cipher with an expanded key.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::try_new`].
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes {
    /// Each round key replicated into all four block lanes.
    keys: [State; MAX_ROUND_KEYS],
    #[zeroize(skip)]
    size: KeySize,
}

impl fmt::Debug for Aes {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes")
            .field("rounds", &self.rounds())
            .finish()
    }
}

impl Aes {
    /// Expands `key`, which must be 16, 24 or 32 bytes long.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        let size = KeySize::for_key(key)?;
        // SubWord goes through the bitsliced S-box, so the schedule is
        // constant time too.
        let w = expand_words(key, size, sub_word);

        let mut keys = [[0u64; 8]; MAX_ROUND_KEYS];
        for (state, words) in keys.iter_mut().zip(w.chunks_exact(4)) {
            let mut group = [0u8; GROUP];
            for block in group.chunks_exact_mut(BLOCK_SIZE) {
                for (b, word) in block.chunks_exact_mut(4).zip(words) {
                    b.copy_from_slice(&word.to_le_bytes());
                }
            }
            *state = pack(&group);
        }

        Ok(Aes { keys, size })
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.size.rounds()
    }

    /// Encrypts one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        match self.size {
            KeySize::Aes128 => encrypt_many::<10>(&self.keys, block),
            KeySize::Aes192 => encrypt_many::<12>(&self.keys, block),
            KeySize::Aes256 => encrypt_many::<14>(&self.keys, block),
        }
    }

    /// Decrypts one block in place.
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        match self.size {
            KeySize::Aes128 => decrypt_many::<10>(&self.keys, block),
            KeySize::Aes192 => decrypt_many::<12>(&self.keys, block),
            KeySize::Aes256 => decrypt_many::<14>(&self.keys, block),
        }
    }

    /// Encrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of 16; nothing is changed
    /// otherwise.
    pub fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::NotBlockAligned(data.len()));
        }
        match self.size {
            KeySize::Aes128 => encrypt_many::<10>(&self.keys, data),
            KeySize::Aes192 => encrypt_many::<12>(&self.keys, data),
            KeySize::Aes256 => encrypt_many::<14>(&self.keys, data),
        }
        Ok(())
    }

    /// Decrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of 16; nothing is changed
    /// otherwise.
    pub fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::NotBlockAligned(data.len()));
        }
        match self.size {
            KeySize::Aes128 => decrypt_many::<10>(&self.keys, data),
            KeySize::Aes192 => decrypt_many::<12>(&self.keys, data),
            KeySize::Aes256 => decrypt_many::<14>(&self.keys, data),
        }
        Ok(())
    }
}

impl BlockCipher for Aes {
    const BLOCK_SIZE: usize = BLOCK_SIZE;

    fn try_new(key: &[u8]) -> Result<Self, Error> {
        Aes::try_new(key)
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        Aes::encrypt_blocks(self, data)
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        Aes::decrypt_blocks(self, data)
    }
}

/// `SubWord` for the key schedule, through the bitsliced S-box.
pub(crate) fn sub_word(w: u32) -> u32 {
    let mut group = [0u8; GROUP];
    group[..4].copy_from_slice(&w.to_le_bytes());
    let mut q = pack(&group);
    sbox(&mut q);
    unpack(&q, &mut group);
    u32::from_le_bytes([group[0], group[1], group[2], group[3]])
}

/// Encrypts a whole number of blocks, four at a time; a short final
/// group runs with its unused lanes zero.
fn encrypt_many<const R: usize>(
    keys: &[State; MAX_ROUND_KEYS],
    data: &mut [u8],
) {
    for group in data.chunks_mut(GROUP) {
        let mut q = pack(group);
        encrypt_state::<R>(keys, &mut q);
        unpack(&q, group);
    }
}

/// Decrypts a whole number of blocks; see [`encrypt_many`].
fn decrypt_many<const R: usize>(
    keys: &[State; MAX_ROUND_KEYS],
    data: &mut [u8],
) {
    for group in data.chunks_mut(GROUP) {
        let mut q = pack(group);
        decrypt_state::<R>(keys, &mut q);
        unpack(&q, group);
    }
}

#[inline(always)]
fn encrypt_state<const R: usize>(
    keys: &[State; MAX_ROUND_KEYS],
    q: &mut State,
) {
    add_round_key(q, &keys[0]);
    for k in &keys[1..R] {
        sbox(q);
        shift_rows(q);
        mix_columns(q);
        add_round_key(q, k);
    }
    sbox(q);
    shift_rows(q);
    add_round_key(q, &keys[R]);
}

#[inline(always)]
fn decrypt_state<const R: usize>(
    keys: &[State; MAX_ROUND_KEYS],
    q: &mut State,
) {
    add_round_key(q, &keys[R]);
    for k in keys[1..R].iter().rev() {
        inv_shift_rows(q);
        inv_sbox(q);
        add_round_key(q, k);
        inv_mix_columns(q);
    }
    inv_shift_rows(q);
    inv_sbox(q);
    add_round_key(q, &keys[0]);
}

/// Packs up to four blocks (`data.len()` a multiple of 16, at most
/// 64) into bit planes. Missing blocks leave their lanes zero.
fn pack(data: &[u8]) -> State {
    let mut q = [0u64; 8];
    for (b, block) in data.chunks_exact(BLOCK_SIZE).enumerate() {
        let (even, odd) = interleave(block);
        q[b] = even;
        q[LANES + b] = odd;
    }
    transpose(&mut q);
    q
}

/// Inverse of [`pack`]: writes the blocks back into `data`.
fn unpack(q: &State, data: &mut [u8]) {
    let mut q = *q;
    transpose(&mut q);
    for (b, block) in data.chunks_exact_mut(BLOCK_SIZE).enumerate() {
        deinterleave(q[b], q[LANES + b], block);
    }
}

/// Spreads one block into two words: columns 0 and 2 byte-interleaved
/// (row 0 of column 0, row 0 of column 2, row 1 of column 0, ...) and
/// likewise columns 1 and 3. After [`transpose`] this puts each byte
/// at bit `16 * row + 4 * column` of its plane, plus the block lane.
fn interleave(block: &[u8]) -> (u64, u64) {
    let mut w = [0u64; 4];
    for (w, c) in w.iter_mut().zip(block.chunks_exact(4)) {
        *w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64;
    }
    for w in w.iter_mut() {
        *w = (*w | (*w << 16)) & 0x0000_ffff_0000_ffff;
        *w = (*w | (*w << 8)) & 0x00ff_00ff_00ff_00ff;
    }
    (w[0] | (w[2] << 8), w[1] | (w[3] << 8))
}

/// Inverse of [`interleave`].
fn deinterleave(even: u64, odd: u64, block: &mut [u8]) {
    let mut w = [even, odd, even >> 8, odd >> 8];
    for w in w.iter_mut() {
        *w &= 0x00ff_00ff_00ff_00ff;
        *w = (*w | (*w >> 8)) & 0x0000_ffff_0000_ffff;
        *w |= *w >> 16;
    }
    for (c, w) in block.chunks_exact_mut(4).zip(w) {
        c.copy_from_slice(&(w as u32).to_le_bytes());
    }
}

/// Transposes the 8x8 bit matrix formed by the same byte position of
/// all eight words, so word `i` ends up holding bit `i` of every byte.
/// It is its own inverse.
fn transpose(q: &mut State) {
    fn swap(q: &mut State, a: usize, b: usize, mask: u64, shift: u32) {
        let (x, y) = (q[a], q[b]);
        q[a] = (x & mask) | ((y & mask) << shift);
        q[b] = ((x & !mask) >> shift) | (y & !mask);
    }
    for i in [0, 2, 4, 6] {
        swap(q, i, i + 1, 0x5555_5555_5555_5555, 1);
    }
    for i in [0, 1, 4, 5] {
        swap(q, i, i + 2, 0x3333_3333_3333_3333, 2);
    }
    for i in [0, 1, 2, 3] {
        swap(q, i, i + 4, 0x0f0f_0f0f_0f0f_0f0f, 4);
    }
}

#[inline(always)]
fn add_round_key(q: &mut State, k: &State) {
    for (q, k) in q.iter_mut().zip(k) {
        *q ^= k;
    }
}

/// Rotates row `r` right by `r` columns: 4 bits per column inside
/// each 16-bit row group.
#[inline(always)]
fn shift_rows(q: &mut State) {
    for x in q.iter_mut() {
        let v = *x;
        *x = (v & 0x0000_0000_0000_ffff)
            | ((v & 0x0000_0000_fff0_0000) >> 4)
            | ((v & 0x0000_0000_000f_0000) << 12)
            | ((v & 0x0000_ff00_0000_0000) >> 8)
            | ((v & 0x0000_00ff_0000_0000) << 8)
            | ((v & 0xf000_0000_0000_0000) >> 12)
            | ((v & 0x0fff_0000_0000_0000) << 4);
    }
}

#[inline(always)]
fn inv_shift_rows(q: &mut State) {
    for x in q.iter_mut() {
        let v = *x;
        *x = (v & 0x0000_0000_0000_ffff)
            | ((v & 0x0000_0000_0fff_0000) << 4)
            | ((v & 0x0000_0000_f000_0000) >> 12)
            | ((v & 0x0000_00ff_0000_0000) << 8)
            | ((v & 0x0000_ff00_0000_0000) >> 8)
            | ((v & 0x000f_0000_0000_0000) << 12)
            | ((v & 0xfff0_0000_0000_0000) >> 4);
    }
}

/// Multiplies every byte by x in GF(2^8): shift the planes up one and
/// fold the top bit back into planes 0, 1, 3 and 4 (x^8 = x^4 + x^3 +
/// x + 1).
#[inline(always)]
fn xtime(q: &State) -> State {
    [
        q[7],
        q[0] ^ q[7],
        q[1],
        q[2] ^ q[7],
        q[3] ^ q[7],
        q[4],
        q[5],
        q[6],
    ]
}

/// Brings row `r + n` of each column to row `r`.
#[inline(always)]
fn rows_down(q: &State, n: u32) -> State {
    let mut r = *q;
    for r in r.iter_mut() {
        *r = r.rotate_right(16 * n);
    }
    r
}

/// `out = 2a + 3b + c + d` for rows `a, b, c, d` of each column,
/// arranged as `x(a + b) + b + (c + d)`.
#[inline(always)]
fn mix_columns(q: &mut State) {
    let b = rows_down(q, 1);
    let mut ab = *q;
    add_round_key(&mut ab, &b);
    let two_ab = xtime(&ab);
    let cd = rows_down(&ab, 2);
    for i in 0..8 {
        q[i] = two_ab[i] ^ b[i] ^ cd[i];
    }
}

/// `out = 14a + 11b + 13c + 9d`, with the multiples formed once on
/// the unrotated state and then rotated into place.
#[inline(always)]
fn inv_mix_columns(q: &mut State) {
    let q2 = xtime(q);
    let q4 = xtime(&q2);
    let q8 = xtime(&q4);
    let mut a = [0u64; 8];
    let mut b = [0u64; 8];
    let mut c = [0u64; 8];
    let mut d = [0u64; 8];
    for i in 0..8 {
        a[i] = q8[i] ^ q4[i] ^ q2[i];
        b[i] = q8[i] ^ q2[i] ^ q[i];
        c[i] = q8[i] ^ q4[i] ^ q[i];
        d[i] = q8[i] ^ q[i];
    }
    let b = rows_down(&b, 1);
    let c = rows_down(&c, 2);
    let d = rows_down(&d, 3);
    for i in 0..8 {
        q[i] = a[i] ^ b[i] ^ c[i] ^ d[i];
    }
}

/// The AES S-box on bit planes: the circuit of Boyar and Peralta,
/// "A new combinational logic minimization technique with
/// applications to cryptology" (2009). Their `x0` is the high bit and
/// `x7` the low bit, the reverse of the plane numbering.
#[inline(always)]
fn sbox(q: &mut State) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    // Top linear layer.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear middle layer.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear layer.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/// The inverse of the S-box's affine map: xor with 0x63 (planes 0, 1,
/// 5, 6), then bit `i` becomes the xor of bits `i + 2`, `i + 5` and
/// `i + 7`.
#[inline(always)]
fn inv_affine(q: &mut State) {
    let mut a = *q;
    for i in [0, 1, 5, 6] {
        a[i] = !a[i];
    }
    for i in 0..8 {
        q[i] = a[(i + 2) % 8] ^ a[(i + 5) % 8] ^ a[(i + 7) % 8];
    }
}

/// The inverse S-box. With `S = A o inv` (affine map after field
/// inverse) and `inv` its own inverse, `S^-1 = A^-1 o S o A^-1`.
#[inline(always)]
fn inv_sbox(q: &mut State) {
    inv_affine(q);
    sbox(q);
    inv_affine(q);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::portable;
    use crate::symmetric::aes::portable::ttable::tables::{INV_SBOX, SBOX};

    /// Runs `f` on a state holding the 64 bytes of `input` and returns
    /// the resulting bytes.
    fn on_bytes(input: &[u8; GROUP], f: fn(&mut State)) -> [u8; GROUP] {
        let mut q = pack(input);
        f(&mut q);
        let mut out = [0u8; GROUP];
        unpack(&q, &mut out);
        out
    }

    #[test]
    fn pack_round_trips() {
        let mut data = [0u8; GROUP];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 29 + 7) as u8;
        }
        assert_eq!(on_bytes(&data, |_| {}), data);
    }

    #[test]
    fn sbox_matches_table() {
        for base in [0usize, 64, 128, 192] {
            let mut input = [0u8; GROUP];
            for (i, b) in input.iter_mut().enumerate() {
                *b = (base + i) as u8;
            }
            let out = on_bytes(&input, sbox);
            let inv = on_bytes(&input, inv_sbox);
            for (i, &x) in input.iter().enumerate() {
                assert_eq!(out[i], SBOX[x as usize], "sbox {x:#04x}");
                assert_eq!(inv[i], INV_SBOX[x as usize], "inv {x:#04x}");
            }
        }
    }

    #[test]
    fn shift_rows_inverts() {
        let mut data = [0u8; GROUP];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let shifted = on_bytes(&data, shift_rows);
        // Block 0, column 1, row 1 takes column 2, row 1: byte 9.
        assert_eq!(shifted[5], 9);
        // Block 2 (bytes 32..48), column 0, row 3 takes column 3: 47.
        assert_eq!(shifted[32 + 3], 32 + 15);
        assert_eq!(on_bytes(&shifted, inv_shift_rows), data);
    }

    #[test]
    fn mix_columns_inverts_and_matches_fips() {
        // FIPS 197 section 5.1.3 example column.
        let mut data = [0u8; GROUP];
        data[..4].copy_from_slice(&[0xdb, 0x13, 0x53, 0x45]);
        let mixed = on_bytes(&data, mix_columns);
        assert_eq!(&mixed[..4], &[0x8e, 0x4d, 0xa1, 0xbc]);
        assert_eq!(on_bytes(&mixed, inv_mix_columns), data);
    }

    fn unhex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            let hex = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(hex, 16).unwrap();
        }
        out
    }

    fn check(key: &str, plain: &str, cipher: &str) {
        let key = &unhex(key)[..key.len() / 2];
        let plain: [u8; 16] = unhex(plain)[..16].try_into().unwrap();
        let cipher: [u8; 16] = unhex(cipher)[..16].try_into().unwrap();
        let aes = Aes::try_new(key).unwrap();

        let mut block = plain;
        aes.encrypt_block(&mut block);
        assert_eq!(block, cipher, "encrypt");
        aes.decrypt_block(&mut block);
        assert_eq!(block, plain, "decrypt");
    }

    // FIPS 197 Appendix C.
    #[test]
    fn fips197_aes128() {
        check(
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        );
    }

    #[test]
    fn fips197_aes192() {
        check(
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        );
    }

    #[test]
    fn fips197_aes256() {
        check(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        );
    }

    #[test]
    fn matches_portable() {
        const MAX: usize = 10;
        for klen in [16, 24, 32] {
            let mut key = [0u8; 32];
            for (i, k) in key.iter_mut().enumerate() {
                *k = (i * 37 + klen) as u8;
            }
            let bs = Aes::try_new(&key[..klen]).unwrap();
            let tt = portable::Aes::try_new(&key[..klen]).unwrap();
            // Lengths cover zero, partial and whole groups of four.
            for nblocks in 0..MAX {
                let mut data = [0u8; MAX * BLOCK_SIZE];
                for (i, b) in data.iter_mut().enumerate() {
                    *b = (i * 13 + klen) as u8;
                }
                let data = &mut data[..nblocks * BLOCK_SIZE];
                let mut expected = [0u8; MAX * BLOCK_SIZE];
                let expected = &mut expected[..data.len()];
                expected.copy_from_slice(data);
                let mut orig = [0u8; MAX * BLOCK_SIZE];
                orig[..data.len()].copy_from_slice(data);

                tt.encrypt_blocks(expected).unwrap();
                bs.encrypt_blocks(data).unwrap();
                assert_eq!(data, expected, "encrypt {klen} {nblocks}");
                bs.decrypt_blocks(data).unwrap();
                assert_eq!(data, &orig[..data.len()], "decrypt {klen}");
            }
        }
    }

    #[test]
    fn rejects_bad_key_lengths() {
        for n in [0, 1, 15, 17, 23, 25, 31, 33, 64] {
            assert_eq!(
                Aes::try_new(&[0; 64][..n]).unwrap_err(),
                Error::InvalidKeyLength(n)
            );
        }
    }

    #[test]
    fn blocks_reject_partial_block() {
        let aes = Aes::try_new(&[0; 16]).unwrap();
        for n in [1, 15, 17, 31, 33] {
            let mut data = [0x33u8; 33];
            let data = &mut data[..n];
            assert_eq!(
                aes.encrypt_blocks(data).unwrap_err(),
                Error::NotBlockAligned(n)
            );
            assert_eq!(
                aes.decrypt_blocks(data).unwrap_err(),
                Error::NotBlockAligned(n)
            );
            assert!(data.iter().all(|&b| b == 0x33), "data untouched");
        }
    }

    #[test]
    fn round_counts() {
        assert_eq!(Aes::try_new(&[0; 16]).unwrap().rounds(), 10);
        assert_eq!(Aes::try_new(&[0; 24]).unwrap().rounds(), 12);
        assert_eq!(Aes::try_new(&[0; 32]).unwrap().rounds(), 14);
    }
}
