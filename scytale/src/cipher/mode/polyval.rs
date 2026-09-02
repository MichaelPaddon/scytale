//! POLYVAL, the universal hash that GCM-SIV authenticates with.
//!
//! POLYVAL does the same job as [GHASH](super::ghash) but reads its
//! blocks the other way round, which suits machines that are
//! little-endian. RFC 8452 defines it in terms of GHASH, and that is
//! how it is built here: reverse the bytes of each block, hash with
//! GHASH under a converted key, and reverse the result. Reusing the
//! tested multiplication is worth more than the few operations saved
//! by writing the field arithmetic out again.

use super::ghash::{multiply_by_x, Ghash, BLOCK};

/// A POLYVAL computation in progress.
#[derive(Clone)]
pub(crate) struct Polyval {
    inner: Ghash,
    block: [u8; BLOCK],
    used: usize,
}

/// Reverses a block, which is all that separates the two hashes'
/// conventions.
fn reverse(block: &[u8]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    out.copy_from_slice(block);
    out.reverse();
    out
}

impl Polyval {
    /// Starts a hash under subkey `h`, which is one block.
    pub(crate) fn new(h: &[u8]) -> Self {
        debug_assert_eq!(h.len(), BLOCK);
        let mut key = reverse(h);
        multiply_by_x(&mut key);
        Polyval {
            inner: Ghash::new(&key),
            block: [0; BLOCK],
            used: 0,
        }
    }

    /// Adds more of the current field.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        if self.used > 0 {
            let take = data.len().min(BLOCK - self.used);
            self.block[self.used..self.used + take]
                .copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used < BLOCK {
                return;
            }
            let block = self.block;
            self.absorb(&block);
            self.used = 0;
        }
        let mut blocks = data.chunks_exact(BLOCK);
        for block in &mut blocks {
            self.absorb(block);
        }
        let rest = blocks.remainder();
        self.block[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
    }

    /// Ends the current field, padding it with zeros to a block.
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
        reverse(&self.inner.finish())
    }

    fn absorb(&mut self, block: &[u8]) {
        self.inner.update(&reverse(block));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subkey from RFC 8452's worked example, reused throughout
    /// so that a failure here and a failure there are comparable.
    const H: &str = "25629347589242761d31f826ba4b757b";

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(s.len(), 2 * N);
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    /// RFC 8452 section 4, the only place the specification works
    /// POLYVAL on its own rather than through GCM-SIV. It is the one
    /// check here that does not lean on GHASH being right, so it is
    /// what pins the byte order and the subkey conversion.
    #[test]
    fn matches_rfc8452_example() {
        let mut p = Polyval::new(&hex::<16>(H));
        p.update(&hex::<16>("4f4f95668c83dfb6401762bb2d01a262"));
        p.update(&hex::<16>("d1a24ddd2721d006bbe45f20d3c9f362"));
        assert_eq!(p.finish(), hex::<16>("f7a3b47b846119fae5b7866cf5e5b77e"));
    }

    /// Hashing nothing gives zero, and padding an empty field must
    /// not quietly absorb a block of zeros instead.
    #[test]
    fn empty_input_hashes_to_zero() {
        let mut p = Polyval::new(&hex::<16>(H));
        p.pad();
        assert_eq!(p.finish(), [0; BLOCK]);
    }

    /// The buffering is this module's own code rather than GHASH's,
    /// so it has to hold at every length and for pieces that never
    /// line up with a block.
    #[test]
    fn pieces_agree_with_one_call() {
        let h = hex::<16>(H);
        let data: [u8; 5 * BLOCK] = core::array::from_fn(|i| (i * 7 + 3) as u8);

        for len in 0..=data.len() {
            let mut whole = Polyval::new(&h);
            whole.update(&data[..len]);
            whole.pad();
            let want = whole.finish();

            for piece in [1, 3, 7, 16, 17, 31] {
                let mut p = Polyval::new(&h);
                for part in data[..len].chunks(piece) {
                    p.update(part);
                }
                p.pad();
                assert_eq!(
                    p.finish(),
                    want,
                    "{len} bytes in pieces of {piece}"
                );
            }
        }
    }

    /// `pad` ends a field by zero-filling it, which is how GCM-SIV
    /// hashes associated data that is not a whole number of blocks.
    #[test]
    fn pad_zero_fills_the_partial_block() {
        let h = hex::<16>(H);
        let short = [0xa5; 3];
        let mut filled = [0u8; BLOCK];
        filled[..short.len()].copy_from_slice(&short);

        let mut a = Polyval::new(&h);
        a.update(&short);
        a.pad();

        let mut b = Polyval::new(&h);
        b.update(&filled);
        b.pad();

        assert_eq!(a.finish(), b.finish());
    }

    /// A field that already ends on a block boundary has nothing to
    /// pad, so padding it must not add one.
    #[test]
    fn pad_on_a_boundary_does_nothing() {
        let h = hex::<16>(H);
        let data = [0x5a; BLOCK];

        let mut once = Polyval::new(&h);
        once.update(&data);
        let want = once.finish();

        let mut twice = Polyval::new(&h);
        twice.update(&data);
        twice.pad();
        twice.pad();

        assert_eq!(twice.finish(), want);
    }

    /// Two fields hashed one after the other must not depend on how
    /// either was handed over, which is what GCM-SIV relies on when
    /// it hashes associated data and then the plaintext.
    #[test]
    fn fields_are_independent_of_how_they_arrive() {
        let h = hex::<16>(H);
        let aad = [0x11; 20];
        let text = [0x22; 37];

        let mut want = Polyval::new(&h);
        want.update(&aad);
        want.pad();
        want.update(&text);
        want.pad();
        let want = want.finish();

        let mut p = Polyval::new(&h);
        for part in aad.chunks(6) {
            p.update(part);
        }
        p.pad();
        for part in text.chunks(9) {
            p.update(part);
        }
        p.pad();

        assert_eq!(p.finish(), want);
    }
}
