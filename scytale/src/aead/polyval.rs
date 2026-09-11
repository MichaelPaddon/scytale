//! POLYVAL, the universal hash that GCM-SIV authenticates with.
//!
//! POLYVAL does the same job as [GHASH](super::ghash) but reads its
//! blocks the other way round, which suits machines that are
//! little-endian. RFC 8452 defines it in terms of GHASH, and that is
//! how it is built here: reverse the bytes of each block, hash with
//! GHASH under a converted key, and reverse the result. Reusing the
//! tested multiplication is worth more than the few operations saved
//! by writing the field arithmetic out again.

use super::ghash::{BLOCK, Ghash, MAX_GROUP, multiply_by_x};

/// Blocks reversed at a time on the way into GHASH.
///
/// GHASH hashes a whole group of blocks at once only when a single
/// call brings it one; handed a block at a time it waits out the
/// full latency of a multiply for each. Reversing in batches is what
/// lets the blocks arrive in groups. A multiple of the group means
/// every batch is an exact number of them.
const BATCH: usize = 2 * MAX_GROUP;

/// A POLYVAL computation in progress.
#[derive(Clone)]
pub(crate) struct Polyval {
    inner: Inner,
    block: [u8; BLOCK],
    used: usize,
}

/// Where the field arithmetic comes from.
///
/// Where the processor has one, the same loop GCM's hash runs, with
/// the byte reversal left out: the identical field and the identical
/// powers of the subkey, so reversing every block on the way in only
/// to have that loop reverse it back is work for nothing.
///
/// Anywhere else, GHASH over reversed blocks, which is how RFC 8452
/// defines POLYVAL and what the reversal is standing in for.
// The native arm carries the powers of the subkey, which is most of
// the difference; there is no heap to put them on.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum Inner {
    #[cfg(target_arch = "x86_64")]
    Native(super::gcm::x86_64::Polyval),
    Generic(Ghash),
}

/// The shortest field for which the powers of the subkey are worth
/// working out. Named by the tests, and by the arm that has powers.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
///
/// Building them is eight multiplications in the field. Measured on
/// this machine the two arms come out level at about this length, and
/// above it the loop written out pulls away.
const WORTH_IT: usize = 1024;

impl Inner {
    fn new(
        key: &[u8; BLOCK],
        #[cfg_attr(not(target_arch = "x86_64"), allow(unused_variables))]
        bytes: usize,
    ) -> Self {
        #[cfg(target_arch = "x86_64")]
        if let Some(hash) = (bytes >= WORTH_IT)
            .then(|| super::gcm::x86_64::Polyval::new(key))
            .flatten()
        {
            return Inner::Native(hash);
        }
        Inner::Generic(Ghash::new(key))
    }

    /// Adds whole blocks, as they lie.
    fn blocks(&mut self, data: &[u8]) {
        debug_assert_eq!(data.len() % BLOCK, 0);
        match self {
            #[cfg(target_arch = "x86_64")]
            Inner::Native(hash) => hash.hash(data),
            Inner::Generic(ghash) => {
                // Reversed in batches, so that GHASH sees whole
                // groups rather than a block at a time.
                let mut batches = data.chunks_exact(BATCH * BLOCK);
                let mut reversed = [[0u8; BLOCK]; BATCH];
                for batch in &mut batches {
                    reverse_batch(batch, &mut reversed);
                    ghash.update(reversed.as_flattened());
                }
                for block in batches.remainder().chunks_exact(BLOCK) {
                    ghash.update(&reverse(block));
                }
            }
        }
    }

    fn finish(&self) -> [u8; BLOCK] {
        match self {
            #[cfg(target_arch = "x86_64")]
            Inner::Native(hash) => hash.finish(),
            Inner::Generic(ghash) => ghash.finish(),
        }
    }
}

/// Reverses a block, which is all that separates the two hashes'
/// conventions.
fn reverse(block: &[u8]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    out.copy_from_slice(block);
    out.reverse();
    out
}

/// Reverses each block of `src`, which is [`BATCH`] whole blocks,
/// into `dst`.
fn reverse_batch(src: &[u8], dst: &mut [[u8; BLOCK]; BATCH]) {
    debug_assert_eq!(src.len(), BATCH * BLOCK);
    let (blocks, _) = src.as_chunks::<BLOCK>();
    for (block, out) in blocks.iter().zip(dst.iter_mut()) {
        *out = *block;
        out.reverse();
    }
}

impl Polyval {
    /// Starts a hash under subkey `h`, which is one block, over a
    /// field of about `bytes` bytes.
    ///
    /// The length is a hint and nothing more: it decides whether the
    /// powers of the subkey are worth working out, which for a key
    /// used once, as GCM-SIV uses its own, a short message cannot
    /// earn back. A wrong hint costs speed and nothing else.
    pub(crate) fn new(h: &[u8], bytes: usize) -> Self {
        debug_assert_eq!(h.len(), BLOCK);
        let mut key = reverse(h);
        multiply_by_x(&mut key);
        Polyval {
            inner: Inner::new(&key, bytes),
            block: [0; BLOCK],
            used: 0,
        }
    }

    /// The loop written out for this processor, where there is one.
    ///
    /// For a mode that can run the cipher beside the hash: it reaches
    /// the running value and the powers, which this type otherwise
    /// keeps to itself. The key conversion and the reversal of the
    /// result stay here, so a caller cannot forget them.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn native(
        &mut self,
    ) -> Option<&mut super::gcm::x86_64::Polyval> {
        match &mut self.inner {
            Inner::Native(hash) => Some(hash),
            Inner::Generic(_) => None,
        }
    }

    /// The portable construction, whichever processor this is.
    ///
    /// For the tests: where the loop written out is available it is
    /// always taken, so this is the only way to exercise the other
    /// one and keep both validated.
    #[cfg(test)]
    pub(crate) fn generic(h: &[u8]) -> Self {
        debug_assert_eq!(h.len(), BLOCK);
        let mut key = reverse(h);
        multiply_by_x(&mut key);
        Polyval {
            inner: Inner::Generic(Ghash::new(&key)),
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
        let blocks = data.len() / BLOCK * BLOCK;
        self.inner.blocks(&data[..blocks]);
        let rest = &data[blocks..];
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
        self.inner.blocks(block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both arms must agree, at every length around the group
    /// boundaries the loop written out works in and with the pieces
    /// landing anywhere.
    #[test]
    fn both_arms_agree() {
        const MAX: usize = 5 * 16 * BLOCK + 7;
        let h: [u8; BLOCK] = hex(H);
        let mut data = [0u8; MAX];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 13 + 7) as u8;
        }

        for len in 0..MAX {
            let mut want = Polyval::generic(&h);
            want.update(&data[..len]);
            want.pad();
            let want = want.finish();

            let mut got = Polyval::new(&h, WORTH_IT);
            got.update(&data[..len]);
            got.pad();
            assert_eq!(got.finish(), want, "{len} bytes");

            for piece in [1, 17, 128, 512, 513] {
                let mut got = Polyval::new(&h, WORTH_IT);
                for part in data[..len].chunks(piece) {
                    got.update(part);
                }
                got.pad();
                assert_eq!(got.finish(), want, "{len} bytes in {piece}");
            }
        }
    }

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
        let mut p = Polyval::new(&hex::<16>(H), WORTH_IT);
        p.update(&hex::<16>("4f4f95668c83dfb6401762bb2d01a262"));
        p.update(&hex::<16>("d1a24ddd2721d006bbe45f20d3c9f362"));
        assert_eq!(p.finish(), hex::<16>("f7a3b47b846119fae5b7866cf5e5b77e"));
    }

    /// Hashing nothing gives zero, and padding an empty field must
    /// not quietly absorb a block of zeros instead.
    #[test]
    fn empty_input_hashes_to_zero() {
        let mut p = Polyval::new(&hex::<16>(H), WORTH_IT);
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
            let mut whole = Polyval::new(&h, WORTH_IT);
            whole.update(&data[..len]);
            whole.pad();
            let want = whole.finish();

            for piece in [1, 3, 7, 16, 17, 31] {
                let mut p = Polyval::new(&h, WORTH_IT);
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

    /// Blocks are reversed a batch at a time so that GHASH sees
    /// whole groups, which puts a seam at every batch boundary and
    /// another where the last batch gives way to single blocks.
    /// Pieces that straddle those seams must hash the same as one
    /// call over the lot.
    #[test]
    fn batches_agree_with_one_call() {
        let h = hex::<16>(H);
        const LEN: usize = (2 * BATCH + 3) * BLOCK + 5;
        let data: [u8; LEN] = core::array::from_fn(|i| (i * 11 + 1) as u8);

        let mut whole = Polyval::new(&h, WORTH_IT);
        whole.update(&data);
        whole.pad();
        let want = whole.finish();

        // Sizes that land inside a batch, on its boundary and just
        // past it, and one that is a whole batch itself.
        for piece in [BLOCK, BATCH * BLOCK - 1, BATCH * BLOCK, 129] {
            let mut p = Polyval::new(&h, WORTH_IT);
            for part in data.chunks(piece) {
                p.update(part);
            }
            p.pad();
            assert_eq!(p.finish(), want, "pieces of {piece}");
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

        let mut a = Polyval::new(&h, WORTH_IT);
        a.update(&short);
        a.pad();

        let mut b = Polyval::new(&h, WORTH_IT);
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

        let mut once = Polyval::new(&h, WORTH_IT);
        once.update(&data);
        let want = once.finish();

        let mut twice = Polyval::new(&h, WORTH_IT);
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

        let mut want = Polyval::new(&h, WORTH_IT);
        want.update(&aad);
        want.pad();
        want.update(&text);
        want.pad();
        let want = want.finish();

        let mut p = Polyval::new(&h, WORTH_IT);
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
