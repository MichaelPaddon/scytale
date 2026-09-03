//! SLH-DSA (FIPS 205), the stateless hash-based signature
//! standardised from SPHINCS+, in its twelve parameter sets.
//!
//! Nothing here rests on a lattice or a curve: a key is a tree of
//! hashes, and a signature is a chain of one-time signatures up the
//! tree together with a few-time signature of the message at a
//! leaf chosen by hashing the message itself. Forging one means
//! finding a preimage or a second preimage in the hash, which is the
//! most conservative assumption cryptography has, and the reason to
//! carry SLH-DSA beside [`ml_dsa`](crate::sig::ml_dsa) despite its
//! size: signatures run from 7.9 to 49.9 kilobytes, and signing the
//! `s` sets takes on the order of a second.
//!
//! The sets are named for their hash family, SHA2 or SHAKE, their
//! security category, 128, 192 or 256, and their trade: `s` for
//! small signatures and slow signing, `f` for fast signing and
//! signatures twice the size. Each is a module of its own,
//! [`sha2_128s`] through [`shake_256f`], with the same two key types
//! and the same calls.
//!
//! Signing is hedged by default, as FIPS 205 prefers: `n` random
//! bytes seed the message digest's randomiser, so a fault leaks
//! nothing; [`sign_deterministic`](shake_128s::PrivateKey::sign_deterministic)
//! uses the public seed instead, for repeatable output where faults
//! can be ruled out. Every signature takes a context string of up to
//! 255 bytes, empty unless a protocol assigns one. This is the pure
//! SLH-DSA of FIPS 205 section 10.2; the pre-hashed variant is not
//! offered.
//!
//! ```
//! use scytale::random::{Rng, System};
//! use scytale::sig::slh_dsa::shake_128f::{PrivateKey, PublicKey};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let key = PrivateKey::generate(&mut rng)?;
//! let signature = key.sign(&mut rng, b"", b"release v1.2")?;
//!
//! let public = PublicKey::try_new(&key.public_key().bytes())?;
//! public.verify(b"", b"release v1.2", &signature)?;
//! assert!(public.verify(b"", b"release v1.3", &signature).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! Every operation is a fixed schedule of hash calls over fixed
//! layouts; the only values that steer control flow are the message
//! digest's indices, which are public, since they can be recomputed
//! from the signature. Secret material reaches the hashes as input
//! and nowhere else.

use zeroize::Zeroize;

use crate::hash::sha2::{Sha256, Sha512};
use crate::hash::sha3::Shake256;
use crate::hash::{Hash, Xof, XofReader};
use crate::mac::hmac::Hmac;
use crate::mac::Mac;
use crate::util;
use crate::Error;

/// The largest `n` of any set, which sizes every node buffer.
const MAX_N: usize = 32;

/// The largest WOTS+ length, `2n + 3` at `n = 32`.
const MAX_LEN: usize = 67;

/// The largest FORS tree count `k`.
const MAX_K: usize = 35;

/// The longest context string.
const CONTEXT_MAX: usize = 255;

/// A parameter set, table 2 of FIPS 205.
struct Params {
    /// The security parameter: the node and seed length in bytes.
    n: usize,
    /// The hypertree height.
    h: usize,
    /// The hypertree layers.
    d: usize,
    /// The height of each layer's tree, `h / d`.
    hp: usize,
    /// The height of each FORS tree.
    a: usize,
    /// The number of FORS trees.
    k: usize,
    /// The message digest length.
    m: usize,
}

impl Params {
    /// The WOTS+ chain count, `len1 + len2` for `w = 16`.
    const fn len(&self) -> usize {
        2 * self.n + 3
    }

    const fn public_len(&self) -> usize {
        2 * self.n
    }

    const fn private_len(&self) -> usize {
        4 * self.n
    }

    const fn signature_len(&self) -> usize {
        (1 + self.k * (1 + self.a) + self.h + self.d * self.len()) * self.n
    }
}

/// The six shapes; each is shared by a SHA2 set and a SHAKE set.
const fn params(
    n: usize,
    h: usize,
    d: usize,
    a: usize,
    k: usize,
    m: usize,
) -> Params {
    Params {
        n,
        h,
        d,
        hp: h / d,
        a,
        k,
        m,
    }
}

const P_128S: Params = params(16, 63, 7, 12, 14, 30);
const P_128F: Params = params(16, 66, 22, 6, 33, 34);
const P_192S: Params = params(24, 63, 7, 14, 17, 39);
const P_192F: Params = params(24, 66, 22, 8, 33, 42);
const P_256S: Params = params(32, 64, 8, 14, 22, 47);
const P_256F: Params = params(32, 68, 17, 9, 35, 49);

// Addresses: the 32-byte structure every tweakable hash takes.

const WOTS_HASH: u32 = 0;
const WOTS_PK: u32 = 1;
const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

/// An `ADRS`: layer, tree, type, and three words whose meaning the
/// type fixes.
#[derive(Clone, Copy)]
struct Adrs([u8; 32]);

impl Adrs {
    const ZERO: Adrs = Adrs([0; 32]);

    fn word(&mut self, index: usize, value: u32) {
        self.0[4 * index..4 * index + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn set_layer(&mut self, layer: u32) {
        self.word(0, layer);
    }

    /// The tree index, whose 96 bits never exceed 64.
    fn set_tree(&mut self, tree: u64) {
        self.word(1, 0);
        self.0[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// Sets the type, the word after the twelve-byte tree address,
    /// and clears the three words after it.
    fn set_type(&mut self, kind: u32) {
        self.word(4, kind);
        self.0[20..].fill(0);
    }

    fn set_key_pair(&mut self, index: u32) {
        self.word(5, index);
    }

    fn key_pair(&self) -> u32 {
        u32::from_be_bytes([self.0[20], self.0[21], self.0[22], self.0[23]])
    }

    /// The chain address for WOTS+, the tree height for trees.
    fn set_chain(&mut self, value: u32) {
        self.word(6, value);
    }

    /// The hash address for WOTS+, the tree index for trees.
    fn set_hash(&mut self, value: u32) {
        self.word(7, value);
    }

    fn hash(&self) -> u32 {
        u32::from_be_bytes([self.0[28], self.0[29], self.0[30], self.0[31]])
    }

    /// The 22-byte compressed form the SHA2 family hashes.
    fn compressed(&self) -> [u8; 22] {
        let mut out = [0u8; 22];
        out[0] = self.0[3];
        out[1..9].copy_from_slice(&self.0[8..16]);
        out[9] = self.0[19];
        out[10..].copy_from_slice(&self.0[20..32]);
        out
    }
}

// The hash families: section 11's instantiations of the six
// functions. Each writes `n` bytes, or `m` for the message digest.

trait Family {
    /// `H_msg`.
    fn h_msg(
        p: &Params,
        r: &[u8],
        pk_seed: &[u8],
        pk_root: &[u8],
        message: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), Error>;

    /// `PRF`.
    fn prf(
        p: &Params,
        pk_seed: &[u8],
        sk_seed: &[u8],
        adrs: &Adrs,
        out: &mut [u8],
    ) -> Result<(), Error>;

    /// `PRF_msg`.
    fn prf_msg(
        p: &Params,
        sk_prf: &[u8],
        opt_rand: &[u8],
        message: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), Error>;

    /// `F`, over one node.
    fn f(
        p: &Params,
        pk_seed: &[u8],
        adrs: &Adrs,
        m1: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error>;

    /// `H` over two nodes and `T_l` over `l`, which are the same
    /// function at different lengths.
    fn t(
        p: &Params,
        pk_seed: &[u8],
        adrs: &Adrs,
        parts: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), Error>;
}

/// The SHAKE family: everything is SHAKE256 over the concatenation.
struct Shake;

fn shake(parts: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    let mut xof = Shake256::try_new()?;
    for part in parts {
        xof.update(part);
    }
    xof.finalize_xof().squeeze(out);
    Ok(())
}

impl Family for Shake {
    fn h_msg(
        _: &Params,
        r: &[u8],
        pk_seed: &[u8],
        pk_root: &[u8],
        message: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut xof = Shake256::try_new()?;
        xof.update(r);
        xof.update(pk_seed);
        xof.update(pk_root);
        for part in message {
            xof.update(part);
        }
        xof.finalize_xof().squeeze(out);
        Ok(())
    }

    fn prf(
        _: &Params,
        pk_seed: &[u8],
        sk_seed: &[u8],
        adrs: &Adrs,
        out: &mut [u8],
    ) -> Result<(), Error> {
        shake(&[pk_seed, &adrs.0, sk_seed], out)
    }

    fn prf_msg(
        _: &Params,
        sk_prf: &[u8],
        opt_rand: &[u8],
        message: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut xof = Shake256::try_new()?;
        xof.update(sk_prf);
        xof.update(opt_rand);
        for part in message {
            xof.update(part);
        }
        xof.finalize_xof().squeeze(out);
        Ok(())
    }

    fn f(
        _: &Params,
        pk_seed: &[u8],
        adrs: &Adrs,
        m1: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        shake(&[pk_seed, &adrs.0, m1], out)
    }

    fn t(
        _: &Params,
        pk_seed: &[u8],
        adrs: &Adrs,
        parts: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut xof = Shake256::try_new()?;
        xof.update(pk_seed);
        xof.update(&adrs.0);
        for part in parts {
            xof.update(part);
        }
        xof.finalize_xof().squeeze(out);
        Ok(())
    }
}

/// The SHA2 family: SHA-256 throughout at category 1, and SHA-512
/// for the message digest and the wider tweakable hashes above it,
/// with the public seed padded to a block so the seed's compression
/// can be shared, and the address compressed to 22 bytes.
struct Sha2;

/// `Trunc_n` of a hash over the parts, the seed padded to `block`.
fn sha2_tweaked<H: Hash>(
    block: usize,
    pk_seed: &[u8],
    adrs: &Adrs,
    parts: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    let mut hash = H::try_new()?;
    hash.update(pk_seed);
    hash.update(&[0u8; 128][..block - pk_seed.len()]);
    hash.update(&adrs.compressed());
    for part in parts {
        hash.update(part);
    }
    let digest = hash.finalize();
    out.copy_from_slice(&digest.as_ref()[..out.len()]);
    Ok(())
}

/// MGF1 over `seed`, `out.len()` bytes.
fn mgf1<H: Hash>(seed: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    let size = <H::Output as crate::cipher::Block>::SIZE;
    for (counter, chunk) in out.chunks_mut(size).enumerate() {
        let mut hash = H::try_new()?;
        for part in seed {
            hash.update(part);
        }
        hash.update(&(counter as u32).to_be_bytes());
        let digest = hash.finalize();
        chunk.copy_from_slice(&digest.as_ref()[..chunk.len()]);
    }
    Ok(())
}

/// `H_msg` for the SHA2 family with hash `H`: MGF1 over the
/// randomiser, the seed and a digest of everything.
fn sha2_h_msg<H: Hash>(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    message: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    let mut hash = H::try_new()?;
    hash.update(r);
    hash.update(pk_seed);
    hash.update(pk_root);
    for part in message {
        hash.update(part);
    }
    let digest = hash.finalize();
    mgf1::<H>(&[r, pk_seed, digest.as_ref()], out)
}

/// `PRF_msg` for the SHA2 family: truncated HMAC.
fn sha2_prf_msg<H: Hash>(
    sk_prf: &[u8],
    opt_rand: &[u8],
    message: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    let mut mac = Hmac::<H>::try_new(sk_prf)?;
    mac.update(opt_rand);
    for part in message {
        mac.update(part);
    }
    let tag = mac.finalize();
    out.copy_from_slice(&tag.as_ref()[..out.len()]);
    Ok(())
}

impl Family for Sha2 {
    fn h_msg(
        p: &Params,
        r: &[u8],
        pk_seed: &[u8],
        pk_root: &[u8],
        message: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), Error> {
        if p.n == 16 {
            sha2_h_msg::<Sha256>(r, pk_seed, pk_root, message, out)
        } else {
            sha2_h_msg::<Sha512>(r, pk_seed, pk_root, message, out)
        }
    }

    fn prf(
        _: &Params,
        pk_seed: &[u8],
        sk_seed: &[u8],
        adrs: &Adrs,
        out: &mut [u8],
    ) -> Result<(), Error> {
        sha2_tweaked::<Sha256>(64, pk_seed, adrs, &[sk_seed], out)
    }

    fn prf_msg(
        p: &Params,
        sk_prf: &[u8],
        opt_rand: &[u8],
        message: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), Error> {
        if p.n == 16 {
            sha2_prf_msg::<Sha256>(sk_prf, opt_rand, message, out)
        } else {
            sha2_prf_msg::<Sha512>(sk_prf, opt_rand, message, out)
        }
    }

    fn f(
        _: &Params,
        pk_seed: &[u8],
        adrs: &Adrs,
        m1: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        sha2_tweaked::<Sha256>(64, pk_seed, adrs, &[m1], out)
    }

    fn t(
        p: &Params,
        pk_seed: &[u8],
        adrs: &Adrs,
        parts: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), Error> {
        if p.n == 16 {
            sha2_tweaked::<Sha256>(64, pk_seed, adrs, parts, out)
        } else {
            sha2_tweaked::<Sha512>(128, pk_seed, adrs, parts, out)
        }
    }
}

// The scheme, section 4 through 9.

/// A node or seed of up to `MAX_N` bytes; the parameter set says how
/// many are meaningful.
type Node = [u8; MAX_N];

/// `base_2b`: the first `out.len()` values of `b` bits from `x`.
fn base_2b(x: &[u8], b: usize, out: &mut [u32]) {
    let mut acc = 0u64;
    let mut bits = 0;
    let mut pos = 0;
    for o in out.iter_mut() {
        while bits < b {
            acc = (acc << 8) | u64::from(x[pos]);
            pos += 1;
            bits += 8;
        }
        bits -= b;
        *o = ((acc >> bits) & ((1 << b) - 1)) as u32;
    }
}

/// The public seed and the parameters, which every step needs.
struct Ctx<'a, F: Family> {
    p: &'a Params,
    pk_seed: &'a [u8],
    family: core::marker::PhantomData<F>,
}

impl<F: Family> Ctx<'_, F> {
    fn n(&self) -> usize {
        self.p.n
    }

    /// `chain`: `F` applied `steps` times from index `start`.
    fn chain(
        &self,
        x: &[u8],
        start: u32,
        steps: u32,
        adrs: &mut Adrs,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let n = self.n();
        let mut tmp = Node::default();
        tmp[..n].copy_from_slice(x);
        for j in start..start + steps {
            adrs.set_hash(j);
            let mut next = Node::default();
            F::f(self.p, self.pk_seed, adrs, &tmp[..n], &mut next[..n])?;
            tmp = next;
        }
        out.copy_from_slice(&tmp[..n]);
        Ok(())
    }

    /// The WOTS+ secret for chain `i` of the key pair `adrs` names.
    fn wots_secret(
        &self,
        sk_seed: &[u8],
        adrs: &Adrs,
        i: u32,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut sk_adrs = *adrs;
        sk_adrs.set_type(WOTS_PRF);
        sk_adrs.set_key_pair(adrs.key_pair());
        sk_adrs.set_chain(i);
        F::prf(self.p, self.pk_seed, sk_seed, &sk_adrs, out)
    }

    /// The message's WOTS+ digits with their checksum, `len` of them.
    fn wots_digits(&self, message: &[u8]) -> [u32; MAX_LEN] {
        let p = self.p;
        let mut digits = [0u32; MAX_LEN];
        let len1 = 2 * p.n;
        base_2b(message, 4, &mut digits[..len1]);
        let csum: u32 = digits[..len1].iter().map(|d| 15 - d).sum();
        // Three checksum digits are twelve bits, left-aligned in two
        // bytes.
        let csum_bytes = (csum << 4).to_be_bytes();
        base_2b(&csum_bytes[2..], 4, &mut digits[len1..len1 + 3]);
        digits
    }

    /// `wots_pkGen`.
    fn wots_pk(
        &self,
        sk_seed: &[u8],
        adrs: &mut Adrs,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let n = self.n();
        let mut tmp = [Node::default(); MAX_LEN];
        for (i, node) in tmp[..self.p.len()].iter_mut().enumerate() {
            let mut sk = Node::default();
            self.wots_secret(sk_seed, adrs, i as u32, &mut sk[..n])?;
            adrs.set_chain(i as u32);
            self.chain(&sk[..n], 0, 15, adrs, &mut node[..n])?;
            sk.zeroize();
        }
        let mut pk_adrs = *adrs;
        pk_adrs.set_type(WOTS_PK);
        pk_adrs.set_key_pair(adrs.key_pair());
        self.t_nodes(&pk_adrs, &tmp[..self.p.len()], out)
    }

    /// `T_l` over `l` nodes.
    fn t_nodes(
        &self,
        adrs: &Adrs,
        nodes: &[Node],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let n = self.n();
        let mut parts = [&[][..]; MAX_LEN];
        for (part, node) in parts.iter_mut().zip(nodes) {
            *part = &node[..n];
        }
        F::t(self.p, self.pk_seed, adrs, &parts[..nodes.len()], out)
    }

    /// `wots_sign`, `len` nodes into `sig`.
    fn wots_sign(
        &self,
        message: &[u8],
        sk_seed: &[u8],
        adrs: &mut Adrs,
        sig: &mut [u8],
    ) -> Result<(), Error> {
        let n = self.n();
        let digits = self.wots_digits(message);
        for i in 0..self.p.len() {
            let mut sk = Node::default();
            self.wots_secret(sk_seed, adrs, i as u32, &mut sk[..n])?;
            adrs.set_chain(i as u32);
            self.chain(
                &sk[..n],
                0,
                digits[i],
                adrs,
                &mut sig[n * i..n * (i + 1)],
            )?;
            sk.zeroize();
        }
        Ok(())
    }

    /// `wots_pkFromSig`.
    fn wots_pk_from_sig(
        &self,
        sig: &[u8],
        message: &[u8],
        adrs: &mut Adrs,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let n = self.n();
        let digits = self.wots_digits(message);
        let mut tmp = [Node::default(); MAX_LEN];
        for i in 0..self.p.len() {
            adrs.set_chain(i as u32);
            let mut node = Node::default();
            self.chain(
                &sig[n * i..n * (i + 1)],
                digits[i],
                15 - digits[i],
                adrs,
                &mut node[..n],
            )?;
            tmp[i] = node;
        }
        let mut pk_adrs = *adrs;
        pk_adrs.set_type(WOTS_PK);
        pk_adrs.set_key_pair(adrs.key_pair());
        self.t_nodes(&pk_adrs, &tmp[..self.p.len()], out)
    }

    /// `xmss_node`: the node at height `z`, index `i`, of the tree
    /// `adrs` names, by recursion down to the WOTS+ public keys.
    fn xmss_node(
        &self,
        sk_seed: &[u8],
        i: u32,
        z: u32,
        adrs: &mut Adrs,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let n = self.n();
        if z == 0 {
            adrs.set_type(WOTS_HASH);
            adrs.set_key_pair(i);
            return self.wots_pk(sk_seed, adrs, out);
        }
        let mut left = Node::default();
        let mut right = Node::default();
        self.xmss_node(sk_seed, 2 * i, z - 1, adrs, &mut left[..n])?;
        self.xmss_node(sk_seed, 2 * i + 1, z - 1, adrs, &mut right[..n])?;
        adrs.set_type(TREE);
        adrs.set_chain(z);
        adrs.set_hash(i);
        F::t(self.p, self.pk_seed, adrs, &[&left[..n], &right[..n]], out)
    }

    /// `xmss_sign`: the WOTS+ signature and the authentication path,
    /// `(len + h') n` bytes.
    fn xmss_sign(
        &self,
        message: &[u8],
        sk_seed: &[u8],
        idx: u32,
        adrs: &mut Adrs,
        sig: &mut [u8],
    ) -> Result<(), Error> {
        let n = self.n();
        let len = self.p.len();
        for j in 0..self.p.hp {
            let k = (idx >> j) ^ 1;
            let auth = &mut sig[n * (len + j)..n * (len + j + 1)];
            self.xmss_node(sk_seed, k, j as u32, adrs, auth)?;
        }
        adrs.set_type(WOTS_HASH);
        adrs.set_key_pair(idx);
        self.wots_sign(message, sk_seed, adrs, &mut sig[..n * len])
    }

    /// `xmss_pkFromSig`: the root the signature implies.
    fn xmss_pk_from_sig(
        &self,
        idx: u32,
        sig: &[u8],
        message: &[u8],
        adrs: &mut Adrs,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let n = self.n();
        let len = self.p.len();
        adrs.set_type(WOTS_HASH);
        adrs.set_key_pair(idx);
        let mut node = Node::default();
        self.wots_pk_from_sig(&sig[..n * len], message, adrs, &mut node[..n])?;
        adrs.set_type(TREE);
        adrs.set_hash(idx);
        for k in 0..self.p.hp {
            let auth = &sig[n * (len + k)..n * (len + k + 1)];
            adrs.set_chain(k as u32 + 1);
            let mut next = Node::default();
            if (idx >> k) & 1 == 0 {
                adrs.set_hash(adrs.hash() / 2);
                F::t(
                    self.p,
                    self.pk_seed,
                    adrs,
                    &[&node[..n], auth],
                    &mut next[..n],
                )?;
            } else {
                adrs.set_hash((adrs.hash() - 1) / 2);
                F::t(
                    self.p,
                    self.pk_seed,
                    adrs,
                    &[auth, &node[..n]],
                    &mut next[..n],
                )?;
            }
            node = next;
        }
        out.copy_from_slice(&node[..n]);
        Ok(())
    }

    /// `ht_sign`: one XMSS signature per layer, `d (len + h') n`
    /// bytes.
    fn ht_sign(
        &self,
        message: &[u8],
        sk_seed: &[u8],
        mut idx_tree: u64,
        mut idx_leaf: u32,
        sig: &mut [u8],
    ) -> Result<(), Error> {
        let p = self.p;
        let n = p.n;
        let layer_len = n * (p.len() + p.hp);
        let mut adrs = Adrs::ZERO;
        adrs.set_tree(idx_tree);
        let mut root = Node::default();
        root[..n].copy_from_slice(message);
        for j in 0..p.d {
            adrs.set_layer(j as u32);
            adrs.set_tree(idx_tree);
            let layer = &mut sig[layer_len * j..layer_len * (j + 1)];
            let mut next = Node::default();
            self.xmss_sign(&root[..n], sk_seed, idx_leaf, &mut adrs, layer)?;
            self.xmss_pk_from_sig(
                idx_leaf,
                layer,
                &root[..n],
                &mut adrs,
                &mut next[..n],
            )?;
            root = next;
            idx_leaf = (idx_tree & ((1 << p.hp) - 1)) as u32;
            idx_tree >>= p.hp;
        }
        Ok(())
    }

    /// `ht_verify`: whether the layers lead from `message` to
    /// `pk_root`.
    fn ht_verify(
        &self,
        message: &[u8],
        sig: &[u8],
        mut idx_tree: u64,
        mut idx_leaf: u32,
        pk_root: &[u8],
    ) -> Result<bool, Error> {
        let p = self.p;
        let n = p.n;
        let layer_len = n * (p.len() + p.hp);
        let mut adrs = Adrs::ZERO;
        let mut node = Node::default();
        node[..n].copy_from_slice(message);
        for j in 0..p.d {
            adrs.set_layer(j as u32);
            adrs.set_tree(idx_tree);
            let layer = &sig[layer_len * j..layer_len * (j + 1)];
            let mut next = Node::default();
            self.xmss_pk_from_sig(
                idx_leaf,
                layer,
                &node[..n],
                &mut adrs,
                &mut next[..n],
            )?;
            node = next;
            idx_leaf = (idx_tree & ((1 << p.hp) - 1)) as u32;
            idx_tree >>= p.hp;
        }
        Ok(util::equal(&node[..n], pk_root))
    }

    /// `fors_skGen`: the secret at leaf `idx` of the FORS instance
    /// `adrs` names.
    fn fors_secret(
        &self,
        sk_seed: &[u8],
        adrs: &Adrs,
        idx: u32,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut sk_adrs = *adrs;
        sk_adrs.set_type(FORS_PRF);
        sk_adrs.set_key_pair(adrs.key_pair());
        sk_adrs.set_hash(idx);
        F::prf(self.p, self.pk_seed, sk_seed, &sk_adrs, out)
    }

    /// `fors_node`.
    fn fors_node(
        &self,
        sk_seed: &[u8],
        i: u32,
        z: u32,
        adrs: &mut Adrs,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let n = self.n();
        if z == 0 {
            let mut sk = Node::default();
            self.fors_secret(sk_seed, adrs, i, &mut sk[..n])?;
            adrs.set_chain(0);
            adrs.set_hash(i);
            let result = F::f(self.p, self.pk_seed, adrs, &sk[..n], out);
            sk.zeroize();
            return result;
        }
        let mut left = Node::default();
        let mut right = Node::default();
        self.fors_node(sk_seed, 2 * i, z - 1, adrs, &mut left[..n])?;
        self.fors_node(sk_seed, 2 * i + 1, z - 1, adrs, &mut right[..n])?;
        adrs.set_chain(z);
        adrs.set_hash(i);
        F::t(self.p, self.pk_seed, adrs, &[&left[..n], &right[..n]], out)
    }

    /// `fors_sign`: for each of the `k` trees, the leaf secret and
    /// its authentication path, `k (1 + a) n` bytes.
    fn fors_sign(
        &self,
        md: &[u8],
        sk_seed: &[u8],
        adrs: &mut Adrs,
        sig: &mut [u8],
    ) -> Result<(), Error> {
        let p = self.p;
        let n = p.n;
        let mut indices = [0u32; MAX_K];
        base_2b(md, p.a, &mut indices[..p.k]);
        for i in 0..p.k {
            let tree = &mut sig[n * (1 + p.a) * i..n * (1 + p.a) * (i + 1)];
            let leaf = (i << p.a) as u32 + indices[i];
            self.fors_secret(sk_seed, adrs, leaf, &mut tree[..n])?;
            for j in 0..p.a {
                let s = (indices[i] >> j) ^ 1;
                let node = ((i << (p.a - j)) as u32) + s;
                let auth = &mut tree[n * (1 + j)..n * (2 + j)];
                self.fors_node(sk_seed, node, j as u32, adrs, auth)?;
            }
        }
        Ok(())
    }

    /// `fors_pkFromSig`.
    fn fors_pk_from_sig(
        &self,
        sig: &[u8],
        md: &[u8],
        adrs: &mut Adrs,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let p = self.p;
        let n = p.n;
        let mut indices = [0u32; MAX_K];
        base_2b(md, p.a, &mut indices[..p.k]);
        let mut roots = [Node::default(); MAX_K];
        for i in 0..p.k {
            let tree = &sig[n * (1 + p.a) * i..n * (1 + p.a) * (i + 1)];
            adrs.set_chain(0);
            adrs.set_hash((i << p.a) as u32 + indices[i]);
            let mut node = Node::default();
            F::f(p, self.pk_seed, adrs, &tree[..n], &mut node[..n])?;
            for j in 0..p.a {
                let auth = &tree[n * (1 + j)..n * (2 + j)];
                adrs.set_chain(j as u32 + 1);
                let mut next = Node::default();
                if (indices[i] >> j) & 1 == 0 {
                    adrs.set_hash(adrs.hash() / 2);
                    F::t(
                        p,
                        self.pk_seed,
                        adrs,
                        &[&node[..n], auth],
                        &mut next[..n],
                    )?;
                } else {
                    adrs.set_hash((adrs.hash() - 1) / 2);
                    F::t(
                        p,
                        self.pk_seed,
                        adrs,
                        &[auth, &node[..n]],
                        &mut next[..n],
                    )?;
                }
                node = next;
            }
            roots[i] = node;
        }
        let mut pk_adrs = *adrs;
        pk_adrs.set_type(FORS_ROOTS);
        pk_adrs.set_key_pair(adrs.key_pair());
        self.t_nodes(&pk_adrs, &roots[..p.k], out)
    }
}

/// `slh_keygen_internal`: the public root from the three seeds; the
/// private key is `sk_seed || sk_prf || pk_seed || pk_root` and the
/// public key `pk_seed || pk_root`.
fn key_gen<F: Family>(
    p: &Params,
    seeds: &[u8],
    sk: &mut [u8],
) -> Result<(), Error> {
    let n = p.n;
    debug_assert_eq!(seeds.len(), 3 * n);
    debug_assert_eq!(sk.len(), 4 * n);
    sk[..3 * n].copy_from_slice(seeds);
    let (secret, root) = sk.split_at_mut(3 * n);
    let ctx = Ctx::<F> {
        p,
        pk_seed: &secret[2 * n..],
        family: core::marker::PhantomData,
    };
    let mut adrs = Adrs::ZERO;
    adrs.set_layer(p.d as u32 - 1);
    ctx.xmss_node(&secret[..n], 0, p.hp as u32, &mut adrs, root)
}

/// The digest's three parts: `md`, the tree index and the leaf index.
fn split_digest(p: &Params, digest: &[u8]) -> (usize, u64, u32) {
    let md_len = (p.k * p.a).div_ceil(8);
    let tree_len = (p.h - p.hp).div_ceil(8);
    let leaf_len = p.hp.div_ceil(8);
    let mut tree = 0u64;
    for &b in &digest[md_len..md_len + tree_len] {
        tree = (tree << 8) | u64::from(b);
    }
    let tree_bits = p.h - p.hp;
    if tree_bits < 64 {
        tree &= (1 << tree_bits) - 1;
    }
    let mut leaf = 0u32;
    for &b in &digest[md_len + tree_len..md_len + tree_len + leaf_len] {
        leaf = (leaf << 8) | u32::from(b);
    }
    leaf &= (1 << p.hp) - 1;
    (md_len, tree, leaf)
}

/// `slh_sign_internal`, over the formatted message, with `opt_rand`
/// the hedging bytes or the public seed.
fn sign<F: Family>(
    p: &Params,
    sk: &[u8],
    message: &[&[u8]],
    opt_rand: &[u8],
    sig: &mut [u8],
) -> Result<(), Error> {
    let n = p.n;
    let (sk_seed, sk_prf, pk_seed, pk_root) =
        (&sk[..n], &sk[n..2 * n], &sk[2 * n..3 * n], &sk[3 * n..]);
    let ctx = Ctx::<F> {
        p,
        pk_seed,
        family: core::marker::PhantomData,
    };
    let (r, rest) = sig.split_at_mut(n);
    F::prf_msg(p, sk_prf, opt_rand, message, r)?;
    let mut digest = [0u8; 49];
    F::h_msg(p, r, pk_seed, pk_root, message, &mut digest[..p.m])?;
    let (md_len, idx_tree, idx_leaf) = split_digest(p, &digest[..p.m]);
    let md = &digest[..md_len];

    let mut adrs = Adrs::ZERO;
    adrs.set_tree(idx_tree);
    adrs.set_type(FORS_TREE);
    adrs.set_key_pair(idx_leaf);
    let fors_len = n * p.k * (1 + p.a);
    let (sig_fors, sig_ht) = rest.split_at_mut(fors_len);
    ctx.fors_sign(md, sk_seed, &mut adrs, sig_fors)?;
    let mut pk_fors = Node::default();
    ctx.fors_pk_from_sig(sig_fors, md, &mut adrs, &mut pk_fors[..n])?;
    ctx.ht_sign(&pk_fors[..n], sk_seed, idx_tree, idx_leaf, sig_ht)
}

/// `slh_verify_internal`.
fn verify<F: Family>(
    p: &Params,
    pk: &[u8],
    message: &[&[u8]],
    sig: &[u8],
) -> Result<(), Error> {
    let n = p.n;
    let (pk_seed, pk_root) = pk.split_at(n);
    let ctx = Ctx::<F> {
        p,
        pk_seed,
        family: core::marker::PhantomData,
    };
    let r = &sig[..n];
    let mut digest = [0u8; 49];
    F::h_msg(p, r, pk_seed, pk_root, message, &mut digest[..p.m])?;
    let (md_len, idx_tree, idx_leaf) = split_digest(p, &digest[..p.m]);
    let md = &digest[..md_len];

    let mut adrs = Adrs::ZERO;
    adrs.set_tree(idx_tree);
    adrs.set_type(FORS_TREE);
    adrs.set_key_pair(idx_leaf);
    let fors_len = n * p.k * (1 + p.a);
    let sig_fors = &sig[n..n + fors_len];
    let sig_ht = &sig[n + fors_len..];
    let mut pk_fors = Node::default();
    ctx.fors_pk_from_sig(sig_fors, md, &mut adrs, &mut pk_fors[..n])?;
    if ctx.ht_verify(&pk_fors[..n], sig_ht, idx_tree, idx_leaf, pk_root)? {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// The message as the pure interface formats it, or
/// [`Error::InvalidLength`] for a context too long.
fn format_message<'a>(
    context: &'a [u8],
    message: &'a [u8],
    prefix: &'a mut [u8; 2],
) -> Result<[&'a [u8]; 3], Error> {
    if context.len() > CONTEXT_MAX {
        return Err(Error::InvalidLength(context.len()));
    }
    prefix[1] = context.len() as u8;
    Ok([&prefix[..], context, message])
}

/// The OID prefix of the twelve parameter sets,
/// 2.16.840.1.101.3.4.3; the last arc runs from 20 to 31.
const OID_PREFIX: [u8; 8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];

/// Room for any encoding of any key here.
const SCRATCH: usize = 512;

const PRIVATE_LABEL: &str = "PRIVATE KEY";
const PUBLIC_LABEL: &str = "PUBLIC KEY";

/// One parameter set's public types.
macro_rules! parameter_set {
    ($params:expr, $family:ty, $arc:literal, $name:literal) => {
        use zeroize::Zeroize;

        use crate::random::Random;
        use crate::sig::slh_dsa::{self, Params};
        use crate::Error;

        const P: &Params = &$params;

        /// The length of a private key: two secret seeds, then the
        /// public key.
        pub const KEY_SIZE: usize = P.private_len();

        /// The length of a public key: the public seed and the root.
        pub const PUBLIC_KEY_SIZE: usize = P.public_len();

        /// The length of a signature.
        pub const SIGNATURE_SIZE: usize = P.signature_len();

        /// The longest context string a signature takes.
        pub const CONTEXT_MAX: usize = 255;

        const OID: [u8; 9] = {
            let mut oid = [0u8; 9];
            let mut i = 0;
            while i < 8 {
                oid[i] = slh_dsa::OID_PREFIX[i];
                i += 1;
            }
            oid[8] = $arc;
            oid
        };

        #[doc = concat!("An ", $name, " signing key; wiped on drop.")]
        pub struct PrivateKey {
            bytes: [u8; KEY_SIZE],
            public: PublicKey,
        }

        #[doc = concat!("An ", $name, " verification key.")]
        #[derive(Clone)]
        pub struct PublicKey {
            bytes: [u8; PUBLIC_KEY_SIZE],
        }

        impl Drop for PrivateKey {
            fn drop(&mut self) {
                self.bytes.zeroize();
            }
        }

        impl PrivateKey {
            fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
                let mut public = [0u8; PUBLIC_KEY_SIZE];
                public.copy_from_slice(&bytes[KEY_SIZE - PUBLIC_KEY_SIZE..]);
                PrivateKey {
                    bytes,
                    public: PublicKey { bytes: public },
                }
            }

            /// A fresh key from three random seeds, `3n` bytes, with
            /// the public root computed from them, which costs about
            /// as much as a signature.
            pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
                let mut seeds = [0u8; 3 * P.n];
                rng.fill(&mut seeds)?;
                let mut bytes = [0u8; KEY_SIZE];
                let result = slh_dsa::key_gen::<$family>(P, &seeds, &mut bytes);
                seeds.zeroize();
                result?;
                Ok(Self::from_bytes(bytes))
            }

            /// A key from its bytes, `SK.seed || SK.prf || PK.seed ||
            /// PK.root`. FIPS 205 has no check to make on them, and
            /// recomputing the root would cost a signature's worth of
            /// hashing, so they are taken as given: a wrong root makes
            /// signatures that do not verify, and nothing worse.
            pub fn try_new(bytes: &[u8; KEY_SIZE]) -> Result<Self, Error> {
                Ok(Self::from_bytes(*bytes))
            }

            /// The key's bytes. The caller holds a secret now, and
            /// should wipe it when done.
            pub fn key_bytes(&self) -> [u8; KEY_SIZE] {
                self.bytes
            }

            /// The public half.
            pub fn public_key(&self) -> &PublicKey {
                &self.public
            }

            /// Signs `message` under `context`, hedged with `n` bytes
            /// from `rng`, which is FIPS 205's default. The context is
            /// usually empty; a protocol that assigns one must present
            /// the same one to verify, and one over 255 bytes is
            /// [`Error::InvalidLength`].
            pub fn sign<R: Random>(
                &self,
                rng: &mut R,
                context: &[u8],
                message: &[u8],
            ) -> Result<[u8; SIGNATURE_SIZE], Error> {
                let mut rnd = [0u8; P.n];
                rng.fill(&mut rnd)?;
                let signature = self.sign_with(context, message, &rnd);
                rnd.zeroize();
                signature
            }

            /// Signs with the public seed in place of the hedging
            /// bytes, so the same key, context and message always
            /// give the same signature. Only for settings that need
            /// repeatable output and can rule out faults.
            pub fn sign_deterministic(
                &self,
                context: &[u8],
                message: &[u8],
            ) -> Result<[u8; SIGNATURE_SIZE], Error> {
                let mut pk_seed = [0u8; P.n];
                pk_seed.copy_from_slice(&self.public.bytes[..P.n]);
                self.sign_with(context, message, &pk_seed)
            }

            fn sign_with(
                &self,
                context: &[u8],
                message: &[u8],
                opt_rand: &[u8],
            ) -> Result<[u8; SIGNATURE_SIZE], Error> {
                let mut prefix = [0u8; 2];
                let m_prime =
                    slh_dsa::format_message(context, message, &mut prefix)?;
                let mut out = [0u8; SIGNATURE_SIZE];
                slh_dsa::sign::<$family>(
                    P,
                    &self.bytes,
                    &m_prime,
                    opt_rand,
                    &mut out,
                )?;
                Ok(out)
            }

            /// A key from its DER PKCS#8 `PrivateKeyInfo`, the form
            /// under `PRIVATE KEY` in a PEM file: the key's bytes as an
            /// OCTET STRING under this parameter set's OID. Another set,
            /// or anything else wrong with the bytes, is
            /// [`Error::InvalidEncoding`].
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                let info = crate::der::read_pkcs8(der)?;
                let algorithm = &info.algorithm;
                if algorithm.oid != OID || !algorithm.params.is_empty() {
                    return Err(Error::InvalidEncoding);
                }
                let mut inner = crate::der::Reader::new(info.private_key);
                let bytes = inner.octet_string()?;
                inner.end()?;
                let bytes: &[u8; KEY_SIZE] =
                    bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
                Self::try_new(bytes)
            }

            /// Writes the key as a `PrivateKeyInfo` into the front of
            /// `out`, returning the length. A secret, to be wiped.
            pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                crate::der::write_pkcs8(out, &OID, false, |w| {
                    w.octet_string(&self.bytes)
                })
            }

            /// A key from a `PRIVATE KEY` PEM block (RFC 7468) around
            /// the DER above; whitespace and line ends are read
            /// leniently, and anything else that is not exactly one
            /// well-formed block is [`Error::InvalidEncoding`].
            pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
                let mut der = [0u8; slh_dsa::SCRATCH];
                let labels = [slh_dsa::PRIVATE_LABEL];
                let result = crate::pem::decode(&labels, pem, &mut der)
                    .and_then(|(_, n)| Self::try_from_der(&der[..n]));
                der.zeroize();
                result
            }

            /// Writes the key as a `PRIVATE KEY` PEM block, ASCII with
            /// LF line ends, into the front of `out`, returning the
            /// length. A secret, to be wiped.
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let mut der = [0u8; slh_dsa::SCRATCH];
                let label = slh_dsa::PRIVATE_LABEL;
                let result = self
                    .der_bytes(&mut der)
                    .and_then(|n| crate::pem::write(label, &der[..n], out));
                der.zeroize();
                result
            }
        }

        impl PublicKey {
            /// A public key from its bytes, `PK.seed || PK.root`. Any
            /// bytes of the length are a key.
            pub fn try_new(
                bytes: &[u8; PUBLIC_KEY_SIZE],
            ) -> Result<Self, Error> {
                Ok(PublicKey { bytes: *bytes })
            }

            /// The key's bytes.
            pub fn bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
                self.bytes
            }

            /// Checks that `signature` signs `message` under
            /// `context`. [`Error::InvalidSignature`] for anything
            /// that does not, which deliberately says no more.
            pub fn verify(
                &self,
                context: &[u8],
                message: &[u8],
                signature: &[u8; SIGNATURE_SIZE],
            ) -> Result<(), Error> {
                let mut prefix = [0u8; 2];
                let m_prime =
                    slh_dsa::format_message(context, message, &mut prefix)?;
                slh_dsa::verify::<$family>(P, &self.bytes, &m_prime, signature)
            }

            /// A key from its DER `SubjectPublicKeyInfo`, the form
            /// under `PUBLIC KEY` in a PEM file, which must name this
            /// parameter set.
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                let (algorithm, key) = crate::der::read_spki(der)?;
                if algorithm.oid != OID || !algorithm.params.is_empty() {
                    return Err(Error::InvalidEncoding);
                }
                let key: &[u8; PUBLIC_KEY_SIZE] =
                    key.try_into().map_err(|_| Error::InvalidEncoding)?;
                Self::try_new(key)
            }

            /// Writes the key as a `SubjectPublicKeyInfo` into the
            /// front of `out`, returning the length.
            pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                crate::der::write_spki(out, &OID, false, |w| w.raw(&self.bytes))
            }

            /// A key from a `PUBLIC KEY` PEM block, read as
            /// [`PrivateKey::try_from_pem`] reads its own.
            pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
                let mut der = [0u8; slh_dsa::SCRATCH];
                let labels = [slh_dsa::PUBLIC_LABEL];
                let (_, n) = crate::pem::decode(&labels, pem, &mut der)?;
                Self::try_from_der(&der[..n])
            }

            /// Writes the key as a `PUBLIC KEY` PEM block into the
            /// front of `out`, returning the length.
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let mut der = [0u8; slh_dsa::SCRATCH];
                let n = self.der_bytes(&mut der)?;
                crate::pem::write(slh_dsa::PUBLIC_LABEL, &der[..n], out)
            }
        }
    };
}

/// SLH-DSA-SHA2-128s.
pub mod sha2_128s {
    parameter_set!(slh_dsa::P_128S, slh_dsa::Sha2, 20, "SLH-DSA-SHA2-128s");
}
/// SLH-DSA-SHA2-128f.
pub mod sha2_128f {
    parameter_set!(slh_dsa::P_128F, slh_dsa::Sha2, 21, "SLH-DSA-SHA2-128f");
}
/// SLH-DSA-SHA2-192s.
pub mod sha2_192s {
    parameter_set!(slh_dsa::P_192S, slh_dsa::Sha2, 22, "SLH-DSA-SHA2-192s");
}
/// SLH-DSA-SHA2-192f.
pub mod sha2_192f {
    parameter_set!(slh_dsa::P_192F, slh_dsa::Sha2, 23, "SLH-DSA-SHA2-192f");
}
/// SLH-DSA-SHA2-256s.
pub mod sha2_256s {
    parameter_set!(slh_dsa::P_256S, slh_dsa::Sha2, 24, "SLH-DSA-SHA2-256s");
}
/// SLH-DSA-SHA2-256f.
pub mod sha2_256f {
    parameter_set!(slh_dsa::P_256F, slh_dsa::Sha2, 25, "SLH-DSA-SHA2-256f");
}
/// SLH-DSA-SHAKE-128s.
pub mod shake_128s {
    parameter_set!(slh_dsa::P_128S, slh_dsa::Shake, 26, "SLH-DSA-SHAKE-128s");
}
/// SLH-DSA-SHAKE-128f.
pub mod shake_128f {
    parameter_set!(slh_dsa::P_128F, slh_dsa::Shake, 27, "SLH-DSA-SHAKE-128f");
}
/// SLH-DSA-SHAKE-192s.
pub mod shake_192s {
    parameter_set!(slh_dsa::P_192S, slh_dsa::Shake, 28, "SLH-DSA-SHAKE-192s");
}
/// SLH-DSA-SHAKE-192f.
pub mod shake_192f {
    parameter_set!(slh_dsa::P_192F, slh_dsa::Shake, 29, "SLH-DSA-SHAKE-192f");
}
/// SLH-DSA-SHAKE-256s.
pub mod shake_256s {
    parameter_set!(slh_dsa::P_256S, slh_dsa::Shake, 30, "SLH-DSA-SHAKE-256s");
}
/// SLH-DSA-SHAKE-256f.
pub mod shake_256f {
    parameter_set!(slh_dsa::P_256F, slh_dsa::Shake, 31, "SLH-DSA-SHAKE-256f");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sizes of table 2, from the formula.
    #[test]
    fn sizes() {
        assert_eq!(P_128S.signature_len(), 7856);
        assert_eq!(P_128F.signature_len(), 17088);
        assert_eq!(P_192S.signature_len(), 16224);
        assert_eq!(P_192F.signature_len(), 35664);
        assert_eq!(P_256S.signature_len(), 29792);
        assert_eq!(P_256F.signature_len(), 49856);
        assert_eq!(sha2_128s::KEY_SIZE, 64);
        assert_eq!(shake_256f::PUBLIC_KEY_SIZE, 64);
    }

    #[test]
    fn base_2b_reads_left_to_right() {
        let mut out = [0u32; 4];
        base_2b(&[0xab, 0xcd], 4, &mut out);
        assert_eq!(out, [0xa, 0xb, 0xc, 0xd]);
        let mut out = [0u32; 2];
        base_2b(&[0xab, 0xcd, 0xef], 12, &mut out);
        assert_eq!(out, [0xabc, 0xdef]);
        let mut out = [0u32; 3];
        base_2b(&[0b1011_0110, 0b0100_0000, 0b1111_0000], 6, &mut out);
        assert_eq!(out, [0b101101, 0b100100, 0b000011]);
    }

    /// The fast sets sign and verify in both families, refuse what
    /// they should, and round-trip their formats; the slow sets are
    /// left to the vector suites.
    #[test]
    fn round_trips() {
        macro_rules! check {
            ($module:ident) => {{
                use $module::*;
                let mut rng = crate::random::Rng::try_new(
                    crate::random::System::try_new().unwrap(),
                )
                .unwrap();
                let key = PrivateKey::generate(&mut rng).unwrap();
                let public = key.public_key();
                let sig = key.sign(&mut rng, b"ctx", b"message").unwrap();
                public.verify(b"ctx", b"message", &sig).unwrap();
                assert!(public.verify(b"ctx", b"messagf", &sig).is_err());
                assert!(public.verify(b"", b"message", &sig).is_err());
                let mut bad = sig;
                bad[SIGNATURE_SIZE - 1] ^= 1;
                assert!(public.verify(b"ctx", b"message", &bad).is_err());
                let det = key.sign_deterministic(b"", b"m").unwrap();
                assert_eq!(det, key.sign_deterministic(b"", b"m").unwrap());
                public.verify(b"", b"m", &det).unwrap();
                assert_eq!(
                    key.sign(&mut rng, &[0u8; 256], b"m").err(),
                    Some(Error::InvalidLength(256))
                );
                let again = PrivateKey::try_new(&key.key_bytes()).unwrap();
                assert_eq!(again.public_key().bytes(), public.bytes());

                let mut out = [0u8; 1024];
                let n = key.der_bytes(&mut out).unwrap();
                let back = PrivateKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.key_bytes(), key.key_bytes());
                let n = key.pem_bytes(&mut out).unwrap();
                let back = PrivateKey::try_from_pem(&out[..n]).unwrap();
                assert_eq!(back.key_bytes(), key.key_bytes());
                let n = public.der_bytes(&mut out).unwrap();
                let back = PublicKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.bytes(), public.bytes());
                let n = public.pem_bytes(&mut out).unwrap();
                let back = PublicKey::try_from_pem(&out[..n]).unwrap();
                assert_eq!(back.bytes(), public.bytes());
            }};
        }
        check!(sha2_128f);
        check!(shake_128f);
    }

    #[test]
    fn sets_do_not_mix() {
        let mut rng = crate::random::Rng::try_new(
            crate::random::System::try_new().unwrap(),
        )
        .unwrap();
        let key = shake_128f::PrivateKey::generate(&mut rng).unwrap();
        let mut out = [0u8; 1024];
        let n = key.der_bytes(&mut out).unwrap();
        assert_eq!(
            sha2_128f::PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
        let n = key.public_key().der_bytes(&mut out).unwrap();
        assert_eq!(
            shake_128s::PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
    }
}
