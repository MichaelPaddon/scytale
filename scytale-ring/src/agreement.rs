//! Ephemeral key agreement: X25519, and ECDH over P-256 and P-384.
//!
//! A private key is used once. [`agree_ephemeral`] consumes it, and
//! hands the shared secret to a closure rather than returning it, so
//! the secret is gone when the closure returns.

use core::fmt;

use scytale::Key;
use scytale::kex::ecdh::{p256, p384};
use scytale::kex::x25519;
use zeroize::Zeroize;

use crate::debug::HexStr;
use crate::{error, rand};

/// Which curve, and what [`Debug`] prints for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Curve {
    Curve25519,
    P256,
    P384,
}

/// A key agreement algorithm. The only values are the `static`s in
/// this module.
pub struct Algorithm {
    curve: Curve,
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Algorithm")
            .field("curve", &self.curve)
            .finish()
    }
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.curve == other.curve
    }
}

impl Eq for Algorithm {}

/// X25519 (RFC 7748).
pub static X25519: Algorithm = Algorithm {
    curve: Curve::Curve25519,
};

/// ECDH over P-256. Public keys are uncompressed points.
pub static ECDH_P256: Algorithm = Algorithm { curve: Curve::P256 };

/// ECDH over P-384. Public keys are uncompressed points.
pub static ECDH_P384: Algorithm = Algorithm { curve: Curve::P384 };

/// How many draws a scalar out of range is redrawn before generation
/// gives up. A draw is out of range with probability about 2^-32 on
/// P-256 and far less on P-384, so this is only ever reached by a
/// source that is broken.
const SCALAR_DRAWS: usize = 100;

enum Private {
    X25519(x25519::PrivateKey),
    P256(p256::PrivateKey),
    P384(p384::PrivateKey),
}

/// A private key for one agreement.
pub struct EphemeralPrivateKey {
    private_key: Private,
    algorithm: &'static Algorithm,
}

impl fmt::Debug for EphemeralPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EphemeralPrivateKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// A scalar drawn from `rng` as big-endian bytes, redrawn while it is
/// out of range. The bytes drawn are the key, so a source that returns
/// fixed bytes gives a known key, as ring's tests rely on.
fn draw<const N: usize, K>(
    rng: &dyn rand::SecureRandom,
    make: impl Fn(&[u8; N]) -> Result<K, scytale::Error>,
) -> Result<K, error::Unspecified> {
    let mut bytes = [0u8; N];
    let mut result = Err(error::Unspecified);
    for _ in 0..SCALAR_DRAWS {
        if let Err(e) = rng.fill(&mut bytes) {
            result = Err(e);
            break;
        }
        if let Ok(key) = make(&bytes) {
            result = Ok(key);
            break;
        }
    }
    bytes.zeroize();
    result
}

impl EphemeralPrivateKey {
    /// A fresh private key from `rng`.
    pub fn generate(
        alg: &'static Algorithm,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::Unspecified> {
        let private_key = match alg.curve {
            Curve::Curve25519 => {
                let mut key = Key::from([0u8; x25519::KEY_SIZE]);
                rng.fill(key.as_mut())?;
                Private::X25519(x25519::PrivateKey::new(&key))
            }
            Curve::P256 => Private::P256(draw(rng, p256::PrivateKey::try_new)?),
            Curve::P384 => Private::P384(draw(rng, p384::PrivateKey::try_new)?),
        };
        Ok(Self {
            private_key,
            algorithm: alg,
        })
    }

    /// The public key to send to the peer.
    #[inline]
    pub fn compute_public_key(&self) -> Result<PublicKey, error::Unspecified> {
        let mut bytes = [0u8; MAX_PUBLIC_KEY_LEN];
        let len = match &self.private_key {
            Private::X25519(k) => put(&mut bytes, &k.public_key().bytes()),
            Private::P256(k) => put(&mut bytes, &k.public_key().sec1_bytes()),
            Private::P384(k) => put(&mut bytes, &k.public_key().sec1_bytes()),
        };
        Ok(PublicKey {
            algorithm: self.algorithm,
            bytes,
            len,
        })
    }

    /// The algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// The longest public key: an uncompressed P-384 point.
const MAX_PUBLIC_KEY_LEN: usize = p384::PUBLIC_KEY_SIZE;

fn put(out: &mut [u8; MAX_PUBLIC_KEY_LEN], bytes: &[u8]) -> usize {
    out[..bytes.len()].copy_from_slice(bytes);
    bytes.len()
}

/// A public key, in the form sent to the peer.
#[derive(Clone)]
pub struct PublicKey {
    algorithm: &'static Algorithm,
    bytes: [u8; MAX_PUBLIC_KEY_LEN],
    len: usize,
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &HexStr(self.as_ref()))
            .finish()
    }
}

impl PublicKey {
    /// The algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// A peer's public key, not yet checked. It is checked when used.
#[derive(Clone, Copy)]
pub struct UnparsedPublicKey<B> {
    algorithm: &'static Algorithm,
    bytes: B,
}

impl<B> AsRef<[u8]> for UnparsedPublicKey<B>
where
    B: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<B: fmt::Debug> fmt::Debug for UnparsedPublicKey<B>
where
    B: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UnparsedPublicKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &HexStr(self.bytes.as_ref()))
            .finish()
    }
}

impl<B> UnparsedPublicKey<B> {
    /// A peer's key for `algorithm`.
    pub fn new(algorithm: &'static Algorithm, bytes: B) -> Self {
        Self { algorithm, bytes }
    }

    /// The algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    /// The bytes as given.
    #[inline]
    pub fn bytes(&self) -> &B {
        &self.bytes
    }
}

/// An uncompressed point of exactly the curve's length. scytale also
/// takes compressed points; ring does not, and TLS never sends them.
fn uncompressed(bytes: &[u8], len: usize) -> Result<&[u8], error::Unspecified> {
    match bytes.first() {
        Some(0x04) if bytes.len() == len => Ok(bytes),
        _ => Err(error::Unspecified),
    }
}

/// Agrees a secret with the peer and passes it to `kdf`.
///
/// Fails if the peer's key is for another algorithm, is malformed, is
/// not on the curve, or (for X25519) yields the all-zero secret. `kdf`
/// is not called on failure.
#[inline]
pub fn agree_ephemeral<B: AsRef<[u8]>, R>(
    my_private_key: EphemeralPrivateKey,
    peer_public_key: &UnparsedPublicKey<B>,
    kdf: impl FnOnce(&[u8]) -> R,
) -> Result<R, error::Unspecified> {
    if peer_public_key.algorithm != my_private_key.algorithm {
        return Err(error::Unspecified);
    }
    let peer = peer_public_key.bytes.as_ref();
    let mut shared = [0u8; p384::KEY_SIZE];
    let len = match &my_private_key.private_key {
        Private::X25519(k) => {
            let peer: &[u8; x25519::KEY_SIZE] = peer.try_into()?;
            let secret = k
                .shared_secret(&x25519::PublicKey::new(peer))
                .map_err(error::erase)?;
            put_secret(&mut shared, secret)
        }
        Private::P256(k) => {
            let peer = uncompressed(peer, p256::PUBLIC_KEY_SIZE)?;
            let peer =
                p256::PublicKey::try_from_sec1(peer).map_err(error::erase)?;
            put_secret(&mut shared, k.shared_secret(&peer))
        }
        Private::P384(k) => {
            let peer = uncompressed(peer, p384::PUBLIC_KEY_SIZE)?;
            let peer =
                p384::PublicKey::try_from_sec1(peer).map_err(error::erase)?;
            put_secret(&mut shared, k.shared_secret(&peer))
        }
    };
    let r = kdf(&shared[..len]);
    shared.zeroize();
    Ok(r)
}

/// Copies a secret out and wipes the copy it came in.
fn put_secret<const N: usize>(
    out: &mut [u8; p384::KEY_SIZE],
    mut secret: [u8; N],
) -> usize {
    out[..N].copy_from_slice(&secret);
    secret.zeroize();
    N
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::format;
    use std::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// A source that returns the same bytes every time.
    #[derive(Debug)]
    struct Fixed<'a>(&'a [u8]);

    impl rand::sealed::SecureRandom for Fixed<'_> {
        fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
            dest.copy_from_slice(self.0);
            Ok(())
        }
    }

    // RFC 7748 section 6.1.
    #[test]
    fn x25519_gives_the_published_secret() {
        let alice = hex("77076d0a7318a57d3c16c17251b26645\
             df4c2f87ebc0992ab177fba51db92c2a");
        let bob_public = hex("de9edb7d7b7dc1b4d35b61c2ece43537\
             3f8343c85b78674dadfc7e146f882b4f");
        let key = EphemeralPrivateKey::generate(&X25519, &Fixed(&alice))
            .expect("key");
        assert_eq!(
            key.compute_public_key().expect("public").as_ref(),
            &hex("8520f0098930a754748b7ddcb43ef75a\
                 0dbf3a0d26381af4eba4a98eaa9b4e6a")[..]
        );
        let peer = UnparsedPublicKey::new(&X25519, &bob_public);
        let secret =
            agree_ephemeral(key, &peer, |s| s.to_vec()).expect("agree");
        assert_eq!(
            secret,
            hex("4a5d9d5ba4ce2de1728e3bf480350f25\
                 e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn a_low_order_point_is_refused_without_calling_the_kdf() {
        let rng = rand::SystemRandom::new();
        let key = EphemeralPrivateKey::generate(&X25519, &rng).expect("key");
        let zero = [0u8; 32];
        let peer = UnparsedPublicKey::new(&X25519, &zero);
        assert!(agree_ephemeral(key, &peer, |_| panic!("kdf called")).is_err());
    }

    fn ecdh_round_trip(alg: &'static Algorithm, len: usize) {
        let rng = rand::SystemRandom::new();
        let a = EphemeralPrivateKey::generate(alg, &rng).expect("a");
        let b = EphemeralPrivateKey::generate(alg, &rng).expect("b");
        let a_public = a.compute_public_key().expect("a public");
        let b_public = b.compute_public_key().expect("b public");
        assert_eq!(a_public.as_ref().len(), len);
        assert_eq!(a_public.as_ref()[0], 0x04);

        let ab = agree_ephemeral(
            a,
            &UnparsedPublicKey::new(alg, b_public.as_ref()),
            |s| s.to_vec(),
        )
        .expect("ab");
        let ba = agree_ephemeral(
            b,
            &UnparsedPublicKey::new(alg, a_public.as_ref()),
            |s| s.to_vec(),
        )
        .expect("ba");
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), (len - 1) / 2);

        // A compressed point, a truncated one and one off the curve.
        let mut compressed = a_public.as_ref()[..len.div_ceil(2)].to_vec();
        compressed[0] = 0x02;
        let mut off = a_public.as_ref().to_vec();
        off[len - 1] ^= 1;
        for bad in [&compressed[..], &a_public.as_ref()[..len - 1], &off] {
            let c = EphemeralPrivateKey::generate(alg, &rng).expect("c");
            let peer = UnparsedPublicKey::new(alg, bad);
            assert!(agree_ephemeral(c, &peer, |_| panic!("kdf")).is_err());
        }
    }

    #[test]
    fn ecdh_agrees_and_refuses_bad_points() {
        ecdh_round_trip(&ECDH_P256, 65);
        ecdh_round_trip(&ECDH_P384, 97);
    }

    #[test]
    fn keys_for_different_curves_do_not_agree() {
        let rng = rand::SystemRandom::new();
        let a = EphemeralPrivateKey::generate(&ECDH_P256, &rng).expect("a");
        let b = EphemeralPrivateKey::generate(&ECDH_P384, &rng).expect("b");
        let b_public = b.compute_public_key().expect("b public");
        let peer = UnparsedPublicKey::new(&ECDH_P384, b_public.as_ref());
        assert!(agree_ephemeral(a, &peer, |_| panic!("kdf")).is_err());
    }

    #[test]
    fn a_scalar_out_of_range_is_redrawn_then_refused() {
        // All ones is above the order of both curves.
        let ones = [0xffu8; 48];
        assert!(
            EphemeralPrivateKey::generate(&ECDH_P256, &Fixed(&ones[..32]))
                .is_err()
        );
        assert!(
            EphemeralPrivateKey::generate(&ECDH_P384, &Fixed(&ones)).is_err()
        );
    }

    #[test]
    fn things_print_as_ring_prints_them() {
        let rng = rand::SystemRandom::new();
        let key = EphemeralPrivateKey::generate(&ECDH_P256, &rng).expect("key");
        assert_eq!(
            format!("{key:?}"),
            "EphemeralPrivateKey { algorithm: Algorithm { curve: P256 } }"
        );
        let peer = UnparsedPublicKey::new(&X25519, &[0x01u8, 0x02, 0x03]);
        assert_eq!(
            format!("{peer:?}"),
            "UnparsedPublicKey { algorithm: Algorithm { curve: Curve25519 }, \
             bytes: \"010203\" }"
        );
    }
}
