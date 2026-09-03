//! ECDH (SP 800-56A) over the NIST prime curves P-256 and P-384.
//!
//! Each party keeps a secret scalar and publishes the point it makes
//! from the base point; multiplying the other's point by one's own
//! scalar lands both on the same point, whose x-coordinate is the
//! shared secret. Each curve is a module of its own, [`p256`] and
//! [`p384`], with the same two key types and the same calls.
//!
//! This is the agreement TLS, IKE and most standards-track
//! protocols name; where nothing names a curve,
//! [`x25519`](crate::kex::x25519) does the same job with less to
//! get wrong. The shared secret is a curve coordinate, not a
//! uniform string: feed it to [`hkdf`](crate::kdf::hkdf) to make
//! keys, never use it as one.
//!
//! # Invalid curve points
//!
//! A peer who sends a point that is not on the curve can learn the
//! secret scalar a few bits at a time, since the arithmetic then
//! runs in a group of the attacker's choosing. Every [`PublicKey`]
//! here is checked to lie on the curve when it is constructed, so
//! no such point reaches [`shared_secret`]; the curves have prime
//! order, so there are no small subgroups to check for besides.
//!
//! [`PublicKey`]: p256::PublicKey
//! [`shared_secret`]: p256::PrivateKey::shared_secret
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::hkdf;
//! use scytale::kex::ecdh::p256::PrivateKey;
//! use scytale::random::{Rng, System};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = Rng::try_new(System::try_new()?)?;
//! let alice = PrivateKey::generate(&mut rng)?;
//! let bob = PrivateKey::generate(&mut rng)?;
//!
//! // Each side needs only the other's public key.
//! let shared = alice.shared_secret(bob.public_key())?;
//! assert_eq!(shared, bob.shared_secret(alice.public_key())?);
//! let mut key = [0u8; 32];
//! hkdf::derive::<Sha256>(b"", &shared, b"session v1", &mut key)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! The scalar multiplication is a fixed sequence of field
//! operations for a given curve: complete addition formulas, fixed
//! windows, and a table scanned whole.

macro_rules! ecdh_curve {
    (
        $constants:expr, $limbs:literal, $curve:literal,
        $der:literal, $public_der:literal
    ) => {
        crate::math::ec::key_types!(
            $constants, $limbs, $curve, "key agreement",
            der $der, public der $public_der
        );

        impl PrivateKey {
            /// The secret shared with the holder of `public`: the
            /// x-coordinate of the product of the two keys, big-endian.
            ///
            /// The point was checked when `public` was made, so the
            /// only refusal left is the one the arithmetic cannot
            /// produce, the identity, and it is checked anyway.
            pub fn shared_secret(
                &self,
                public: &PublicKey,
            ) -> Result<[u8; KEY_SIZE], Error> {
                let e = Engine::new(&$constants);
                let mut out = [0u8; KEY_SIZE];
                self.secret.shared_secret(&e, &public.point, &mut out)?;
                Ok(out)
            }
        }
    };
}

/// ECDH over P-256.
pub mod p256 {
    ecdh_curve!(crate::math::ec::P256, 4, "P-256", 138, 91);
}

/// ECDH over P-384.
pub mod p384 {
    ecdh_curve!(crate::math::ec::P384, 6, "P-384", 185, 120);
}

#[cfg(test)]
mod tests {
    use super::{p256, p384};
    use crate::Error;

    /// Wycheproof's first ECDH case on P-256: a private scalar, the
    /// peer's SubjectPublicKeyInfo, and the shared secret.
    #[test]
    fn wycheproof_normal_case() {
        fn unhex<'a>(hex: &str, buf: &'a mut [u8]) -> &'a [u8] {
            let hex = hex.as_bytes();
            for (byte, pair) in buf.iter_mut().zip(hex.chunks(2)) {
                let s = core::str::from_utf8(pair).unwrap();
                *byte = u8::from_str_radix(s, 16).unwrap();
            }
            &buf[..hex.len() / 2]
        }
        let mut buf = [0u8; 32];
        let private: [u8; 32] = unhex(
            "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
            &mut buf,
        )
        .try_into()
        .unwrap();
        let mut buf = [0u8; 91];
        let peer = unhex(
            "3059301306072a8648ce3d020106082a8648ce3d0301070342000462d5bd3372\
             af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9\
             e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf",
            &mut buf,
        );
        let mut buf = [0u8; 32];
        let shared = unhex(
            "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285",
            &mut buf,
        );
        let key = p256::PrivateKey::try_new(&private).unwrap();
        let peer = p256::PublicKey::try_from_der(peer).unwrap();
        assert_eq!(key.shared_secret(&peer).unwrap()[..], shared[..]);
    }

    /// Both curves agree from either side, through every public
    /// key form.
    #[test]
    fn agreement_through_formats() {
        let mut rng = crate::random::Rng::try_new(
            crate::random::System::try_new().unwrap(),
        )
        .unwrap();
        let a = p384::PrivateKey::generate(&mut rng).unwrap();
        let b = p384::PrivateKey::generate(&mut rng).unwrap();
        let shared = a.shared_secret(b.public_key()).unwrap();
        let mut out = [0u8; 512];
        let n = b.public_key().der_bytes(&mut out).unwrap();
        assert_eq!(n, p384::PUBLIC_KEY_DER_SIZE);
        let via_der = p384::PublicKey::try_from_der(&out[..n]).unwrap();
        assert_eq!(a.shared_secret(&via_der), Ok(shared));
        let n = b.public_key().pem_bytes(&mut out).unwrap();
        let via_pem = p384::PublicKey::try_from_pem(&out[..n]).unwrap();
        assert_eq!(a.shared_secret(&via_pem), Ok(shared));
        let n = a.der_bytes(&mut out).unwrap();
        assert_eq!(n, p384::DER_SIZE);
        let a2 = p384::PrivateKey::try_from_der(&out[..n]).unwrap();
        assert_eq!(b.shared_secret(a2.public_key()), Ok(shared));

        // A P-256 point is not a P-384 key, however presented.
        let c = p256::PrivateKey::generate(&mut rng).unwrap();
        let n = c.public_key().der_bytes(&mut out).unwrap();
        assert_eq!(
            p384::PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
        assert_eq!(
            p384::PublicKey::try_from_sec1(&c.public_key().sec1_bytes()).err(),
            Some(Error::InvalidPublicKey)
        );
    }
}
