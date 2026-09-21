//! Random bytes, from the system.
//!
//! [`SecureRandom`] is sealed, as ring's is: the only sources are the
//! ones this crate defines. Keys are generated from whichever the
//! caller hands in.

use crate::error;

/// A source of random bytes.
///
/// It fills through a shared reference, as ring's does, so one source
/// can be handed to several operations at once.
pub trait SecureRandom: sealed::SecureRandom {
    /// Fills `dest` entirely, or fails.
    fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified>;
}

impl<T> SecureRandom for T
where
    T: sealed::SecureRandom,
{
    #[inline]
    fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        self.fill_impl(dest)
    }
}

/// A random value, held until the caller takes it out.
pub struct Random<T: RandomlyConstructable>(T);

impl<T: RandomlyConstructable> Random<T> {
    /// The value.
    #[inline]
    pub fn expose(self) -> T {
        self.0
    }
}

/// A value of type `T` filled from `rng`.
#[inline]
pub fn generate<T: RandomlyConstructable>(
    rng: &dyn SecureRandom,
) -> Result<Random<T>, error::Unspecified> {
    let mut r = T::zero();
    rng.fill(r.as_mut_bytes())?;
    Ok(Random(r))
}

pub(crate) mod sealed {
    use crate::error;

    pub trait SecureRandom: core::fmt::Debug {
        fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified>;
    }

    pub trait RandomlyConstructable: Sized {
        fn zero() -> Self;
        fn as_mut_bytes(&mut self) -> &mut [u8];
    }

    impl<const N: usize> RandomlyConstructable for [u8; N] {
        #[inline]
        fn zero() -> Self {
            [0; N]
        }

        #[inline]
        fn as_mut_bytes(&mut self) -> &mut [u8] {
            &mut self[..]
        }
    }
}

/// A type [`generate`] can fill: a byte array.
pub trait RandomlyConstructable: sealed::RandomlyConstructable {}

impl<T> RandomlyConstructable for T where T: sealed::RandomlyConstructable {}

/// The system's own source of randomness.
///
/// Each call asks scytale's [`System`](scytale::random::entropy::System)
/// source afresh, which is the operating system wherever there is one.
/// Nothing is kept between calls, so a clone, a fork or a restored
/// snapshot can never replay what an earlier call returned.
#[derive(Clone, Debug)]
pub struct SystemRandom(());

impl SystemRandom {
    /// The system's source.
    #[inline]
    pub fn new() -> Self {
        Self(())
    }
}

impl Default for SystemRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::sealed::Sealed for SystemRandom {}

impl sealed::SecureRandom for SystemRandom {
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        use scytale::random::Entropy;
        let mut system = scytale::random::entropy::System::try_new()
            .map_err(error::erase)?;
        system.fill(dest).map_err(error::erase)
    }
}

/// A caller's source, in the shape scytale's key generation takes.
///
/// ring's sources fill through `&self` and scytale's through
/// `&mut self`; this is the whole of the difference.
pub(crate) struct Bridge<'a>(pub(crate) &'a dyn SecureRandom);

impl scytale::Random for Bridge<'_> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), scytale::Error> {
        // ring says only that the source failed, so no reason is
        // lost here.
        self.0
            .fill(out)
            .map_err(|error::Unspecified| scytale::Error::EntropyUnavailable(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::format;

    #[test]
    fn the_system_fills_every_length() {
        let rng = SystemRandom::new();
        for len in [0, 1, 7, 16, 255, 256, 257, 4096] {
            let mut buf = [0u8; 4096];
            rng.fill(&mut buf[..len]).expect("fill");
            // One byte in 256 is zero by chance, so ask whether any
            // byte moved rather than all of them.
            assert!(len == 0 || buf[..len].iter().any(|&b| b != 0), "{len}");
            assert!(buf[len..].iter().all(|&b| b == 0), "{len}");
        }
    }

    #[test]
    fn the_system_prints_as_ring_prints_it() {
        assert_eq!(format!("{:?}", SystemRandom::new()), "SystemRandom(())");
    }

    #[test]
    fn generate_fills_an_array() {
        let a: [u8; 32] =
            generate(&SystemRandom::new()).expect("generate").expose();
        let b: [u8; 32] =
            generate(&SystemRandom::new()).expect("generate").expose();
        assert_ne!(a, b);
    }

    #[test]
    fn the_bridge_passes_bytes_and_failure_through() {
        #[derive(Debug)]
        struct Broken;
        impl sealed::SecureRandom for Broken {
            fn fill_impl(
                &self,
                _: &mut [u8],
            ) -> Result<(), error::Unspecified> {
                Err(error::Unspecified)
            }
        }
        let mut out = [0u8; 8];
        assert_eq!(
            scytale::Random::fill(&mut Bridge(&Broken), &mut out),
            Err(scytale::Error::EntropyUnavailable(0))
        );
        scytale::Random::fill(&mut Bridge(&SystemRandom::new()), &mut out)
            .expect("fill");
    }
}
