use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key<const SIZE: usize> (
    Box<[u8; SIZE]>
);

impl<const SIZE: usize> Key<SIZE> {
    fn new() -> Self {
        let mut key = Self(Box::new([0u8; SIZE]));
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut *key.0);
        key
    }
}

impl<const SIZE: usize> From<[u8; SIZE]> for Key<SIZE> {
    fn from(mut bytes: [u8; SIZE]) -> Self {
        let key = Self(Box::new(bytes));
        bytes.zeroize();
        key
    }
}

impl<const SIZE: usize> TryFrom<&[u8]> for Key<SIZE> {
    type Error = std::array::TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; SIZE] = bytes.try_into()?;
        Ok(Self::from(bytes))
    }
}
