use core::fmt::Debug;
use core::ops::{Deref, DerefMut};

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Array<T, const N: usize> ([T; N]);

impl <T, const N: usize> Array<T, N>
where
    T: Copy + Default
{
    pub fn new() -> Self {
        Self([T::default(); N])
    }
}

impl <T, const N: usize> Default for Array<T, N>
where
    T: Copy + Default
{
    fn default() -> Self {
        Self([T::default(); N])
    }
}

impl <T, const N: usize> Deref for Array<T, N>
{
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl <T, const N: usize> DerefMut for Array<T, N>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut_slice()
    }
}

impl <T, const N: usize> From<[T; N]> for Array<T, N>
{
    fn from(array: [T; N]) -> Self {
        Self(array)
    }
}
