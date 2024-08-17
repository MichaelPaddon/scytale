use hybrid_array::{Array, ArraySize};

pub trait AsBlocks<T, N: ArraySize> {
    fn as_blocks<'a>(&'a self) -> (&'a [Array<T, N>], &'a [T]);
}

impl<T, N: ArraySize> AsBlocks<T, N> for &[T] {
    #[inline(always)]
    fn as_blocks<'a>(&'a self) -> (&'a [Array<T, N>], &'a [T]) {
        Array::<T, N>::slice_as_chunks(self)
    }
}

pub trait AsBlocksMut<T, N: ArraySize> {
    fn as_blocks_mut<'a>(&'a mut self) -> (&'a mut [Array<T, N>], &'a mut [T]);
}

impl<T, N: ArraySize> AsBlocksMut<T, N> for &mut [T] {
    #[inline(always)]
    fn as_blocks_mut<'a>(&'a mut self) -> (&'a mut [Array<T, N>], &'a mut [T]) {
        Array::<T, N>::slice_as_chunks_mut(self)
    }
}
