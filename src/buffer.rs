use core::cmp::min;
use core::fmt::Debug;
use core::iter::{Chain, FusedIterator};
use core::mem::{MaybeUninit, transmute_copy};
use core::ops::{Deref, DerefMut};
use core::option;
use core::slice;
use crate::array::Slice;

/// A fixed capacity buffer, holding a maximum of N values of type T.
#[derive(Copy, Debug)]
pub struct Buffer<T, const N: usize> {
    buffer: [MaybeUninit<T>; N],
    length: usize
}

impl<T, const N: usize> Buffer<T, N> {
    /// Constructs an empty buffer.
    ///
    /// # Example 
    ///
    #[inline]
    pub fn new() -> Self {
        Self {
            buffer: unsafe {
                MaybeUninit::uninit().assume_init()
            },
            length: 0
        }
    }

    /// Returns a slice containing the buffer's values.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self
    }

    /// Returns a mutable slice containing the buffer's values.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self
    }

    /// Returns a pointer to the buffer's values.
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.buffer.as_ptr().cast()
    }

    /// Returns a mutable pointer to the buffer's values.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.buffer.as_mut_ptr().cast()
    }

    /// Consumes the buffer and returns the contained array.
    /// Panics if the buffer is not full.
    #[inline]
    pub fn into_inner(self) -> [T; N] {
        assert_eq!(self.length,  N);
        unsafe {
            transmute_copy(&*self.buffer.as_ptr().cast::<[T; N]>())
        }
    }

    /// Clears the buffer.
    #[inline]
    pub fn clear(&mut self) {
        self.truncate(0)
    }

    /// Returns true if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns true if the buffer is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.length == N
    }

    /// Returns the number of values in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.length
    }

    /// Returns the total capacity of the buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        N
    }

    /// Returns the remaining capacity of the buffer.
    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        N - self.length
    }

    /// Appends a value to the end of the buffer.
    #[inline]
    pub fn push(&mut self, value: T) {
        self.buffer[self.length].write(value);
        self.length += 1;
    }

    /// Removes and returns the last value in the buffer (if any).
    pub fn pop(&mut self) -> Option<T> {
        if self.length == 0 {
            None
        }
        else {
            self.length -= 1;
            let value = unsafe {
                self.buffer[self.length].assume_init_read()
            };
            Some(value)
        }
    }

    /// Extends the buffer by cloning values from a slice.
    /// Panics if there is not enough room in the buffer.
    pub fn extend_from_slice(&mut self, other: &[T])
    where
        T: Clone
    {
        for i in 0..other.len() {
            self.push(other[i].clone());
        }
    }

    /// Truncates the buffer to a given length.
    pub fn truncate(&mut self, len: usize) {
        for i in len..self.length {
            unsafe {
                self.buffer[i].assume_init_drop();
            }
        }
        self.length = len;
    }

    /// Logically concatenates buffer's contents to a slice of values,
    /// and returns an iterator over the resulting sequence of
    /// blocks of length N.
    ///
    /// After the iterator is dropped, the buffer's contents are any
    /// trailing values from the input slice..
    ///
    /// # Example
    /// 
    /// '''
    /// let buffer = Buffer::<u8; 4>::new();
    /// let mut n = 0;
    /// for block in buffer.blocks("012345678".as_bytes()) {
    ///     // process block
    ///     n += 1
    /// }
    /// assert_eq!(n, 2);
    /// assert_eq!(buffer.len(), 1);
    /// '''
    pub fn blocks<'a: 'b, 'b>(&'a mut self, values: &'b [T])
        -> Blocks<'a, 'b, T, N>
    where
        T: Copy
    {
        Blocks::new(self, values)
    }
}

impl <T, const N: usize> AsRef<[T]> for Buffer<T, N> {
    fn as_ref(&self) -> &[T] {
        self
    }
}

impl <T, const N: usize> AsMut<[T]> for Buffer<T, N> {
    fn as_mut(&mut self) -> &mut [T] {
        self
    }
}

impl <T, const N: usize> Clone for Buffer<T, N>
where
    T: Copy
{
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl <T, const N: usize> Default for Buffer<T, N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl <T, const N: usize> Deref for Buffer<T, N> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe {
            slice::from_raw_parts(self.as_ptr().cast(), self.length)
        }
    }
}

impl <T, const N: usize> DerefMut for Buffer<T, N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            slice::from_raw_parts_mut(self.as_mut_ptr().cast(), self.length)
        }
    }
}

impl <T, const N: usize> Extend<T> for Buffer<T, N> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = T>
    {
        for value in iter {
            self.push(value)
        }
    }
}

impl <T, const N: usize> From<[T; N]> for Buffer<T, N> {
    fn from(values: [T; N]) -> Self {
        let mut buffer = Self::new();
        buffer.extend(values);
        buffer
    }
}

impl <T, const N: usize, U> PartialEq<U> for Buffer<T, N>
where
    T: PartialEq,
    U: AsRef<[T]>
{
    #[inline]
    fn eq(&self, other: &U) -> bool {
        self.as_slice() == other.as_ref()
    }
}

impl <T, const N: usize> Eq for Buffer<T, N>
where
    T: PartialEq
{}

impl <T, const N: usize> Slice<T> for Buffer<T, N>
{}


/// An iterator over blocks.
#[derive(Debug)]
pub struct Blocks<'a, 'b, T, const N: usize>
where
    T: Copy
{
    // a reference to a buffer that survives this iterator
    buffer: &'a mut Buffer<T, N>,

    // an iterator over references to blocks
    blocks: Chain<option::IntoIter<&'b [T; N]>, slice::Iter<'b, [T; N]>>,

    // left over values
    remainder: &'b [T]
}

impl<'a, 'b, T, const N: usize> Blocks<'a, 'b, T, N>
where
    'a: 'b,
    T: Copy
{
    /// Creates a new block iterator.
    fn new(buffer: &'a mut Buffer<T, N>, mut values: &'b [T]) -> Self {
        // construct iterator for optional first block
        let first = if buffer.len() > 0 {
            // try to fill the buffer
            let n = min(values.len(), buffer.remaining_capacity());
            buffer.extend_from_slice(&values[..n]);
            values = &values[n..];

            if buffer.is_full() {
                let block = unsafe {
                    // safe because buffer is full
                    &*buffer.as_ptr().cast()
                        // safe because buffer has lifetime 'a and 'a: 'b
                        as &'b [T; N]
                };
                Some(block)
            }
            else {
                None
            }
        }
        else {
            None
        }.into_iter();

        // construct iterator for following blocks
        let n = values.len() / N;
        let following = unsafe {
            // safe because we know there are at least n blocks
            slice::from_raw_parts(values.as_ptr().cast(), n)
                // safe because &values has lifetime 'b
                as &'b [[T; N]]
        }.into_iter();

        // remaining values that don't fit into a block
        let remainder = &values[n * N..];

        // chain together first and follwoing blocks
        let blocks = first.chain(following);

        Self {buffer, blocks, remainder}
    }
}

impl<'a, 'b, T, const N: usize> Drop for Blocks<'a, 'b, T, N>
where
    T: Copy
{
    fn drop(&mut self) {
        if self.buffer.is_full() {
            // buffer was emitted
            self.buffer.clear();
        }
        // buffer any remaining values
        self.buffer.extend_from_slice(self.remainder);
    }
}

impl<'a, 'b, T: Copy, const N: usize> Iterator for Blocks<'a, 'b, T, N>
where
    T: Copy
{
    type Item = &'b [T; N];

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        self.blocks.next()
    }
}

impl<'a, 'b, T, const N: usize> FusedIterator for Blocks<'a, 'b, T, N>
where
    T: Copy
{}
