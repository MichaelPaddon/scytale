use arrayvec::ArrayVec;
use core::cmp::min;
use core::fmt::Debug;
use core::iter::{Chain, FusedIterator};
use core::option;
use core::slice;

pub type Buffer<T, const N: usize> = ArrayVec<T, N>;

/// An iterator over blocks.
#[derive(Debug)]
pub struct Blocks<'a, 'b, T, const N: usize>
where
    T: Copy
{
    // a mutable reference to a buffer that
    // carries state between iterations.
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
    pub fn new(buffer: &'a mut Buffer<T, N>, mut values: &'b [T]) -> Self {
        // construct iterator for optional first block
        let first = if buffer.len() > 0 {
            // try to fill the buffer
            let n = min(values.len(), buffer.remaining_capacity());
            buffer.try_extend_from_slice(&values[..n]).unwrap();
            values = &values[n..];

            // buffer holds a full block?
            if buffer.is_full() {
                let block = unsafe {
                    // SAFETY: buffer is full
                    &*buffer.as_ptr().cast()
                        // SAFETY: buffer has lifetime 'a and 'a: 'b
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
            // SAFETY: there are at least n blocks
            slice::from_raw_parts(values.as_ptr().cast(), n)
                // SAFETY: &values has lifetime 'b
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
        self.buffer.try_extend_from_slice(self.remainder).unwrap();
    }
}

impl<'a, 'b, T, const N: usize> Iterator for Blocks<'a, 'b, T, N>
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
