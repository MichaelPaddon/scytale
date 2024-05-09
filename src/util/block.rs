use arrayvec::ArrayVec;
use core::cmp::min;
use core::iter::{Chain, FusedIterator};
use core::option;
use core::slice;

///
/// An iterator over references to blocks.
///
#[derive(Debug)]
pub struct Blocks<'a, 'b, T, const N: usize>
where
    T: Copy
{
    // a reference to a buffer that survives this iterator
    buffer: &'a mut ArrayVec<T, N>,

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
    fn new(buffer: &'a mut ArrayVec<T, N>, mut values: &'b [T]) -> Self {
        // construct iterator for optional first block
        let first = if buffer.len() > 0 {
            // try to fill the buffer
            let n = min(values.len(), buffer.remaining_capacity());
            buffer.try_extend_from_slice(&values[..n]).unwrap();
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
        self.buffer.try_extend_from_slice(self.remainder).unwrap();
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

///
/// A BlockBuffer efficiently interprets a stream of values as
/// fixed length blocks.
///
/// It does no heap allocation and minimizes memory to memory copies.
///
#[derive(Clone, Debug, Default)]
pub struct BlockBuffer<T, const N: usize> {
    // a fixed length buffer
    buffer: ArrayVec<T, N>
}

#[allow(dead_code)]
impl<T: Copy, const N: usize> BlockBuffer<T, N>
where
    T: Copy
{
    /// Creates a new BlockBuffer.
    pub fn new() -> Self {
        Self {buffer: ArrayVec::new()}
    }

    /// Consumes a slice of values, and returns an iterator over the
    /// available blocks.
    ///
    /// Any remaining values that don't make a up a complete block
    /// are buffered and prepended to the next slice passed in.
    pub fn blocks<'a: 'b, 'b>(&'a mut self, values: &'b [T])
        -> Blocks<'a, 'b, T, N>
    {
        Blocks::new(&mut self.buffer, values)
    }

   /// Returns the count of buffered values.
   pub fn len(&self) -> usize {
       self.buffer.len()
   }

   /// Returns the remaining capacity of the buffer.
   pub fn remaining_capacity(&self) -> usize {
       N - self.buffer.len()
   }
}
