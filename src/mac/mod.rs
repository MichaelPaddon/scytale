use core::ops::Deref;

pub trait Mac {
    type Tag: AsRef<[u8]> + Deref<Target = [u8]>;

    fn new<T: AsRef<[u8]>>(key: T) -> Self;

    fn rekey<T: AsRef<[u8]>>(&mut self, key: T);

    fn reset(&mut self);

    fn update<T: AsRef<[u8]>>(&mut self, data: T);

    fn finalize(self) -> Self::Tag;

    fn finalize_and_reset(&mut self) -> Self::Tag;

    #[inline]
    fn new_with_prefix<T: AsRef<[u8]>, U: AsRef<[u8]>>(key: T, data: U) -> Self
    where
        Self: Sized
    {
        let mut mac = Self::new(key);
        mac.update(data);
        mac
    }

    #[inline]
    fn tag<T: AsRef<[u8]>, U: AsRef<[u8]>>(key: T, msg: U) -> Self::Tag
    where
        Self: Sized
    {
        Self::new_with_prefix(key, msg).finalize()
    }
}

pub mod hmac;
