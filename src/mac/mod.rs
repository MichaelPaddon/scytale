use core::ops::Deref;

pub trait Mac {
    type Tag: AsRef<[u8]> + Clone + Deref<Target = [u8]>;

    fn new<K>(key: K) -> Self
    where
        K: AsRef<[u8]>;

    fn rekey<K>(&mut self, key: K)
    where
        K: AsRef<[u8]>;

    fn reset(&mut self);

    fn update<T>(&mut self, data: T)
    where
        T: AsRef<[u8]>;

    fn finalize(self) -> Self::Tag;

    fn finalize_and_reset(&mut self) -> Self::Tag;

    #[inline]
    fn new_with_prefix<K, T>(key: K, data: T) -> Self
    where
        K: AsRef<[u8]>,
        T: AsRef<[u8]>,
        Self: Sized
    {
        let mut mac = Self::new(key);
        mac.update(data);
        mac
    }

    #[inline]
    fn mac<K, T>(key: K, message: T) -> Self::Tag
    where
        K: AsRef<[u8]>,
        T: AsRef<[u8]>,
        Self: Sized
    {
        Self::new_with_prefix(key, message).finalize()
    }
}

pub mod hmac;
