//! Message Authentication Code (MAC) algorithms.
//!
//! A MAC algorithm takes a secret key and a message, and
//! generates an authentication tag.
//! Anyone with the secret key can verify this tag.
//! MACs are useful for data origin authentication, which also
//! implies data integrity.

/// A Message Authentication Code algorithm.
pub trait Mac {
    /// Constructs a new instance of the MAC algorithm.
    fn new(key: &[u8]) -> Self
    where
        Self: Sized;

    /// Changes the key, and resets the MAC algorithm,
    fn rekey(&mut self, key: &[u8]);

    /// Resets the MAC algorithm, to its orginal state.
    fn reset(&mut self);

    /// Updates the MAC algorithm with some data.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the MAC algorithm, generating an authentication code.
    fn finalize<'a>(&'a mut self) -> &'a [u8];

    /// Constructs a new instance of the MAC algorithm
    /// and updates it with some data.
    #[inline]
    fn new_with_prefix(key: &[u8], data: &[u8]) -> Self
    where
        Self: Sized
    {
        let mut mac = Self::new(key);
        mac.update(data);
        mac
    }

    /// Generates an authentciation code, given a key and a message.
    #[inline]
    fn mac(key: &[u8], message: &[u8]) -> Vec<u8>
    where
        Self: Sized
    {
        Self::new_with_prefix(key, message).finalize().to_vec()
    }
}

pub mod hmac;
