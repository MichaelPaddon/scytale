//! Filling the last block.
//!
//! The block modes that chain, [`Cbc`](crate::cipher::mode::Cbc)
//! and [`Cfb128`](crate::cipher::mode::Cfb128), and the raw cipher
//! in ECB, take a whole number of blocks and refuse anything else;
//! a message of another length has to be brought up to one, in a
//! way that the receiver can undo. A padding scheme is that: it
//! always adds at least one byte, so the receiver always has
//! something to remove, and what it adds says how much.
//!
//! One submodule per scheme, [`pkcs7`] for now, which is what
//! PKCS#5, PKCS#7, CMS (RFC 5652) and `openssl enc` all use, and
//! what a CBC ciphertext from another library almost certainly
//! carries.
//!
//! ```
//! use scytale::Key;
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::mode::Cbc;
//! use scytale::cipher::padding::pkcs7;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let cbc = Cbc::<Aes128>::new(&Key::from([0u8; 16]));
//! let iv = [0u8; 16];
//!
//! // Room for the message and up to one more block of padding.
//! let mut buffer = [0u8; 32];
//! let message = b"seventeen bytes!!";
//! buffer[..message.len()].copy_from_slice(message);
//! let n = pkcs7::pad(&mut buffer, message.len(), 16)?;
//! cbc.encrypt(&iv, &mut buffer[..n])?;
//!
//! cbc.decrypt(&iv, &mut buffer[..n])?;
//! let m = pkcs7::unpad(&buffer[..n], 16)?;
//! assert_eq!(&buffer[..m], message);
//! # Ok(())
//! # }
//! ```
//!
//! # The padding oracle
//!
//! Removing padding checks something, and a check that can fail is
//! a question an attacker can ask. Given a way to learn whether a
//! ciphertext's padding was valid after decryption -- an error
//! message, a status code, the time taken -- an attacker decrypts
//! any ciphertext without the key, a byte at a time, by submitting
//! altered copies of it. That is the padding oracle attack, and it
//! has been carried out against real systems many times.
//!
//! The defence is not in the padding code, which can only make sure
//! its own timing says nothing. It is a MAC over the ciphertext,
//! verified before any of it is decrypted, so that a ciphertext the
//! attacker altered is rejected before its padding is ever looked
//! at; and one error for every failure after that, so that a MAC
//! failure and a padding failure look the same from outside. The
//! constructions in [`aead`](crate::aead) have that built in and
//! need no padding at all, which is why they come first.

pub mod pkcs7;
