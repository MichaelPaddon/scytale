//! Scytale: correct and fast cryptography.
//!
//! Algorithms are grouped by category. Within a category, name a primitive
//! directly to get the best implementation for the machine the code is
//! running on:
//!
//! ```
//! use scytale::symmetric::aes::Aes128;
//!
//! let cipher = Aes128::new(&[0u8; 16]);
//! let mut block = [0u8; 16];
//! cipher.encrypt_block(&mut block);
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, [0u8; 16]);
//! ```
//!
//! Selection happens at run time, so a binary built for a baseline target
//! still uses whatever the silicon it lands on supports. To pin one exact
//! implementation instead, name it through its `arch` path.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod symmetric;
