pub mod cipher;
pub mod sha2;

use criterion::{criterion_group, criterion_main};
use cipher::cipher_bench;
use sha2::{sha256_bench, sha512_bench};

criterion_group!(cipher, cipher_bench);
criterion_group!(sha2, sha256_bench, sha512_bench);
criterion_main!(cipher, sha2);
