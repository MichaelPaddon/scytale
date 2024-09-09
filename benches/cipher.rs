use criterion::{Criterion, Throughput};
use scytale::cipher::{EncryptingBlockCipher};
use scytale::cipher::aes;
use hybrid_array::Array;
use scytale::convert::*;

fn block_cipher_encrypt_bench<C: EncryptingBlockCipher>(
    group: &str,
    length: usize,
    c: &mut Criterion
) {
    let key = Array::<u8, C::KeySize>::from_fn(|_| 0);
    let mut cipher = C::new(&key).unwrap();
    let pt = vec![0u8; length];
    let mut ct = vec![0u8; length];
    let mut group = c.benchmark_group(group);
    group.throughput(Throughput::Elements(pt.len() as u64));
    group.bench_function(
        format!("{}_encrypt", pt.len()),
        |b| b.iter(
            || {
                cipher.encrypt_blocks(
                    pt.as_slice().as_blocks().0,
                    ct.as_mut_slice().as_blocks_mut().0
                )
            }
        )
    );
}

pub fn cipher_bench(c: &mut Criterion) {
    block_cipher_encrypt_bench::<aes::Aes128>("aes128", 4096, c);
    block_cipher_encrypt_bench::<aes::Aes192>("aes192", 4096, c);
    block_cipher_encrypt_bench::<aes::Aes256>("aes256", 4096, c);
    block_cipher_encrypt_bench::<aes::soft::Aes128>("aes128_soft", 4096, c);
    block_cipher_encrypt_bench::<aes::soft::Aes192>("aes192_soft", 4096, c);
    block_cipher_encrypt_bench::<aes::soft::Aes256>("aes256_soft", 4096, c);
    block_cipher_encrypt_bench::<aes::fast::Aes128>("aes128_fast", 4096, c);
    block_cipher_encrypt_bench::<aes::fast::Aes192>("aes192_fast", 4096, c);
    block_cipher_encrypt_bench::<aes::fast::Aes256>("aes256_fast", 4096, c);
}
