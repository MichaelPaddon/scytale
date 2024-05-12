use criterion::{black_box, criterion_group, criterion_main, Criterion};
use scytale::hash::sha2::*;
use scytale::hash::Hash;

fn sha256_bench(c: &mut Criterion) {
    let block = [0u8; 16384];
    c.bench_function("sha256 16384", |b| b.iter(
            || black_box(Sha256::hash(&block))
    ));
}

fn sha512_bench(c: &mut Criterion) {
    let block = [0u8; 16384];
    c.bench_function("sha512 16384", |b| b.iter(
            || black_box(Sha512::hash(&block))
    ));
}

criterion_group!(benches, sha256_bench, sha512_bench);
criterion_main!(benches);
