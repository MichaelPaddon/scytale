use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use scytale::hash::sha2::{Sha256, Sha512};
use scytale::hash::Hash;

pub fn sha256_bench(c: &mut Criterion) {
    let data = [0u8; 4096];
    let mut group = c.benchmark_group("sha256");
    group.throughput(Throughput::Elements(data.len() as u64));
    group.bench_with_input(format!("{}", data.len()), &data, |b, d| {
        b.iter(|| {Sha256::new_with_prefix(d).finalize();})
    });
}

pub fn sha512_bench(c: &mut Criterion) {
    let data = [0u8; 4096];
    let mut group = c.benchmark_group("sha512");
    group.throughput(Throughput::Elements(data.len() as u64));
    group.bench_with_input(format!("{}", data.len()), &data, |b, d| {
        b.iter(|| {Sha512::new_with_prefix(d).finalize();})
    });
}
