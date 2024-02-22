use criterion::{criterion_group, criterion_main, Criterion};
use sha3::Sha3_256;

use merkle_tree_rs::MerkleTree;

fn bench_initialization(c: &mut Criterion) {
    let initial_value = [0x00; 32].try_into().unwrap();
    c.benchmark_group("initialization")
        .bench_function("initialization_5", |b| {
            b.iter(|| MerkleTree::<Sha3_256>::new(5, &initial_value))
        })
        .bench_function("initialization_10", |b| {
            b.iter(|| MerkleTree::<Sha3_256>::new(10, &initial_value))
        })
        .bench_function("initialization_20", |b| {
            b.iter(|| MerkleTree::<Sha3_256>::new(20, &initial_value))
        });
}

fn bench_set(c: &mut Criterion) {
    let initial_value = [0x00; 32];
    let mut tree = MerkleTree::<Sha3_256>::new(20, &initial_value.try_into().unwrap());
    let updated_value = [0x11; 32].try_into().unwrap();
    c.bench_function("set", |b| b.iter(|| tree.set(5, &updated_value)));
}

fn bench_create_proof(c: &mut Criterion) {
    let initial_value = [0x00; 32];
    let mut tree = MerkleTree::<Sha3_256>::new(20, &initial_value.try_into().unwrap());
    for i in 0..tree.num_leaves() {
        let updated_value = [(i * 0x11) as u8; 32];
        tree.set(i, &updated_value.try_into().unwrap());
    }
    c.bench_function("create_proof", |b| b.iter(|| tree.create_proof(5)));
}

fn bench_verify_proof(c: &mut Criterion) {
    let initial_value = [0x00; 32];
    let mut tree = MerkleTree::<Sha3_256>::new(20, &initial_value.try_into().unwrap());
    for i in 0..tree.num_leaves() {
        let updated_value = [(i * 0x11) as u8; 32];
        tree.set(i, &updated_value.try_into().unwrap());
    }
    let leaf_5 = [5 * 0x11 as u8; 32].try_into().unwrap();
    let proof = tree.create_proof(5);
    c.bench_function("verify_proof", |b| {
        b.iter(|| tree.verify_proof(&leaf_5, &proof))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_initialization, bench_set, bench_create_proof, bench_verify_proof
);
criterion_main!(benches);
