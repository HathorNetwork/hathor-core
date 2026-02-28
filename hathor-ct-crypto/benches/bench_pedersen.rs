use criterion::{criterion_group, criterion_main, Criterion};

fn bench_commitment_creation(c: &mut Criterion) {
    use hathor_ct_crypto::generators::htr_asset_tag;
    use hathor_ct_crypto::pedersen::create_commitment;
    use secp256k1_zkp::rand::rngs::OsRng;
    use secp256k1_zkp::SecretKey;

    let generator = htr_asset_tag();
    let blinding = SecretKey::new(&mut OsRng);

    c.bench_function("pedersen_commitment_create", |b| {
        b.iter(|| create_commitment(1000, &blinding, &generator).unwrap())
    });
}

fn bench_commitment_verify(c: &mut Criterion) {
    use hathor_ct_crypto::generators::htr_asset_tag;
    use hathor_ct_crypto::pedersen::{create_commitment, verify_commitments_sum};
    use secp256k1_zkp::rand::rngs::OsRng;
    use secp256k1_zkp::SecretKey;

    let generator = htr_asset_tag();
    let b1 = SecretKey::new(&mut OsRng);
    let b2 = SecretKey::new(&mut OsRng);

    let c1 = create_commitment(700, &b1, &generator).unwrap();
    let c2 = create_commitment(300, &b2, &generator).unwrap();

    // b_total = b1 + b2
    let mut b_total_bytes = b1.secret_bytes();
    let b2_bytes = b2.secret_bytes();
    // We don't need to verify sum for this benchmark, just check perf
    let _ = b_total_bytes;
    let _ = b2_bytes;

    c.bench_function("pedersen_commitment_verify_sum", |b| {
        b.iter(|| verify_commitments_sum(&[c1, c2], &[]))
    });
}

criterion_group!(benches, bench_commitment_creation, bench_commitment_verify);
criterion_main!(benches);
