use criterion::{criterion_group, criterion_main, Criterion};

fn bench_rangeproof_create(c: &mut Criterion) {
    use hathor_ct_crypto::generators::htr_asset_tag;
    use hathor_ct_crypto::pedersen::create_commitment;
    use hathor_ct_crypto::rangeproof::create_range_proof;
    use secp256k1_zkp::rand::rngs::OsRng;
    use secp256k1_zkp::SecretKey;

    let generator = htr_asset_tag();
    let blinding = SecretKey::new(&mut OsRng);
    let commitment = create_commitment(1000, &blinding, &generator).unwrap();

    c.bench_function("rangeproof_create", |b| {
        b.iter(|| create_range_proof(1000, &blinding, &commitment, &generator, None).unwrap())
    });
}

fn bench_rangeproof_verify(c: &mut Criterion) {
    use hathor_ct_crypto::generators::htr_asset_tag;
    use hathor_ct_crypto::pedersen::create_commitment;
    use hathor_ct_crypto::rangeproof::{create_range_proof, verify_range_proof};
    use secp256k1_zkp::rand::rngs::OsRng;
    use secp256k1_zkp::SecretKey;

    let generator = htr_asset_tag();
    let blinding = SecretKey::new(&mut OsRng);
    let commitment = create_commitment(1000, &blinding, &generator).unwrap();
    let proof = create_range_proof(1000, &blinding, &commitment, &generator, None).unwrap();

    c.bench_function("rangeproof_verify", |b| {
        b.iter(|| verify_range_proof(&proof, &commitment, &generator).unwrap())
    });
}

criterion_group!(benches, bench_rangeproof_create, bench_rangeproof_verify);
criterion_main!(benches);
