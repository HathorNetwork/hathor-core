use criterion::{criterion_group, criterion_main, Criterion};

fn bench_surjection_create(c: &mut Criterion) {
    use hathor_ct_crypto::generators::{create_asset_commitment, derive_asset_tag};
    use hathor_ct_crypto::surjection::create_surjection_proof;
    use secp256k1_zkp::rand::rngs::OsRng;
    use secp256k1_zkp::SecretKey;

    let token_uid = [1u8; 32];
    let tag = derive_asset_tag(&token_uid).unwrap();
    let r_asset = SecretKey::new(&mut OsRng);
    let output_asset = create_asset_commitment(&tag, &r_asset).unwrap();

    let input_assets = vec![tag];
    let input_blindings = vec![SecretKey::from_slice(&[0u8; 32]).unwrap_or_else(|_| {
        // Use a dummy zero blinding for trivial inputs
        SecretKey::new(&mut OsRng)
    })];
    let seed = [42u8; 32];

    c.bench_function("surjection_create_1_input", |b| {
        b.iter(|| {
            create_surjection_proof(
                &output_asset,
                &r_asset,
                &input_assets,
                &input_blindings,
                0,
                &seed,
            )
            .unwrap()
        })
    });
}

fn bench_surjection_verify(c: &mut Criterion) {
    use hathor_ct_crypto::generators::{create_asset_commitment, derive_asset_tag};
    use hathor_ct_crypto::surjection::create_surjection_proof;
    use secp256k1_zkp::rand::rngs::OsRng;
    use secp256k1_zkp::SecretKey;

    let token_uid = [1u8; 32];
    let tag = derive_asset_tag(&token_uid).unwrap();
    let r_asset = SecretKey::new(&mut OsRng);
    let output_asset = create_asset_commitment(&tag, &r_asset).unwrap();

    let input_assets = vec![tag];
    let input_blindings =
        vec![SecretKey::from_slice(&[0u8; 32]).unwrap_or_else(|_| SecretKey::new(&mut OsRng))];
    let seed = [42u8; 32];

    let proof = create_surjection_proof(
        &output_asset,
        &r_asset,
        &input_assets,
        &input_blindings,
        0,
        &seed,
    )
    .unwrap();

    c.bench_function("surjection_verify_1_input", |b| {
        b.iter(|| {
            hathor_ct_crypto::surjection::verify_surjection_proof(
                &proof,
                &output_asset,
                &input_assets,
            )
            .unwrap()
        })
    });
}

criterion_group!(benches, bench_surjection_create, bench_surjection_verify);
criterion_main!(benches);
