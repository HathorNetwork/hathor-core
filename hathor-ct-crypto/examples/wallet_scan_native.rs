//! Native-Rust ("rust-pure") wallet-scan baseline.
//!
//! Zero-overhead twin of `poc-stream-benchmark/benchmark_wallet_scan.py`. It
//! runs the SAME 7-phase wallet pass over a stream of FullShielded txs, but
//! against the `hathor-ct-crypto` crate functions DIRECTLY — no PyO3, no NAPI,
//! no wasm marshalling. The gap between this row and the `python-ffi` /
//! `node-napi` / `wasm` rows in the shared CSV is the binding/runtime overhead.
//!
//! It appends one averaged `binding=rust-pure` row (same column schema) to
//!   poc-stream-benchmark/results_wallet/wallet_scan.csv
//! so all four bindings sit in one comparison table. The CSV is append-only.
//!
//! METHODOLOGY — why we deserialize INSIDE the timed phases:
//!   A wallet receives proofs/commitments as bytes off the wire. Every binding's
//!   verify/rewind entry point deserializes those bytes natively before doing the
//!   crypto (e.g. the wasm `rewind_full_shielded_output` calls
//!   `deserialize_commitment` / `deserialize_range_proof` / `deserialize_generator`
//!   internally; the python FFI `rewind_range_proof` does the same). That native
//!   deserialization is NOT binding overhead — it is library work. So we keep it
//!   inside the timers here. The ONLY thing the bindings add on top is the
//!   language-boundary marshalling, which is exactly what `binding_time -
//!   rust_pure_time` isolates. Stream construction (building the proofs) is prep
//!   and is NOT timed, matching the Python benchmark.
//!
//! The ECDH glue (shared-secret + SHA256 rewind-nonce KDF) is inlined here
//! because the core `hathor-ct-crypto` crate has no `ecdh` module — that lives
//! in the binding crates (`hathor-ct-crypto-wasm` / `-node`). The inlined logic
//! is a byte-for-byte copy of those crates' `ecdh.rs`, so the nonce derivation
//! (and therefore the rewindable proofs) match.
//!
//! Single token (HTR) throughout; every shielded output is addressed to the
//! wallet's scan key, so every rewind succeeds — the heaviest recovery case.
//!
//! Run (release is essential for a perf baseline):
//!   cargo run --release --example wallet_scan_native -- -N 150 -M 1 --total-outputs 2 -k 64
//!   cargo run --release --example wallet_scan_native -- -N 150 -M 2 --total-outputs 4 -Q 3 --total-inputs 4 --runs 3

use std::collections::HashMap;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use clap::Parser;
use sha2::{Digest, Sha256};

use secp256k1_zkp::ecdh::SharedSecret;
use secp256k1_zkp::{PublicKey, SecretKey, Tweak, ZERO_TWEAK};

use hathor_ct_crypto::balance::{compute_balancing_blinding_factor, verify_balance, BalanceEntry};
use hathor_ct_crypto::generators::{
    create_asset_commitment, derive_asset_tag, derive_tag, deserialize_generator,
};
use hathor_ct_crypto::pedersen::{create_commitment, deserialize_commitment};
use hathor_ct_crypto::rangeproof::{
    create_range_proof, deserialize_range_proof, rewind_range_proof, verify_range_proof,
};
use hathor_ct_crypto::surjection::{
    create_surjection_proof, deserialize_surjection_proof, verify_surjection_proof,
};

type R<T> = Result<T, Box<dyn std::error::Error>>;

/// HTR-like canonical asset (token_uid = 32 zero bytes).
const TOKEN_UID: [u8; 32] = [0u8; 32];
/// Domain separator for the rewind-nonce KDF. MUST match the binding crates' ecdh.rs.
const NONCE_DOMAIN_SEPARATOR: &[u8] = b"Hathor_CT_nonce_v1";
/// Fixed dummy scan-key scalar (arbitrary valid non-zero secp256k1 scalar).
const SCAN_SCALAR: [u8; 32] = [
    0x48, 0x61, 0x74, 0x68, 0x6f, 0x72, 0x5f, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x5f, 0x73, 0x63,
    0x61, 0x6e, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x64, 0x75, 0x6d, 0x6d, 0x79, 0x2a, 0x2a, 0x2a, 0x2a,
];
/// Surjection-proof creation is probabilistic; retry a few times before giving up.
const MAX_SURJECTION_RETRIES: usize = 5;

// ──────────────────────────────────────────────────────────────────────────
// ECDH glue (copied from the binding crates' ecdh.rs so nonces match)
// ──────────────────────────────────────────────────────────────────────────

/// libsecp256k1 default ECDH: SHA256(version || x). Returns the 32-byte secret.
fn ecdh_shared_secret(private_key: &SecretKey, peer_pubkey: &PublicKey) -> [u8; 32] {
    SharedSecret::new(peer_pubkey, private_key).secret_bytes()
}

/// nonce = SHA256("Hathor_CT_nonce_v1" || shared_secret), rehashed until it is a
/// valid secp256k1 scalar (retry probability ~2^-128).
fn derive_rewind_nonce(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NONCE_DOMAIN_SEPARATOR);
    hasher.update(shared_secret);
    let mut result: [u8; 32] = hasher.finalize().into();

    let mut counter: u8 = 0;
    while SecretKey::from_slice(&result).is_err() {
        let mut retry = Sha256::new();
        retry.update(NONCE_DOMAIN_SEPARATOR);
        retry.update(result);
        retry.update([counter]);
        result = retry.finalize().into();
        counter = counter.wrapping_add(1);
    }
    result
}

// ──────────────────────────────────────────────────────────────────────────
// Data structures (mirror the Python ShieldedItem / WalletTx)
// ──────────────────────────────────────────────────────────────────────────

/// A FullShielded input or output. Proof material is kept as BYTES (as a wallet
/// has it off the wire); the cleartext secrets are retained only for build-side
/// balancing and the post-rewind correctness asserts.
struct ShieldedItem {
    amount: u64,
    value_blind: Tweak,             // 32B value blinding factor
    r_asset: Tweak,                 // 32B asset blinding factor
    asset_commitment: Vec<u8>,      // 33B blinded generator (== range/rewind generator)
    commitment: Vec<u8>,            // 33B Pedersen commitment
    range_proof: Vec<u8>,           // Borromean range proof
    surjection_proof: Option<Vec<u8>>, // set on outputs, None on inputs
    ephemeral_pubkey: Option<Vec<u8>>, // 33B, set on outputs (for ECDH rewind)
}

struct WalletTx {
    transparent_inputs: Vec<(u64, [u8; 32])>,
    shielded_inputs: Vec<ShieldedItem>,
    transparent_outputs: Vec<(u64, [u8; 32])>,
    shielded_outputs: Vec<ShieldedItem>,
    surjection_domain: Vec<Vec<u8>>, // input asset generators (33B each, verify side)
}

#[derive(Default, Clone)]
struct PhaseTimes {
    range_s: f64,
    surjection_s: f64,
    balance_s: f64,
    ecdh_s: f64,          // ECDH shared-secret + rewind-nonce KDF (per shielded output)
    rewind_s: f64,        // rewind_range_proof ONLY (plus its native deserialization)
    recover_check_s: f64, // AUDIT-C015 asset-commitment recheck of recovered secrets
    update_s: f64,
    total_s: f64,
}

// ──────────────────────────────────────────────────────────────────────────
// Stream construction (NOT timed — wallet/network prep)
// ──────────────────────────────────────────────────────────────────────────

/// Split `total` into `parts` positive integers summing exactly to `total`.
fn split_amount(total: u64, parts: u64) -> Vec<u64> {
    let base = total / parts;
    let mut out = vec![base; parts as usize];
    let last = out.len() - 1;
    out[last] += total - base * parts;
    out
}

/// A per-tx k-bit value budget in [2^(k-1), 2^k). Every amount is a share of it.
fn pick_budget(k: u32, min_parts: u64) -> u64 {
    let lo: u128 = 1u128 << (k - 1);
    let hi: u128 = if k == 64 { (1u128 << 64) - 1 } else { (1u128 << k) - 1 };
    let span: u128 = hi - lo + 1;
    let r: u128 = if span > 1 { (rand::random::<u64>() as u128) % span } else { 0 };
    let t = (lo + r) as u64;
    assert!(t >= min_parts, "k={k} is too small to split into {min_parts} positive parts");
    t
}

fn make_surjection_proof(
    tag_raw: &secp256k1_zkp::Tag,
    r_asset: &Tweak,
    domain_create: &[(secp256k1_zkp::Generator, secp256k1_zkp::Tag, Tweak)],
) -> R<Vec<u8>> {
    let mut last_err: Option<Box<dyn std::error::Error>> = None;
    for _ in 0..MAX_SURJECTION_RETRIES {
        match create_surjection_proof(tag_raw, r_asset, domain_create) {
            Ok(p) => return Ok(p.serialize()),
            Err(e) => last_err = Some(Box::new(e)),
        }
    }
    Err(last_err.unwrap_or_else(|| "surjection proof creation failed".into()))
}

/// A pre-existing FullShielded UTXO the wallet owns and is now spending. Carries
/// a valid (random-nonce) range proof but no surjection proof / ephemeral key.
fn build_shielded_input(amount: u64) -> R<ShieldedItem> {
    let tag_raw = derive_tag(&TOKEN_UID)?;
    let mut rng = rand::thread_rng();
    let r_asset = Tweak::new(&mut rng);
    let vbf = Tweak::new(&mut rng);
    let asset_comm = create_asset_commitment(&tag_raw, &r_asset)?;
    let commitment = create_commitment(amount, &vbf, &asset_comm)?;
    let proof = create_range_proof(amount, &vbf, &commitment, &asset_comm, None, None)?;
    Ok(ShieldedItem {
        amount,
        value_blind: vbf,
        r_asset,
        asset_commitment: asset_comm.serialize().to_vec(),
        commitment: commitment.serialize().to_vec(),
        range_proof: proof.serialize(),
        surjection_proof: None,
        ephemeral_pubkey: None,
    })
}

/// Build a FullShielded output addressed to the wallet's scan key. The range
/// proof is made rewindable: nonce from ECDH(ephemeral_priv, scan_pub), message
/// embeds token_uid || r_asset.
fn seal_shielded_output(
    amount: u64,
    vbf: Tweak,
    r_asset: Tweak,
    scan_pub: &PublicKey,
    domain_create: &[(secp256k1_zkp::Generator, secp256k1_zkp::Tag, Tweak)],
) -> R<ShieldedItem> {
    let tag_raw = derive_tag(&TOKEN_UID)?;
    let asset_comm = create_asset_commitment(&tag_raw, &r_asset)?;
    let commitment = create_commitment(amount, &vbf, &asset_comm)?;

    let eph_priv = SecretKey::new(&mut rand::thread_rng());
    let eph_pub = PublicKey::from_secret_key_global(&eph_priv);
    let shared = ecdh_shared_secret(&eph_priv, scan_pub);
    let nonce_sk = SecretKey::from_slice(&derive_rewind_nonce(&shared))?;

    let mut message = [0u8; 64];
    message[..32].copy_from_slice(&TOKEN_UID);
    message[32..].copy_from_slice(r_asset.as_ref());

    let proof = create_range_proof(
        amount,
        &vbf,
        &commitment,
        &asset_comm,
        Some(&message[..]),
        Some(&nonce_sk),
    )?;
    let surjection = make_surjection_proof(&tag_raw, &r_asset, domain_create)?;

    Ok(ShieldedItem {
        amount,
        value_blind: vbf,
        r_asset,
        asset_commitment: asset_comm.serialize().to_vec(),
        commitment: commitment.serialize().to_vec(),
        range_proof: proof.serialize(),
        surjection_proof: Some(surjection),
        ephemeral_pubkey: Some(eph_pub.serialize().to_vec()),
    })
}

#[allow(clippy::too_many_arguments)]
fn build_tx(m: u64, m_prime: u64, q: u64, q_prime: u64, k: u32, scan_pub: &PublicKey) -> R<WalletTx> {
    let total = pick_budget(k, m_prime.max(q_prime));
    let mut rng = rand::thread_rng();

    // ---- Inputs ----
    let in_values = split_amount(total, q_prime);
    let n_transparent_in = (q_prime - q) as usize;
    let transparent_in_values = &in_values[..n_transparent_in];
    let shielded_in_values = &in_values[n_transparent_in..];
    let transparent_inputs: Vec<(u64, [u8; 32])> =
        transparent_in_values.iter().map(|&v| (v, TOKEN_UID)).collect();
    let shielded_inputs: Vec<ShieldedItem> = shielded_in_values
        .iter()
        .map(|&v| build_shielded_input(v))
        .collect::<R<Vec<_>>>()?;

    // Surjection domain = asset generators of ALL inputs.
    let tag_raw = derive_tag(&TOKEN_UID)?;
    let transparent_gen = derive_asset_tag(&TOKEN_UID)?;
    let mut domain_create: Vec<(secp256k1_zkp::Generator, secp256k1_zkp::Tag, Tweak)> = Vec::new();
    let mut domain_verify: Vec<Vec<u8>> = Vec::new();
    for _ in transparent_inputs.iter() {
        domain_create.push((transparent_gen, tag_raw, ZERO_TWEAK));
        domain_verify.push(transparent_gen.serialize().to_vec());
    }
    for inp in shielded_inputs.iter() {
        let gen = deserialize_generator(&inp.asset_commitment)?;
        domain_create.push((gen, tag_raw, inp.r_asset));
        domain_verify.push(inp.asset_commitment.clone());
    }

    // ---- Outputs ----
    let out_values = split_amount(total, m_prime);
    let n_transparent_out = (m_prime - m) as usize;
    let transparent_out_values = &out_values[..n_transparent_out];
    let shielded_out_values = &out_values[n_transparent_out..];
    let transparent_outputs: Vec<(u64, [u8; 32])> =
        transparent_out_values.iter().map(|&v| (v, TOKEN_UID)).collect();

    // First M-1 shielded outputs get fresh random blinding; the last absorbs the
    // balancing factor. Only shielded entries feed the balancing computation.
    let mut other_secrets: Vec<(u64, Tweak, Tweak)> = Vec::new(); // (value, vbf, r_asset)
    for &v in &shielded_out_values[..shielded_out_values.len() - 1] {
        other_secrets.push((v, Tweak::new(&mut rng), Tweak::new(&mut rng)));
    }
    let last_value = *shielded_out_values.last().unwrap();
    let last_r_asset = Tweak::new(&mut rng);
    let inputs_bf: Vec<(u64, Tweak, Tweak)> =
        shielded_inputs.iter().map(|i| (i.amount, i.value_blind, i.r_asset)).collect();
    let last_vbf =
        compute_balancing_blinding_factor(last_value, &last_r_asset, &inputs_bf, &other_secrets)?;

    let mut shielded_outputs: Vec<ShieldedItem> = Vec::new();
    for (v, vbf, ra) in &other_secrets {
        shielded_outputs.push(seal_shielded_output(*v, *vbf, *ra, scan_pub, &domain_create)?);
    }
    shielded_outputs.push(seal_shielded_output(
        last_value,
        last_vbf,
        last_r_asset,
        scan_pub,
        &domain_create,
    )?);

    Ok(WalletTx {
        transparent_inputs,
        shielded_inputs,
        transparent_outputs,
        shielded_outputs,
        surjection_domain: domain_verify,
    })
}

fn build_stream(
    n: u64,
    m: u64,
    m_prime: u64,
    q: u64,
    q_prime: u64,
    k: u32,
    scan_pub: &PublicKey,
) -> R<Vec<WalletTx>> {
    (0..n).map(|_| build_tx(m, m_prime, q, q_prime, k, scan_pub)).collect()
}

// ──────────────────────────────────────────────────────────────────────────
// The wallet pass (TIMED)
// ──────────────────────────────────────────────────────────────────────────

fn wallet_pass(txs: &[WalletTx], scan_priv: &SecretKey) -> R<(PhaseTimes, HashMap<[u8; 32], u128>)> {
    let mut t = PhaseTimes::default();
    let mut balances: HashMap<[u8; 32], u128> = HashMap::new();

    let wall0 = Instant::now();
    for tx in txs {
        // 1. Range proofs — shielded outputs and shielded inputs. One verify per
        //    proof (no batch). Deserialization is native, so it stays in-bucket.
        let t0 = Instant::now();
        for out in &tx.shielded_outputs {
            let proof = deserialize_range_proof(&out.range_proof)?;
            let comm = deserialize_commitment(&out.commitment)?;
            let gen = deserialize_generator(&out.asset_commitment)?;
            verify_range_proof(&proof, &comm, &gen).expect("range verify failed");
        }
        for inp in &tx.shielded_inputs {
            let proof = deserialize_range_proof(&inp.range_proof)?;
            let comm = deserialize_commitment(&inp.commitment)?;
            let gen = deserialize_generator(&inp.asset_commitment)?;
            verify_range_proof(&proof, &comm, &gen).expect("range verify failed");
        }
        t.range_s += t0.elapsed().as_secs_f64();

        // 2. Surjection proofs — one per shielded output, against the input domain.
        let t0 = Instant::now();
        let domain: Vec<secp256k1_zkp::Generator> = tx
            .surjection_domain
            .iter()
            .map(|b| deserialize_generator(b))
            .collect::<hathor_ct_crypto::Result<Vec<_>>>()?;
        for out in &tx.shielded_outputs {
            let proof = deserialize_surjection_proof(out.surjection_proof.as_ref().unwrap())?;
            let codomain = deserialize_generator(&out.asset_commitment)?;
            verify_surjection_proof(&proof, &codomain, &domain).expect("surjection verify failed");
        }
        t.surjection_s += t0.elapsed().as_secs_f64();

        // 3. Balance — single homomorphic check folding all in/out commitments.
        let t0 = Instant::now();
        let mut inputs_entries: Vec<BalanceEntry> = Vec::new();
        for (amount, token_uid) in &tx.transparent_inputs {
            inputs_entries.push(BalanceEntry::Transparent { amount: *amount, token_uid: *token_uid });
        }
        for inp in &tx.shielded_inputs {
            inputs_entries
                .push(BalanceEntry::Shielded { value_commitment: deserialize_commitment(&inp.commitment)? });
        }
        let mut outputs_entries: Vec<BalanceEntry> = Vec::new();
        for (amount, token_uid) in &tx.transparent_outputs {
            outputs_entries
                .push(BalanceEntry::Transparent { amount: *amount, token_uid: *token_uid });
        }
        for out in &tx.shielded_outputs {
            outputs_entries
                .push(BalanceEntry::Shielded { value_commitment: deserialize_commitment(&out.commitment)? });
        }
        verify_balance(&inputs_entries, &outputs_entries).expect("balance verify failed");
        t.balance_s += t0.elapsed().as_secs_f64();

        // 4. Recover — per shielded output: ECDH-derive nonce, rewind, recheck.
        //    Three DISTINCT costs, timed separately (matches the Python split).
        let mut recovered: Vec<([u8; 32], u64)> = Vec::new();
        for out in &tx.shielded_outputs {
            let t0 = Instant::now();
            let eph_pub = PublicKey::from_slice(out.ephemeral_pubkey.as_ref().unwrap())?;
            let shared = ecdh_shared_secret(scan_priv, &eph_pub);
            let nonce_sk = SecretKey::from_slice(&derive_rewind_nonce(&shared))?;
            t.ecdh_s += t0.elapsed().as_secs_f64();

            let t0 = Instant::now();
            let comm = deserialize_commitment(&out.commitment)?;
            let proof = deserialize_range_proof(&out.range_proof)?;
            let gen = deserialize_generator(&out.asset_commitment)?;
            let (value, _blinding, message) = rewind_range_proof(&proof, &comm, &nonce_sk, &gen)?;
            t.rewind_s += t0.elapsed().as_secs_f64();

            let t0 = Instant::now();
            let token_id: [u8; 32] = message[..32].try_into().unwrap();
            let asset_bf = Tweak::from_slice(&message[32..64])?;
            // AUDIT-C015: reconstruct the asset commitment from recovered secrets.
            let recomputed = create_asset_commitment(&derive_tag(&token_id)?, &asset_bf)?;
            assert_eq!(
                recomputed.serialize().as_slice(),
                out.asset_commitment.as_slice(),
                "recovered token UID does not match asset_commitment"
            );
            assert_eq!(value, out.amount, "rewound value mismatch");
            t.recover_check_s += t0.elapsed().as_secs_f64();

            recovered.push((token_id, value));
        }

        // 5. Balance update — accumulate per-token totals over the whole stream.
        let t0 = Instant::now();
        for (token_id, value) in recovered {
            *balances.entry(token_id).or_insert(0) += value as u128;
        }
        for (value, token_uid) in &tx.transparent_outputs {
            *balances.entry(*token_uid).or_insert(0) += *value as u128;
        }
        t.update_s += t0.elapsed().as_secs_f64();
    }
    t.total_s = wall0.elapsed().as_secs_f64();
    Ok((t, balances))
}

// ──────────────────────────────────────────────────────────────────────────
// CLI + runner
// ──────────────────────────────────────────────────────────────────────────

/// Native-Rust ("rust-pure") wallet-scan baseline. Same scenario + CSV schema as
/// benchmark_wallet_scan.py, but calling the crate directly (no FFI/runtime).
#[derive(Parser)]
#[command(name = "wallet_scan_native")]
struct Args {
    /// N: transactions in the stream.
    #[arg(short = 'N', long = "num-txs", default_value_t = 150)]
    n: u64,
    /// M: shielded outputs per tx (>= 1).
    #[arg(short = 'M', long = "shielded-outputs", default_value_t = 1)]
    m: u64,
    /// M': total outputs per tx (>= M).
    #[arg(long = "total-outputs", default_value_t = 2)]
    m_prime: u64,
    /// Q: shielded inputs per tx (>= 0).
    #[arg(short = 'Q', long = "shielded-inputs", default_value_t = 0)]
    q: u64,
    /// Q': total inputs per tx (>= Q and >= 1).
    #[arg(long = "total-inputs", default_value_t = 1)]
    q_prime: u64,
    /// k: amount bit-width, v in [0, 2^k).
    #[arg(short = 'k', long = "bits", default_value_t = 64)]
    k: u32,
    /// Independent stream rebuilds, arithmetic-mean averaged.
    #[arg(long, default_value_t = 1)]
    runs: u64,
    /// Crypto binding label written to the CSV's `binding` column.
    #[arg(long, default_value = "rust-pure")]
    binding: String,
    /// Directory for wallet_scan.csv (defaults to the shared poc results dir).
    #[arg(long = "output-dir", default_value_t = default_output_dir())]
    output_dir: String,
}

fn default_output_dir() -> String {
    // Absolute, relative to this crate, so cwd doesn't matter.
    format!("{}/../poc-stream-benchmark/results_wallet", env!("CARGO_MANIFEST_DIR"))
}

fn validate(a: &Args) -> R<()> {
    if a.n < 1 {
        return Err("N must be >= 1".into());
    }
    if a.m < 1 {
        return Err("M (shielded outputs) must be >= 1".into());
    }
    if a.m_prime < a.m {
        return Err("M' (total outputs) must be >= M".into());
    }
    if a.q_prime < a.q {
        return Err("Q' (total inputs) must be >= Q".into());
    }
    if a.q_prime < 1 {
        return Err("Q' must be >= 1 (FullShielded outputs need a non-empty surjection domain)".into());
    }
    if !(1..=64).contains(&a.k) {
        return Err("k must be in [1, 64] (amounts are u64)".into());
    }
    if (1u128 << (a.k - 1)) < a.m_prime.max(a.q_prime) as u128 {
        return Err(format!("k={} is too small to give every input/output a positive share", a.k).into());
    }
    if a.runs < 1 {
        return Err("--runs must be >= 1".into());
    }
    Ok(())
}

fn safe_ms(seconds: f64, count: u64) -> f64 {
    if count > 0 { seconds / count as f64 * 1000.0 } else { 0.0 }
}

fn main() -> R<()> {
    let args = Args::parse();
    validate(&args)?;

    let scan_priv = SecretKey::from_slice(&SCAN_SCALAR)?;
    let scan_pub = PublicKey::from_secret_key_global(&scan_priv);

    println!(
        "Wallet-scan benchmark (rust-pure) | N={} M={} M'={} Q={} Q'={} k={} runs={} binding={}",
        args.n, args.m, args.m_prime, args.q, args.q_prime, args.k, args.runs, args.binding
    );
    println!(
        "  tx shape: {} shielded + {} transparent inputs -> {} shielded + {} transparent outputs",
        args.q,
        args.q_prime - args.q,
        args.m,
        args.m_prime - args.m
    );

    let mut samples: Vec<PhaseTimes> = Vec::new();
    for r in 0..args.runs {
        let txs = build_stream(args.n, args.m, args.m_prime, args.q, args.q_prime, args.k, &scan_pub)?;
        let (timing, _balances) = wallet_pass(&txs, &scan_priv)?;
        println!(
            "  run {}/{}: total={:7.3}s [range={:6.3} surj={:6.3} bal={:6.3} ecdh={:6.3} \
             rewind={:6.3} recheck={:6.4} update={:6.4}]",
            r + 1,
            args.runs,
            timing.total_s,
            timing.range_s,
            timing.surjection_s,
            timing.balance_s,
            timing.ecdh_s,
            timing.rewind_s,
            timing.recover_check_s,
            timing.update_s
        );
        samples.push(timing);
    }

    let n_samples = samples.len() as f64;
    let total_s = samples.iter().map(|s| s.total_s).sum::<f64>() / n_samples;
    let range_s = samples.iter().map(|s| s.range_s).sum::<f64>() / n_samples;
    let surj_s = samples.iter().map(|s| s.surjection_s).sum::<f64>() / n_samples;
    let bal_s = samples.iter().map(|s| s.balance_s).sum::<f64>() / n_samples;
    let ecdh_s = samples.iter().map(|s| s.ecdh_s).sum::<f64>() / n_samples;
    let rewind_s = samples.iter().map(|s| s.rewind_s).sum::<f64>() / n_samples;
    let recheck_s = samples.iter().map(|s| s.recover_check_s).sum::<f64>() / n_samples;
    let update_s = samples.iter().map(|s| s.update_s).sum::<f64>() / n_samples;

    let n_range = args.n * (args.m + args.q);
    let n_surj = args.n * args.m;
    let n_out = args.n * args.m;
    let n_balance = args.n;

    println!();
    println!("  AVERAGE over {} run(s): total {:.3}s  ({:.3} ms/tx)", args.runs, total_s, total_s / args.n as f64 * 1000.0);
    println!("    range       {:8.3}s  {:8.3} ms/proof  ({} proofs)", range_s, safe_ms(range_s, n_range), n_range);
    println!("    surjection  {:8.3}s  {:8.3} ms/proof  ({} proofs)", surj_s, safe_ms(surj_s, n_surj), n_surj);
    println!("    balance     {:8.3}s  {:8.3} ms/tx     ({} txs)", bal_s, safe_ms(bal_s, n_balance), n_balance);
    println!("    ecdh+nonce  {:8.3}s  {:8.3} ms/output ({} outputs)", ecdh_s, safe_ms(ecdh_s, n_out), n_out);
    println!("    rewind      {:8.3}s  {:8.3} ms/output ({} outputs)", rewind_s, safe_ms(rewind_s, n_out), n_out);
    println!("    recover-chk {:8.3}s  {:8.3} ms/output ({} outputs)", recheck_s, safe_ms(recheck_s, n_out), n_out);
    println!("    update      {:8.4}s", update_s);

    // Append one row to the shared CSV, same column order as benchmark_wallet_scan.py.
    create_dir_all(&args.output_dir)?;
    let csv_path = format!("{}/wallet_scan.csv", args.output_dir);
    let header = "binding,n,shielded_outputs,total_outputs,shielded_inputs,total_inputs,bits,runs,\
        total_s,range_verify_s,surjection_verify_s,balance_verify_s,ecdh_s,rewind_s,\
        recover_check_s,balance_update_s,per_tx_total_ms,num_range_verifs,num_surjection_verifs,\
        num_shielded_outputs,per_range_verify_ms,per_surjection_verify_ms,per_balance_verify_ms,\
        per_ecdh_ms,per_rewind_ms,per_recover_check_ms";
    let write_header = !Path::new(&csv_path).exists();
    let row = format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        args.binding, args.n, args.m, args.m_prime, args.q, args.q_prime, args.k, args.runs,
        total_s, range_s, surj_s, bal_s, ecdh_s, rewind_s,
        recheck_s, update_s, total_s / args.n as f64 * 1000.0, n_range, n_surj,
        n_out, safe_ms(range_s, n_range), safe_ms(surj_s, n_surj), safe_ms(bal_s, n_balance),
        safe_ms(ecdh_s, n_out), safe_ms(rewind_s, n_out), safe_ms(recheck_s, n_out)
    );
    let mut f = OpenOptions::new().create(true).append(true).open(&csv_path)?;
    if write_header {
        writeln!(f, "{header}")?;
    }
    writeln!(f, "{row}")?;
    println!(
        "\n  {} -> {}",
        if write_header { "wrote header + 1 row" } else { "appended 1 row" },
        csv_path
    );
    Ok(())
}
