# BLS12-381 (`blst`) signing & verification benchmark

- Date: 2026-06-16
- Purpose: decide the digital-signature backend for two-tier finality. The v1 implementation uses
  `py_ecc` (pure-Python BLS) for clean packaging, but it is slow; this measures the production-grade
  native library (`blst`) to confirm the latency/throughput headroom before committing.
- Related: [`0001-two-tier-finality.md`](0001-two-tier-finality.md) (crypto lives in
  `hathor/finality/crypto.py`, written behind a swappable backend wrapper).

## TL;DR

- `blst` single-thread: **sign ≈ 0.23 ms (~4,300/s)**, **verify ≈ 0.60 ms (~1,650/s)**, **one full
  certificate (FastAggregateVerify) ≈ 0.55–0.64 ms** and **constant in committee size**.
- That is **~400× faster than `py_ecc` for a single verify** and **~1,400× faster for a 100-signer
  certificate**.
- At these speeds the signature is **not** the bottleneck: one certificate verify (0.6 ms) is <0.5%
  of the ~150–300 ms global soft-finality network round-trip. The earlier `py_ecc` slowness (≈16 s to
  verify a 100-vote quorum) is what would have blown the sub-second target; `blst` removes it entirely.
- **Decision implication:** keep BLS; the only production change that matters is swapping the backend
  `py_ecc → blst` behind the existing wrapper. Raw speed should not drive BLS-vs-Schnorr — both are
  orders of magnitude under the network budget — so choose on structure (non-interactive
  observe-then-aggregate, constant-size accountable certificates, no nonce state), which favors BLS.

## Environment

| | |
|---|---|
| CPU | 13th Gen Intel(R) Core(TM) i7-13700K (8 P-cores + 8 E-cores, 24 threads) |
| OS | Linux 6.8.0 |
| Toolchain | rustc/cargo 1.95.0 |
| Library | `blst` v0.3.16 (crate; bundles the blst C library with runtime CPU dispatch / asm) |
| Build | `--release`, `opt-level = 3`, `lto = true`, `codegen-units = 1` |
| Scheme | BLS12-381, **min-pubkey-size** layout (pubkey = 48 B in G1, signature = 96 B in G2) — same as Ethereum consensus and the Hathor finality implementation |
| Ciphersuite / DST | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (proof-of-possession variant) |
| Safety setting | **subgroup checks ON** (`sig_groupcheck = true`, `pk_validate = true`) — the correct setting for untrusted network data |

## Methodology

- Each operation runs a warmup pass, then a fixed iteration count timed with `std::time::Instant`;
  ops/s = iters / elapsed, ms/op = elapsed / iters.
- **sign**: `SecretKey::sign(msg, dst, &[])`.
- **verify (single)**: `Signature::verify(true, msg, dst, &[], &pk, true)` — measured both with and
  without subgroup checks.
- **FastAggregateVerify (one certificate)**: `N` validators sign the *same* message; their signatures
  are aggregated into one 96-byte signature, then verified with
  `Signature::fast_aggregate_verify(true, msg, dst, &pks)`. This is exactly the finality-certificate
  check (same-message aggregation against the committee subset).
- **aggregate**: `AggregateSignature::aggregate(&sigs, false)` — the collector folding votes into a cert.
- **parallel verify**: 24 threads each looping single verifies for 3 s; throughput summed. Verification
  is embarrassingly parallel (no shared state).

The single message is a fixed 47-byte stand-in for the finality pin-message
`sha256("hathor-fc-pin-v1" ‖ committee_hash ‖ tx_id)`; message length does not materially affect the
cost (hash-to-curve dominates the message handling and is ~constant).

## Results (`blst`)

### Single-signer / single-thread

| Operation | Throughput | Latency |
|---|---|---|
| sign (1 vote) | ~4,288 ops/s | 0.233 ms |
| verify (single, with groupcheck) | ~1,650 ops/s | 0.60 ms |
| verify (single, no groupcheck) | ~1,620 ops/s | 0.62 ms |
| aggregate 100 sigs → 1 | ~12,121 ops/s | 0.082 ms |

(Subgroup checks add only a small fraction over the two pairings, so with/without are within noise.)

### Certificate verify — FastAggregateVerify by committee size N (single-thread)

| N (signers) | certs/s | ms/cert | aggregate sig size |
|---:|---:|---:|---:|
| 4 | 1,774 | 0.564 | 96 B |
| 7 | 1,864 | 0.537 | 96 B |
| 10 | 1,853 | 0.540 | 96 B |
| 31 | 1,720 | 0.582 | 96 B |
| 64 | 1,747 | 0.573 | 96 B |
| 100 | 1,671 | 0.598 | 96 B |
| 128 | 1,558 | 0.642 | 96 B |

**Key observation:** cost is essentially flat from N=4 to N=128 — the two pairings dominate; folding the
bitmapped public keys is negligible. Certificate verify time **and** size are independent of committee
size, so the committee can grow for decentralization at no verification cost.

### Multi-threaded verification (whole machine)

| Threads | Total verifies/s |
|---:|---:|
| 1 | ~1,650 |
| 24 | ~16,400 |

Scaling is ~10× rather than 24× because the 13700K's E-cores are much slower than its P-cores,
hyperthreading adds little for compute-bound pairing code, and all-core load throttles clock frequency.
A server with many uniform cores and `blst`'s randomized **batch verification**
(`verify_multiple_aggregate_signatures`, not benchmarked here) would push this several-fold higher.

## Comparison: `blst` vs the shipped `py_ecc` reference

`py_ecc` numbers measured earlier on the same machine (pure-Python, single-thread):

| Operation | `py_ecc` | `blst` | Speedup |
|---|---:|---:|---:|
| sign | 91.9 ms | 0.23 ms | ~400× |
| verify (single) | 239.9 ms | 0.60 ms | ~400× |
| FastAggregateVerify, N=10 | 295 ms | 0.54 ms | ~550× |
| FastAggregateVerify, N=31 | 416 ms | 0.58 ms | ~720× |
| FastAggregateVerify, N=100 | 802 ms | 0.60 ms | ~1,340× |

## Interpretation for the decision

Put the crypto next to the latency budget:

- **One certificate verify** (paid by *every* full node per transaction): **0.6 ms** vs a global
  soft-finality round-trip of **~150–300 ms** → crypto is **<0.5%** of the budget.
- **A validator verifying a full quorum of votes** for a 100-node committee: 67 × 0.6 ms ≈ **40 ms**
  single-threaded, or a few ms parallelized — still dwarfed by the network.
- **Throughput**: ~16 k certificate-verifies/s on a single desktop is far above any realistic payment
  rate; signing (~4,300/s/core) is a non-issue.

With `py_ecc` the same 67 vote-verifies were ≈ **16 seconds** — which is precisely why it would have
broken the RFC's sub-second target and why the backend swap is mandatory. `blst` clears that wall with
large margin.

**BLS vs Schnorr on speed:** a Schnorr verify (no pairing) is ~10–50× faster per op, but a Schnorr-list
certificate needs `O(N)` verifies and is `O(N)` bytes, whereas BLS does **one** op per certificate at
**constant** size. Both land orders of magnitude under the network latency, so **raw signature speed is
not a differentiator**. Decide on the structural properties instead (covered in the plan): non-interactive
observe-then-aggregate, constant-size + accountable certificates, and no nonce state — all of which favor
BLS.

**Recommended production action:** keep BLS and swap the backend from `py_ecc` to `blst` behind the
`hathor/finality/crypto.py` wrapper. In-process this is best done via the project's existing Rust crate
(`htr-rs/crates/htr-lib`, already built and bound as `htr_lib`), exposing sign/verify/aggregate/
fast-aggregate-verify with `sig_groupcheck`/`pk_validate` enabled for network-sourced data.

## Caveats

- Numbers are from a consumer desktop CPU (i7-13700K); production server CPUs will differ (often more
  uniform cores, sometimes lower single-core clock).
- Single-thread figures are the primary signal; the 24-thread number reflects this CPU's hybrid-core
  layout and thermal throttling, not a hard ceiling.
- Subgroup checks are enabled (correct for untrusted input). Trusted/own-data paths could disable them
  for a small speedup, but network-sourced votes/certificates must keep them on.
- Batch verification (`blst`'s randomized multi-aggregate verify) was not measured and would further
  raise verify throughput when validating many votes/certificates together.

## Reproducing

Standalone crate used for this report.

`Cargo.toml`:

```toml
[package]
name = "bls_bench"
version = "0.1.0"
edition = "2021"

[dependencies]
blst = "0.3"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
```

`src/main.rs`:

```rust
use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use std::time::Instant;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn keypair(seed: usize) -> (SecretKey, PublicKey) {
    let mut ikm = [0u8; 32];
    ikm[0] = seed as u8;
    ikm[1] = (seed >> 8) as u8;
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();
    (sk, pk)
}

fn run(name: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..(iters / 10).max(1) { f(); } // warmup
    let t0 = Instant::now();
    for _ in 0..iters { f(); }
    let dt = t0.elapsed().as_secs_f64();
    println!("{:<42}{:>12.0} ops/s   ({:>8.3} ms/op)", name, iters as f64 / dt, dt / iters as f64 * 1000.0);
}

fn main() {
    let msg = b"hathor-fc-pin-v1: 32-byte tx id goes here.......";
    let (sk, pk) = keypair(1);
    let sig = sk.sign(msg, DST, &[]);

    println!("blst BLS12-381 (min-pk), single thread\n");
    println!("=== single-signer ===");
    run("sign (1 vote)", 20000, || { let _ = sk.sign(msg, DST, &[]); });
    run("verify (single vote, with groupcheck)", 20000, || {
        assert_eq!(sig.verify(true, msg, DST, &[], &pk, true), BLST_ERROR::BLST_SUCCESS);
    });
    run("verify (single vote, no groupcheck)", 20000, || {
        assert_eq!(sig.verify(false, msg, DST, &[], &pk, false), BLST_ERROR::BLST_SUCCESS);
    });

    println!("\n=== FastAggregateVerify (one FC, same message), by committee size N ===");
    println!("{:<8}{:>14}{:>14}", "N", "certs/s", "ms/cert");
    for &n in &[4usize, 7, 10, 31, 64, 100, 128] {
        let kps: Vec<(SecretKey, PublicKey)> = (0..n).map(|i| keypair(i + 2)).collect();
        let pks: Vec<PublicKey> = kps.iter().map(|(_, p)| p.clone()).collect();
        let sigs: Vec<Signature> = kps.iter().map(|(s, _)| s.sign(msg, DST, &[])).collect();
        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let agg = AggregateSignature::aggregate(&sig_refs, true).unwrap().to_signature();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();

        let iters = 5000u32;
        for _ in 0..200 { let _ = agg.fast_aggregate_verify(true, msg, DST, &pk_refs); }
        let t0 = Instant::now();
        for _ in 0..iters {
            assert_eq!(agg.fast_aggregate_verify(true, msg, DST, &pk_refs), BLST_ERROR::BLST_SUCCESS);
        }
        let dt = t0.elapsed().as_secs_f64();
        println!("{:<8}{:>14.0}{:>14.3}", n, iters as f64 / dt, dt / iters as f64 * 1000.0);
    }

    println!("\n=== signature aggregation throughput ===");
    let n = 100usize;
    let kps: Vec<(SecretKey, PublicKey)> = (0..n).map(|i| keypair(i + 500)).collect();
    let sigs: Vec<Signature> = kps.iter().map(|(s, _)| s.sign(msg, DST, &[])).collect();
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    run("aggregate 100 sigs -> 1", 20000, || {
        let _ = AggregateSignature::aggregate(&sig_refs, false).unwrap();
    });
}
```

Run:

```sh
cargo run --release
```
