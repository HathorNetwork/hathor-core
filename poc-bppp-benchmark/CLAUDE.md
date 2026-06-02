# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

bppp (Bulletproofs++) counterpart of `poc-shielded-benchmark/`. Same benchmark grid
and plotting/PDF pipeline, but the range-proof primitive is swapped from the
Borromean ring-signature rangeproof in `secp256k1-zkp` (via `hathor-ct-crypto/`) to
the u64 Bulletproofs++ range proof from
[distributed-lab/bp-pp](https://github.com/distributed-lab/bp-pp) (Rust crate
`bp-pp = "0.1.1"`).

Pedersen-style value commitments here are bppp's `commit_value = x*g + s*h_vec[0]` —
that is, base points pinned by the bppp protocol setup, **not** the blinded asset
generator coming out of `hathor.crypto.shielded.asset_tag`. The asset surjection
proof side is unchanged: it still operates on the secp256k1-zkp asset commitments.

## Layout

- `hathor-bppp/` — Rust PyO3 crate. Builds the `hathor_bppp` Python extension via
  maturin. Wraps `bp_pp::range_proof::u64_proof::U64RangeProofProtocol` with a
  compact binary proof serializer (33B SEC1 points + 32B scalars + length prefixes).
  Protocol generators are derived deterministically from a fixed ChaCha20 seed —
  this is for benchmarking only, **not** a real shielded-output deployment.
- `bppp_range_proof.py` — thin Python wrapper that re-exports
  `create_commitment` / `create_range_proof` / `verify_range_proof` / `commit_and_prove`
  from `hathor_bppp` with signatures padded to match the Borromean API used in
  `poc-shielded-benchmark/`.
- `benchmark*.py`, `plot_*.py`, `generate_*.py` — copies of the corresponding
  scripts from `poc-shielded-benchmark/`, with their `create_commitment` /
  `create_range_proof` / `verify_range_proof` imports re-routed to
  `bppp_range_proof`. Asset tag + surjection imports are unchanged and still come
  from `hathor.crypto.shielded.*`.

## Building the native module

```bash
# From the hathor-core poetry env:
VIRTUAL_ENV=/home/lyzah/.cache/pypoetry/virtualenvs/hathor--BiNsX2S-py3.11 \
PATH=$VIRTUAL_ENV/bin:$PATH \
maturin develop --release \
    -m poc-bppp-benchmark/hathor-bppp/Cargo.toml
```

or simply, with the env active:

```bash
cd poc-bppp-benchmark/hathor-bppp && make python-release
```

After this, `import hathor_bppp` works inside the same env. The benchmark scripts
expect both `hathor_ct_crypto` (existing) and `hathor_bppp` (new) to be importable.

## Running benchmarks

Same surface as `poc-shielded-benchmark/`:

```bash
python benchmark.py [--max-n 64] [--max-m 64] [--runs 3]
python benchmark_full.py
python benchmark_mixed.py             # surjection-only — unaffected by bppp swap
python benchmark_rust_time_all.py
python benchmark_compare.py
python benchmark_full_compare.py
python benchmark_memory.py
```

Output dirs (`results/`, `results_full/`, `results_memory/`, etc.) and CSV layouts
are kept identical to `poc-shielded-benchmark/` so the plotting and report
scripts work without modification — the only difference is the contents of the
numbers, which reflect bppp performance.

## Plotting / PDFs

```bash
python plot_results.py
python plot_full.py
python plot_mixed.py
python generate_report.py              # → shielded_outputs_report.pdf
python generate_device_table.py        # → shielded_outputs_device_estimates.pdf
python generate_bandwidth_table.py     # → shielded_outputs_bandwidth_estimates.pdf
```

The PDF/report text has been updated to refer to bppp rather than Borromean. The
device-extrapolation ratios (Geekbench-6 single-core, baseline = 1900) and the
device list itself are unchanged from the original folder.

## Key cryptographic differences vs `poc-shielded-benchmark/`

- **Curve**: bp-pp uses the `k256` crate (secp256k1) — same curve as
  `secp256k1-zkp`. Asset tags and surjection proofs from `hathor-ct-crypto`
  still operate on the same curve, so the asset-side pipeline composes.
- **Value commitment**: `x*g + s*h_vec[0]` (bppp protocol generators) — **not**
  `value*blinded_gen + value_blind*G`. Subtraction-to-zero across inputs and
  outputs still works, but only against other bppp commitments; you cannot mix
  bppp and libsecp Pedersen commitments in the same balance check.
- **Range proof size**: ~541 B (constant, full u64) vs ~5000 B Borromean at
  60-bit. bppp also lacks the auto-min-bits shortcut, so `AMOUNT_FOR_SIZING`
  does not affect proof size here.
- **Range proof time**: prover is materially slower (~25x in early
  measurements); verifier is comparable. The trade-off is wire bytes vs
  proving CPU.

## Stable names other scripts depend on

`benchmark_compare.py` / `benchmark_full_compare.py` import these from
`benchmark.py` / `benchmark_full.py`:

- `run_benchmark`, `run_benchmark_rust_time`
- `OUTPUT_DIR`, `RUST_TIME_OUTPUT_DIR`

Keep those names stable. `benchmark_mixed.py` still reaches into
`hathor.crypto.shielded._bindings._lib` for `ZERO_TWEAK` — it is purely a
surjection benchmark and is unchanged by the bppp swap.
