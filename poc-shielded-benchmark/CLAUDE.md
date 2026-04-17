# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

Proof-of-concept benchmarks for Hathor's shielded-outputs cryptography (issue #1603). Measures creation and verification times of Pedersen commitments, Bulletproof range proofs, and asset surjection proofs across grids of (N shielded inputs × M shielded outputs).

## Dependency on hathor-core

These scripts import `hathor.crypto.shielded.*` from a sibling checkout expected at `../hathor-core` (relative to this directory). Each benchmark script prepends that path to `sys.path` at import time. The hathor-core checkout must have the compiled Rust FFI bindings (`_bindings._lib`) built — without them, imports fail.

The cryptographic primitives used:
- `asset_tag`: `derive_tag`, `derive_asset_tag`, `create_asset_commitment` (blind a generator: `A = H_token + r_asset·G`)
- `commitment.create_commitment`: Pedersen commitment over a blinded generator
- `range_proof.create_range_proof` / `verify_range_proof`: Bulletproofs
- `surjection.create_surjection_proof` / `verify_surjection_proof`: asset surjection over a domain of input tags

Surjection proof creation is probabilistic (random subset sampling) and can fail; scripts retry up to `MAX_PROOF_RETRIES` (5).

## Running benchmarks

All scripts are standalone — run from this directory:

```bash
python benchmark.py [--max-n 64] [--max-m 64] [--runs 3]
python benchmark_full.py          # Pedersen + range proof + surjection combined
python benchmark_mixed.py         # fixed 64 total inputs, sweep shielded/transparent split
python benchmark_rust_time_all.py # times only Rust FFI calls, excluding Python loop overhead
python benchmark_compare.py       # runs both Python-loop and Rust-only, plots side-by-side
python benchmark_full_compare.py
```

Each writes CSVs (rows=N, cols=M, values=avg seconds) to its own `results_*/` directory:
- `benchmark.py` → `results/` and `results_rust_time/`
- `benchmark_full.py` → `results_full/` and `results_full_rust_time/` (six CSVs each: pedersen/surjection/total × create/verify)
- `benchmark_mixed.py` → `results_mixed/`
- `benchmark_compare.py` → `results_compare/`
- `benchmark_full_compare.py` → `results_full_compare/`

## Plotting

```bash
python plot_results.py   # heatmaps from results/
python plot_full.py      # heatmaps from results_full/
python plot_mixed.py     # from results_mixed/
```

`benchmark_compare.py` / `benchmark_full_compare.py` generate their own comparison plots directly.

## PDF reports

Two scripts read existing CSVs and render styled PDF reports — they do not re-run benchmarks:

```bash
python generate_report.py         # → shielded_outputs_report.pdf (narrative + heatmaps from results/, results_full/, results_mixed/)
python generate_device_table.py   # → shielded_outputs_device_estimates.pdf (extrapolates the diagonal of results_full/ to a fixed device list via Geekbench 6 single-core ratios; baseline score = 1900)
```

The device table's hardware list, Geekbench scores, and color bins are hard-coded constants at the top of `generate_device_table.py`.

## Code layout notes

- The `*_compare.py` scripts import from `benchmark.py` / `benchmark_full.py` (functions `run_benchmark`, `run_benchmark_rust_time`, and the `OUTPUT_DIR` / `RUST_TIME_OUTPUT_DIR` constants) — keep those names stable.
- `benchmark_mixed.py` reaches into `hathor.crypto.shielded._bindings._lib` directly (to use `ZERO_TWEAK` for unblinded transparent-input generators in the surjection domain).
- N/M sweep values are powers of 2 intersected with `range(1, max+1)`, plus the max itself.
- Each shielded input/output is built with a deterministic 32-byte token UID derived from `index.to_bytes(32, 'big')`.
