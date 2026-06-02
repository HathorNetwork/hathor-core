# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## Purpose

Stream-throughput benchmarks for Hathor's shielded-output stack (Pedersen
commitments + Borromean range proofs + asset surjection). Sweeps streams of
100…1000 transactions across tx shapes (2×2, 4×4, 8×8, 16×16) and two privacy
modes:

- `amount_hidden`: Pedersen commitment + Borromean range proof. Token visible.
  Asset generator is the unblinded `H_token`.
- `fully_shielded`: as above, plus asset commitment `A = H_token + r_asset·G`
  and a surjection proof whose domain is the tx's input asset commitments.

Reports proof-creation time, verification time (split balance/range/surjection),
on-wire payload size, and process memory (RSS + tracemalloc) per combo.

## Files

- `stream_common.py` – shared tx construction. `build_stream()` prepares input
  secrets + balanced output amounts; `seal_tx()` builds the actual proofs.
  All txs balance per-tx via `compute_balancing_blinding_factor`, so
  `verify_balance` always returns True.
- `benchmark_stream_time.py` – time sweep. Writes `results_time/stream_time.csv`.
- `benchmark_stream_memory.py` – payload + RSS + tracemalloc sweep. Writes
  `results_memory/stream_memory.csv`.
- `plot_stream.py` – renders the full set of overview PNGs (one curve per
  mode×shape) from both CSVs into `plots/`.
- `plot_stream_shapes.py` – per-mode "shape overlay" view: two stacked subplots
  (verification time on top, proof-creation time below), each with one curve per
  shape, against stream size.
- `benchmark_wallet_scan.py` – self-contained (does **not** use `stream_common`).
  Emulates a wallet scanning a stream of N txs, each with a mix of shielded and
  transparent inputs/outputs (M shielded of M′ outputs, Q shielded of Q′ inputs).
  Per tx it times the wallet's work: verify range proofs (outputs + shielded
  inputs), verify surjection proofs, `verify_balance`, **rewind** every shielded
  output via ECDH (recover value + token, with the AUDIT-C015 token cross-check),
  and update per-token balances. Stream construction is prep and is not timed.
  Appends one averaged row per invocation to `results_wallet/wallet_scan.csv`
  (the `binding` column tags the crypto binding used). FullShielded outputs
  throughout; single token (HTR). Defaults N=150, M=1, M′=2, Q=0, Q′=1, k=64.
  `--binding python-ffi` (default) runs in-process; `--binding node-napi` and
  `--binding wasm` delegate the whole run to the Node/wasm twins below.
- `benchmark_wallet_scan_node.js` – Node twin of the wallet scan, using the
  `@hathor/ct-crypto-node` **NAPI native addon**. Mirrors the Python build +
  same 7-phase timed pass + same CSV schema, tagging rows `binding=node-napi`, so
  python-ffi vs node-napi rows in `wallet_scan.csv` isolate binding/runtime
  overhead. Runs standalone (`node benchmark_wallet_scan_node.js …`) or via the
  Python launcher's `--binding node-napi` (which just spawns it with translated
  args). Needs **Node ≥ 18** and `npm install @hathor/ct-crypto-node`. Uses
  low-level calls (`verifyRangeProof`, `rewindRangeProof`,
  `deriveEcdhSharedSecret`, …) — not the high-level `rewindFullShieldedOutput`
  helper — so the phase split matches the Python side. Amounts are `BigInt`
  (u64); `process.hrtime.bigint()` for timing.
- `benchmark_wallet_scan_wasm.js` – wasm twin, using the `@hathor/ct-crypto-wasm`
  **browser build** (wasm-pack `--target web`; the real wasm32 target, vs the
  node addon). That build is verifier/auditor-scoped: it exposes
  commitment/tag construction + the high-level `rewindFullShieldedOutput` /
  `rewindAmountShieldedOutput` recovery calls, but **no** verify-proof or
  create-proof surface. So only the **recovery** phase is timed; the stream is
  built — untimed — with `@hathor/ct-crypto-node` (wasm can't create range
  proofs). `rewindFullShieldedOutput` bundles ECDH + rewind + the internal
  AUDIT-C015 recheck into one call, so the row records that whole cost as
  `rewind_s` and leaves `ecdh_s`, `recover_check_s` and every verify column
  **blank** — no second external recheck (that would double-count; this mirrors
  how the `shielded-outputs-audit` browser app consumes the build: call it, trust
  the result). Tags rows `binding=wasm`; accepts but ignores M′/Q/Q′. Runs
  standalone or via `--binding wasm`. Needs **Node ≥ 18** +
  `npm install @hathor/ct-crypto-wasm @hathor/ct-crypto-node`.
- `../hathor-ct-crypto/examples/wallet_scan_native.rs` – the **rust-pure**
  baseline (lives in the parent Rust crate, not this dir). Re-implements the exact
  7-phase pass in native Rust against the `hathor-ct-crypto` crate directly — no
  PyO3 / NAPI / wasm marshalling — and appends a `binding=rust-pure` row to this
  dir's `results_wallet/wallet_scan.csv`. It deserializes proof bytes *inside* the
  timed phases (matching what the bindings' native code does internally), so the
  gap between the `rust-pure` row and the others isolates pure binding/runtime
  overhead — the zero-overhead lower bound. Run with cargo (see Running).
- `sweep_wallet_scan.py` – grid driver for the wallet scan across bindings. Runs
  the full Cartesian product N × M (NOT a dot product); per cell the shape is
  "M shielded outputs + M transparent inputs" (`-M m --total-outputs m -Q 0
  --total-inputs m`). Plain python3 (no `hathor` import): shells out to `cargo`
  for rust-pure and to `node` for the node/wasm twins. Writes one shared
  `wallet_scan.csv` (default `results_sweep/`). Defaults k=63 (see the k ceiling
  below). Flags: `--bindings`, `--n-list`, `--m-list`, `-k`, `--runs`, `--node`
  (point at an nvm Node ≥ 18 binary for node/wasm), `--output-dir`, `--dry-run`.
- `summarize_sweep.py` – reads `results_sweep/wallet_scan.csv` and prints the
  cross-binding comparison tables (per-output recovery ms grouped by M, range
  verify ms/proof, total wall time at the largest N).
- `plot_sweep.py` – sweep analog of `plot_stream.py`. Line plots with color =
  binding, marker/linestyle = M, x = N (recovery ms/output, rewind, total time,
  per-tx, range verify), plus a grouped recovery-overhead bar and a per-binding
  stacked phase-breakdown bar. Writes to `plots_sweep/`.
- `plot_sweep_shapes.py` – sweep analog of `plot_stream_shapes.py`. Per binding,
  two stacked subplots (total time on top, per-output recovery below), one curve
  per M. Writes `plots_sweep/sweep_<binding>.png`.

## Batching

The FFI does not expose batched verification for Borromean range proofs or
surjection proofs (those primitives don't admit upstream batch verify the way
Bulletproofs do). The natural cryptographic batch in this stack is
`verify_balance`, which folds all of a tx's input + output commitments into a
single Rust call. The benchmarks use it per-tx; range and surjection
verifications remain per-output loops.

Note: a `batch_verify_range_proofs` exists in the Rust crate
(`hathor-ct-crypto/src/rangeproof.rs`) but it is **not** a cryptographic batch —
it's a sequential `for` loop calling `verify_range_proof`, and it is **not**
registered as a `#[pyfunction]`, so it is unreachable from Python. There is no
speedup to be had from it; don't reach for it expecting one.

## Dependencies

Imports `hathor.crypto.shielded.*` from the parent `hathor-core` checkout (its
poetry-installed `hathor` package). Run via `poetry run` so the FFI Rust
bindings are loadable. `stream_common.py` prepends the parent dir to `sys.path`,
so it resolves `hathor` regardless of cwd; the benchmark scripts then
`from stream_common import …` (a flat import, not a package), so each script's
own directory must be on `sys.path` — running `poetry run python
poc-stream-benchmark/<script>.py` from the parent satisfies this.

Prerequisites:
- **Build the Rust bindings first**: `make build-shielded-crypto` in the parent.
  Until then `hathor.crypto.shielded._bindings._lib` is `None` and every
  proof/verify call raises `RuntimeError: hathor_ct_crypto native library is
  not available`.
- `psutil` (needed by the memory benchmark) is a declared `hathor` dependency.
  `matplotlib` (needed by both plot scripts) is **not** in `pyproject.toml` —
  install it into the venv if the import fails (`poetry run pip install matplotlib`).
- The `node-napi` / `wasm` bindings of `benchmark_wallet_scan.py` need **Node ≥
  18**: node-napi wants `npm install @hathor/ct-crypto-node`; wasm wants
  `npm install @hathor/ct-crypto-wasm @hathor/ct-crypto-node` (wasm for the timed
  recovery, node to build the untimed stream). Without them the run fails fast
  with an install hint; nothing else in this directory needs Node.
- The `rust-pure` baseline is a cargo **example** in the parent crate, not a
  script here. It needs only the Rust toolchain — run it from the parent with
  `cargo run --release --example wallet_scan_native …` (release matters; it's a
  perf baseline). Heads-up: a bare `cargo bench` in `hathor-ct-crypto/` currently
  fails to build because the older criterion benches (`bench_rangeproof.rs`, …)
  still call `create_range_proof` with its pre-`nonce` 5-arg signature. The
  example is unaffected — `cargo run --example wallet_scan_native` builds only the
  lib + example, which is verified to compile.

## Running

```bash
# Defaults: shapes 2x2,4x4,8x8,16x16 | stream sizes 100..1000 | runs 1 | both modes
poetry run python poc-stream-benchmark/benchmark_stream_time.py
poetry run python poc-stream-benchmark/benchmark_stream_memory.py
poetry run python poc-stream-benchmark/plot_stream.py
poetry run python poc-stream-benchmark/plot_stream_shapes.py

# Wallet-scan scenario (default N=150, M=1, M'=2, Q=0, Q'=1, k=64):
poetry run python poc-stream-benchmark/benchmark_wallet_scan.py
```

Full sweep is heavy: 16×16 fully-shielded × 1000 tx ≈ a few minutes per stream
size. Trim `--shapes` or `--stream-sizes` for quick checks.

## CLI flags

### `benchmark_stream_time.py` and `benchmark_stream_memory.py`

Both benchmark scripts accept the same set of flags.

| Flag | Default | What it does |
| --- | --- | --- |
| `--runs N` | `1` | Number of independent stream rebuilds averaged per (mode, shape, stream_size) cell. Each rebuild generates fresh inputs and output secrets. Time benchmark takes the arithmetic mean; memory benchmark takes the mean for payload bytes and the median for RSS / tracemalloc (median suppresses single outliers from background activity). |
| `--shapes a×b,c×d,…` | `2x2,4x4,8x8,16x16` | Comma-separated list of tx shapes. Each entry is `INPUTSxOUTPUTS` (also accepts `i,o`). |
| `--stream-sizes s1,s2,…` | `100,200,…,1000` | Comma-separated stream sizes (transactions per stream). |
| `--mode {amount_hidden, fully_shielded, both}` | `both` | Which privacy mode(s) to run. |
| `--output-dir PATH` | `results_time/` or `results_memory/` | Where the CSV is written. Created if missing. |

Example:

```bash
# Quick check: only 2x2 and 4x4, three stream sizes, two runs averaged.
poetry run python poc-stream-benchmark/benchmark_stream_time.py \
  --runs 2 --shapes 2x2,4x4 --stream-sizes 100,500,1000 --mode fully_shielded
```

### `benchmark_wallet_scan.py`

| Flag | Default | What it does |
| --- | --- | --- |
| `-N, --num-txs` | `150` | N: transactions in the stream. |
| `-M, --shielded-outputs` | `1` | M: shielded (FullShielded) outputs per tx. Must be ≥ 1. |
| `--total-outputs` | `2` | M′: total outputs per tx (the other M′−M are transparent). Must be ≥ M. |
| `-Q, --shielded-inputs` | `0` | Q: shielded inputs per tx. |
| `--total-inputs` | `1` | Q′: total inputs per tx (the other Q′−Q are transparent). Must be ≥ Q and ≥ 1. |
| `-k, --bits` | `64` | k: amount bit-width. Every amount is a share of a k-bit budget, so all values are in [0, 2^k). |
| `--runs N` | `1` | Independent stream rebuilds, arithmetic-mean averaged. |
| `--binding {python-ffi, node-napi, wasm}` | `python-ffi` | Crypto binding. `python-ffi` runs in-process (PyO3); `node-napi` delegates to `benchmark_wallet_scan_node.js` (@hathor/ct-crypto-node); `wasm` delegates to `benchmark_wallet_scan_wasm.js` (@hathor/ct-crypto-wasm, recovery-only — verify/ecdh/recover-check columns left blank). A fourth label, `rust-pure`, is produced separately by the cargo example. The chosen value is written to the CSV's `binding` column. |
| `--output-dir PATH` | `results_wallet/` | Where `wallet_scan.csv` is appended. Created if missing. |

The CSV is **append-only** (one averaged row per invocation, header written once),
so sweeping params or bindings accumulates a comparison table. Delete the file to
start fresh.

Caveat on `k`: the FFI's `create_range_proof` does not take a bit-width — it
auto-sizes, so the proof's real bit-length tracks the value's magnitude. `k` is
realized purely as the amount magnitude; it is not a settable proof bound. It
still moves the cost: smaller `k` ⇒ smaller, faster proofs (e.g. k=16
range-verify ≈ 1.1 ms/proof vs k=63 ≈ 5 ms/proof).

**k ceiling = 63, not 64.** The rangeproof uses `min_value=1` (VULN-005), and it
**cannot prove a top-bit-set 64-bit amount**: `min_value + 2^64` overflows u64, so
`create_range_proof` fails with "failed to generate range proof". Amounts must
stay `< 2^63`. The default M′=2 hides this (it splits the budget into sub-2^63
shares), but any **un-split single amount ≥ 2^63 fails** — e.g. an M=1 tx with
M′=M at k=64, or the node/wasm twins whose `pickValue` draws each amount from
`[2^(k-1), 2^k)`. Use **k ≤ 63**. `sweep_wallet_scan.py` defaults to k=63 for
exactly this reason.

```bash
# Heavier wallet shape: 2 shielded + 2 transparent outs, 3 shielded + 4 inputs.
poetry run python poc-stream-benchmark/benchmark_wallet_scan.py \
  -N 150 -M 2 --total-outputs 4 -Q 3 --total-inputs 4 -k 64 --runs 3

# Same scenario through the Node binding (needs Node>=18 + @hathor/ct-crypto-node).
# Appends a binding=node-napi row to the same wallet_scan.csv for direct comparison:
poetry run python poc-stream-benchmark/benchmark_wallet_scan.py --runs 3 --binding node-napi
# (equivalently, run the Node twin directly:)
node poc-stream-benchmark/benchmark_wallet_scan_node.js --runs 3

# Through the wasm binding (needs Node>=18 + @hathor/ct-crypto-wasm + -node).
# Recovery-only; appends a binding=wasm row:
poetry run python poc-stream-benchmark/benchmark_wallet_scan.py --runs 3 --binding wasm

# The rust-pure baseline (zero-overhead lower bound) — run from the parent repo
# root with cargo; appends a binding=rust-pure row to the SAME wallet_scan.csv.
# --release is essential (it's a perf baseline). Same flags as the Python script:
cargo run --release --example wallet_scan_native \
  --manifest-path hathor-ct-crypto/Cargo.toml -- --runs 3
```

### `plot_stream.py`

Renders the full overview set (14 PNGs: total/per-tx create+verify time, tps,
verify-time breakdown, payload bytes total/per-tx/breakdown, RSS peak build &
verify, RSS Δpeak, tracemalloc peak).

| Flag | Default | What it does |
| --- | --- | --- |
| `--time-csv PATH` | `results_time/stream_time.csv` | Input CSV from `benchmark_stream_time.py`. Time plots are skipped if the file is missing. |
| `--memory-csv PATH` | `results_memory/stream_memory.csv` | Input CSV from `benchmark_stream_memory.py`. Memory plots are skipped if the file is missing. |
| `--plot-dir PATH` | `plots/` | Output directory for PNGs. Created if missing. |

### `plot_stream_shapes.py`

Per-mode shape-overlay figure (one per mode): two stacked subplots — verify
time on top, proof-creation time below — with one curve per shape.

| Flag | Default | What it does |
| --- | --- | --- |
| `--csv PATH` | `results_time/stream_time.csv` | Input CSV from `benchmark_stream_time.py`. |
| `--plot-dir PATH` | `plots/` | Output directory for PNGs. |
| `--per-tx` | off | Plot per-tx milliseconds instead of total seconds. Useful when total-time curves spread across orders of magnitude. |
| `--logy` | off | Log-scale the y axis on both subplots. Combine with or without `--per-tx`. |

Outputs `plots/shapes_amount_hidden.png` and `plots/shapes_fully_shielded.png`
(with `_per_tx` suffix when `--per-tx` is set).

## Notes

- The range proof here is **Borromean** (libsecp256k1-zkp's classic rangeproof),
  not a Bulletproof. The `range_proof.py` docstrings say "Bulletproof" but the
  Rust crate uses `secp256k1_zkp::RangeProof`.
- In `fully_shielded`, `seal_tx` sets `asset_commitment = blinded_gen` — they are
  the *same* curve point (`H_token + r_asset·G`), reused both as the verify
  generator and as the on-wire asset commitment. So in the payload accounting
  `blinded_gens_bytes` already covers the asset-commitment bytes; they aren't
  counted twice but they aren't independent either.
- Surjection-proof creation is **probabilistic**: `seal_tx` retries
  `create_surjection_proof` up to `MAX_SURJECTION_RETRIES` (5) before
  propagating the `ValueError`. This is build-side only; verification is
  deterministic.
- Timing excludes prep: `build_stream` (input secrets + balanced output
  amounts/vbfs) is **not** timed — only `seal_tx` (creation) and the verify
  pass are. The rationale is that a wallet would prepare inputs ahead of time.
- In `benchmark_wallet_scan.py` the per-output recovery is split into three
  separate timers — **don't lump them**. Measured at k=64: `rewind_range_proof`
  ≈ 6.0 ms/output (the dominant cost, slightly above range-verify's ≈ 5.3 ms),
  ECDH shared-secret derivation ≈ 1.0 ms/output (the `cryptography` lib rebuilds
  the scan key object per output, as the production wallet does), and the
  AUDIT-C015 recover-check ≈ 0.08 ms/output. An earlier version folded all three
  into one "rewind" bucket, overstating the rewind primitive by ~15%. Surjection
  (1-element domain) and `verify_balance` are nearly free. The rewind primitive
  is the optimization target.
- Cross-binding reading of `wallet_scan.csv` (the `binding` column has up to four
  values: `python-ffi`, `node-napi`, `rust-pure`, `wasm`). The first three fill
  every phase column; `wasm` fills only `rewind_s` (bundled) + `balance_update_s`.
  So compare wasm's `rewind_s` against the **sum** `ecdh_s + rewind_s +
  recover_check_s` of the others, not against their `rewind_s` alone. `rust-pure`
  is the zero-overhead floor — read per-phase binding overhead as roughly
  (binding row − `rust-pure` row). All four append to the same CSV, so a sweep
  over `--binding` (plus the cargo example) builds the comparison table in place.
- `benchmark_wallet_scan.py` assumes **every** shielded output is addressed to
  the wallet, so every rewind succeeds. That's the worst case for the recovery
  phase (a real wallet skips outputs whose script doesn't match before rewinding).
  The balancing factor is computed from shielded entries only — transparent
  inputs/outputs are zero-blinded and contribute nothing to the blinding sum
  (mirrors the Rust `test_compute_balancing_factor_with_fee`).
- Memory numbers from `psutil` RSS are noisy: they include Python allocator
  caching, the Rust FFI's own allocations, and unrelated background activity.
  Treat the *delta* (peak − baseline) as the meaningful figure, not absolute.
- `tracemalloc` only tracks Python allocations and undercounts the FFI side; use
  it as a lower bound on per-stream attributable allocation.
