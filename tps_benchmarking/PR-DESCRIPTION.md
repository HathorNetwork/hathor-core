# tps: a benchmarking engine for Hathor Network throughput (Phase 1 — full-node processing)

## Summary

This PR adds **`hathor_tps_bench`**, a small, modular, reusable engine for measuring how much throughput
Hathor can sustain — starting with the part that sets the hard ceiling: **how fast a single full node can
*process* an incoming transaction**. It stands up a real `HathorManager` in-process, drives valid
transactions through the node's own S1–S6 pipeline, and reports a defensible **transactions-per-second
(TPS)** figure broken down by stage, with plots, CSV/JSON, and a written report.

It is built so that **other transaction types** (shielded, nano, fee, token-creation) and **other cost
sources** (wallet emission, inter-node relay, block confirmation) plug in as opt-in modules later — and so
that today's CLI can be fronted by a UI tomorrow.

## Motivation

"How many TPS can Hathor handle?" has no single answer — a wallet emitting, the network relaying, and a
node validating+storing are three different bottlenecks. We want to:

1. **Measure, not guess, the node's processing ceiling** — the per-transaction CPU-bound work
   (deserialize → verify → consensus → store) that caps single-node throughput.
2. **Find the bottlenecks** — a per-stage breakdown that says where the time actually goes (and it
   surfaced a real one: full verification runs *twice* per accepted tx).
3. **Have a reusable instrument** — not a one-off script, but an engine we re-run as the code evolves,
   point at different transaction shapes, and grow toward a network-level throughput model.

Phase-1 headline (single-thread, i5-11300H, 1-in/2-out): **≈ 215 tx/s**, dominated by double verification
+ consensus; inputs are expensive (~2.6 ms each), outputs are cheap; per-tx cost is bounded in batch size
once the workload is a tip-confirming DAG (a naïve genesis-parented workload degrades as O(N²)).

## What's included (Phase 1)

- In-process node **harness** (real `HathorManager`, real verifiers, RocksDB temp, weight-1 PoW).
- A **driver** that replays the node's S1–S6 chain by hand, timing each stage (wall + CPU).
- **Resource probes** (`/proc`): RSS, disk I/O, FDs + a background time-series sampler.
- **Workloads** via `DAGBuilder`: `organic` (tip-confirming chain, realistic) and `transparent`
  (genesis-parented, kept to demonstrate the O(N²) pathology), with a registry for future tx types.
- **Analysis & reporting**: per-stage stats + percentiles, the transient→steady rolling-**median** curve
  (robust to RocksDB write-stall spikes), C(N)/M-Tb, CSV/JSON, `summary.md`, and timestamped plots.
- A flag-driven **CLI** (`run` / sweeps / `script` / `list` / `validate`).
- Docs: per-checkpoint write-ups (CP-1…CP-6), `docs/baseline-results.md`, and a Phase-1 PDF report.

## Usage (see `benchmarks/engine/README.md` for the full reference)

```bash
hathor-tps-bench run -n 2500 -i 7 -o 13          # one batch: 2500 txs, 7-in/13-out
hathor-tps-bench run -n 3600 --sweep-inputs 1 10  # sweep inputs (overlaid + per-axis plots)
hathor-tps-bench script demo_experiments all      # bespoke multi-experiment script
```

## Acceptance criteria

**Phase 1 (this PR) — done:**

- [x] Operable via a **CLI** with flags for `--num-txs`, `--num-inputs`, `--num-outputs`, `--warmup`,
      `--window`, `--seed`, `--tx-type`, and a config file (optional).
- [x] **Simulate a batch of transactions** of a configurable shape (I inputs / O outputs) and drive them
      through the full node's processing pipeline.
- [x] Two transaction types implemented (`organic`, `transparent`) behind a **registry** so further types
      slot in without touching the core.
- [x] **Operate scripts / sweeps**: `--sweep-inputs`, `--sweep-outputs`, `--sweep-txs`, and named
      `script`s, each producing plots + data.
- [x] **Simulate the TPS and other consumables** of node processing — per-stage timing **plus** RAM
      (RSS), disk I/O, and file descriptors — with reproducible CSV/JSON/plots and a written report.
- [x] Results are **reproducible** (seeded) and the methodology, findings, and limitations are documented.

**Future phases (out of scope here, the architecture accommodates them):**

- [ ] A **UI** front-end over the same engine/CLI.
- [ ] Additional transaction types: **shielded** (hidden-amount), **nano** contracts, **fee**-based
      tokens, **token-creation** — via the workload registry.
- [ ] Additional cost sources / "load" modules toward a **network-level** figure: **wallet** emission
      latency, **HTTP `push_tx`** round-trip, **inter-node** relay, and **block confirmation**.
- [ ] A more representative **k-tip-frontier** DAG (2–3 tips, mainnet-like).
- [ ] Mainnet-snapshot runs to measure the **real RAM ceiling**.

## Notes

- The engine lives entirely under `tps_benchmarking/` and is **additive** — it imports hathor-core but
  changes none of the node's code. Run outputs are gitignored.
- Numbers are single-machine and **must be scaled** by single-thread CPU performance (PassMark) before
  being read as a Hathor figure; see the caveats in the README and report.
