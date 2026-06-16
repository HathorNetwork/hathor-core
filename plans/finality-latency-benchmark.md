# End-to-end finality latency benchmark (collect `2f+1` → admit to mempool)

- Date: 2026-06-16
- Purpose: measure the time for a finality-eligible transaction to **collect a quorum (weight `≥ 2f+1`)
  of validator votes and be admitted to the mempool as certified** — the soft-finality latency the RFC
  targets at sub-second — as a function of two parameters: the **number of validators** `N` and the
  one-way **network latency between validators** `L`.
- Related: [`0001-two-tier-finality.md`](0001-two-tier-finality.md) and the primitive-level
  `internal-rfcs/projects/finality/bls-benchmark.md`. This benchmark composes those raw BLS costs with
  the actual gossip protocol; read the BLS benchmark first for the crypto-backend context.
- Harness: `hathor_tests/finality/test_finality_latency_benchmark.py` (driving the real
  `hathor/finality/service.py` fast path over a simulated network).
- Backend: the production **`blst`** native backend, reached through the `htr_lib` Rust extension
  (`hathor/finality/crypto.py`). An earlier revision of this benchmark ran on the pure-Python `py_ecc`
  backend; the "before/after" of that swap is in the comparison section below.

## TL;DR

- The benchmark runs the whole validator fast path — pin, sign, flood the vote, accumulate votes,
  assemble the `FinalityCertificate`, verify it, admit the tx — through the **real `FinalityService`**,
  over a **discrete-event simulated network** whose per-hop latency is a parameter and whose handler CPU
  is the **real measured `blst` cost**.
- With `blst`, node-local certification is **≈ 3–5 ms and essentially flat from `N = 4` to `N = 100`**:
  the crypto is off the critical path. A quorum verify (`FastAggregateVerify`) is constant in committee
  size, so larger committees cost nothing extra.
- Total soft finality is therefore **≈ 2·L + ~5 ms** — the two flood hops (tx out, vote back) plus a few
  ms of crypto. Even a **100-validator committee on 100 ms links reaches soft finality in ~205 ms**,
  comfortably sub-second with large margin.
- This is the measured confirmation of the BLS-benchmark decision: swapping the backend `py_ecc → blst`
  removed the ~1 s pure-Python crypto floor (see comparison) and made the RFC's sub-second target real.

## Environment

| | |
|---|---|
| CPU | 13th Gen Intel(R) Core(TM) i7-13700K (8 P-cores + 8 E-cores, 24 threads) |
| OS | Linux 6.8.0 |
| BLS backend | `blst` (native BLS12-381, `G2ProofOfPossession`, min-pubkey-size) via the `htr_lib` Rust extension, single-thread per handler |
| Committee weights | uniform (weight 1 each), so `N = total weight = 3f + 1` and `quorum = 2f + 1` |

## Methodology

The harness wires one real `FinalityService` per validator (the same object the node runs) onto an
in-process **discrete-event simulator** with a virtual clock:

- The submission is delivered to validator 0 at virtual time `t = 0`.
- Each message a handler sends (`flood_to_validators`, `flood_vote`, `broadcast_certificate`) is
  buffered and, once the handler returns, scheduled for delivery to each recipient at
  `virtual_now + handler_cpu + L` — i.e. "process the message, then it costs one network hop `L` to
  reach the peer".
- `handler_cpu` is the **real wall-clock `perf_counter` time** of that handler — which for these
  handlers is almost entirely the `blst` sign/verify work (plus the small PyO3 boundary cost). So the
  simulation combines *measured* crypto cost with the *configured* network latency.
- **Soft finality** is recorded the first time any validator's `admit_certified_tx` fires — the instant
  some node first sees weight `≥ 2f+1` and promotes the transaction to its mempool. That virtual
  timestamp is the reported latency.

This isolates the protocol's own latency (crypto on the critical path + network hops to a quorum); it
does not model bandwidth, queueing under load, packet loss, or validator-CPU contention from concurrent
transactions. Votes are sent all-to-all (every validator floods to every other), so a quorum is
collected in ~2 hops regardless of `N`.

For each `(N, L)` cell the transaction and committee (including the one-time proof-of-possession
verification at committee load) are built **outside** the timing; only the certify round is measured,
on a fresh pin store / pending pool / certificate store. Reported numbers are the best and median of 2
timed iterations.

## Results (`blst`)

`finality(best)` / `finality(med)` = virtual time from submission to first mempool admission.

| N | f | quorum | L = 0 ms | L = 25 ms | L = 100 ms |
|---:|---:|---:|---:|---:|---:|
| 4 | 1 | 3 | 3.9 ms | 53.4 ms | 203.0 ms |
| 7 | 2 | 5 | 3.6 ms | 53.2 ms | 203.0 ms |
| 10 | 3 | 7 | 3.1 ms | 53.1 ms | 203.2 ms |
| 13 | 4 | 9 | 3.1 ms | 53.2 ms | 203.1 ms |
| 31 | 10 | 21 | 3.7 ms | 53.7 ms | 203.6 ms |
| 64 | 21 | 43 | 5.2 ms | 54.4 ms | 204.4 ms |
| 100 | 33 | 67 | 5.3 ms | 55.3 ms | 205.4 ms |

(Values are the best of 2 iterations; median was within ~1 ms in every cell.)

**Reading the two axes:**

- **Latency `L` → `≈ 2·L`, flat in `N`.** Across every committee size, the network term is the two
  flood hops (tx out, vote back): +~50 ms at `L = 25`, +~200 ms at `L = 100`, independent of the
  committee. Flooding collects a quorum in a constant number of hops.
- **Committee size `N` → no meaningful growth.** The node-local floor (`L = 0`) stays ~3–5 ms from
  `N = 4` (quorum 3) all the way to `N = 100` (quorum 67). `FastAggregateVerify` is constant in `N`, and
  per-vote verification is ~1 ms, so the critical path barely moves — the committee can grow for
  decentralization at no latency cost.
- **Crypto is off the critical path.** Soft finality is now `2·L + ~5 ms`; the network round-trip
  dominates, exactly the regime the design wants. Sub-second holds with huge margin for any realistic
  inter-validator latency.

## Comparison: the `py_ecc → blst` backend swap

The same benchmark on the previously-shipped pure-Python `py_ecc` backend (same machine, same harness),
showing the node-local floor that swap removed:

| N | quorum | `py_ecc` L = 0 | `blst` L = 0 | speedup | `py_ecc` L = 100 | `blst` L = 100 |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 3 | 982 ms | 3.9 ms | ~250× | 1183 ms | 203 ms |
| 7 | 5 | 1001 ms | 3.6 ms | ~280× | 1205 ms | 203 ms |
| 10 | 7 | 1027 ms | 3.1 ms | ~330× | 1222 ms | 203 ms |
| 13 | 9 | 1043 ms | 3.1 ms | ~340× | 1242 ms | 203 ms |

With `py_ecc`, node-local certification alone was **≈ 1 s for the smallest committee before a single
network packet** — the whole sub-second budget spent on pure-Python pairings — and it grew with the
committee. A 100-validator committee would have spent ~16 s just verifying a 67-vote quorum (see
`internal-rfcs/projects/finality/bls-benchmark.md`). `blst` collapses that floor to a few milliseconds
and flattens it across committee size, leaving the `~2·L` network round-trip as the only material cost.

## Caveats

- Same consumer desktop CPU as the BLS benchmark (i7-13700K); production server CPUs differ.
- The simulated network is uniform, lossless and uncongested, with a single in-flight transaction. It
  captures critical-path crypto + hop count, not bandwidth, queueing, contention, or stragglers under
  real load.
- `handler_cpu` is real `perf_counter` time and so carries normal measurement noise; the soft-finality
  timestamp is the *first* admission across the committee.
- The `blst` handler cost includes the PyO3 call boundary (bytes marshalling + per-call key/signature
  parsing with subgroup checks), so a single verify here (~1 ms) is somewhat above the pure-Rust
  `blst` figure in `internal-rfcs/projects/finality/bls-benchmark.md` (~0.6 ms). It is still ~250×
  under `py_ecc` and far below the network term.

## Reproducing

The benchmark lives in the test tree but is gated behind an environment variable so it never runs in the
normal suite. Small committees are fast; large committees are dominated by the all-to-all vote
verification (`O(N²)` total `blst` verifies — e.g. the `N = 100` rows take tens of seconds of wall
clock to *run*, even though the *measured* soft-finality time is ~5 ms).

```sh
HATHOR_FINALITY_BENCH=1 \
HATHOR_FINALITY_BENCH_SIZES=4,7,10,13,31,64,100 \
HATHOR_FINALITY_BENCH_LATENCY_MS=0,25,100 \
HATHOR_FINALITY_BENCH_ITERS=2 \
  uv run pytest -p no:warnings -s hathor_tests/finality/test_finality_latency_benchmark.py
```

Parameters (all optional, comma-separated to sweep): `HATHOR_FINALITY_BENCH_SIZES` (number of
validators `N`), `HATHOR_FINALITY_BENCH_LATENCY_MS` (one-way inter-validator latency `L`),
`HATHOR_FINALITY_BENCH_ITERS` (timed iterations per cell). Set `HATHOR_FINALITY_BENCH_OUT=<path>` to
also write the results table to a file.
