# Hathor Network — TPS Benchmark Engine (Plan)

> Status: **planning** (no code written yet). First implementation scope: transparent simple
> transactions. We will return to this document before executing.

## Context

We want to establish the **theoretical and practical maximum transactions-per-second a Hathor
full node can accept and confirm**, and build a reusable engine to measure it repeatedly under
varying workloads. Two repos are in play:

- `hathor-core/` — the Python/Twisted **full node** (the system under test).
- `hathor-wallet-headless/` — the Node.js **wallet** HTTP service that creates, signs, and sends
  transactions and manages keys.

**Primary question:** how many tx/s can *the full node* process — not how many one wallet can emit.
Two distinct metrics are tracked throughout:

- **Accepted** — node admits the tx into the mempool (`push_tx` returns success).
- **Processed / Confirmed** — a later block confirms the tx (`transaction.meta.first_block` is set).

This plan delivers: (1) a documented transaction lifecycle map, (2) a bottleneck analysis, (3) the
benchmark strategy (where to measure, which tests), (4) a fixed scope, and (5) the design of a
Python, Docker-Compose-based, modular benchmark engine with automatic reporting (CSV, Excel, plots,
Markdown/HTML) and documentation.

---

## 1. Transaction lifecycle (the routes a tx travels)

### 1a. Wallet side (creation → signing → submission) — `hathor-wallet-headless`
HTTP `POST /wallet/simple-send-tx` (or `/wallet/send-tx`) →
1. **Request validation** — `src/routes/wallet/wallet.routes.js:134`.
2. **Per-wallet mutex** `lockTypes.SEND_TX` (2-min timeout) — `src/controllers/wallet/wallet.controller.js:268`,
   `src/lock.js`. **Only one tx in-flight per wallet** → a single wallet is inherently serial.
3. **UTXO selection** — `getUtxosToFillTx()` `src/helpers/tx.helper.js:58`.
4. **prepareTx → signTx** (ECDSA/secp256k1, BIP32 HD keys) + weight calc + parent/tips selection —
   wallet-lib `@hathor/wallet-lib@3.1.1`, invoked from `src/helpers/tx.helper.js:272`.
5. **PoW via tx-mining-service** — `runFromMining()`; PoW is **offloaded** to an external
   tx-mining-service (`txMiningUrl`), *not* mined locally. Confirmed by the integration
   docker-compose (tx-mining-service + cpuminer).
6. **Submit** signed+mined tx to the full node.

### 1b. Full-node side (ingestion → consensus → storage) — `hathor-core`
HTTP `POST /v1a/push_tx` (`hathor/transaction/resources/push_tx.py:69`) →
1. **Deserialize** — `VertexParser.deserialize()` `hathor/transaction/vertex_parser/_vertex_parser.py:65`.
2. **Manager checks** — double-spend / voided-input — `hathor/manager.py:828`.
3. **Verification (single-threaded on the reactor):**
   - Structural / version / parents — `hathor/verification/vertex_verifier.py:71`.
   - **PoW** (`verify_pow`) `vertex_verifier.py:131`; weight via `verify_weight` `transaction_verifier.py:94`.
   - Script/signature verification (secp256k1) and token/balance checks — `transaction_verifier.py`.
4. **Consensus update** (accumulated weight, voided-by, reorg) — `hathor/consensus/consensus.py:126`.
5. **Persist** to RocksDB + index updates — `hathor/vertex_handler/vertex_handler.py:217`.
6. **Relay** to peers (out of scope: single node).
`push_tx` **returns immediately on mempool acceptance** (does not wait for confirmation). Response =
`{success, message, tx}`.

### 1c. Confirmation (the "processed" metric)
Confirmation requires a **block**. Blocks are produced by the tx-mining-service + cpuminer (or via
node mining API `get_block_template`/`submit_block`, `hathor/transaction/resources/mining.py`).
Default `AVG_TIME_BETWEEN_BLOCKS ≈ 30s` but tunable on privnet; a block confirms the **whole reachable
DAG** (no per-block tx cap). So confirmation throughput is gated by block rate, independent of
acceptance throughput. A tx is confirmed when `GET /v1a/transaction?id=<hash>` shows `meta.first_block`.

### 1d. Other tx types (planning-level route divergence; not implemented now)
Header-gated variants exist (`hathor/transaction/vertex_parser`): **shielded**
(`ShieldedOutputsHeader`/`UnshieldBalanceHeader`, `ENABLE_SHIELDED_TRANSACTIONS`), **nano**
(`NanoHeader`, `ENABLE_NANO_CONTRACTS` — adds contract execution on the reactor), **fee-based**
(`FeeHeader`, `ENABLE_FEE_BASED_TOKENS`). They diverge mainly at deserialization + verification
(extra crypto / contract execution) and are documented as future pluggable tx types.

---

## 2. Candidate bottlenecks (what we will measure)

| # | Stage | Why it limits throughput | In scope now |
|---|-------|--------------------------|--------------|
| B1 | **Per-wallet send lock** | Serializes one wallet to `1 / pipeline_latency`. | Yes (folder 1 measures it) |
| B2 | **tx-mining-service PoW round-trip** | HTTP job + poll per tx, even at weight=1. | Yes (folder 3) |
| B3 | **Full-node single-threaded verification** | PoW + secp256k1 sig + script checks on the reactor. | **Yes (folder 2, primary)** |
| B4 | **Consensus recomputation** | Accumulated-weight / voided-by / reorg on the reactor. | Yes (folder 2) |
| B5 | **RocksDB writes + index updates** | Write amplification per tx. | Yes (folder 2) |
| B6 | **push_tx rate limits** | Global 100 req/s, per-IP 3 req/s burst 10 (`push_tx.py:172`). Bypass via direct `:8080` / `--disable-rate-limits`. | Yes |
| B7 | **Block production rate** | Gates confirmation TPS. | Yes (confirmation metric) |
| B8 | UTXO selection / signing cost | Scales with #inputs and UTXO-set size. | Partial (folder 3) |

---

## 3. Benchmark strategy — three approaches, three result folders

**Approach 2 (full-node ingestion) is the primary target** of the stated question.

- **Folder 1 — `single-wallet-e2e`**: drive `POST /wallet/send-tx` end-to-end through the headless
  wallet; measure realistic single-wallet TPS. The lock (B1) is itself a finding.
- **Folder 2 — `fullnode-ingestion` (PRIMARY)**: bypass the wallet lock and the mining round-trip by
  **pre-building a batch** of independent txs and firing them at `push_tx` under controlled
  concurrency/rate. Measures node **acceptance TPS** and **confirmation TPS** separately. Build
  recipe (de-risked against the code):
  1. Pre-fund one wallet; **fan-out** one UTXO into N independent UTXOs (one split tx).
  2. Build + sign N independent 1-in/1-out txs (distinct UTXO each → no input conflicts), reusing a
     fixed set of parents captured once. **Verified viable**: parents only need to *exist* in storage
     (not be current tips) — `vertex_verifier.py:95`; only constraint is tx timestamp within ~36h
     (`MAX_PAST_TIMESTAMP_ALLOWED`). For very large/long runs, regenerate in **waves** refreshing
     parents/timestamps.
  3. Pre-mine all N at weight=1 (trivial PoW on privnet), store hex.
  4. Fire all N at `push_tx` (direct `:8080`, rate limits bypassed) with semaphore + pacer.
  5. Drive block production at a controlled rate; poll `transaction.meta.first_block` for confirmation.
- **Folder 3 — `stage-latency`**: instrument per-tx stage timestamps (UTXO select → sign → mining
  round-trip → submit → confirm) on a sample, to attribute where latency goes (B2, B8).

**Tests per approach (initial, transparent only):** burst-to-ceiling (raw accept rate), constant-rate
sweep, ramp-up to find the knee, and confirmation-lag under a fixed block cadence.

---

## 4. Scope (this iteration)

- One wallet emitting; **all transparent, simple** transactions (transparent first-class; shielded /
  nano / fee are stubbed pluggable tx-types only).
- Single full node; **no inter-node latency / P2P propagation**.
- Local **privnet** with `MIN_TX_WEIGHT=1` / `--test-mode-tx-weight` (trivial PoW) and
  `--test-mode-block-weight`.
- Engine = **Python**; environment = **Docker Compose** (fullnode + tx-mining-service + cpuminer +
  headless wallet), mirroring `hathor-wallet-headless/__tests__/integration/docker-compose.yml` and
  its `privnet.yml` (pre-funded genesis).

---

## 5. Engine design (Python, modular, registry-based)

Root: `tps_benchmarking/benchmarks/engine/`. Importable package `tps_bench`.

```
tps_benchmarking/benchmarks/engine/
  tps_bench/
    __main__.py  cli.py                 # typer: run / list / validate / report
    config/      schema.py loader.py     # pydantic v2 models + YAML loader (+env interpolation)
    clients/     node_client.py wallet_client.py mining_client.py base.py models.py
    workload/    base.py registry.py batch.py
                 builders/transparent.py  (+ stubs: shielded.py nano.py fee.py)
    benchmarks/  base.py registry.py
                 single_wallet_e2e.py  fullnode_ingestion.py  stage_latency.py
    load/        profiles.py pacer.py concurrency.py     # constant|ramp|step|burst
    metrics/     model.py collector.py poller.py compute.py
    reporting/   frames.py csv_writer.py excel_writer.py plots.py report.py templates/
    orchestration/ runner.py run_dir.py
    util/        timebase.py logging.py
  scenarios/     transparent.yaml ingestion_ramp.yaml stage_latency.yaml
  results/       single-wallet-e2e/<run>/  fullnode-ingestion/<run>/  stage-latency/<run>/
  docker/        docker-compose.yml privnet.yml          # the benchmark environment
  docs/          README.md usage.md config-reference.md benchmarks/*.md
  pyproject.toml
```

**Plugin interfaces (registry pattern — new approaches/tx-types need no core changes):**
- `TxType` ABC — `prepare_batch(spec, ctx) -> Sequence[PreparedTx]` (folder 2) and
  `send_one_e2e(spec, ctx)` (folder 1); `@register_txtype("transparent")`.
- `Benchmark` ABC — `run(ctx) -> BenchmarkResult`, `validate(ctx)`; `name` + `output_folder`;
  `@register_benchmark(...)`. Runner discovers via the registry; `--select` chooses a subset.

**Clients (httpx async):**
- `NodeClient`: `push_tx`, `get_mempool`, `get_status`, `get_transaction` (confirmation),
  `get_block_template`/`submit_block`.
- `WalletClient`: `start`, `balance`, `address`, `send_tx`, and tx-proposal endpoints
  (`/wallet/tx-proposal/*`, `tx-proposal/tx-proposal.routes.js`) for build-without-send. **Phase 1
  must confirm** the proposal flow returns pushable signed hex; fallback = build/sign offline via
  wallet-lib or a small JS helper.
- `MiningClient`: tx-mining-service job submit/poll; node mining API for on-demand blocks.

**Metrics model:** per-tx `TxRecord` (lifecycle timestamps created/signed/mined/submitted/accepted/
confirmed, outcome, derived latencies); periodic `PollSample` (mempool size, best-block height,
cumulative accepted/confirmed); `RunSummary` (counts, acceptance/confirmation TPS mean+peak, latency
p50/p90/p99, success rate).

**Concurrency/rate (folder 2):** single asyncio loop, `httpx.AsyncClient` (HTTP/2, pooled),
`asyncio.Semaphore(max_concurrency)` + token-bucket `Pacer`; load profiles `constant|ramp|step|burst`.
`429`/rate-limit recorded as `rate_limited` (a measurement, not a failure). Acceptance TPS and
confirmation TPS plotted on the same time axis.

**Reporting (benchmark-agnostic):** records → pandas DataFrame → CSV (`tx_records.csv`,
`poll_samples.csv`); multi-sheet `report.xlsx` (openpyxl: Summary, TxRecords, PollSamples,
LatencyPercentiles, StageBreakdown); matplotlib plots (throughput-over-time, latency hist/CDF,
accept-vs-confirm curve, stage breakdown); jinja2 `summary.md` + `summary.html`. One timestamped
run-dir per approach folder, also dumping `config.resolved.yaml`.

**Config (YAML, pydantic-validated):** sections `run`, `environment` (node/wallet/mining endpoints),
`workload` (num_txs, tx_type, num_inputs, num_outputs, value_distribution, tx_type_params),
`benchmarks.select` + per-benchmark options (e.g. load_profile), `reporting.formats`. CLI `--select`
overrides `benchmarks.select`.

**CLI:**
`python -m tps_bench run --config scenarios/ingestion_ramp.yaml [--select fullnode-ingestion]` /
`list` / `validate` / `report --run-dir ...`.

**Libraries:** httpx, pydantic v2, pyyaml, typer, pandas, openpyxl, matplotlib, jinja2, structlog.

---

## 6. Phased build order

- **Phase 0 — Environment**: `docker/docker-compose.yml` + `privnet.yml` bringing up fullnode
  (`--test-mode-tx-weight`, `--test-mode-block-weight`, status `:8080`) + tx-mining-service + cpuminer
  + headless wallet (`:8000`); verify funding (mine blocks → wallet balance). Document startup.
- **Phase 1 — Skeleton + clients**: package layout, pydantic config + loader, typer `list`/`validate`,
  registries; `NodeClient` + `WalletClient` smoke-tested against the compose privnet. Confirm
  tx-proposal returns pushable hex.
- **Phase 2 — Minimal folder-2 vertical slice (PRIMARY)**: `TransparentSimpleTxType.prepare_batch`
  (fan-out + N independent signed txs), `FullnodeIngestionBenchmark` (burst/constant + semaphore),
  `MetricsCollector` + `Poller`, CSV + one throughput plot + Markdown summary. *Minimal working
  benchmark + report.*
- **Phase 3 — Full metrics & reporting**: percentiles/bucketing, accept-vs-confirm correlation via
  `first_block`, latency hist/CDF, multi-sheet xlsx, HTML report.
- **Phase 4 — Load profiles**: ramp/step/burst pacing wired to config.
- **Phase 5 — Folders 1 & 3**: `SingleWalletE2EBenchmark` (`send-tx`, lock-bound) and
  `StageLatencyBenchmark` (per-stage marks).
- **Phase 6 — Extensibility & docs**: shielded/nano/fee tx-type stubs proving zero core changes;
  README, usage, per-benchmark docs, config reference.

---

## 7. Verification

- **Env up**: `docker compose up` → `curl :8080/v1a/status` healthy; mine blocks → wallet balance > 0.
- **Folder-2 slice**: run a small `num_txs` burst → confirm `tx_records.csv`, a throughput plot, and a
  Markdown summary appear under `results/fullnode-ingestion/<run>/`; cross-check accepted count vs
  node `mempool`, and confirmed count vs `transaction.meta.first_block` after a block.
- **Determinism/repeatability**: re-run same scenario → comparable summary; `validate` rejects bad
  configs; `list` shows registered benchmarks/tx-types.

---

## 8. Open items to confirm during implementation
- Exact `/wallet/tx-proposal/*` flow yields pushable signed hex (else offline-sign fallback).
- Cleanest way to drive block production on demand at a fixed cadence (cpuminer cadence vs node mining API).
- Whether long runs need parent/timestamp refresh **waves** (36h window) — likely fine for first runs.
- "Theoretical max" definition: folder 2 measures an *empirical* ceiling on this hardware. An
  *analytical* ceiling (per-tx verification cost × single-thread budget) is a separate add-on.
- Confirmation semantics: first-block vs deeper accumulated-weight finality.
- Realism vs ceiling: trivial PoW (weight=1) inflates TPS vs mainnet weights — parameterize weight to
  show the curve.
