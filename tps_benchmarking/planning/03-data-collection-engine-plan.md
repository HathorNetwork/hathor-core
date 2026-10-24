# Data-Collection Engine — Plan of Action (Phase 1: full-node single-thread processing)

## Context

We are building the first, basic version of a **benchmark / data-collection engine** that measures a
Hathor **full node's intrinsic per-transaction processing capability** — the work done on the node's
single processing thread from **S1 deserialize → S6 post-consensus** — and from it derives a **valid
processing transactions-per-second (TPS)** figure plus a **per-stage resource-consumption** profile.

It deliberately measures the node **in isolation**: no wallet emission, no inter-node latency, no relay,
no block confirmation — those become **toggleable "load" modules later**. 
Transactions are **transparent**, with a **modular `I` inputs / `O` outputs**; other tx types come later.

**Decisions locked:**
- **In-process, white-box.** Stand up a real `HathorManager` in the same Python process and feed it
  pre-built valid txs one at a time, on a single thread, wrapping the real processing functions with
  timing/resource probes. (No HTTP, no network.)
- **Storage = RocksDB temp-dir** — the production engine (the node's own `Builder` ships
  `RocksDBStorage.create_temp()`). We can also have an in-memory folder to store data, 
  which is only an optional CPU-only baseline, not representative.
- **Hybrid measurement:** We measure the per-stage **time** for each tx sent (allowing for an analysis on
histograms/distributions); **memory / disk-I/O / FDs** , on the other hand,  are studied at the **batch** level 
(totals/peaks) AND also at a **diagnostic** per-stage-per-tx level (with no flushing done at low-level and no probe 
distortion) and a **background time-series** for consumption-over-time study, enabling processed-vs-N scaling charts 
which can more easily help to identify bottlenecks.
- **Energy = analytical** study on energy spent, calculated (CPU-seconds × TDP × util; mining model 
trivial here since the node only *verifies* PoW).
- **No UI this week.** A CLI + auto-generated plots + CSV. In the future we'll build a slick-looking panel.

Modular packages are the name of the game, as we wish to plug in different features soon.so future "loads" plug in.

---

###1. What we measure, and how (the locked scheme)

The driver feeds N pre-built txs sequentially. Per transaction we time these stages:

| Stage | What | Function wrapped (probe point) |
|-------|------|-------------------------------|
| **S1** deserialize | bytes → vertex | `manager.vertex_parser.deserialize(tx_bytes)` |
| **S2** pre-checks | exists / double-spend / voided / reward-lock | the checks in `HathorManager.push_tx` (`manager.py:828`) |
| **S3+S4** verify | basic + full verification (PoW-verify, sigs, balance) | `VertexHandler._validate_vertex` (`vertex_handler.py:185`) |
| **S5** save+consensus | RocksDB cache write + DAG/voided/mempool-tips | `VertexHandler._unsafe_save_and_run_consensus` (`:217`) |
| **S6** post-consensus | **2nd** `validate_full` + critical/non-critical indexes + pubsub | `VertexHandler._post_consensus` (`:232`) |

These tx-path calls are **synchronous** (return `bool`/`list`, not Deferreds — unlike the
`@inlineCallbacks` block path), so they wrap cleanly with timers.

- **Time** (authoritative, per-stage per-tx): `time.perf_counter()` (wall) **and** `time.process_time()`
  (CPU). The detected **double `validate_full`** (S4 then S6) is captured naturally and used as a
  correctness sanity check.
- **Memory / I-O / FDs** — three views:
  1. **Batch (authoritative)**: over a run of N txs → **disk-I/O** = cumulative read+write bytes
     (`/proc/self/io`, a true sum) + peak rate; **memory** = peak RSS (RAM used by a process) + net growth
     +mean (not a sum); **FDs** = peak count + net change. `tx_storage.flush()` is called at batch boundaries 
     so deferred RocksDB writes are counted in the batch totals; RocksDB stats (`total_sst_files_size`, memtable)
     read via `hathor/sysctl/storage/manager.py`.
  2. **Diagnostic (per-stage per-tx, "as-is")**: cheap RSS/FD/io deltas around each stage, **no flush**
     — low-confidence (S5 disk-IO will often read ≈0, which itself confirms deferred writes), useful
     for spotting allocation patterns.
  3. **Time-series**: a background sampler thread polls RSS / `num_fds` / `/proc/self/io` at a fixed
     interval (e.g. 50–200 ms) → consumption-over-time and **processed-vs-N** curves.
- **Energy (analytical)**: node ≈ Σ(per-stage CPU-seconds) × TDP × util (constants in config);
  mining = work(2^weight)×J/hash (≈trivial at weight 1 — reported for completeness).
- **Headline TPS**: `processing_TPS = N / Σ(per-tx total processing time)`; also report `1/mean` and the
  full latency distribution + per-stage share.

> Note on threading: processing stays strictly single-thread. The **only** other threads are the
> sampler (reads `/proc` only) and RocksDB's own flush/compaction — the latter's cost shows up in the
> batch `/proc` totals (acknowledged, not attributed to a stage).

---

## 2. Engine architecture (modular Python package)

Runs inside hathor-core's environment (imports `hathor`). Root: `tps_benchmarking/benchmarks/engine/`.

```
benchmarks/engine/
  hathor_tps_bench/
    cli.py                      # `python -m hathor_tps_bench run --config scenarios/basic.yaml`
    config.py                   # dataclass: N, I, O, n_sweep, storage(rocksdb_temp), seed,
                                #   sampler_interval, metrics toggles, tdp/util, deep_sample_size
    node/
      harness.py                # build HathorManager via hathor.builder.Builder:
                                #   RocksDBStorage.create_temp(), test reactor, internal HD wallet,
                                #   TestMode tx-weight=1; start/stop + temp-dir teardown
    workload/
      base.py                   # TxSource interface (registry) — future tx types plug in here
      transparent.py            # fund (add_blocks_unlock_reward) -> fan-out UTXOs -> build N
                                #   reproducible txs with exactly I inputs / O outputs via
                                #   wallet.prepare_transaction + cpu_mining_service.resolve(weight=1);
                                #   serialize each to bytes (so S1 is measurable); keep ground-truth
    driver/
      runner.py                 # the single-thread loop over N txs; orchestrates probes + collector
    probes/
      stages.py                 # per-stage wrappers (perf_counter + process_time + diagnostic deltas)
      sampler.py                # background psutil/proc time-series sampler
      storage_stats.py          # RocksDB stats + controlled flush() at batch boundaries
      memory.py                 # optional tracemalloc deep pass on a sample (per-stage allocations)
    metrics/
      model.py collector.py     # TxStageRecord, Sample, BatchSummary
    analysis/
      compute.py                # percentiles, TPS, consumption rates, scaling fits
      plots.py                  # per-stage latency histograms; consumption time-series lineplots;
                                #   throughput-vs-N + consumption-vs-N performance charts
      report.py                 # CSV (+ xlsx) + summary.md
  scenarios/                    # basic.yaml, n_sweep.yaml, io_scaling.yaml
  results/<run-id>/             # per_tx_stages.csv, samples.csv, batch_summary.json, plots/, summary.md
  docs/                         # README + usage
  pyproject.toml
```

**Modularity seams (built now, used later):**
- `TxSource` registry → drop in `token_creation` / `nano` / `fee` / `shielded` builders with no core change.
- **"Load" plugins** toggled by config → future *wallet-emission timing*, *relay-to-peers*,
  *multi-node latency*, *block confirmation* attach as extra stages/sources; the metrics model and
  driver already carry arbitrary named stages.
- **Probe registry** → enable/disable each consumable per run.

---

## 3. Reuse vs. build

**Reuse (hathor-core, do not reinvent):** `hathor/builder/builder.py` (`Builder`,
`RocksDBStorage.create_temp` at `:464`); `hathor_tests/utils.py` (`add_blocks_unlock_reward`,
`gen_new_tx`) and `hathor/simulator/utils.py`; `hathor/wallet/base_wallet.py`
(`prepare_transaction`, `WalletInputInfo/OutputInfo`); `hathor/mining/cpu_mining_service.py`
(`resolve`); `hathor/daa` `TestMode` (weight=1); the processing functions in `manager.py` /
`vertex_handler.py`; RocksDB stats in `hathor/sysctl/storage/manager.py`.

**Build:** the `hathor_tps_bench` package above (probes, driver, workload, metrics, analysis, CLI).

---

## 4. Experiments (Phase-1 runs)

1. **Baseline** — N=500, I=1, O=2: per-stage latency histograms + headline processing TPS + batch
   resource summary (peak RAM usage, total disk bytes, peak FDs) + time-series.
2. **N / batch-size sweep** — N ∈ {100, 500, 1k, 5k, …}: **throughput-vs-N** and **consumption-vs-N**
   to reveal scaling (does per-tx cost rise as the DAG/UTXO set and mempool grow? → verify-reads,
   mempool-tips). This is the "processed vs number of tx" chart.
3. **I/O scaling** — vary `I` (1…k) and `O`: isolate S3/S4 signature cost and size effects on time +
   batch memory/IO.

---

## 5. Verification

- **Validity**: every fed tx is accepted (`on_new_tx` → True / no raise); final storage tx-count ==
  setup + N; mempool tips consistent.
- **Timing integrity**: Σ(stage times) ≈ measured total per tx (within probe overhead); the **two**
  `validate_full` calls (S4, S6) are both observed — sanity confirmation of the theoretical finding.
- **Outputs present**: `results/<run>/` has `per_tx_stages.csv`, `samples.csv`,
  `batch_summary.json`, `plots/*.png`, `summary.md`, and a clearly-stated **TPS** value.
- **Reproducibility**: same seed → identical tx hashes and comparable timings across runs.

## 6. Risks / notes to handle during build
- **Funding scale**: fan-out must mint enough UTXOs to build N txs with `I` inputs each; size the
  fan-out from N×I. Use fixed seed words + test-reactor timestamps for determinism.
- **Deferred writes**: per-stage S5 disk-IO is not faithful (documented); batch totals + boundary
  `flush()` are the authoritative disk figures.
- **Background threads**: sampler reads `/proc` only; RocksDB compaction is background — its cost is in
  batch `/proc` totals, acknowledged as not stage-attributable.
- **Energy constants**: TDP/util are config inputs; document the assumption in the report.
