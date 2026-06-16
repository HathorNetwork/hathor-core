# `hathor_tps_bench` — module & function call tree

A map of the benchmark engine we built (CP‑1…CP‑6, plus the CP‑7 shielded de‑risk spike). It covers the
engine package `hathor_tps_bench/`, the `scripts/`, and the `spikes/`. The engine stands up a real in‑process
Hathor node, feeds it pre‑built transactions one at a time on a single thread, and times the
`S1…S6` processing pipeline per transaction while sampling resource use.

> Stage keys are **`S1`, `S2`, `S3S4`, `S5`, `S6`** (five keys — S3 and S4 are timed together as one
> `validate_full`). The same keys flow through the metrics model, analysis, CSV, and plots.

---

## 1. Package layout

```
hathor_tps_bench/
  __init__.py          # version + package docstring
  __main__.py          # `python -m hathor_tps_bench` -> cli.main()
  cli.py               # argparse entrypoint: list | validate | run | sweep | script
  config.py            # dataclass config tree + YAML loader + STAGES constant
  node/
    harness.py         # NodeHarness: real in-process node (RocksDB temp, trivial PoW)
  workload/
    base.py            # TxSource ABC + PreparedTx record
    registry.py        # @register_txtype / get_txtype / list_txtypes
    transparent.py     # base builder + DefunctTxSource("defunct") + OneTipTransparentTxSource("1-tip-transparent")
  driver/
    runner.py          # the timed single-thread S1..S6 loop  ← the heart of the engine
  probes/
    procstats.py       # /proc/self resource readers (RSS, FDs, disk IO)
    sampler.py         # ProcSampler: background time-series sampler thread
    storage_stats.py   # RocksDB flush() at batch boundary (+ sst-size stub)
  metrics/
    model.py           # StageTiming, TxRecord, Sample, BatchResources, RunSummary
    collector.py       # RunResult bundle + light reductions (means, TPS)
  analysis/
    compute.py         # pure reductions: percentiles, stage table, curves, M/Tb, headline
    persist.py         # CSV (per-tx, samples) + summary JSON writers
    plots.py           # matplotlib charts (single-run + sweep), degrades gracefully
    report.py          # summary.md renderer
    sweep.py           # multi-point sweeps (fresh node per point)
  benchmarks/
    registry.py        # @register_benchmark / get_benchmark / list_benchmarks
scripts/demo_experiments.py
spikes/spike_cp1.py, spike_cp3_batch.py, spike_cp4_{stages,diag,reset}.py, spike_cp7_shielded.py
```

`[hathor]` below marks calls into hathor‑core / the node (not engine code).

---

## 2. Runtime call trees

### 2a. `run` — a single measured batch (the main path)

```
cli.main()
└─ build_parser() → args.fn = _cmd_run
   └─ _cmd_run(args)
      ├─ _load_config(args) → RootConfig.from_yaml + _apply_overrides + cfg.validate()
      ├─ get_txtype(cfg.workload.tx_type)()              # workload/registry → a TxSource
      ├─ NodeHarness(seed, trivial_pow).start()          # node/harness → real node  [hathor]
      ├─ source.build(harness, W+K, I, O)                # workload/transparent: DSL → batch
      │   ├─ render_dsl(...)                             #   emit the DAGBuilder DSL string
      │   ├─ harness.dag_builder().build_from_str(dsl)   #   [hathor] build+sign+PoW the DAG
      │   └─ manager.vertex_handler.on_new_relayed_vertex(funding)  # preload blocks/funds [hathor]
      ├─ run_batch(harness, prepared, sampler_interval_s, warmup=W)   # driver/runner ↓↓↓
      ├─ _print_run_summary(result, cfg)
      └─ reporting:
         ├─ compute.headline(result, tdp, util)
         ├─ compute.stage_table(result)
         ├─ compute.mtb_table(compute.cumulative_curve(result), [7.5,15,30,60,90])
         ├─ persist.write_per_tx_csv / write_samples_csv / write_summary_json
         ├─ plots.generate(run_dir/"plots", result, window)
         └─ report.write_report(run_dir/"summary.md", cfg, head, rows, plot_names)

driver.run_batch(harness, prepared, *, sampler_interval_s, warmup)
├─ build_params(manager)                                  # rebuild VerificationParams once
│  ├─ vh._tx_storage.get_best_block()                     [hathor]
│  ├─ Features.for_mempool(...)                           [hathor]
│  └─ VerificationParams(...)                             [hathor]
├─ procstats.read_io(), procstats.read_rss_bytes()        # pre-measure snapshot
├─ ProcSampler(interval_s).start()                        # background thread:
│  └─ _loop: procstats.read_rss_bytes/read_fd_count/read_io → Sample (every interval)
├─ for i in range(warmup): _drive_one(...)                # warm-up, records DISCARDED
├─ for each measured tx:
│  ├─ _drive_one(manager, vh, settings, params, raw, i) → TxRecord
│  │  └─ timed(key, fn): perf_counter_ns + process_time_ns → StageTiming
│  │     ├─ S1   manager.vertex_parser.deserialize(raw)                 [hathor]
│  │     ├─ S2   tx_storage.transaction_exists / vtx.is_double_spending
│  │     │        / vtx.is_spending_voided_tx / is_spent_reward_locked  [hathor]
│  │     ├─ S3S4 vh._validate_vertex(vtx, params)                       [hathor]  (validate_full)
│  │     ├─ S5   vh._unsafe_save_and_run_consensus(vtx)                 [hathor]
│  │     └─ S6   vh._post_consensus(vtx, params, events, quiet=True)    [hathor]  (2nd validate_full)
│  └─ sampler.set_progress(i+1)
├─ storage_stats.flush(manager) → tx_storage.flush()      [hathor]  (realise deferred writes)
├─ sampler.stop()
├─ procstats.read_io(), procstats.read_rss_bytes()        # post-measure snapshot
└─ return RunResult(records, batch=BatchResources(...), samples=sampler.samples)
```

### 2b. `run --sweep-*` / `sweep` — multi-point sweep

```
_cmd_run → _run_sweep(cfg, args)            (or _cmd_sweep for the back-compat --axis form)
└─ sweep.io_sweep / sweep.n_sweep(cfg, tx_type, points, K, W, on_point=log)
   └─ for each point: sweep._run_one(cfg, tx_type, I, O, K, W)
      ├─ NodeHarness(...).start()           # FRESH node per point (no state carryover)
      ├─ get_txtype(tx_type)().build(harness, W+K, I, O)
      ├─ driver.run_batch(harness, prepared, warmup=W)
      ├─ compute.headline(...) + compute.stage_table(...)
      └─ harness.stop()                     # in finally
   → _emit_sweep: plots.sweep_plots(...) + _write_sweep_report(summary.md)
```

### 2c. `list` / `validate` — hathor‑free, fast

```
_cmd_list   → list_txtypes() + list_benchmarks() + _list_scripts()       # no hathor import
_cmd_validate → RootConfig.from_yaml(path).validate() → print resolved config
```

---

## 3. Module reference

### `cli.py` — argparse entrypoint
- `main(argv)` — parse args, dispatch to `args.fn`.
- `build_parser()` — defines subcommands `list | validate | run | sweep | script` and their flags.
- `_cmd_run(args)` — single run, or a sweep if any `--sweep-*` flag is present; builds node+workload, drives, reports.
- `_cmd_sweep(args)` — back‑compat sweep via `--axis io|n --values …`.
- `_cmd_list / _cmd_validate / _cmd_script` — registry listing / config validation / run a `scripts/*.py`.
- `_load_config / _apply_overrides / _load_and_validate` — load YAML (or defaults) and apply CLI overrides.
- `_run_sweep / _emit_sweep / _write_sweep_report` — sweep dispatch + output.
- `_print_run_summary` — console table of per‑stage means + TPS + resources.
- helpers: `_parse_shapes`, `_parse_ints`, `_scripts_dir`, `_list_scripts`.

### `config.py` — configuration
- `STAGES = ("S1","S2","S3S4","S5","S6")` — canonical stage keys (single source of truth).
- `WorkloadConfig` — `tx_type, num_txs(K), num_inputs(I), num_outputs(O), warmup_txs(W)` + `validate()`.
- `EnvConfig` — `network, storage, seed, trivial_pow` + `validate()`.
- `MeasureConfig` — `sampler_interval_s, tdp_watts, cpu_util, deep_tracemalloc_sample` + `validate()`.
- `ReportingConfig` — `formats, window` + `validate()`.
- `RootConfig` — top object; `from_yaml/from_dict/to_dict/validate`; `_build()` recursively builds nested dataclasses (rejecting unknown keys).

### `node/harness.py` — the node under test
- `NodeHarness(seed, trivial_pow)` — builds a real in‑process node: `TestBuilder` on RocksDB temp‑dir storage, **real verifiers**, weight‑1 PoW (`TestMode.TEST_ALL_WEIGHT`), test reactor clock.
  - `start()` — build + start the manager, settle the clock; returns self.
  - `dag_builder()` — `TestDAGBuilder.from_manager(manager)`.
  - `stop()` — stop manager, close the temp RocksDB.
  - properties `vertex_parser`, `tx_storage`; `__enter__/__exit__`.

### `workload/` — building the transaction batch
- `base.py`
  - `PreparedTx(tx, raw, n_inputs, n_outputs)` — a built/signed/PoW‑resolved tx + its serialized bytes (kept so S1 can re‑parse them).
  - `TxSource` (ABC) — `build(harness, num_txs, num_inputs, num_outputs) → list[PreparedTx]`.
- `registry.py` — `register_txtype(name)` decorator, `get_txtype(name)`, `list_txtypes()`, `TXTYPE_REGISTRY`.
- `transparent.py`
  - `TransparentTxSource` — **unregistered** shared transparent-output builder (base). Its default `_frontier_lines` is genesis-parenting.
    - `render_dsl(N,I,O)` — emit the DAGBuilder DSL: funding blocks, `dummy` past the reward lock, chunked `fund` txs minting pinned UTXOs, then N payload txs with pinned exact‑I/O outputs.
    - `_frontier_lines(t, name, tx_anchor)` — parent/ordering policy (base default: genesis-parenting, timestamp anchor only).
    - `build(...)` — render DSL, `build_from_str`, preload non‑target vertices, return payload txs as `PreparedTx`.
  - `DefunctTxSource` (`@register_txtype("defunct")`) — registers the base's genesis‑parenting unchanged: every tx is a tip → O(N²) consensus. Pathological; kept ONLY to demonstrate the effect.
  - `OneTipTransparentTxSource` (`@register_txtype("1-tip-transparent")`) — overrides `_frontier_lines` to chain `tx_k → tx_{k-1}` so tips≈1 (flat O(1) consensus); the realistic transparent workload (room for a future `k-tip-transparent`).

### `driver/runner.py` — the timed loop (engine core)
- `build_params(manager) → VerificationParams` — reconstruct the params `on_new_relayed_vertex` would build (once per batch).
- `_drive_one(manager, vh, settings, params, raw, index) → TxRecord` — drive one tx through S1…S6 via the nested `timed(key, fn)` helper (wall `perf_counter_ns` + cpu `process_time_ns` → `StageTiming`); compute `accepted`; return a `TxRecord`.
- `run_batch(harness, prepared, *, sampler_interval_s, warmup) → RunResult` — orchestrate: warm‑up (discarded) → snapshot → start sampler → measured loop → flush → stop sampler → snapshot → assemble `BatchResources` + `RunResult`.

### `probes/` — resource measurement
- `procstats.py` — `read_rss_bytes()`, `read_vmhwm_bytes()`, `read_fd_count()`, `read_io() → (read,write)`: dependency‑free `/proc/self` readers.
- `sampler.py` — `ProcSampler(interval_s)` background daemon thread: `start/stop/set_progress`, `_loop` appends `Sample`s and tracks `rss_peak`/`fd_peak`.
- `storage_stats.py` — `flush(manager)` (force deferred RocksDB writes at batch boundary), `read_sst_bytes(manager)` (stub → 0).

### `metrics/` — the data model
- `model.py`
  - `StageTiming(wall_ns, cpu_ns)` — one stage of one tx.
  - `TxRecord(index, tx_id, n_inputs, n_outputs, size_bytes, accepted, error, stages)` — per‑tx record; `total_wall_ns()`, `total_cpu_ns()`.
  - `Sample(t_rel_s, tx_done, rss_bytes, num_fds, io_read_bytes, io_write_bytes)` — one time‑series point.
  - `BatchResources(wall_s, cpu_s, io_*_bytes, rss_*_bytes, fd_peak, sst_bytes)` — batch‑level; `rss_growth_bytes`, `energy_joules(tdp, util)`.
  - `RunSummary` — flat reportable summary (counts, throughput, per‑stage, latency percentiles, resources, provenance).
- `collector.py`
  - `RunResult(records, batch, samples)` — the bundle a run produces; `n`, `accepted`, `stage_mean_wall_us()`, `stage_mean_cpu_us()`, `total_mean_wall_us()`, `processing_tps()`.

### `analysis/` — reduction, persistence, reporting
- `compute.py` — `rolling_window`, `_pct`, `per_tx_totals_us`, `stage_table`, `rolling_tps`, `rolling_tps_median`, `cumulative_curve`, `mtb_table`, `scale_to_specs`, `headline`. Pure stdlib reductions over a `RunResult`.
- `persist.py` — `write_per_tx_csv`, `write_samples_csv`, `write_summary_json`.
- `plots.py` — `generate` (4 single‑run charts), `sweep_plots` (3 cross‑run charts), `_pyplot/timestamp/_stamped` helpers; returns `[]` if matplotlib is missing.
- `report.py` — `write_report(path, cfg, head, stage_rows, plot_names)` → `summary.md`.
- `sweep.py` — `SweepPoint` record; `_run_one` (fresh node per point); `io_sweep` (vary tx shape), `n_sweep` (vary batch size).

### `benchmarks/registry.py` — benchmark selectors
- `BenchmarkEntry(cls, output_folder)`, `register_benchmark(name, output_folder)`, `get_benchmark(name)`, `list_benchmarks()`. (Selector layer; concrete benchmarks land in later CPs.)

---

## 4. Spikes & scripts (throwaway / utility)

- `spikes/spike_cp1.py` — CP‑1: prove one transparent tx builds + processes on a real node.
- `spikes/spike_cp3_batch.py` — CP‑3: prove a *batch* of N independent txs (255‑output cap, reward lock, input disjointness).
- `spikes/spike_cp4_{stages,diag,reset}.py` — CP‑4: de‑risk per‑stage timing, diagnostic deltas, and the consensus/tip behaviour.
- `spikes/spike_cp7_shielded.py` — CP‑7: prove `hathor_ct_crypto` round‑trips and a `[full-shielded]`/`[shielded]` tx **builds + verifies** end‑to‑end (the shielded de‑risk).
- `scripts/demo_experiments.py` — runnable via `cli script demo_experiments`; drives the Phase‑1 experiment set.

---

## 5. Notes

- **Single‑threaded by design:** only the measured `_drive_one` loop is timed; the only other threads are the
  `ProcSampler` (reads `/proc` only) and RocksDB's own flush/compaction (its cost shows up in batch `/proc`
  totals, acknowledged as not stage‑attributable).
- **Two authoritative views:** per‑stage **time** is per‑tx (histograms/percentiles); **memory/IO/FDs** are
  authoritative at the **batch** boundary (`flush()` then `/proc` deltas), with the sampler giving a
  diagnostic time‑series.
- **The double `validate_full`:** S3S4 and S6 both run `validate_full` — visible as two comparable stage costs
  and the basis of the "verification runs twice" finding (amplified for shielded txs).
- `mtb_table` / `scale_to_specs` (in `compute.py`) are invoked from `cli.py`, not from the other analysis
  modules. `read_vmhwm_bytes` and `read_sst_bytes` are defined but currently unused/stubbed.
</content>
