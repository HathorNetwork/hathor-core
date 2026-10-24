# Checkpoint CP‑4 — Per‑stage probes + driver, the consensus finding, and the organic fix

- **Snapshot A:** end of CP‑3 — a real node harness + `transparent` workload that *produces* a
  provably‑acceptable batch of N txs. Nothing is measured.
- **Snapshot B:** a single‑thread **driver** that times the node's S1–S6 processing per tx, plus
  resource **probes** (`/proc` sampler, flush) — the first checkpoint that *measures*. Measuring then
  surfaced a real result: **per‑tx throughput collapses as N grows**, root‑caused to consensus’s
  `mempool_tips.update` being **O(tips)** while our genesis‑parented workload makes **tips = N**
  (so O(N²)). The fix — an **`organic` tip‑confirming workload** — flattens it and is validated here.
- **Status:** PASS ✓ — drives N = 3 → 1000; `transparent` TPS falls 169→36, `organic` is stable
  ~220; a single block confirms **250/250** of an organic chain (vs **2/250** genesis‑parented).
- **Files:** 9 new engine modules + 3 diagnostic spikes; `cli.py` / `workload/transparent.py` /
  `metrics/model.py` modified; accompanying RFC (M/Tb model), editable‑install tooling, and a findings memo.

---

## 1. Summary

CP‑4 builds the measuring machinery and uses it. The **driver** (`driver/runner.py`) replays the node's
own `VertexHandler._old_on_new_vertex` chain by hand, wrapping each stage with `perf_counter_ns` (wall)
and `process_time_ns` (CPU): **S1** deserialize, **S2** pre‑checks, **S3S4** verify, **S5** save+consensus,
**S6** post‑consensus. **Probes** (`probes/`) read `/proc` directly (no psutil) for RSS/FDs/disk and run a
background time‑series sampler; a batch‑boundary `flush()` makes deferred RocksDB writes count. The CLI's
`run` now drives a real batch and prints the per‑stage table + headline TPS + resources.

Measuring immediately paid off. The per‑tx cost **grows with batch size** — and the growth is entirely in
**S5 consensus**. We traced it to a single hot loop and found that our CP‑3 workload was *unrepresentative*
in a way that inflated consensus quadratically. The second half of CP‑4 is the fix: an **`organic`**
workload that links each tx to the previous one, collapsing the tip set from N to 1. With it, consensus is
flat and the node's real processing rate (~**230 tx/s** for 1‑in/2‑out, single thread) becomes measurable.

---

## 2. The arc — what we built, what we found, what we fixed

### 2.1 The driver: replaying S1–S6 by hand
`on_new_tx` runs the whole pipeline opaquely; to time the *stages* we replay the inner chain. `build_params`
reconstructs the `VerificationParams` that `on_new_relayed_vertex` builds (best block is fixed across a
batch, so it's built once). Then per tx (`_drive_one`): deserialize (S1) → manager pre‑checks (S2) →
`vh._validate_vertex` (S3S4) → `vh._unsafe_save_and_run_consensus` (S5) → `vh._post_consensus` (S6), each
inside a tiny `timed()` wrapper. This is faithful — it's the node's own functions, in the node's order.

### 2.2 The probes: /proc, a sampler, and honest disk I/O
`probes/procstats.py` reads `/proc/self/{status,io,fd}` for RSS/VmHWM, disk read/write **bytes**, and FD
count — dependency‑free. `probes/sampler.py` runs a daemon thread snapshotting those at a fixed interval
(the time‑series for over‑time / vs‑N charts), tracking peaks; it only *reads* /proc so the measured path
stays single‑threaded. `probes/storage_stats.py` calls `tx_storage.flush()` at the batch boundary so the
deferred RocksDB writes show up in the `/proc` disk delta. Empirically **wall ≈ cpu** in every stage →
the path is CPU‑bound (no I/O stalls), which validates the timing.

### 2.3 The finding: throughput collapses as N grows
The batch sweep is damning for the CP‑3 workload:

| N | `transparent` TPS |
|---|---|
| 100 | 169 |
| 500 | 65 |
| 1000 | 36 |

Per‑tx cost roughly *quadruples* from N=100→1000. The per‑stage split shows it's **all S5**: S1/S2/S3S4
are flat, S5 goes from ~1.6 ms to ~5 ms as the batch grows. (S3S4 verify is flat in N — it scales with
inputs I, not batch size.)

### 2.4 Root cause: `mempool_tips.update` is O(tips), and our tips = N
Splitting S5 into sub‑steps (`spike_cp4_diag.py`): `update_initial_metadata` and `save_transaction` are
**flat** (~50 µs); the entire growth is in `consensus.unsafe_update`. That method calls
`tx_storage.indexes.mempool_tips.update(...)` per affected tx, and `mempool_tips_index.py:133`'s `update`
**iterates every current tip** (`for tip_tx in self.iter(tx_storage)`) — i.e. **O(tip count)**.

A "tip" is a mempool tx with **no tx‑child**. CP‑3's `transparent` workload leans on the DAGBuilder filler,
whose `fill_parents` parents every tx to **genesis** and *deliberately never uses DAG txs* ("it would
confirm them"). So **no tx is ever anyone's parent → every tx is a tip → tips = N → S5 = O(N) per tx →
O(N²) batch.** Measured: 250 txs → 251 tips.

Two corollaries, both verified:
- **A block can't rescue it.** A block confirms only the txs in its *past* (ancestors via **parent**
  edges; `block_consensus`). In a flat genesis‑fan its 2 tx‑parents reach only themselves → a block
  confirmed **2/250**.
- **The “10× jump right after a block” is a caching artifact, not consensus.** Post‑block the read *count*
  per tx barely moved (1250→1340) but read *time* went ~10× (≈5 µs warm → ≈90 µs cold); a bare `flush()`
  does **not** reproduce it (1.0×). The block's processing evicts the tx‑object LRU cache, so the O(tips)
  scan then reads cold from RocksDB. It only exists *because* tips = N forces ~250 reads/tx.

### 2.5 The fix: an `organic` tip‑confirming chain
The cure follows directly from the cause: give each tx a **recent tx** as parent so the tip set stays
bounded. `OrganicTxSource` (a subclass that changes *only the parent pointers* — funding/inputs/outputs are
identical) emits `tx_k --> tx_{k-1}`; the filler fills the 2nd slot with genesis. Now each tx confirms its
predecessor → **only the latest tx is a tip → tips = 1** → `mempool_tips.update` is O(1).

The refactor is a one‑method hook: `render_dsl` calls `self._frontier_lines(t, name, tx_anchor)`; the base
returns the genesis‑parented anchor line, `OrganicTxSource` adds the `-->` edge. (Per‑tx ordering: the
anchor `b{anchor} < tx_k` is kept on every tx as a harmless belt‑and‑suspenders; in the chain each tx also
inherits a late timestamp from its parent.)

---

## 3. File‑by‑file walkthrough

**New — the driver:**
- `driver/runner.py` — `build_params` (reconstructs `VerificationParams`), `_drive_one` (replays S1–S6 with
  wall+cpu timing → `TxRecord`), `run_batch` (the single‑thread loop + sampler + batch‑boundary flush →
  `RunResult`). `driver/__init__.py` re‑exports `run_batch` (lazy hathor import).

**New — the probes:**
- `probes/procstats.py` — `/proc/self` readers: `read_rss_bytes`, `read_vmhwm_bytes`, `read_fd_count`,
  `read_io` (disk read/write bytes). All ints‑of‑bytes, no psutil.
- `probes/sampler.py` — `ProcSampler`: daemon thread → `Sample` time‑series + RSS/FD peaks; `set_progress`
  tags samples with txs‑done for vs‑N curves.
- `probes/storage_stats.py` — `flush(manager)` (realise deferred writes, best‑effort) + `read_sst_bytes`
  hook (0 for now; disk signal comes from `/proc`).

**New — metrics + scenario:**
- `metrics/collector.py` — `RunResult` (records + batch + samples) with reductions: `stage_mean_wall_us`,
  `processing_tps = N / Σ(per‑tx total wall)`.
- `scenarios/organic.yaml` — the organic baseline scenario (tx_type: organic).

**New — diagnostic spikes** (throwaway, de‑risk/root‑cause):
- `spike_cp4_stages.py` — proves the S1–S6 decomposition on a small batch.
- `spike_cp4_reset.py` — the block‑reset experiment (drive M → block → drive M).
- `spike_cp4_diag.py` — splits S5 into meta/save/cons, tracks acceptance/voiding/mempool; argv `[tx_type][M]`
  so it runs against both workloads (the key root‑cause + fix‑validation tool).

**Modified:**
- `cli.py` — `run` now lazily imports the driver, drives the batch, and prints the per‑stage table + TPS +
  resources (`_print_run_summary`).
- `workload/transparent.py` — extracted the `_frontier_lines` hook; **added `OrganicTxSource`** (the fix).
- `metrics/model.py` — a one‑line clarifying comment on `Sample.rss_bytes` (units).

---

## 4. Verified — the data

**Stage decomposition (organic, N=500), wall≈cpu throughout:**

```text
stage   mean wall   share
S1        131 µs    3.1%
S2         57 µs    1.4%
S3S4     1007 µs   23.7%   verify, ∝ I, flat in N
S5       1856 µs   43.7%   save+consensus — flat with organic (tips=1)
S6       1193 µs   28.1%   2nd validate_full + indexes
TOTAL    4245 µs → 236 tx/s    accepted 500/500 · 0 voided · exact I/O 500/500
```

**TPS vs N — the fix in one table:**

| N | `transparent` (genesis, tips=N) | `organic` (chain, tips=1) |
|---|---|---|
| 100 | 169 | 162 |
| 500 | **65** | **220** |
| 1000 | **36** | **205** |

**Block‑reset (M=250):**

| | `transparent` | `organic` |
|---|---|---|
| tips before block | 251 | 2 |
| block confirms | 2 / 250 | **250 / 250 (mempool→0)** |
| S5 `cons` p1‑early→late | 1.8 → 11.8 ms | 1.5 → 1.6 ms |
| S5 `cons` post‑block | **125 ms** (cache cliff) | **1.9 / 1.2 ms (flat)** |

**Root‑cause instrumentation:** S5 sub‑steps meta/save flat (~50 µs), all growth in `cons`; `txs_affected`
constant = 5; storage reads/tx ∝ tips; post‑block read‑*time* 10× but bare `flush()` = 1.0× (cache proof).

---

## 5. Accompanying changes (folded in, per request)

- **RFC — the M/Tb throughput model** (`003‑prime` + mirror, +49): a single batch TPS is meaningless because
  the mempool grows; the report should give a **clean‑slate ceiling `1/τ₀`** and a **sustainable `M/Tb`**
  (where `C(M)=Tb`, the cumulative processing time fills a block interval; geometrically the
  perceived‑TPS‑vs‑N curve crossed with a slope‑`1/Tb` line). Status: **hypothesis** — CP‑4's finding shows
  the deeper lever is the *tip structure*, which the organic workload now controls.
- **Editable‑install tooling** (`pyproject.toml` new, `README.md` updated): `pip install -e` the engine into
  the poetry venv so `hathor_tps_bench` resolves from any cwd and Pylance stops flagging imports; adds the
  `hathor-tps-bench` console script.
- **Findings memo** (`discussions/project-context.md`): a dense, agentic‑readable record of the engine
  architecture, the consensus finding (with code anchors), conventions, and next actions — written to
  survive context compaction.

---

## 6. What's next (CP‑5)

- Analysis + reporting: persist `per_tx_stages.csv` / `samples.csv` / `batch_summary.json`; the **C(N)**
  curve and per‑stage tables across N = 1…1000; the **M/Tb** table over Tb ∈ {7.5,15,30,60,90}s; plots.
- Confirm whether organic is *perfectly* flat or creeps slightly (the permanent S6 non‑critical‑index /
  storage component); discard a warm‑up prefix when reporting `τ₀`.
- Then a **k‑tip frontier** organic variant (each tx confirms 2 recent tips, ~2–3 tips, no genesis filler)
  for a more mainnet‑like DAG shape — deferred from CP‑4 by decision.

---

## 7. The diff (A → B) — appendix

```diff
diff --git a/tps_benchmarking/benchmarks/engine/README.md b/tps_benchmarking/benchmarks/engine/README.md
index f1bd9974..5d586809 100644
--- a/tps_benchmarking/benchmarks/engine/README.md
+++ b/tps_benchmarking/benchmarks/engine/README.md
@@ -3,19 +3,33 @@
 In-process benchmark engine for Hathor full-node transaction processing.
 Design: `tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md`.
 
+## Install (once)
+
+Editable-install the package into the hathor-core poetry env so it resolves from any cwd
+(and so editors/Pylance can resolve `hathor_tps_bench.*`). Run from the hathor-core repo root:
+
+```bash
+poetry run pip install -e tps_benchmarking/benchmarks/engine
+```
+
+In VS Code, also select the poetry interpreter
+(`Python: Select Interpreter` → the `hathor-...-py3.11` env) so `hathor` / `hathor_tests`
+resolve too.
+
 ## Running
 
-The package imports nothing from `hathor` for `list`/`validate` (scaffold only); the
-node harness and driver arrive in CP-3/CP-4. Run from this `engine/` directory so the
-package is importable:
+`list` / `validate` import nothing from `hathor` (fast); `run` boots a real in-process node.
+After the install above you can use the console script or `-m`, from anywhere:
 
 ```bash
-cd tps_benchmarking/benchmarks/engine
-poetry run python -m hathor_tps_bench list
-poetry run python -m hathor_tps_bench validate --config scenarios/basic.yaml
-poetry run python -m hathor_tps_bench run --config scenarios/basic.yaml   # stub until CP-4/CP-5
+poetry run hathor-tps-bench list
+poetry run hathor-tps-bench validate --config tps_benchmarking/benchmarks/engine/scenarios/basic.yaml
+poetry run hathor-tps-bench run --config tps_benchmarking/benchmarks/engine/scenarios/basic.yaml --num-txs 100
+# (equivalently: poetry run python -m hathor_tps_bench ...)
 ```
 
+`run` currently builds the workload on a real node and reports it; per-stage timing + reports land in CP-4/CP-5.
+
 ## Layout (built incrementally)
 
 | Path | Purpose | Checkpoint |
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/cli.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/cli.py
index 4b2a5bda..35e67aff 100644
--- a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/cli.py
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/cli.py
@@ -56,9 +56,10 @@ def _cmd_run(args: argparse.Namespace) -> int:
         print("config invalid; run `validate` for details", file=sys.stderr)
         return 1
 
-    # CP-3: build the workload on a real in-process node and report it.
-    # (Per-stage timing + reporting are wired in CP-4 / CP-5.) Imports are lazy here so
-    # `list`/`validate` never pull in hathor.
+    # CP-3 builds the workload; CP-4 drives + measures it. (Reporting = CP-5.)
+    # Imports are lazy here so `list`/`validate` never pull in hathor.
+    from hathor_tps_bench.config import STAGES
+    from hathor_tps_bench.driver import run_batch
     from hathor_tps_bench.node import NodeHarness
     from hathor_tps_bench.workload import get_txtype
 
@@ -72,18 +73,38 @@ def _cmd_run(args: argparse.Namespace) -> int:
     harness = NodeHarness(seed=cfg.env.seed, trivial_pow=cfg.env.trivial_pow).start()
     try:
         prepared = source.build(harness, w.num_txs, w.num_inputs, w.num_outputs)
-        exact = sum(1 for p in prepared
-                    if p.n_inputs == w.num_inputs and p.n_outputs == w.num_outputs)
-        distinct_inputs = {(i.tx_id, i.index) for p in prepared for i in p.tx.inputs}
-        print(f"[run] built {len(prepared)} txs preloaded with funding")
-        print(f"[run] exact I/O     : {exact}/{len(prepared)}")
-        print(f"[run] distinct inputs: {len(distinct_inputs)} (expected {w.num_txs * w.num_inputs})")
-        print("[run] driver/timing lands in CP-4 — nothing measured yet.")
+        print(f"[run] built {len(prepared)} txs; driving S1..S6 on the single thread...")
+        result = run_batch(harness, prepared, sampler_interval_s=cfg.measure.sampler_interval_s)
+        _print_run_summary(result, cfg)
     finally:
         harness.stop()
     return 0
 
 
+def _print_run_summary(result, cfg) -> None:
+    means_w = result.stage_mean_wall_us()
+    means_c = result.stage_mean_cpu_us()
+    total = result.total_mean_wall_us()
+    b = result.batch
+    mb = 1024 * 1024
+
+    print(f"\n[result] accepted {result.accepted}/{result.n}")
+    print(f"  {'stage':6} {'mean wall us':>13} {'mean cpu us':>12} {'share':>7}")
+    for s in result.stage_mean_wall_us():
+        share = (means_w[s] / total) if total else 0.0
+        print(f"  {s:6} {means_w[s]:13.1f} {means_c[s]:12.1f} {share:7.1%}")
+    print(f"  {'TOTAL':6} {total:13.1f}")
+    print(f"\n  processing throughput : {result.processing_tps():.0f} tx/s "
+          f"(1 / mean per-tx total wall)")
+    print(f"  batch wall / cpu      : {b.wall_s:.3f} s / {b.cpu_s:.3f} s")
+    print(f"  peak RSS / growth     : {b.rss_peak_bytes / mb:.1f} MB / {b.rss_growth_bytes / mb:.1f} MB")
+    print(f"  disk written (flushed): {b.io_write_bytes / mb:.2f} MB")
+    print(f"  peak open FDs         : {b.fd_peak}")
+    energy = b.energy_joules(cfg.measure.tdp_watts, cfg.measure.cpu_util)
+    print(f"  energy (analytical)   : {energy:.2f} J  (cpu_s x {cfg.measure.tdp_watts} W x {cfg.measure.cpu_util})")
+    print("\n  [note] CSV / plots / report land in CP-5.")
+
+
 def build_parser() -> argparse.ArgumentParser:
     p = argparse.ArgumentParser(prog="hathor_tps_bench", description=__doc__)
     p.add_argument("--version", action="version", version=f"hathor_tps_bench {__version__}")
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/driver/__init__.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/driver/__init__.py
new file mode 100644
index 00000000..35ca9466
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/driver/__init__.py
@@ -0,0 +1,5 @@
+"""Single-thread driver: replays the node's S1..S6 processing with per-stage timing.
+Imports hathor — import lazily (e.g. inside the CLI `run` handler)."""
+from hathor_tps_bench.driver.runner import run_batch
+
+__all__ = ["run_batch"]
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/driver/runner.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/driver/runner.py
new file mode 100644
index 00000000..e0c7cb5e
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/driver/runner.py
@@ -0,0 +1,116 @@
+"""The single-thread driver.
+
+For each prepared tx, it replays `VertexHandler._old_on_new_vertex` by hand around the
+real anchor functions, timing each stage (S1..S6) with perf_counter_ns (wall) +
+process_time_ns (CPU). Funding is already in storage (the workload preloaded it); this
+only drives the *target* txs. A background sampler runs alongside, and disk I/O is read
+at the batch boundary after a flush.
+
+Stage → anchor (RFC §"The pipeline and its anchor functions"):
+  S1   manager.vertex_parser.deserialize(raw)
+  S2   manager pre-checks (exists / double-spend / spending-voided / reward-lock)
+  S3S4 VertexHandler._validate_vertex            (full verification)
+  S5   VertexHandler._unsafe_save_and_run_consensus
+  S6   VertexHandler._post_consensus             (incl. the 2nd validate_full)
+"""
+from __future__ import annotations
+
+import time
+from typing import Any
+
+from hathor.feature_activation.utils import Features
+from hathor.reward_lock import is_spent_reward_locked
+from hathor.verification.verification_params import VerificationParams
+
+from hathor_tps_bench.metrics.collector import RunResult
+from hathor_tps_bench.metrics.model import BatchResources, StageTiming, TxRecord
+from hathor_tps_bench.probes import procstats, storage_stats
+from hathor_tps_bench.probes.sampler import ProcSampler
+
+
+def build_params(manager: Any) -> VerificationParams:
+    """Reconstruct what VertexHandler.on_new_relayed_vertex builds. best_block is fixed
+    during the timed loop (we add no blocks), so this is built once per batch."""
+    vh = manager.vertex_handler
+    best_block = vh._tx_storage.get_best_block()
+    features = Features.for_mempool(
+        settings=vh._settings, feature_service=vh._feature_service, best_block=best_block
+    )
+    return VerificationParams(
+        reject_locked_reward=True,
+        nc_block_root_id=best_block.get_metadata().nc_block_root_id,
+        features=features,
+    )
+
+
+def _drive_one(manager, vh, settings, params, raw: bytes, index: int) -> TxRecord:
+    stages: dict[str, StageTiming] = {}
+
+    def timed(key: str, fn):
+        w, c = time.perf_counter_ns(), time.process_time_ns()
+        result = fn()
+        stages[key] = StageTiming(
+            wall_ns=time.perf_counter_ns() - w,
+            cpu_ns=time.process_time_ns() - c,
+        )
+        return result
+
+    vtx = timed("S1", lambda: manager.vertex_parser.deserialize(raw))
+    vtx.storage = manager.tx_storage
+    timed("S2", lambda: (
+        not manager.tx_storage.transaction_exists(vtx.hash)
+        and not vtx.is_double_spending()
+        and not vtx.is_spending_voided_tx()
+        and not is_spent_reward_locked(settings, vtx)
+    ))
+    valid = timed("S3S4", lambda: vh._validate_vertex(vtx, params))
+    events = timed("S5", lambda: vh._unsafe_save_and_run_consensus(vtx))
+    timed("S6", lambda: vh._post_consensus(vtx, params, events, quiet=True))
+
+    accepted = bool(valid) and not vtx.get_metadata().voided_by
+    return TxRecord(
+        index=index,
+        tx_id=vtx.hash_hex,
+        n_inputs=len(vtx.inputs),
+        n_outputs=len(vtx.outputs),
+        size_bytes=len(raw),
+        accepted=accepted,
+        stages=stages,
+    )
+
+
+def run_batch(harness, prepared, *, sampler_interval_s: float = 0.1) -> RunResult:
+    manager = harness.manager
+    vh = manager.vertex_handler
+    settings = manager._settings
+    params = build_params(manager)
+
+    io_r0, io_w0 = procstats.read_io()
+    rss_start = procstats.read_rss_bytes()
+    sampler = ProcSampler(interval_s=sampler_interval_s).start()
+
+    records: list[TxRecord] = []
+    w0, c0 = time.perf_counter(), time.process_time()
+    for i, p in enumerate(prepared):
+        records.append(_drive_one(manager, vh, settings, params, p.raw, i))
+        sampler.set_progress(i + 1)
+    wall_s = time.perf_counter() - w0
+    cpu_s = time.process_time() - c0
+
+    storage_stats.flush(manager)  # realise deferred writes before reading disk I/O
+    sampler.stop()
+
+    io_r1, io_w1 = procstats.read_io()
+    rss_end = procstats.read_rss_bytes()
+    batch = BatchResources(
+        wall_s=wall_s,
+        cpu_s=cpu_s,
+        io_read_bytes=io_r1 - io_r0,
+        io_write_bytes=io_w1 - io_w0,
+        rss_start_bytes=rss_start,
+        rss_peak_bytes=max(sampler.rss_peak, rss_end),
+        rss_end_bytes=rss_end,
+        fd_peak=sampler.fd_peak,
+        sst_bytes=storage_stats.read_sst_bytes(manager),
+    )
+    return RunResult(records=records, batch=batch, samples=sampler.samples)
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/metrics/collector.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/metrics/collector.py
new file mode 100644
index 00000000..331d8bb9
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/metrics/collector.py
@@ -0,0 +1,48 @@
+"""RunResult — the bundle a driver run produces, plus light reductions.
+
+Heavy analysis (percentiles, plots, CSV/markdown report) is CP-5; this holds the raw
+records + batch resources + samples and a few convenience reductions for the CLI."""
+from __future__ import annotations
+
+from dataclasses import dataclass
+from statistics import mean
+
+from hathor_tps_bench.config import STAGES
+from hathor_tps_bench.metrics.model import BatchResources, Sample, TxRecord
+
+
+@dataclass
+class RunResult:
+    records: list[TxRecord]
+    batch: BatchResources
+    samples: list[Sample]
+
+    @property
+    def n(self) -> int:
+        return len(self.records)
+
+    @property
+    def accepted(self) -> int:
+        return sum(1 for r in self.records if r.accepted)
+
+    def stage_mean_wall_us(self) -> dict[str, float]:
+        out: dict[str, float] = {}
+        for s in STAGES:
+            vals = [r.stages[s].wall_ns for r in self.records if s in r.stages]
+            out[s] = (mean(vals) / 1000.0) if vals else 0.0
+        return out
+
+    def stage_mean_cpu_us(self) -> dict[str, float]:
+        out: dict[str, float] = {}
+        for s in STAGES:
+            vals = [r.stages[s].cpu_ns for r in self.records if s in r.stages]
+            out[s] = (mean(vals) / 1000.0) if vals else 0.0
+        return out
+
+    def total_mean_wall_us(self) -> float:
+        return sum(self.stage_mean_wall_us().values())
+
+    def processing_tps(self) -> float:
+        """N / sum(per-tx total wall) == 1 / mean(per-tx total wall)."""
+        total_ns = sum(r.total_wall_ns() for r in self.records)
+        return (self.n * 1e9 / total_ns) if total_ns else 0.0
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/metrics/model.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/metrics/model.py
index dc0901ea..cfa9a6ea 100644
--- a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/metrics/model.py
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/metrics/model.py
@@ -44,7 +44,7 @@ class Sample:
     """One background time-series sample (read from /proc)."""
     t_rel_s: float        # seconds since batch start
     tx_done: int          # how many txs processed by this instant
-    rss_bytes: int
+    rss_bytes: int      # shouldn't it be bytes here??
     num_fds: int
     io_read_bytes: int    # cumulative since process start
     io_write_bytes: int
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/__init__.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/__init__.py
new file mode 100644
index 00000000..1db33884
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/__init__.py
@@ -0,0 +1 @@
+"""Resource probes: /proc readers, the background time-series sampler, storage stats."""
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/procstats.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/procstats.py
new file mode 100644
index 00000000..4342c4de
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/procstats.py
@@ -0,0 +1,50 @@
+"""Dependency-free process resource readers (Linux /proc).
+
+We read /proc/self directly rather than depend on psutil: zero new deps, and these are
+exactly the fields we need. Bytes are returned as ints (a count of bytes)."""
+from __future__ import annotations
+
+import os
+
+
+def read_rss_bytes() -> int:
+    """Resident set size — physical RAM held by this process, in bytes."""
+    with open("/proc/self/status", encoding="ascii") as fh:
+        for line in fh:
+            if line.startswith("VmRSS:"):
+                return int(line.split()[1]) * 1024  # value is in kB
+    return 0
+
+
+def read_vmhwm_bytes() -> int:
+    """Peak RSS ever reached by this process (high-water mark), in bytes."""
+    with open("/proc/self/status", encoding="ascii") as fh:
+        for line in fh:
+            if line.startswith("VmHWM:"):
+                return int(line.split()[1]) * 1024
+    return 0
+
+
+def read_fd_count() -> int:
+    """Number of open file descriptors."""
+    try:
+        return len(os.listdir("/proc/self/fd"))
+    except OSError:
+        return 0
+
+
+def read_io() -> tuple[int, int]:
+    """(read_bytes, write_bytes) — actual block-device I/O since process start.
+
+    These are the disk-level counters (not rchar/wchar, which include page cache)."""
+    read_bytes = write_bytes = 0
+    try:
+        with open("/proc/self/io", encoding="ascii") as fh:
+            for line in fh:
+                if line.startswith("read_bytes:"):
+                    read_bytes = int(line.split()[1])
+                elif line.startswith("write_bytes:"):
+                    write_bytes = int(line.split()[1])
+    except OSError:
+        pass
+    return read_bytes, write_bytes
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/sampler.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/sampler.py
new file mode 100644
index 00000000..2456c297
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/sampler.py
@@ -0,0 +1,57 @@
+"""Background time-series sampler.
+
+A daemon thread that reads /proc at a fixed interval, producing the Sample series used
+for over-time / versus-N charts, and tracking RSS/FD peaks for the batch summary. It
+only *reads* /proc, so it does no processing work — the measured pipeline stays
+single-threaded (see RFC §"Note on threading")."""
+from __future__ import annotations
+
+import threading
+import time
+
+from hathor_tps_bench.metrics.model import Sample
+from hathor_tps_bench.probes import procstats
+
+
+class ProcSampler:
+    def __init__(self, interval_s: float = 0.1) -> None:
+        self.interval_s = interval_s
+        self.samples: list[Sample] = []
+        self.rss_peak: int = 0
+        self.fd_peak: int = 0
+        self._stop = threading.Event()
+        self._thread: threading.Thread | None = None
+        self._t0 = 0.0
+        self._progress = 0
+
+    def set_progress(self, n_done: int) -> None:
+        """Record how many txs are done, so samples carry a tx-axis for vs-N charts."""
+        self._progress = n_done
+
+    def start(self) -> "ProcSampler":
+        self._t0 = time.perf_counter()
+        self._thread = threading.Thread(target=self._loop, name="proc-sampler", daemon=True)
+        self._thread.start()
+        return self
+
+    def _loop(self) -> None:
+        while not self._stop.is_set():
+            rss = procstats.read_rss_bytes()
+            fds = procstats.read_fd_count()
+            io_r, io_w = procstats.read_io()
+            self.rss_peak = max(self.rss_peak, rss)
+            self.fd_peak = max(self.fd_peak, fds)
+            self.samples.append(Sample(
+                t_rel_s=time.perf_counter() - self._t0,
+                tx_done=self._progress,
+                rss_bytes=rss,
+                num_fds=fds,
+                io_read_bytes=io_r,
+                io_write_bytes=io_w,
+            ))
+            self._stop.wait(self.interval_s)
+
+    def stop(self) -> None:
+        self._stop.set()
+        if self._thread is not None:
+            self._thread.join(timeout=2.0)
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/storage_stats.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/storage_stats.py
new file mode 100644
index 00000000..25cf2c42
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/probes/storage_stats.py
@@ -0,0 +1,26 @@
+"""Storage-side probes: force deferred RocksDB writes, read storage size.
+
+RocksDB writes are deferred to a background flush, so per-stage S5 disk I/O is not
+faithful; we `flush()` at the batch boundary and read the authoritative disk figure
+from /proc afterwards (RFC §"Measuring memory, disk I/O, and file descriptors")."""
+from __future__ import annotations
+
+from typing import Any
+
+
+def flush(manager: Any) -> None:
+    """Realise any deferred RocksDB writes (best-effort)."""
+    fn = getattr(manager.tx_storage, "flush", None)
+    if callable(fn):
+        try:
+            fn()
+        except Exception:  # noqa: BLE001 — flushing must never break a run
+            pass
+
+
+def read_sst_bytes(manager: Any) -> int:
+    """Total RocksDB SST-file size, if cheaply available; else 0.
+
+    Not wired in CP-4 — the authoritative disk signal is the /proc write_bytes delta.
+    Left as a hook for a later RocksDB-stats probe."""
+    return 0
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/workload/transparent.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/workload/transparent.py
index aa9bd0d8..fcdc971a 100644
--- a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/workload/transparent.py
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/workload/transparent.py
@@ -64,9 +64,15 @@ class TransparentTxSource(TxSource):
             for j in range(num_outputs):
                 v = base + (rem if j == num_outputs - 1 else 0)
                 lines.append(f"{name}.out[{j}] = {v} HTR")         # pinned outputs
-            lines.append(f"b{tx_anchor} < {name}")
+            lines.extend(self._frontier_lines(t, name, tx_anchor))
         return "\n".join(lines)
 
+    def _frontier_lines(self, t: int, name: str, tx_anchor: int) -> list[str]:
+        """Parent/ordering lines for tx `t`. Base = genesis-parented (the filler fills
+        both parent slots with genesis), so EVERY tx is a tip -> O(N) mempool-tips scan.
+        Overridden by OrganicTxSource to chain txs and bound the tip set."""
+        return [f"b{tx_anchor} < {name}"]
+
     def build(self, harness: Any, num_txs: int, num_inputs: int, num_outputs: int) -> list[PreparedTx]:
         dsl = self.render_dsl(num_txs, num_inputs, num_outputs)
         artifacts = harness.dag_builder().build_from_str(dsl)
@@ -95,3 +101,21 @@ class TransparentTxSource(TxSource):
             )
             for t in range(num_txs)
         ]
+
+
+@register_txtype("organic")
+class OrganicTxSource(TransparentTxSource):
+    """Organic, tip-confirming workload: each tx names the PREVIOUS tx as a parent, so
+    the chain is `tx0 <- tx1 <- tx2 <- ...`. Every tx therefore confirms its predecessor
+    -> only the latest tx is ever a tip -> the mempool-tips set stays at ~1 instead of
+    growing to N. Funding / inputs / outputs are identical to `transparent`; only the
+    parent edges differ (`tx_t --> tx_{t-1}`; the filler fills tx_t's 2nd parent slot with
+    genesis, which is never a mempool tip). `tx0` has no predecessor -> 2 genesis parents.
+    This is the linear-chain, single-tip variant (Option A); a wider k-tip frontier can
+    come later for a more representative DAG."""
+
+    def _frontier_lines(self, t: int, name: str, tx_anchor: int) -> list[str]:
+        lines = [f"b{tx_anchor} < {name}"]
+        if t >= 1:
+            lines.append(f"tx{t} --> tx{t - 1}")  # tx_{t-1} becomes a parent of tx_t
+        return lines
diff --git a/tps_benchmarking/benchmarks/engine/pyproject.toml b/tps_benchmarking/benchmarks/engine/pyproject.toml
new file mode 100644
index 00000000..27478f85
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/pyproject.toml
@@ -0,0 +1,18 @@
+[build-system]
+requires = ["setuptools>=61"]
+build-backend = "setuptools.build_meta"
+
+[project]
+name = "hathor-tps-bench"
+version = "0.0.1"
+description = "In-process benchmark engine for Hathor full-node transaction processing."
+requires-python = ">=3.11"
+# Runtime deps are provided by the ambient hathor-core poetry env (pyyaml, hathor, ...).
+# Reporting deps (pandas, matplotlib, openpyxl) are added in CP-5.
+
+[project.scripts]
+hathor-tps-bench = "hathor_tps_bench.cli:main"
+
+[tool.setuptools.packages.find]
+where = ["."]
+include = ["hathor_tps_bench*"]
diff --git a/tps_benchmarking/benchmarks/engine/scenarios/organic.yaml b/tps_benchmarking/benchmarks/engine/scenarios/organic.yaml
new file mode 100644
index 00000000..4ba5c393
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/scenarios/organic.yaml
@@ -0,0 +1,30 @@
+# Organic scenario — tip-confirming linear chain (Option A). Each tx parents the
+# previous tx, so the mempool-tips set stays ~1 and consensus stays O(1) (vs the
+# genesis-parented `transparent`, where tips = N and consensus is O(N)).
+name: organic-baseline
+
+benchmarks:
+  - stage-latency
+
+results_root: results
+
+workload:
+  tx_type: organic
+  num_txs: 500
+  num_inputs: 1      # I
+  num_outputs: 2     # O
+
+env:
+  network: unittests
+  storage: rocksdb_temp
+  seed: 1234
+  trivial_pow: true
+
+measure:
+  sampler_interval_s: 0.1
+  tdp_watts: 65.0
+  cpu_util: 1.0
+  deep_tracemalloc_sample: 0
+
+reporting:
+  formats: [csv, plots, markdown]
diff --git a/tps_benchmarking/benchmarks/engine/spikes/spike_cp4_diag.py b/tps_benchmarking/benchmarks/engine/spikes/spike_cp4_diag.py
new file mode 100644
index 00000000..8c8d581e
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/spikes/spike_cp4_diag.py
@@ -0,0 +1,112 @@
+"""
+CP-4 diagnostic: localise the S5 cost (and the post-block explosion).
+
+Splits S5 (_unsafe_save_and_run_consensus) into its three sub-steps:
+  meta   = vertex.update_initial_metadata  (adds tx as a CHILD of each parent)
+  save   = tx_storage.save_transaction
+  cons   = consensus.unsafe_update
+and tracks acceptance / voiding / mempool size, across: phase1 (M) -> block -> phase2 (M).
+"""
+import os
+
+from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
+os.environ.setdefault("HATHOR_CONFIG_YAML", UNITTESTS_SETTINGS_FILEPATH)
+
+from hathor.reactor import initialize_global_reactor
+initialize_global_reactor(use_asyncio_reactor=True)
+
+import sys
+import time
+
+from hathor.execution_manager import non_critical_code
+from hathor.reward_lock import is_spent_reward_locked
+from hathor.simulator.utils import add_new_blocks
+from hathor_tests.utils import BURN_ADDRESS
+
+from hathor_tps_bench.driver.runner import build_params
+from hathor_tps_bench.node import NodeHarness
+from hathor_tps_bench.workload import get_txtype
+
+# argv: [tx_type=transparent] [M=250]
+TXTYPE = sys.argv[1] if len(sys.argv) > 1 else "transparent"
+M = int(sys.argv[2]) if len(sys.argv) > 2 else 250
+
+
+def mempool_size(manager):
+    return sum(1 for _ in manager.tx_storage.iter_mempool_tips())
+
+
+def confirmed_count(manager, hashes):
+    n = 0
+    for h in hashes:
+        try:
+            if manager.tx_storage.get_transaction(h).get_metadata().first_block is not None:
+                n += 1
+        except Exception:
+            pass
+    return n
+
+
+def drive_split(manager, vh, settings, params, raw):
+    ns = time.perf_counter_ns
+    vtx = manager.vertex_parser.deserialize(raw)
+    vtx.storage = manager.tx_storage
+    _ = (not manager.tx_storage.transaction_exists(vtx.hash) and not vtx.is_double_spending()
+         and not vtx.is_spending_voided_tx() and not is_spent_reward_locked(settings, vtx))
+    vh._validate_vertex(vtx, params)
+    # ---- S5 split ----
+    t = ns(); vtx.update_initial_metadata(save=False); meta_us = (ns() - t) / 1000
+    t = ns(); manager.tx_storage.save_transaction(vtx); save_us = (ns() - t) / 1000
+    with non_critical_code(vh._log):
+        manager.tx_storage.indexes.add_to_non_critical_indexes(vtx)
+    t = ns(); events = vh._consensus.unsafe_update(vtx); cons_us = (ns() - t) / 1000
+    vh._post_consensus(vtx, params, events, quiet=True)
+    voided = bool(vtx.get_metadata().voided_by)
+    return vtx.hash, meta_us, save_us, cons_us, voided
+
+
+def avg(xs, sl):
+    xs = xs[sl]
+    return sum(xs) / len(xs) if xs else 0.0
+
+
+def main():
+    harness = NodeHarness(seed=1234).start()
+    manager, vh, settings = harness.manager, harness.manager.vertex_handler, harness.manager._settings
+    prepared = get_txtype(TXTYPE)().build(harness, 2 * M, 1, 2)
+    exact = sum(1 for p in prepared if p.n_inputs == 1 and p.n_outputs == 2)
+    print(f"workload={TXTYPE!r}  M={M}  exact I/O={exact}/{2 * M}")
+
+    meta, save, cons, voided = [], [], [], 0
+    hashes = []
+
+    params = build_params(manager)
+    for i in range(M):
+        h, m, s, c, v = drive_split(manager, vh, settings, params, prepared[i].raw)
+        meta.append(m); save.append(s); cons.append(c); voided += v; hashes.append(h)
+    mp_before = mempool_size(manager)
+
+    t0 = time.perf_counter()
+    add_new_blocks(manager, 1, address=BURN_ADDRESS)
+    block_ms = (time.perf_counter() - t0) * 1000
+    mp_after = mempool_size(manager)
+    conf = confirmed_count(manager, hashes)
+
+    params = build_params(manager)
+    for i in range(M, 2 * M):
+        h, m, s, c, v = drive_split(manager, vh, settings, params, prepared[i].raw)
+        meta.append(m); save.append(s); cons.append(c); voided += v
+    harness.stop()
+
+    e, l = slice(5, 15), slice(M - 15, M - 5)
+    e2, l2 = slice(M + 5, M + 15), slice(2 * M - 15, 2 * M - 5)
+    print(f"block: confirmed {conf}/{M} phase-1 txs; mempool {mp_before} -> {mp_after}; cost {block_ms:.1f} ms")
+    print(f"total voided (both phases): {voided}/{2 * M}\n")
+    print(f"{'sub-step':6} {'p1 early':>9} {'p1 late':>9} {'p2 early':>9} {'p2 late':>9}   (us)")
+    for name, arr in (("meta", meta), ("save", save), ("cons", cons)):
+        print(f"{name:6} {avg(arr, e):9.1f} {avg(arr, l):9.1f} {avg(arr, e2):9.1f} {avg(arr, l2):9.1f}")
+    return 0
+
+
+if __name__ == "__main__":
+    raise SystemExit(main())
diff --git a/tps_benchmarking/benchmarks/engine/spikes/spike_cp4_reset.py b/tps_benchmarking/benchmarks/engine/spikes/spike_cp4_reset.py
new file mode 100644
index 00000000..57148db4
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/spikes/spike_cp4_reset.py
@@ -0,0 +1,96 @@
+"""
+CP-4 block-reset experiment: is S5's (and S6's) growth mempool-driven and reset by a block?
+
+Drives M txs (watch S5/S6 climb), injects ONE block to confirm the mempool (timing the
+block's O(M) cost), then drives M more txs and checks whether S5/S6 drop back toward
+their clean-slate values. This validates the M/Tb sustainable-throughput model:
+  - if S5 resets -> growth is unconfirmed-mempool-driven, Tb bounds it (model holds);
+  - if S6 does NOT reset -> part of it is permanent (storage), a separate bottleneck.
+
+Run:  poetry run python tps_benchmarking/benchmarks/engine/spikes/spike_cp4_reset.py
+"""
+import os
+
+from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
+os.environ.setdefault("HATHOR_CONFIG_YAML", UNITTESTS_SETTINGS_FILEPATH)
+
+from hathor.reactor import initialize_global_reactor
+initialize_global_reactor(use_asyncio_reactor=True)
+
+import time
+
+from hathor.simulator.utils import add_new_blocks
+from hathor_tests.utils import BURN_ADDRESS
+
+from hathor_tps_bench.driver.runner import _drive_one, build_params
+from hathor_tps_bench.node import NodeHarness
+from hathor_tps_bench.workload import get_txtype
+
+M = 250  # txs per phase
+
+
+def mempool_size(manager) -> int:
+    return sum(1 for _ in manager.tx_storage.iter_mempool_tips())
+
+
+def avg(xs):
+    return sum(xs) / len(xs) if xs else 0.0
+
+
+def main():
+    harness = NodeHarness(seed=1234).start()
+    manager = harness.manager
+    vh = manager.vertex_handler
+    settings = manager._settings
+
+    prepared = get_txtype("transparent")().build(harness, 2 * M, 1, 2)
+    s5, s6 = [], []
+
+    # ---- phase 1: drive M txs (no blocks) ----
+    params = build_params(manager)
+    for i in range(M):
+        rec = _drive_one(manager, vh, settings, params, prepared[i].raw, i)
+        s5.append(rec.stages["S5"].wall_ns / 1000)
+        s6.append(rec.stages["S6"].wall_ns / 1000)
+    mp_before = mempool_size(manager)
+
+    # ---- inject ONE block (confirm the mempool); time its O(M) cost ----
+    t0 = time.perf_counter()
+    add_new_blocks(manager, 1, address=BURN_ADDRESS)
+    block_ms = (time.perf_counter() - t0) * 1000
+    mp_after = mempool_size(manager)
+
+    # ---- phase 2: drive M more txs (best_block changed -> rebuild params) ----
+    params = build_params(manager)
+    for i in range(M, 2 * M):
+        rec = _drive_one(manager, vh, settings, params, prepared[i].raw, i)
+        s5.append(rec.stages["S5"].wall_ns / 1000)
+        s6.append(rec.stages["S6"].wall_ns / 1000)
+
+    harness.stop()
+
+    p1_early, p1_late = slice(5, 15), slice(M - 15, M - 5)
+    p2_early, p2_late = slice(M + 5, M + 15), slice(2 * M - 15, 2 * M - 5)
+
+    print(f"mempool tips: before block = {mp_before}, after block = {mp_after}  "
+          f"(block confirmed ~{mp_before - mp_after})")
+    print(f"block confirm cost: {block_ms:.1f} ms  for M={M}\n")
+
+    print(f"{'stage':4} {'p1 early':>9} {'p1 late':>9} {'p2 early':>9} {'p2 late':>9}   (us)")
+    for name, arr in (("S5", s5), ("S6", s6)):
+        print(f"{name:4} {avg(arr[p1_early]):9.0f} {avg(arr[p1_late]):9.0f} "
+              f"{avg(arr[p2_early]):9.0f} {avg(arr[p2_late]):9.0f}")
+
+    s5_reset = avg(s5[p2_early]) / avg(s5[p1_late]) if avg(s5[p1_late]) else 0
+    s6_reset = avg(s6[p2_early]) / avg(s6[p1_late]) if avg(s6[p1_late]) else 0
+    print(f"\nS5 reset ratio (p2-early / p1-late): {s5_reset:.2f}  (<<1 => block reset it)")
+    print(f"S6 reset ratio (p2-early / p1-late): {s6_reset:.2f}")
+    print("\nverdict:",
+          "S5 IS mempool-driven & block-resettable -> M/Tb model holds"
+          if s5_reset < 0.6 else
+          "S5 did NOT reset -> growth is (partly) permanent; model needs rethink")
+    return 0
+
+
+if __name__ == "__main__":
+    raise SystemExit(main())
diff --git a/tps_benchmarking/benchmarks/engine/spikes/spike_cp4_stages.py b/tps_benchmarking/benchmarks/engine/spikes/spike_cp4_stages.py
new file mode 100644
index 00000000..a8e90c62
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/spikes/spike_cp4_stages.py
@@ -0,0 +1,106 @@
+"""
+CP-4 stage-timing mini-spike: de-risk decomposing tx processing into S1..S6.
+
+Replays VertexHandler._old_on_new_vertex by hand around the real anchor functions,
+timing each stage with perf_counter_ns (wall) + process_time_ns (CPU). Confirms every
+tx is accepted and that the per-stage split is sane (S3+S4 verify and S6's second
+validate_full should dominate).
+
+Run:  poetry run python tps_benchmarking/benchmarks/engine/spikes/spike_cp4_stages.py
+"""
+import os
+
+from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
+os.environ.setdefault("HATHOR_CONFIG_YAML", UNITTESTS_SETTINGS_FILEPATH)
+
+from hathor.reactor import initialize_global_reactor
+initialize_global_reactor(use_asyncio_reactor=True)
+
+import time
+from statistics import mean
+
+from hathor.feature_activation.utils import Features
+from hathor.reward_lock import is_spent_reward_locked
+from hathor.verification.verification_params import VerificationParams
+
+from hathor_tps_bench.node import NodeHarness
+from hathor_tps_bench.workload import get_txtype
+
+N_TXS = 50
+N_INPUTS = 1
+N_OUTPUTS = 2
+STAGES = ("S1", "S2", "S3S4", "S5", "S6")
+
+
+def build_params(manager) -> VerificationParams:
+    # Reconstruct what VertexHandler.on_new_relayed_vertex builds. best_block is fixed
+    # during the timed loop (we add no blocks), so build it once.
+    vh = manager.vertex_handler
+    best_block = vh._tx_storage.get_best_block()
+    features = Features.for_mempool(
+        settings=vh._settings, feature_service=vh._feature_service, best_block=best_block
+    )
+    return VerificationParams(
+        reject_locked_reward=True,
+        nc_block_root_id=best_block.get_metadata().nc_block_root_id,
+        features=features,
+    )
+
+
+def timed(store, key, fn):
+    w, c = time.perf_counter_ns(), time.process_time_ns()
+    r = fn()
+    store[key].append((time.perf_counter_ns() - w, time.process_time_ns() - c))
+    return r
+
+
+def main():
+    harness = NodeHarness(seed=1234).start()
+    manager = harness.manager
+    vh = manager.vertex_handler
+    settings = manager._settings
+    parser = manager.vertex_parser
+
+    prepared = get_txtype("transparent")().build(harness, N_TXS, N_INPUTS, N_OUTPUTS)
+    params = build_params(manager)
+
+    timings = {s: [] for s in STAGES}
+    accepted = 0
+
+    for p in prepared:
+        raw = p.raw
+        vtx = timed(timings, "S1", lambda: parser.deserialize(raw))
+        vtx.storage = manager.tx_storage
+
+        ok2 = timed(timings, "S2", lambda: (
+            not manager.tx_storage.transaction_exists(vtx.hash)
+            and not vtx.is_double_spending()
+            and not vtx.is_spending_voided_tx()
+            and not is_spent_reward_locked(settings, vtx)
+        ))
+        valid = timed(timings, "S3S4", lambda: vh._validate_vertex(vtx, params))
+        events = timed(timings, "S5", lambda: vh._unsafe_save_and_run_consensus(vtx))
+        timed(timings, "S6", lambda: vh._post_consensus(vtx, params, events, quiet=True))
+
+        if ok2 and valid and not vtx.get_metadata().voided_by:
+            accepted += 1
+
+    harness.stop()
+
+    print(f"accepted: {accepted}/{N_TXS}\n")
+    print(f"{'stage':6} {'mean wall us':>13} {'mean cpu us':>12} {'share':>7}")
+    means_w = {s: mean(t[0] for t in timings[s]) / 1000 for s in STAGES}
+    total_w = sum(means_w.values())
+    for s in STAGES:
+        mc = mean(t[1] for t in timings[s]) / 1000
+        print(f"{s:6} {means_w[s]:13.1f} {mc:12.1f} {means_w[s] / total_w:7.1%}")
+    print(f"{'TOTAL':6} {total_w:13.1f}")
+    print(f"\nprocessing TPS (1 / mean per-tx total wall): {1e6 / total_w:.0f} tx/s")
+
+    ok = accepted == N_TXS
+    print(f"\nSPIKE RESULT: {'PASS ✓' if ok else 'FAIL ✗'}")
+    return 0 if ok else 1
+
+
+if __name__ == "__main__":
+    raise SystemExit(main())
diff --git a/tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md b/tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md
index 4b553cee..383166aa 100644
--- a/tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md
+++ b/tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md
@@ -442,6 +442,55 @@ Node **energy** is modelled, not measured (no reliable RAPL counters under WSL/c
 so the assumption is explicit in the report. The mining-energy term (`2^weight × J/hash`) is trivial
 at weight 1 and reported only for completeness.
 
+## Throughput is bounded by block cadence — the M/Tb model (and a measurement confound)
+
+A single batch number is **not** a network rate, and treating it as one is the easiest way to get this
+wrong. Here is why, and how we propose to read the benchmark correctly.
+
+**The mempool-growth problem.** If we drive transactions without ever adding a block, the unconfirmed
+mempool grows without bound. Consensus (S5) scales with the unconfirmed mempool, so the *per-tx* cost
+climbs as the batch proceeds, and the perceived throughput keeps falling: "I sent 100 → 120 tx/s" but
+"I sent 200 → 80 tx/s." In real Hathor this never runs away, because **blocks arrive about every
+`Tb` seconds** (DAA-adjusted, order of tens of seconds) and confirm the mempool, resetting the
+between-blocks transaction count `M`. Mainnet today is block-dominated (far more blocks than txs), so
+each tx effectively arrives to a near-empty mempool — close to the *clean-slate* cost.
+
+**Two numbers, not one.** Let `C(N)` be the cumulative processing time for a batch of `N` (mempool
+growing 0→N) — exactly what the driver records. Then `perceived_TPS(N) = N / C(N)`, a decreasing curve.
+
+- **Clean-slate ceiling** `1 / τ₀` (τ₀ = per-tx total at an empty mempool): the optimistic upper bound.
+- **Sustainable rate** `M / Tb`: the node can clear at most the `M` txs whose cumulative cost fills a
+  block interval, i.e. `C(M) = Tb`. Geometrically, on the `perceived_TPS`-vs-`N` plot the line
+  `Y = N/Tb` (slope **1/Tb**, not 1) crosses the curve exactly at `(M, M/Tb)`, since
+  `N/Tb = N/C(N) ⟺ C(N) = Tb`. We report `M/Tb` as a small table over `Tb ∈ {7.5, 15, 30, 60, 90} s`.
+
+Because per-tx cost grows ~linearly with the mempool, `C(N)` is ~quadratic, so the sustainable rate is
+far below the clean-slate ceiling and **rises as `Tb` shrinks** (more frequent blocks reset the mempool
+sooner) — block cadence is a first-order lever on tx throughput.
+
+**Status: this model is a HYPOTHESIS, not yet validated — and the current workload confounds it.** A
+CP-4 block-reset experiment (drive M txs → inject one block → drive M more) did **not** confirm that a
+block resets S5. The cause is the workload, not the node: our transparent batch parents every tx to
+**genesis**, so the mempool is a *disconnected fan*. A block selects 2 tips as parents and transitively
+confirms only what is reachable from them — with genesis-parenting, just those ~2 txs (measured: a block
+confirmed 2 of 251). Worse, feeding genesis-parented txs into a chain that has advanced by a block sends
+consensus into a pathological state (per-tx S5 jumped ~10 ms → ~120 ms). So the earlier "S5 grows with
+M" figures are **provisional/inflated**, and the M/Tb model cannot be tested until the workload builds
+an **organic, tip-confirming DAG** (each tx confirms 2 recent tips, like real traffic), so that (a) a
+block sweeps the whole reachable mempool and (b) consensus traverses a realistic connected DAG.
+
+**A second, non-resettable component.** S6 (`_post_consensus`) is the 2nd `validate_full` (∝ inputs)
+plus index updates. The **mempool-tips** index is resettable by a block, but the **non-critical
+indexes** (utxo / address / timestamp) grow with *total* stored txs and are **never** reset — a
+permanent storage-scaling cost the M/Tb model does not capture. We should therefore split S6 reporting
+into "re-verify" vs "index" sub-costs and track the permanent part against storage size.
+
+**Plan (prerequisite-ordered):** (1) build the organic tip-confirming workload; (2) re-run the
+block-reset experiment to validate (or refute) the M/Tb model and measure how much a block actually
+resets; (3) tabulate `C(N)` and per-stage times across `N` (1…1000) and the resulting `M/Tb` for each
+`Tb`, with plots; (4) measure the block's own O(M) confirmation cost and fold it into the `Tb` budget
+(`C(M) + block_confirm(M) ≤ Tb`).
+
 ## Example
 
 A single transaction from an `N=500, I=1, O=2` run produces a record like this (illustrative shape,
```
