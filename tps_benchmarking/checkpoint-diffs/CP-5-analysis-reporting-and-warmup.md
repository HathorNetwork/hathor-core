# Checkpoint CP‑5 — Analysis & reporting (warm‑up + the transient→steady curve)

- **Snapshot A:** end of CP‑4 — the driver times S1–S6 and prints a summary, but nothing is
  persisted and the cold start is still in the numbers.
- **Snapshot B:** a **steady‑state** measurement (warm‑up prefix) reduced to **CSV + JSON + plots +
  `summary.md`**, including the per‑tx **throughput‑vs‑tx‑index** curve (transient → steady) and the
  cumulative **C(N)** that the M/Tb model needs.
- **Status:** PASS ✓ — organic K=500/W=100 → 215 tx/s; `per_tx_stages.csv` has exactly K rows;
  4 plots; results land under `engine/results/` (gitignored).
- **Files:** 5 new (`analysis/`) + 6 touched (`config.py`, `driver/runner.py`, `cli.py`,
  `pyproject.toml`, two scenario YAMLs) + `.gitignore`.

---

## 1. Summary

CP‑5 turns a `RunResult` into a report **and makes the numbers honest**. Two engine ideas carry it:

1. **Warm‑up** — drive `W` transactions through the real pipeline but **discard** their records, so
   what we report is the *steady state*, not the cold start.
2. **An analysis pipeline** — `compute → {persist, plots, report}` — that reduces the per‑tx records to
   percentiles, the throughput curve, the cumulative cost curve, and a headline TPS.

Everything downstream of the driver is stdlib except the plots (matplotlib); if a reporting library
isn't there it degrades to "skipped" rather than failing the run. That part is plumbing — the engine
content is the warm‑up semantics and the two curves below.

## 2. Warm‑up: measuring steady state, not the cold start

CP‑4's sweep showed a cold‑start transient — N=100 measured *slower* than N=500 — because the first
chunk of a batch pays for a cold RocksDB read cache and interpreter warm‑up. A benchmark should report
the regime the node actually lives in, so:

- `workload.num_txs` is now **K, the measured count**; `workload.warmup_txs` is **W**. We build `W+K`
  txs, drive the first `W` through the *full* pipeline (real processing — they genuinely extend the
  DAG), keep nothing, then snapshot resources + start the sampler **after** warm‑up and measure `K`.
- **No block in the warm‑up.** This is the CP‑4 lesson made operational: in the organic chain tips are
  already ~1, so a block confirms nothing useful — and block processing *evicts the tx cache*, which
  would re‑introduce the very cold transient we're removing. So warm‑up is transactions‑only.
- Effect: excluding the cold prefix lifts the measured rate (organic K=80 went ~230 → **273 tx/s** once
  the warm‑up txs were no longer dragging the mean down).

## 3. The two curves that matter

The per‑tx `TxRecord`s the driver already produces are enough to draw the two curves this project keeps
returning to:

- **`rolling_tps.png` — throughput vs tx index.** A sliding‑window TPS over the measured txs: you watch
  the transient settle into the steady state. This is also how we *size W empirically* — pick W past
  where the curve flattens.
- **`cumulative_cn.png` — C(N).** The cumulative processing time for the first N measured txs. This is
  the exact curve the **M/Tb sustainable‑rate model** crosses with a slope‑`1/Tb` line (RFC) to read off
  the per‑block‑interval throughput. CP‑5 produces it; CP‑6 will use it across a real N‑sweep.

## 4. The analysis pipeline (what each module computes)

- **`analysis/compute.py`** — the reductions: nearest‑rank percentiles; the per‑stage table
  (mean/p50/p90/p99 wall, mean cpu, share of the per‑tx total); `rolling_tps` (the transient→steady
  series); `cumulative_curve` (N, C(N), perceived‑TPS); and `headline` (TPS, latency percentiles,
  batch resources, analytical energy).
- **`analysis/persist.py`** — `per_tx_stages.csv` (one row per measured tx: identity, I/O, accepted,
  every stage's wall+cpu, total), `samples.csv` (the `/proc` time‑series), `batch_summary.json`.
- **`analysis/plots.py`** — the four charts; matplotlib/Agg, returns `[]` (skips) if unavailable.
- **`analysis/report.py`** — `summary.md`: the headline, the per‑stage table, resources, embedded plots.
- **`cli.py`** — `run` now builds `W+K`, measures `K`, and writes everything to
  `results/<name>_<type>_N<K>_I<I>_O<O>/`.

## 5. Verified

Organic, K=500, W=100:

```text
accepted 500/500 · processing throughput 215 tx/s
S1 3% · S2 1% · S3S4 27% · S5 37% · S6 31%   (flat — organic)
artifacts: per_tx_stages.csv (500 rows) · samples.csv · batch_summary.json · summary.md
           plots/{rolling_tps,stage_means,latency_hist,cumulative_cn}.png
```

- `per_tx_stages.csv` row count = **K** (warm‑up correctly excluded).
- `list`/`validate` stay light (0.54 s; no hathor/matplotlib pulled); `validate` resolves `warmup_txs`.
- Results are gitignored under the engine; no repo‑root clutter.

## 6. What's next (CP‑6 — the experiments)

CP‑5 is the *reporting machinery for one run*. CP‑6 *runs it for real*:
- the **N‑sweep** (N = 10…10000) → throughput‑vs‑N and the **M/Tb** table over Tb ∈ {7.5,15,30,60,90}s;
- the **I/O sweep** (vary I, then O);
- **scale** the machine's numbers to a typical Hathor full‑node's recommended + bare‑minimum specs;
- the final headline TPS + docs.

---

## 7. The diff (A → B) — appendix

_Diff vs `b70ed4c4` (the CP‑4 commit) — CP‑5 changes only._

```diff
diff --git a/tps_benchmarking/benchmarks/engine/.gitignore b/tps_benchmarking/benchmarks/engine/.gitignore
new file mode 100644
index 00000000..97385380
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/.gitignore
@@ -0,0 +1,3 @@
+results/
+__pycache__/
+*.pyc
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/__init__.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/__init__.py
new file mode 100644
index 00000000..196e4605
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/__init__.py
@@ -0,0 +1,2 @@
+"""Analysis + reporting: reduce a RunResult to stats, CSV/JSON, plots, and a summary.md.
+Stdlib-only except `plots` (matplotlib), which degrades gracefully if unavailable."""
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/compute.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/compute.py
new file mode 100644
index 00000000..781462bf
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/compute.py
@@ -0,0 +1,84 @@
+"""Reductions over a RunResult — percentiles, per-stage table, the transient->steady
+rolling-TPS series, the cumulative C(N) curve, and the headline figures. Stdlib only."""
+from __future__ import annotations
+
+from statistics import mean
+
+from hathor_tps_bench.config import STAGES
+from hathor_tps_bench.metrics.collector import RunResult
+
+_MB = 1024 * 1024
+
+
+def _pct(sorted_vals: list[float], p: float) -> float:
+    """Nearest-rank percentile of an already-sorted list."""
+    if not sorted_vals:
+        return 0.0
+    k = int(round((p / 100.0) * (len(sorted_vals) - 1)))
+    return sorted_vals[max(0, min(len(sorted_vals) - 1, k))]
+
+
+def per_tx_totals_us(result: RunResult) -> list[float]:
+    return [r.total_wall_ns() / 1000.0 for r in result.records]
+
+
+def stage_table(result: RunResult) -> list[dict]:
+    """Per-stage mean/p50/p90/p99 wall (µs), mean cpu, and share of the per-tx total."""
+    total_mean = result.total_mean_wall_us()
+    rows: list[dict] = []
+    for s in STAGES:
+        wall = sorted(r.stages[s].wall_ns / 1000.0 for r in result.records if s in r.stages)
+        cpu = [r.stages[s].cpu_ns / 1000.0 for r in result.records if s in r.stages]
+        m = mean(wall) if wall else 0.0
+        rows.append({
+            "stage": s,
+            "mean_wall_us": m,
+            "mean_cpu_us": mean(cpu) if cpu else 0.0,
+            "p50_us": _pct(wall, 50), "p90_us": _pct(wall, 90), "p99_us": _pct(wall, 99),
+            "share": (m / total_mean) if total_mean else 0.0,
+        })
+    return rows
+
+
+def rolling_tps(result: RunResult, window: int = 25) -> list[tuple[int, float]]:
+    """Sliding-window TPS vs measured-tx index — the transient->steady-state curve.
+    TPS at i = window_size / Σ(per-tx total wall over the window)."""
+    totals_ns = [r.total_wall_ns() for r in result.records]
+    out: list[tuple[int, float]] = []
+    for i in range(len(totals_ns)):
+        win = totals_ns[max(0, i - window + 1): i + 1]
+        s = sum(win)
+        out.append((i, (len(win) * 1e9 / s) if s else 0.0))
+    return out
+
+
+def cumulative_curve(result: RunResult) -> list[tuple[int, float, float]]:
+    """(N, C(N) seconds, perceived_TPS = N / C(N)) for N = 1..K — feeds the M/Tb model."""
+    cum_ns = 0
+    out: list[tuple[int, float, float]] = []
+    for i, r in enumerate(result.records):
+        cum_ns += r.total_wall_ns()
+        n = i + 1
+        out.append((n, cum_ns / 1e9, (n * 1e9 / cum_ns) if cum_ns else 0.0))
+    return out
+
+
+def headline(result: RunResult, *, tdp_watts: float, cpu_util: float) -> dict:
+    totals = sorted(per_tx_totals_us(result))
+    b = result.batch
+    return {
+        "n_measured": result.n,
+        "accepted": result.accepted,
+        "processing_tps": result.processing_tps(),
+        "mean_total_us": mean(totals) if totals else 0.0,
+        "p50_total_us": _pct(totals, 50),
+        "p90_total_us": _pct(totals, 90),
+        "p99_total_us": _pct(totals, 99),
+        "batch_wall_s": b.wall_s,
+        "batch_cpu_s": b.cpu_s,
+        "rss_peak_mb": b.rss_peak_bytes / _MB,
+        "rss_growth_mb": b.rss_growth_bytes / _MB,
+        "disk_written_mb": b.io_write_bytes / _MB,
+        "fd_peak": b.fd_peak,
+        "energy_j": b.energy_joules(tdp_watts, cpu_util),
+    }
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/persist.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/persist.py
new file mode 100644
index 00000000..c05e1512
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/persist.py
@@ -0,0 +1,44 @@
+"""Persist a RunResult to disk — per-tx stages CSV, time-series samples CSV, and a
+machine-readable summary JSON. Stdlib `csv`/`json` only (no pandas)."""
+from __future__ import annotations
+
+import csv
+import json
+from pathlib import Path
+
+from hathor_tps_bench.config import STAGES
+from hathor_tps_bench.metrics.collector import RunResult
+
+
+def write_per_tx_csv(path: Path, result: RunResult) -> None:
+    """One row per measured tx: identity, I/O, accepted, each stage's wall+cpu, total."""
+    with open(path, "w", newline="", encoding="utf-8") as fh:
+        w = csv.writer(fh)
+        w.writerow(
+            ["index", "tx_id", "n_inputs", "n_outputs", "size_bytes", "accepted"]
+            + [f"{s}_wall_us" for s in STAGES]
+            + [f"{s}_cpu_us" for s in STAGES]
+            + ["total_wall_us"]
+        )
+        for r in result.records:
+            w.writerow(
+                [r.index, r.tx_id, r.n_inputs, r.n_outputs, r.size_bytes, int(r.accepted)]
+                + [f"{r.stages[s].wall_ns / 1000:.3f}" if s in r.stages else "" for s in STAGES]
+                + [f"{r.stages[s].cpu_ns / 1000:.3f}" if s in r.stages else "" for s in STAGES]
+                + [f"{r.total_wall_ns() / 1000:.3f}"]
+            )
+
+
+def write_samples_csv(path: Path, result: RunResult) -> None:
+    """The background /proc time-series (one row per sample)."""
+    with open(path, "w", newline="", encoding="utf-8") as fh:
+        w = csv.writer(fh)
+        w.writerow(["t_rel_s", "tx_done", "rss_bytes", "num_fds", "io_read_bytes", "io_write_bytes"])
+        for s in result.samples:
+            w.writerow([f"{s.t_rel_s:.4f}", s.tx_done, s.rss_bytes, s.num_fds,
+                        s.io_read_bytes, s.io_write_bytes])
+
+
+def write_summary_json(path: Path, payload: dict) -> None:
+    with open(path, "w", encoding="utf-8") as fh:
+        json.dump(payload, fh, indent=2)
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/plots.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/plots.py
new file mode 100644
index 00000000..03ae1de5
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/plots.py
@@ -0,0 +1,69 @@
+"""Charts (matplotlib, Agg backend). Returns the filenames written; if matplotlib is
+unavailable it returns [] so a run never fails for lack of a plotting library."""
+from __future__ import annotations
+
+from pathlib import Path
+
+from hathor_tps_bench.analysis import compute
+from hathor_tps_bench.metrics.collector import RunResult
+
+
+def _pyplot():
+    import matplotlib
+    matplotlib.use("Agg")  # headless: render to file, no display
+    import matplotlib.pyplot as plt
+    return plt
+
+
+def generate(out_dir: Path, result: RunResult, *, window: int = 25) -> list[str]:
+    try:
+        plt = _pyplot()
+    except Exception:
+        return []  # graceful degrade — CSV/JSON/markdown still get written
+    out_dir.mkdir(parents=True, exist_ok=True)
+    made: list[str] = []
+
+    def _save(fig, name: str) -> None:
+        fig.tight_layout()
+        fig.savefig(out_dir / name, dpi=120)
+        plt.close(fig)
+        made.append(name)
+
+    # 1) The headline chart: rolling TPS vs tx index — transient (warm-up tail / cache) -> steady.
+    roll = compute.rolling_tps(result, window=window)
+    fig, ax = plt.subplots(figsize=(8, 4))
+    ax.plot([i for i, _ in roll], [t for _, t in roll], lw=1.1, color="#1f6feb")
+    ax.set(xlabel="measured tx index", ylabel=f"rolling TPS (window={window})",
+           title="Throughput vs tx index — transient → steady state")
+    ax.grid(alpha=0.3)
+    _save(fig, "rolling_tps.png")
+
+    # 2) Per-stage mean latency, annotated with each stage's share of the total.
+    rows = compute.stage_table(result)
+    fig, ax = plt.subplots(figsize=(7, 4))
+    bars = ax.bar([r["stage"] for r in rows], [r["mean_wall_us"] for r in rows], color="#57606a")
+    for bar, r in zip(bars, rows):
+        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
+                f"{r['share']:.0%}", ha="center", va="bottom", fontsize=8)
+    ax.set(ylabel="mean wall µs / tx", title="Per-stage latency (share of per-tx total)")
+    ax.grid(axis="y", alpha=0.3)
+    _save(fig, "stage_means.png")
+
+    # 3) Per-tx total-latency distribution.
+    totals = compute.per_tx_totals_us(result)
+    fig, ax = plt.subplots(figsize=(7, 4))
+    ax.hist(totals, bins=40, color="#1f6feb", alpha=0.85)
+    ax.set(xlabel="per-tx total wall µs", ylabel="count", title="Per-tx total-latency distribution")
+    ax.grid(alpha=0.3)
+    _save(fig, "latency_hist.png")
+
+    # 4) Cumulative processing time C(N) — basis for the M/Tb sustainable-rate model.
+    cum = compute.cumulative_curve(result)
+    fig, ax = plt.subplots(figsize=(8, 4))
+    ax.plot([n for n, _, _ in cum], [c for _, c, _ in cum], lw=1.1, color="#116329")
+    ax.set(xlabel="N (measured txs)", ylabel="C(N) — cumulative processing time (s)",
+           title="Cumulative processing time C(N)")
+    ax.grid(alpha=0.3)
+    _save(fig, "cumulative_cn.png")
+
+    return made
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/report.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/report.py
new file mode 100644
index 00000000..409434c5
--- /dev/null
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/analysis/report.py
@@ -0,0 +1,40 @@
+"""Render a human-readable summary.md from the headline figures + per-stage table."""
+from __future__ import annotations
+
+from pathlib import Path
+
+
+def write_report(path: Path, cfg, head: dict, stage_rows: list[dict], plot_names: list[str]) -> None:
+    w = cfg.workload
+    L: list[str] = [
+        f"# TPS benchmark — {cfg.name}",
+        "",
+        f"- workload: **{w.tx_type}**, I={w.num_inputs} O={w.num_outputs}, "
+        f"K={head['n_measured']} measured (+{w.warmup_txs} warm-up discarded)",
+        f"- accepted: **{head['accepted']}/{head['n_measured']}**",
+        f"- **processing throughput: {head['processing_tps']:.0f} tx/s** "
+        f"(1 / mean per-tx total wall)",
+        "",
+        "## Per-stage latency (µs/tx)",
+        "",
+        "| stage | mean wall | mean cpu | p50 | p90 | p99 | share |",
+        "|---|---|---|---|---|---|---|",
+    ]
+    for r in stage_rows:
+        L.append(f"| {r['stage']} | {r['mean_wall_us']:.1f} | {r['mean_cpu_us']:.1f} | "
+                 f"{r['p50_us']:.1f} | {r['p90_us']:.1f} | {r['p99_us']:.1f} | {r['share']:.1%} |")
+    L += [
+        "",
+        f"- mean per-tx total: **{head['mean_total_us']:.1f} µs** "
+        f"(p50 {head['p50_total_us']:.0f} / p90 {head['p90_total_us']:.0f} / p99 {head['p99_total_us']:.0f})",
+        f"- batch wall / cpu: {head['batch_wall_s']:.3f} / {head['batch_cpu_s']:.3f} s",
+        f"- peak RSS {head['rss_peak_mb']:.1f} MB (+{head['rss_growth_mb']:.1f}) · "
+        f"disk written {head['disk_written_mb']:.2f} MB · peak FDs {head['fd_peak']} · "
+        f"energy {head['energy_j']:.1f} J (analytical)",
+    ]
+    if plot_names:
+        L += ["", "## Plots", ""]
+        L += [f"![{n}](plots/{n})" for n in plot_names]
+    else:
+        L += ["", "_(plots skipped — matplotlib unavailable)_"]
+    Path(path).write_text("\n".join(L) + "\n", encoding="utf-8")
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/cli.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/cli.py
index 35e67aff..d1e6f4e4 100644
--- a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/cli.py
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/cli.py
@@ -57,27 +57,51 @@ def _cmd_run(args: argparse.Namespace) -> int:
         return 1
 
     # CP-3 builds the workload; CP-4 drives + measures it. (Reporting = CP-5.)
-    # Imports are lazy here so `list`/`validate` never pull in hathor.
-    from hathor_tps_bench.config import STAGES
+    # Imports are lazy here so `list`/`validate` never pull in hathor/matplotlib.
+    from dataclasses import asdict
+    from pathlib import Path
+
+    from hathor_tps_bench.analysis import compute, persist, plots, report
     from hathor_tps_bench.driver import run_batch
     from hathor_tps_bench.node import NodeHarness
     from hathor_tps_bench.workload import get_txtype
 
     w = cfg.workload
     if args.num_txs:
-        w.num_txs = args.num_txs  # quick override for smoke tests
-    print(f"[run] scenario '{cfg.name}': building {w.num_txs} {w.tx_type} tx "
-          f"(I={w.num_inputs}, O={w.num_outputs}) on an in-process node...")
+        w.num_txs = args.num_txs            # override K (measured)
+    if args.warmup is not None:
+        w.warmup_txs = args.warmup          # override W (warm-up, discarded)
+    K, W = w.num_txs, w.warmup_txs
+    print(f"[run] scenario '{cfg.name}': {w.tx_type} I={w.num_inputs} O={w.num_outputs}, "
+          f"K={K} measured (+{W} warm-up) on an in-process node...")
 
     source = get_txtype(w.tx_type)()
     harness = NodeHarness(seed=cfg.env.seed, trivial_pow=cfg.env.trivial_pow).start()
     try:
-        prepared = source.build(harness, w.num_txs, w.num_inputs, w.num_outputs)
-        print(f"[run] built {len(prepared)} txs; driving S1..S6 on the single thread...")
-        result = run_batch(harness, prepared, sampler_interval_s=cfg.measure.sampler_interval_s)
+        prepared = source.build(harness, W + K, w.num_inputs, w.num_outputs)  # build W+K
+        print(f"[run] built {len(prepared)} txs; warming {W}, measuring {K} through S1..S6...")
+        result = run_batch(harness, prepared,
+                           sampler_interval_s=cfg.measure.sampler_interval_s, warmup=W)
         _print_run_summary(result, cfg)
     finally:
         harness.stop()
+
+    # ---- reporting: CSV + JSON + plots + summary.md into results/<run>/ ----
+    head = compute.headline(result, tdp_watts=cfg.measure.tdp_watts, cpu_util=cfg.measure.cpu_util)
+    rows = compute.stage_table(result)
+    run_dir = Path(cfg.results_root) / f"{cfg.name}_{w.tx_type}_N{K}_I{w.num_inputs}_O{w.num_outputs}"
+    run_dir.mkdir(parents=True, exist_ok=True)
+    fmts = cfg.reporting.formats
+    if "csv" in fmts:
+        persist.write_per_tx_csv(run_dir / "per_tx_stages.csv", result)
+        persist.write_samples_csv(run_dir / "samples.csv", result)
+    persist.write_summary_json(run_dir / "batch_summary.json",
+                               {"scenario": cfg.name, "workload": asdict(w),
+                                "headline": head, "stages": rows})
+    plot_names = plots.generate(run_dir / "plots", result) if "plots" in fmts else []
+    if "markdown" in fmts:
+        report.write_report(run_dir / "summary.md", cfg, head, rows, plot_names)
+    print(f"\n[run] results → {run_dir}/  ({len(plot_names)} plots)")
     return 0
 
 
@@ -102,7 +126,6 @@ def _print_run_summary(result, cfg) -> None:
     print(f"  peak open FDs         : {b.fd_peak}")
     energy = b.energy_joules(cfg.measure.tdp_watts, cfg.measure.cpu_util)
     print(f"  energy (analytical)   : {energy:.2f} J  (cpu_s x {cfg.measure.tdp_watts} W x {cfg.measure.cpu_util})")
-    print("\n  [note] CSV / plots / report land in CP-5.")
 
 
 def build_parser() -> argparse.ArgumentParser:
@@ -119,7 +142,8 @@ def build_parser() -> argparse.ArgumentParser:
     pr = sub.add_parser("run", help="run a scenario (CP-4/CP-5)")
     pr.add_argument("--config", required=True, help="path to scenario YAML")
     pr.add_argument("--select", nargs="*", help="override which benchmarks to run")
-    pr.add_argument("--num-txs", type=int, dest="num_txs", help="override workload.num_txs")
+    pr.add_argument("--num-txs", type=int, dest="num_txs", help="override workload.num_txs (K, measured)")
+    pr.add_argument("--warmup", type=int, dest="warmup", help="override workload.warmup_txs (W, discarded)")
     pr.set_defaults(fn=_cmd_run)
     return p
 
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/config.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/config.py
index 82a3bbfa..10143295 100644
--- a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/config.py
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/config.py
@@ -20,9 +20,11 @@ STAGES: tuple[str, ...] = ("S1", "S2", "S3S4", "S5", "S6")
 @dataclass
 class WorkloadConfig:
     tx_type: str = "transparent"   # registry key
-    num_txs: int = 500
+    num_txs: int = 500             # K — the MEASURED txs
     num_inputs: int = 1            # I
     num_outputs: int = 2           # O
+    warmup_txs: int = 100          # W — driven but DISCARDED, to burn in caches/JIT
+                                   # (steady-state; NO block — that would re-cool the cache)
 
     def validate(self) -> list[str]:
         errs: list[str] = []
@@ -32,6 +34,8 @@ class WorkloadConfig:
             errs.append("workload.num_inputs must be >= 1")
         if self.num_outputs < 1:
             errs.append("workload.num_outputs must be >= 1")
+        if self.warmup_txs < 0:
+            errs.append("workload.warmup_txs must be >= 0")
         return errs
 
 
diff --git a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/driver/runner.py b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/driver/runner.py
index e0c7cb5e..00b5f2df 100644
--- a/tps_benchmarking/benchmarks/engine/hathor_tps_bench/driver/runner.py
+++ b/tps_benchmarking/benchmarks/engine/hathor_tps_bench/driver/runner.py
@@ -79,19 +79,32 @@ def _drive_one(manager, vh, settings, params, raw: bytes, index: int) -> TxRecor
     )
 
 
-def run_batch(harness, prepared, *, sampler_interval_s: float = 0.1) -> RunResult:
+def run_batch(harness, prepared, *, sampler_interval_s: float = 0.1, warmup: int = 0) -> RunResult:
+    """Drive `prepared` through S1..S6. The first `warmup` txs are driven through the full
+    pipeline but their records are DISCARDED — they burn in the RocksDB read cache and the
+    interpreter so the measured window reflects steady state, not the cold start. (We do
+    NOT inject a block before measuring: in the organic chain tips are already ~1 so a block
+    resets nothing, and block processing evicts the tx LRU cache — which would re-introduce
+    the very cold transient we are removing; see CP-4.)"""
     manager = harness.manager
     vh = manager.vertex_handler
     settings = manager._settings
-    params = build_params(manager)
+    params = build_params(manager)  # best_block is fixed across the batch (no blocks added)
 
+    # --- warm-up: drive W txs, keep nothing. They still extend the DAG (real processing). ---
+    warmup = max(0, min(warmup, len(prepared)))
+    for i in range(warmup):
+        _drive_one(manager, vh, settings, params, prepared[i].raw, i)
+    measured = prepared[warmup:]
+
+    # Snapshot resources AFTER warm-up so batch figures cover only the measured K txs.
     io_r0, io_w0 = procstats.read_io()
     rss_start = procstats.read_rss_bytes()
     sampler = ProcSampler(interval_s=sampler_interval_s).start()
 
     records: list[TxRecord] = []
     w0, c0 = time.perf_counter(), time.process_time()
-    for i, p in enumerate(prepared):
+    for i, p in enumerate(measured):  # i = position within the measured window (0..K-1)
         records.append(_drive_one(manager, vh, settings, params, p.raw, i))
         sampler.set_progress(i + 1)
     wall_s = time.perf_counter() - w0
diff --git a/tps_benchmarking/benchmarks/engine/pyproject.toml b/tps_benchmarking/benchmarks/engine/pyproject.toml
index 27478f85..a6516786 100644
--- a/tps_benchmarking/benchmarks/engine/pyproject.toml
+++ b/tps_benchmarking/benchmarks/engine/pyproject.toml
@@ -7,8 +7,10 @@ name = "hathor-tps-bench"
 version = "0.0.1"
 description = "In-process benchmark engine for Hathor full-node transaction processing."
 requires-python = ">=3.11"
-# Runtime deps are provided by the ambient hathor-core poetry env (pyyaml, hathor, ...).
-# Reporting deps (pandas, matplotlib, openpyxl) are added in CP-5.
+# Most runtime deps come from the ambient hathor-core poetry env (pyyaml, hathor, ...).
+# CSV/JSON reporting uses the stdlib; matplotlib (CP-5) is the only added dep — plots
+# degrade gracefully to "skipped" if it is somehow unavailable.
+dependencies = ["matplotlib>=3.5"]
 
 [project.scripts]
 hathor-tps-bench = "hathor_tps_bench.cli:main"
diff --git a/tps_benchmarking/benchmarks/engine/scenarios/basic.yaml b/tps_benchmarking/benchmarks/engine/scenarios/basic.yaml
index bad44d7a..4372677d 100644
--- a/tps_benchmarking/benchmarks/engine/scenarios/basic.yaml
+++ b/tps_benchmarking/benchmarks/engine/scenarios/basic.yaml
@@ -10,7 +10,7 @@ benchmarks:
 # Optional batch-size sweep (throughput-vs-N). Omit for a single run.
 # n_sweep: [100, 500, 1000, 5000]
 
-results_root: results
+results_root: tps_benchmarking/benchmarks/engine/results   # run from the hathor-core repo root
 
 workload:
   tx_type: transparent
diff --git a/tps_benchmarking/benchmarks/engine/scenarios/organic.yaml b/tps_benchmarking/benchmarks/engine/scenarios/organic.yaml
index 4ba5c393..2819fe28 100644
--- a/tps_benchmarking/benchmarks/engine/scenarios/organic.yaml
+++ b/tps_benchmarking/benchmarks/engine/scenarios/organic.yaml
@@ -6,7 +6,7 @@ name: organic-baseline
 benchmarks:
   - stage-latency
 
-results_root: results
+results_root: tps_benchmarking/benchmarks/engine/results   # run from the hathor-core repo root
 
 workload:
   tx_type: organic
```
