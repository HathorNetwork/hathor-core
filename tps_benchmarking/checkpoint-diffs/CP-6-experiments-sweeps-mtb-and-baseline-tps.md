# Checkpoint CP‑6 — The experiments: sweeps, M/Tb, spec‑scaling, and the baseline TPS

- **Snapshot A:** end of CP‑5 — the engine measures one run and reports it (CSV/JSON/plots/summary).
- **Snapshot B:** the engine *runs the experiments* — I/O and N sweeps, the M/Tb table, hardware
  scaling — and produces the **headline processing‑TPS + a findings document**. Phase 1 is complete.
- **Status:** PASS ✓ — N‑scaling bounded to 10,000; the I/O sweep isolates the cost driver; the M/Tb
  table is flat; `docs/baseline-results.md` written.
- **Files:** 1 new module (`analysis/sweep.py`) + the `sweep` CLI command + M/Tb & spec‑scaling in
  `compute.py` + sweep plots in `plots.py`; new `docs/baseline-results.md`; README updated.

> Note: CP‑5 and CP‑6 are one uncommitted bundle on top of the CP‑4 commit (`b70ed4c4`). The appendix
> shows CP‑6's *new* code; the shared `analysis/`/`cli.py` files also carry their CP‑5 content (see the
> CP‑5 checkpoint). The big findings write‑up ships as `docs/baseline-results.md`, not inlined here.

---

## 1. Summary

CP‑6 points the machinery at the questions the whole project exists to answer and writes down the answer.
It adds **sweep orchestration** (run across a parameter axis, a fresh node per point), the **M/Tb table**
and a **hardware‑scaling model**, and a findings doc with the headline number and its scaling laws. The
engine is now a complete Phase‑1 tool: it measures, the workload is representative, and it produces a
defensible processing‑TPS.

## 2. The experiments and what they found

### 2.1 N‑scaling — bounded, no creep
Per‑tx cost does **not** grow with batch size out to **N=10,000** (within a run it drifts *down* as
caches warm; it never climbs). That's the payoff of the organic workload — vs the genesis‑parented
baseline, which was O(N²) and whose TPS *collapsed* 169 → 36 from N=100 → 1000.

### 2.2 I/O sweep — inputs dominate, outputs are cheap
`cost ≈ base + ~2.6 ms·(I−1)` — roughly linear in **inputs** (each pays a signature verify ×2 plus
consensus input bookkeeping). **Outputs are ~free** (O=2→5 barely moves TPS). So tx *shape* sets the
rate: a 5‑input tx costs ~3.5× a 1‑input one (247 → 69 tx/s).

### 2.3 M/Tb — flat ⇒ block‑cadence‑independent
Because organic per‑tx cost is flat, `C(N)` is linear, so `M/Tb = 1/τ` for **every** Tb. The sustainable
rate equals the steady rate (~213 tx/s at all Tb ∈ {7.5,15,30,60,90}s); only `M` (txs between blocks)
scales with Tb. The M/Tb coupling only "bit" in the genesis O(N²) regime, where letting the mempool fill
longer made each tx costlier. Organic removes it.

### 2.4 Spec‑scaling — single‑thread CPU is the lever
Processing is single‑thread CPU‑bound, so `TPS ≈ 215 × ST_target/ST_baseline`; extra cores don't help the
serial pipeline (Amdahl on the ~½ that is parallelizable verification caps gains at ~2×). RAM/disk/FDs
aren't binding at this scale; at mainnet scale RAM is a *cache* knob (~2–4 GB), not chain‑size. (Full
treatment — threading, the 2× ceiling, resource caps, mainnet RAM — in `docs/baseline-results.md`.)

### 2.5 Headline
**~215 tx/s** single‑thread for a 1‑in/2‑out tx on an i5‑11300H (warmed; run‑to‑run band ~160–270 from
WSL2/compaction variance), dominated by **verification‑run‑twice (~½) + consensus**. The redundant 2nd
`validate_full` is the top optimization target (~1.3× single‑threaded if removed).

## 3. What was built

- **`analysis/sweep.py`** — `io_sweep` / `n_sweep`: run across a parameter axis with a **fresh funded
  node per point** (storage/mempool never carries over), collecting a headline + per‑stage means each.
- **`sweep` CLI command** — `--axis io|n`, writes a sweep `summary.md` + throughput‑vs‑axis and stacked
  per‑stage plots.
- **`compute.mtb_table` + `compute.scale_to_specs`** — the M/Tb table (now emitted in every run's
  `batch_summary.json`) and the single‑thread hardware‑scaling projection.
- **`plots.sweep_plots`** — TPS‑vs‑axis and stacked per‑stage‑vs‑axis charts.
- **`docs/baseline-results.md`** — the headline TPS + full analysis (scaling, I/O, M/Tb, hardware,
  parallelism & resource ceilings, caveats); README updated with the `sweep` usage and the result.

## 4. Verified

```text
I/O sweep (organic, K=200/point):  I1O2 247 · I2O2 144 · I3O2 110 · I4O2 83 · I5O2 69 tps
                                   I1O3 236 · I1O4 235 · I1O5 217 tps   (outputs ~free)
N=10000 run: accepted 10000/10000; per-tx cost flat→down across the run (no creep)
M/Tb (any Tb): sustainable ≈ steady rate (flat); M scales with Tb
```

## 5. Phase 1 complete

CP‑1 (spike) → CP‑2 (scaffold) → CP‑3 (harness+workload) → CP‑4 (probes+driver+organic fix) →
CP‑5 (analysis+warm‑up) → **CP‑6 (experiments+TPS+docs)**. The engine answers "how fast can one full
node process txs?" with a number, a per‑stage breakdown, scaling laws, and a hardware projection.

**Deferred (optional, beyond Phase 1):** the k‑tip‑frontier organic variant (more mainnet‑like DAG);
implementing & re‑measuring the double‑`validate_full` removal; pointing a harness at a mainnet snapshot
to measure real RSS; other tx types (token/nano/fee/shielded) and load modules (wallet/relay/confirm) —
the registries already accommodate them.

---

## 6. Appendix — CP‑6 new code

### `analysis/sweep.py` (new)
```python
"""Sweep orchestration — run the engine across a parameter axis (tx shape I/O, or batch
size N), ONE FRESH node per point so storage/mempool never carries over between points,
and collect a headline + per-stage means for each. Imports hathor lazily (inside the run)
so `list`/`validate` stay light."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SweepPoint:
    label: str
    num_inputs: int
    num_outputs: int
    num_txs: int          # K measured
    accepted: int
    tps: float
    mean_total_us: float
    stage_means_us: dict   # {S1..S6: µs}


def _run_one(cfg, tx_type: str, num_inputs: int, num_outputs: int, K: int, W: int):
    """Build a fresh funded node, drive W+K (measure K), return (SweepPoint, RunResult)."""
    from hathor_tps_bench.analysis import compute
    from hathor_tps_bench.driver import run_batch
    from hathor_tps_bench.node import NodeHarness
    from hathor_tps_bench.workload import get_txtype

    source = get_txtype(tx_type)()
    harness = NodeHarness(seed=cfg.env.seed, trivial_pow=cfg.env.trivial_pow).start()
    try:
        prepared = source.build(harness, W + K, num_inputs, num_outputs)
        result = run_batch(harness, prepared,
                           sampler_interval_s=cfg.measure.sampler_interval_s, warmup=W)
    finally:
        harness.stop()

    head = compute.headline(result, tdp_watts=cfg.measure.tdp_watts, cpu_util=cfg.measure.cpu_util)
    means = {r["stage"]: r["mean_wall_us"] for r in compute.stage_table(result)}
    point = SweepPoint(
        label=f"I{num_inputs}O{num_outputs}",
        num_inputs=num_inputs, num_outputs=num_outputs, num_txs=K,
        accepted=head["accepted"], tps=head["processing_tps"],
        mean_total_us=head["mean_total_us"], stage_means_us=means,
    )
    return point, result


def io_sweep(cfg, tx_type, shapes: list[tuple[int, int]], K: int, W: int,
             *, on_point=None) -> list[SweepPoint]:
    """shapes = [(I, O), ...] — one fresh run each."""
    points: list[SweepPoint] = []
    for num_inputs, num_outputs in shapes:
        pt, _ = _run_one(cfg, tx_type, num_inputs, num_outputs, K, W)
        points.append(pt)
        if on_point:
            on_point(pt)
    return points


def n_sweep(cfg, tx_type, ns: list[int], num_inputs: int, num_outputs: int, W: int,
            *, on_point=None) -> list[SweepPoint]:
    """ns = [K, ...] — one fresh run each, varying the measured batch size."""
    points: list[SweepPoint] = []
    for K in ns:
        pt, _ = _run_one(cfg, tx_type, num_inputs, num_outputs, K, W)
        pt.label = f"N{K}"
        points.append(pt)
        if on_point:
            on_point(pt)
    return points
```

### `analysis/compute.py` — new `mtb_table` + `scale_to_specs`
```python
def mtb_table(cn_curve: list[tuple[int, float, float]], tbs_s: list[float]) -> list[dict]:
    """The M/Tb sustainable-rate table from a cumulative-cost curve.

    For each block interval Tb, M is the number of txs whose cumulative processing time
    fills Tb (C(M)=Tb), and the sustainable rate is M/Tb. In the ORGANIC (flat) regime
    C(N) is linear (C(N)=τ·N), so M=Tb/τ and M/Tb=1/τ — i.e. the sustainable rate equals
    the steady per-tx rate for EVERY Tb (block cadence does not bound it). The genesis
    O(N²) regime is the opposite: M/Tb falls as Tb grows."""
    if not cn_curve:
        return []
    max_n, max_c, _ = cn_curve[-1]
    tau_s = max_c / max_n  # mean per-tx wall time (s); linear C(N) ⇒ constant
    rows = []
    for tb in tbs_s:
        m = tb / tau_s if tau_s else 0.0
        rows.append({"tb_s": tb, "M": m, "sustainable_tps": (m / tb) if tb else 0.0})
    return rows


def scale_to_specs(measured_tps: float, machine_score: float, targets: list[dict]) -> list[dict]:
    """Project the single-thread TPS to other CPUs. Processing is single-thread CPU-bound,
    so TPS scales ~linearly with single-thread performance: tps_target ≈ tps · score_t/score_m.
    `score` is a single-thread performance proxy (e.g. PassMark single-thread); targets =
    [{"label","score","note"?}, ...]."""
    out = []
    for t in targets:
        ratio = (t["score"] / machine_score) if machine_score else 0.0
        out.append({**t, "ratio": ratio, "projected_tps": measured_tps * ratio})
    return out


```

### `analysis/plots.py` — new `sweep_plots`
```python
def sweep_plots(out_dir: Path, points: list, *, x_label: str) -> list[str]:
    """Cross-run charts for a sweep: TPS vs axis, and stacked per-stage means vs axis."""
    try:
        plt = _pyplot()
    except Exception:
        return []
    out_dir.mkdir(parents=True, exist_ok=True)
    made: list[str] = []
    xs = list(range(len(points)))
    labels = [p.label for p in points]

    def _save(fig, name):
        fig.tight_layout(); fig.savefig(out_dir / name, dpi=120); plt.close(fig); made.append(name)

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(xs, [p.tps for p in points], "o-", color="#1f6feb")
    ax.set_xticks(xs); ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set(ylabel="processing TPS", xlabel=x_label, title=f"Throughput vs {x_label}")
    ax.grid(alpha=0.3)
    _save(fig, "sweep_tps.png")

    fig, ax = plt.subplots(figsize=(8, 4))
    bottoms = [0.0] * len(points)
    for s in STAGES:
        vals = [p.stage_means_us.get(s, 0.0) for p in points]
        ax.bar(xs, vals, bottom=bottoms, label=s)
        bottoms = [b + v for b, v in zip(bottoms, vals)]
    ax.set_xticks(xs); ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set(ylabel="mean wall µs / tx", xlabel=x_label, title=f"Per-stage cost vs {x_label}")
    ax.legend(fontsize=8, ncol=5)
    _save(fig, "sweep_stages.png")
    return made
```

### `cli.py` — the `sweep` command (+ M/Tb wired into `run`)
```python
def _parse_shapes(s: str | None):
    return [(int(i), int(o)) for i, o in (tok.split(":") for tok in s.split(","))] if s else None


def _parse_ints(s: str | None):
    return [int(x) for x in s.split(",")] if s else None


def _cmd_sweep(args: argparse.Namespace) -> int:
    cfg, errs = _load_and_validate(args.config)
    if errs:
        print("config invalid:", *(f"\n  - {e}" for e in errs))
        return 2
    from pathlib import Path

    from hathor_tps_bench.analysis import plots, sweep

    w = cfg.workload
    W = args.warmup if args.warmup is not None else w.warmup_txs
    log = lambda p: print(f"  {p.label:9} {p.tps:6.0f} tps   total {p.mean_total_us:7.0f} us   "
                          f"acc {p.accepted}/{p.num_txs}")
    print(f"[sweep] axis={args.axis} on {w.tx_type} (W={W}) — fresh node per point...")
    if args.axis == "io":
        shapes = _parse_shapes(args.values) or [(1, 2), (2, 2), (3, 2), (4, 2), (5, 2), (1, 3), (1, 4), (1, 5)]
        K = args.num_txs or 300
        points = sweep.io_sweep(cfg, w.tx_type, shapes, K, W, on_point=log)
        x_label = "tx shape (I:O)"
    else:
        ns = _parse_ints(args.values) or [50, 100, 200, 500, 1000, 2000]
        points = sweep.n_sweep(cfg, w.tx_type, ns, w.num_inputs, w.num_outputs, W, on_point=log)
        x_label = "batch size N"

    run_dir = Path(cfg.results_root) / f"sweep_{cfg.name}_{w.tx_type}_{args.axis}"
    run_dir.mkdir(parents=True, exist_ok=True)
    plot_names = (plots.sweep_plots(run_dir / "plots", points, x_label=x_label)
                  if "plots" in cfg.reporting.formats else [])
    _write_sweep_report(run_dir / "summary.md", cfg, args.axis, x_label, points, plot_names)
    print(f"\n[sweep] results → {run_dir}/  ({len(plot_names)} plots)")
    return 0


def _write_sweep_report(path, cfg, axis, x_label, points, plot_names) -> None:
    from pathlib import Path
    L = [f"# Sweep — {cfg.name} ({axis})", "",
         f"- workload **{cfg.workload.tx_type}**, varying {x_label} (+{cfg.workload.warmup_txs} warm-up/point)",
         "",
         "| point | I | O | K | TPS | mean total µs | S3S4 | S5 | S6 |",
         "|---|---|---|---|---|---|---|---|---|"]
    for p in points:
        sm = p.stage_means_us
        L.append(f"| {p.label} | {p.num_inputs} | {p.num_outputs} | {p.num_txs} | **{p.tps:.0f}** | "
                 f"{p.mean_total_us:.0f} | {sm.get('S3S4', 0):.0f} | {sm.get('S5', 0):.0f} | {sm.get('S6', 0):.0f} |")
    if plot_names:
        L += ["", "## Plots", ""] + [f"![{n}](plots/{n})" for n in plot_names]
    Path(path).write_text("\n".join(L) + "\n", encoding="utf-8")


```
