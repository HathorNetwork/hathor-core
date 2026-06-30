"""Charts (matplotlib, Agg backend). Returns the filenames written; if matplotlib is
unavailable it returns [] so a run never fails for lack of a plotting library."""
from __future__ import annotations

from pathlib import Path

from hathor_tps_bench.analysis import compute
from hathor_tps_bench.config import STAGES
from hathor_tps_bench.metrics.collector import RunResult


def _pyplot():
    import matplotlib
    matplotlib.use("Agg")  # headless: render to file, no display
    import matplotlib.pyplot as plt
    return plt


def timestamp() -> str:
    """A filename-safe stamp, e.g. '05-06-2026-05h-43min-57s' (DD-MM-YYYY-HHh-MMmin-SSs)."""
    from datetime import datetime
    return datetime.now().strftime("%d-%m-%Y-%Hh-%Mmin-%Ss")


def _stamped(name: str, stamp: str) -> str:
    """'rolling_tps.png' -> 'rolling_tps-<stamp>.png'."""
    base = name[:-4] if name.endswith(".png") else name
    return f"{base}-{stamp}.png"


def generate(out_dir: Path, result: RunResult, *, window: int | None = None) -> list[str]:
    try:
        plt = _pyplot()
    except Exception:
        return []  # graceful degrade — CSV/JSON/markdown still get written
    out_dir.mkdir(parents=True, exist_ok=True)
    made: list[str] = []
    stamp = timestamp()

    def _save(fig, name: str) -> None:
        fname = _stamped(name, stamp)
        fig.tight_layout()
        fig.savefig(out_dir / fname, dpi=120)
        plt.close(fig)
        made.append(fname)

    # 1) The headline chart: rolling TPS vs tx index — transient (warm-up tail / cache) -> steady.
    #    Mean (faint) shows the RocksDB write-stall dips; median (bold) is the robust trend.
    w = window if window else compute.rolling_window(len(result.records))
    roll_mean = compute.rolling_tps(result, window=w)
    roll_med = compute.rolling_tps_median(result, window=w)
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot([i for i, _ in roll_mean], [t for _, t in roll_mean], lw=0.6, color="#c9c9c9",
            label="rolling mean (spikes = write-stalls)")
    ax.plot([i for i, _ in roll_med], [t for _, t in roll_med], lw=1.2, color="#1f6feb",
            label="rolling median (robust)")
    ax.set(xlabel="measured tx index", ylabel=f"rolling TPS (window={w})",
           title="Throughput vs tx index — transient → steady state")
    ax.legend(fontsize=8); ax.grid(alpha=0.3)
    _save(fig, "rolling_tps.png")

    # 2) Per-stage mean latency, annotated with each stage's share of the total.
    rows = compute.stage_table(result)
    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar([r["stage"] for r in rows], [r["mean_wall_us"] for r in rows], color="#57606a")
    for bar, r in zip(bars, rows):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{r['share']:.0%}", ha="center", va="bottom", fontsize=8)
    ax.set(ylabel="mean wall µs / tx", title="Per-stage latency (share of per-tx total)")
    ax.grid(axis="y", alpha=0.3)
    _save(fig, "stage_means.png")

    # 3) Per-tx total-latency distribution.
    totals = compute.per_tx_totals_us(result)
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(totals, bins=40, color="#1f6feb", alpha=0.85)
    ax.set(xlabel="per-tx total wall µs", ylabel="count", title="Per-tx total-latency distribution")
    ax.grid(alpha=0.3)
    _save(fig, "latency_hist.png")

    # 4) Cumulative processing time C(N) — basis for the M/Tb sustainable-rate model.
    cum = compute.cumulative_curve(result)
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot([n for n, _, _ in cum], [c for _, c, _ in cum], lw=1.1, color="#116329")
    ax.set(xlabel="N (measured txs)", ylabel="C(N) — cumulative processing time (s)",
           title="Cumulative processing time C(N)")
    ax.grid(alpha=0.3)
    _save(fig, "cumulative_cn.png")

    return made


def sweep_plots(out_dir: Path, points: list, *, x_label: str, window: int | None = None) -> list[str]:
    """Cross-run charts for a sweep: TPS vs axis, stacked per-stage means, and overlaid
    rolling-median TPS curves (one per point)."""
    try:
        plt = _pyplot()
    except Exception:
        return []
    out_dir.mkdir(parents=True, exist_ok=True)
    made: list[str] = []
    stamp = timestamp()
    xs = list(range(len(points)))
    labels = [p.label for p in points]

    def _save(fig, name):
        fname = _stamped(name, stamp)
        fig.tight_layout(); fig.savefig(out_dir / fname, dpi=120); plt.close(fig); made.append(fname)

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

    # 3) Overlaid rolling-median TPS curves — one per point (the demo-style chart).
    from statistics import median
    fig, ax = plt.subplots(figsize=(10, 5))
    drew = False
    for p in points:
        if not p.totals_us:
            continue
        w = window if window else compute.rolling_window(len(p.totals_us))
        ys = [1e6 / median(p.totals_us[max(0, i - w + 1): i + 1]) for i in range(len(p.totals_us))]
        ax.plot(range(len(ys)), ys, lw=1.0, label=f"{p.label} (~{p.tps:.0f} tps)")
        drew = True
    if drew:
        ax.set(xlabel="measured tx index", ylabel="rolling median TPS",
               title=f"Rolling median TPS per {x_label}")
        ax.legend(title=x_label, fontsize=8); ax.grid(alpha=0.3)
        _save(fig, "sweep_rolling.png")
    else:
        plt.close(fig)
    return made
