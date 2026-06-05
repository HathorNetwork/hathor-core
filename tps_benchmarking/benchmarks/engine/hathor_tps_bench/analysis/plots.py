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


def generate(out_dir: Path, result: RunResult, *, window: int = 25) -> list[str]:
    try:
        plt = _pyplot()
    except Exception:
        return []  # graceful degrade — CSV/JSON/markdown still get written
    out_dir.mkdir(parents=True, exist_ok=True)
    made: list[str] = []

    def _save(fig, name: str) -> None:
        fig.tight_layout()
        fig.savefig(out_dir / name, dpi=120)
        plt.close(fig)
        made.append(name)

    # 1) The headline chart: rolling TPS vs tx index — transient (warm-up tail / cache) -> steady.
    roll = compute.rolling_tps(result, window=window)
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot([i for i, _ in roll], [t for _, t in roll], lw=1.1, color="#1f6feb")
    ax.set(xlabel="measured tx index", ylabel=f"rolling TPS (window={window})",
           title="Throughput vs tx index — transient → steady state")
    ax.grid(alpha=0.3)
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
