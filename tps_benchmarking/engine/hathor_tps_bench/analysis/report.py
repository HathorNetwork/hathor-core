"""Render a human-readable summary.md from the headline figures + per-stage table."""
from __future__ import annotations

from pathlib import Path


def write_report(path: Path, cfg, head: dict, stage_rows: list[dict], plot_names: list[str]) -> None:
    w = cfg.workload
    L: list[str] = [
        f"# TPS benchmark — {cfg.name}",
        "",
        f"- workload: **{w.tx_type}**, I={w.num_inputs} O={w.num_outputs}, "
        f"K={head['n_measured']} measured (+{w.warmup_txs} warm-up discarded)",
        f"- accepted: **{head['accepted']}/{head['n_measured']}**",
        f"- **processing throughput: {head['processing_tps']:.0f} tx/s** "
        f"(1 / mean per-tx total wall)",
        "",
        "## Per-stage latency (µs/tx)",
        "",
        "| stage | mean wall | mean cpu | p50 | p90 | p99 | share |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in stage_rows:
        L.append(f"| {r['stage']} | {r['mean_wall_us']:.1f} | {r['mean_cpu_us']:.1f} | "
                 f"{r['p50_us']:.1f} | {r['p90_us']:.1f} | {r['p99_us']:.1f} | {r['share']:.1%} |")
    L += [
        "",
        f"- mean per-tx total: **{head['mean_total_us']:.1f} µs** "
        f"(p50 {head['p50_total_us']:.0f} / p90 {head['p90_total_us']:.0f} / p99 {head['p99_total_us']:.0f})",
        f"- batch wall / cpu: {head['batch_wall_s']:.3f} / {head['batch_cpu_s']:.3f} s",
        f"- peak RSS {head['rss_peak_mb']:.1f} MB (+{head['rss_growth_mb']:.1f}) · "
        f"disk written {head['disk_written_mb']:.2f} MB · peak FDs {head['fd_peak']} · "
        f"energy {head['energy_j']:.1f} J (analytical)",
    ]
    if plot_names:
        L += ["", "## Plots", ""]
        L += [f"![{n}](plots/{n})" for n in plot_names]
    else:
        L += ["", "_(plots skipped — matplotlib unavailable)_"]
    Path(path).write_text("\n".join(L) + "\n", encoding="utf-8")
