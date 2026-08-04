"""Master report-data plots (P1–P11) — STAGE 2.

Renders per-scenario figures from a report-data/<ts>/ dir produced by report_data.py (Stage 1). Reads
ONLY the saved artifacts (<P>/<cell>.meta.json + <cell>.band.csv + manifest.json) — no hathor imports,
no node — so it is fast and can be re-run/iterated independently of the (heavy) data collection.

Per scenario it picks the right figure family (into <ts>/<P>/plots/):
  * latency band        — avg per-tx total latency vs tx-index, min–max shaded (all scenarios; shows
                          the WSL head transient + k-rep spread);
  * stage breakdown     — stacked S1..S6 mean µs per cell (P1/P3/P6/P7);
  * TPS scaling         — TPS vs #inputs (P2/P4) or #outputs (P5), min–max band from the k reps;
  * transparent vs shielded — grouped bars (P6) / paired lines (P7);
  * surjection grid P8  — BOTH a single line-family figure AND 3 grouped panels AND a heatmap;
  * opt vs no-opt P9    — bars + speedup ratio;
  * per-section P10     — bars (full + no-sX) with each section's marginal contribution.
Range-proof-bits are labelled on every shielded figure.

Run (from repo root, after a report_data.py run):
  <venv>/bin/python tps_benchmarking/engine/scripts/report_plots.py report-data/<ts>
  <venv>/bin/python tps_benchmarking/engine/scripts/report_plots.py report-data/<ts> P8   # one scenario
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

BLUE, GRAY, GREEN, ORANGE = "#1f6feb", "#57606a", "#116329", "#bc4c00"
PURPLE, RED, LIGHT = "#8250df", "#cf222e", "#c9c9c9"
STAGE_ORDER = ["S1", "S2", "S3S4", "S5", "S6"]
# palette (distinct hues) + pipeline tags used in every legend/label instead of S1..S6
STAGE_COLORS = {"S1": GREEN, "S2": BLUE, "S3S4": ORANGE, "S5": RED, "S6": PURPLE}
STAGE_TAGS = {"S1": "ser/de", "S2": "gate", "S3S4": "verify", "S5": "cons.", "S6": "post-cons."}
SERIES = [BLUE, ORANGE, GREEN, PURPLE, RED, GRAY]
SIGMA_CLIP = 3.5   # per-tx-index band points beyond mean+Nσ are hidden (rare GC/compaction spikes)

# which figure family(ies) each scenario gets. Every latency figure (µs) has a TPS twin:
# latency_band ↔ tps_band, and stage_breakdown ↔ stage_throughput.
PLOT_SPECS: dict[str, list[str]] = {
    "P1": ["stage_breakdown", "stage_throughput", "latency_band", "tps_band"],
    "P2": ["scaling_i", "latency_band", "tps_band"],
    "P3": ["stage_breakdown", "stage_throughput", "latency_band", "tps_band"],
    "P4": ["scaling_i", "latency_band", "tps_band"],
    "P5": ["scaling_o", "latency_band", "tps_band"],
    "P6": ["compare_ts_bar", "stage_breakdown", "stage_throughput"],
    "P7": ["compare_ts_lines", "stage_breakdown", "stage_throughput", "latency_band", "tps_band"],
    "P8": ["grid_family", "grid_grouped", "grid_heatmap"],
    "P9": ["opt_bars", "latency_band", "tps_band"],
    "P10": ["section_bars"],
    "P11": ["transition", "transition_tps"],
    "P12": ["bits_sweep"],
}
_DIR_LABEL = {"T2S": "transparent → shielded", "S2T": "shielded → transparent"}


def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"axes.titlesize": 11, "figure.titlesize": 11, "legend.fontsize": 8})
    return plt


def _save(fig, pdir: Path, name: str) -> str:
    """Write a PNG (screen) AND a PDF (vector, print quality) twin. Returns the PNG name."""
    pdir.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(pdir / name, dpi=140, bbox_inches="tight")           # bbox_inches keeps outside legends
    fig.savefig(pdir / (Path(name).stem + ".pdf"), bbox_inches="tight")
    _plt().close(fig)
    return name


def _clip_band(rows, k=SIGMA_CLIP, passes=3):
    """Sigma-clip a per-tx-index band series: drop indices whose avg OR max exceeds mean+kσ of the
    surviving points (iterated to convergence). Removes rare latency explosions (GC / RocksDB
    compaction) that otherwise stretch the y-axis and flatten the real signal. Returns (rows, n_dropped).
    Each value is tested against its own series' distribution, so clean data is not over-filtered."""
    from statistics import mean, pstdev
    keep = list(rows)
    if len(keep) < 8:
        return keep, 0
    for _ in range(passes):
        avgs, maxs = [r[2] for r in keep], [r[3] for r in keep]
        ta = mean(avgs) + k * (pstdev(avgs) or 0.0)
        tm = mean(maxs) + k * (pstdev(maxs) or 0.0)
        new = [r for r in keep if r[2] <= ta and r[3] <= tm]
        if len(new) == len(keep):
            break
        keep = new
    return keep, len(rows) - len(keep)


def _sigma_note(ax, dropped: int) -> None:
    if dropped:
        ax.text(0.995, 0.02, f"{dropped} pt(s) >{SIGMA_CLIP}σ hidden", transform=ax.transAxes,
                ha="right", va="bottom", fontsize=7, color=GRAY, style="italic")


def _pretty_cell(cell: str) -> str:
    """Map a raw cell label to a display label: 'no-s5' → '−cons.', others unchanged."""
    if cell.startswith("no-s") and len(cell) > 4:
        return "−" + STAGE_TAGS.get(cell[3:].upper(), cell[3:])
    return cell


def _load_scenario(sdir: Path) -> tuple[list[dict], dict[str, list]]:
    """Return (metas sorted by (i,o,cell), {cell -> band rows})."""
    metas, bands = [], {}
    for mp in sorted(sdir.glob("*.meta.json")):
        m = json.loads(mp.read_text())
        metas.append(m)
        bp = sdir / f"{m['cell']}.band.csv"
        if bp.exists():
            with bp.open() as f:
                bands[m["cell"]] = [(int(r["tx_index"]), float(r["min_us"]),
                                     float(r["avg_us"]), float(r["max_us"]))
                                    for r in csv.DictReader(f)]
    metas.sort(key=lambda m: (m["i"], m["o"], m["cell"]))
    return metas, bands


def _bits_note(metas: list[dict]) -> str:
    bits = sorted({m["bits"] for m in metas if m.get("shielded")})
    return f"  ·  RP={'/'.join(map(str, bits))}" if bits else ""


def _title(scn_id: str, metas: list[dict], what: str) -> str:
    t = metas[0]["title"] if metas else scn_id
    t = (t[:1].upper() + t[1:]) if t else t   # no "P*" prefix; capitalize the first word
    return f"{t} — {what}{_bits_note(metas)}"


# P7 only: pair colours by tx SHAPE (hue) and tx TYPE (shade) so transparent/shielded of the same
# shape read together — 1i2o green, 4i4o orange, 8i8o red; shielded = dark, transparent = light.
P7_SHAPE_COLORS = {
    (1, 2): ("#0b6623", "#7fca8b"),
    (4, 4): ("#b34700", "#f6a860"),
    (8, 8): ("#a50f15", "#f0776a"),
}


def _cell_color(scn_id: str, m: dict, k: int) -> str:
    pair = P7_SHAPE_COLORS.get((m["i"], m["o"]))
    if scn_id == "P7" and pair:
        return pair[0] if m.get("shielded") else pair[1]
    return SERIES[k % len(SERIES)]


# -- figure families -------------------------------------------------------------------------------
def _band_fig(pdir, metas, bands, scn_id, as_tps: bool):
    """Per-tx-index band (latency µs, or its TPS twin). Sigma-clipped so rare spikes don't distort
    the y-scale."""
    plt = _plt()
    fig, ax = plt.subplots(figsize=(9, 4.5))
    dropped = 0
    for k, m in enumerate(metas):
        rows = bands.get(m["cell"])
        if not rows:
            continue
        rows, d = _clip_band(rows)
        dropped += d
        xs = [r[0] for r in rows]
        if as_tps:
            lo = [1e6 / r[3] for r in rows]   # MAX latency → MIN tps
            av = [1e6 / r[2] for r in rows]
            hi = [1e6 / r[1] for r in rows]   # MIN latency → MAX tps
        else:
            lo, av, hi = [r[1] for r in rows], [r[2] for r in rows], [r[3] for r in rows]
        c = _cell_color(scn_id, m, k)
        ax.fill_between(xs, lo, hi, color=c, alpha=0.15)
        ax.plot(xs, av, lw=1.0, color=c, label=_pretty_cell(m["cell"]))
    ax.set_xlabel("measured tx index (steady state, warm-up discarded)")
    ax.set_ylabel("per-tx throughput = 1 / latency (tx/s)" if as_tps else "total per-tx latency (µs)")
    ax.set_title(_title(scn_id, metas, "per-tx throughput band" if as_tps else "per-tx latency band"))
    if len(metas) > 1:
        ax.legend(ncol=2)
    _sigma_note(ax, dropped)
    ax.grid(True, alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_{'tps' if as_tps else 'latency'}_band.png")]


def latency_band(pdir, metas, bands, scn_id):
    return _band_fig(pdir, metas, bands, scn_id, as_tps=False)


def tps_band(pdir, metas, bands, scn_id):
    return _band_fig(pdir, metas, bands, scn_id, as_tps=True)


def stage_breakdown(pdir, metas, bands, scn_id):
    plt = _plt()
    n = len(metas)
    fig, ax = plt.subplots(figsize=(max(7.5, 1.6 * n + 3.5), 4.8))
    x = list(range(n))
    labels = [m["cell"] for m in metas]
    bottom = [0.0] * n
    for s in STAGE_ORDER:
        vals = [m.get("stage_mean_us", {}).get(s, 0.0) for m in metas]
        ax.bar(x, vals, width=0.55, bottom=bottom, label=STAGE_TAGS[s], color=STAGE_COLORS.get(s, GRAY))
        bottom = [b + v for b, v in zip(bottom, vals)]
    top = max(bottom)
    ax.set_ylim(0, top * 1.12)
    trans = ax.get_xaxis_transform()   # x = data, y = axes-fraction → pin totals inside, at the top
    for xi in x:
        ax.text(xi, 0.965, f"{metas[xi]['processing_tps']:.0f} tx/s", transform=trans,
                ha="center", va="top", fontsize=9, weight="bold")
    ax.set_xticks(x, [_pretty_cell(la) for la in labels])
    ax.set_xlim(-0.8, n - 0.2)
    ax.set_ylabel("mean stage wall time (µs)")
    ax.set_title(_title(scn_id, metas, "per-stage breakdown + TPS"))
    ax.legend(loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False)
    ax.grid(True, axis="y", alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_stage_breakdown.png")]


def stage_throughput(pdir, metas, bands, scn_id):
    """TPS twin of stage_breakdown: each stage's isolated throughput ceiling (1 / stage time) as
    grouped bars — the stage with the LOWEST bar is the bottleneck. Actual total TPS annotated
    (throughput is not additive across stages, so it can't be stacked like the µs view)."""
    plt = _plt()
    n, nst = len(metas), len(STAGE_ORDER)
    width = 0.8 / nst
    fig, ax = plt.subplots(figsize=(max(7.5, 1.9 * n + 3), 4.8))
    base = list(range(n))
    for si, s in enumerate(STAGE_ORDER):
        xs = [b + (si - (nst - 1) / 2) * width for b in base]
        ys = []
        for m in metas:
            us = m.get("stage_mean_us", {}).get(s, 0.0)
            ys.append(1e6 / us if us > 0 else 0.0)
        ax.bar(xs, ys, width=width, label=STAGE_TAGS[s], color=STAGE_COLORS.get(s, GRAY))
    ax.set_yscale("log")
    ymin, ymax = ax.get_ylim()
    ax.set_ylim(ymin, ymax * 2.5)      # log headroom so the totals sit above the bars, inside the box
    trans = ax.get_xaxis_transform()
    for b, m in zip(base, metas):
        ax.text(b, 0.965, f"{m['processing_tps']:.0f} tx/s", transform=trans,
                ha="center", va="top", fontsize=8, weight="bold")
    ax.set_xticks(base, [_pretty_cell(m["cell"]) for m in metas])
    ax.set_ylabel("per-stage ceiling = 1 / stage time (tx/s, log)")
    ax.set_title(_title(scn_id, metas, "per-stage throughput ceiling (bottleneck = lowest)"))
    ax.legend(loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False)
    ax.grid(True, axis="y", alpha=0.25, which="both")
    return [_save(fig, pdir, f"{scn_id}_stage_throughput.png")]


def _scaling(pdir, metas, scn_id, axis: str, xlabel: str):
    plt = _plt()
    ms = sorted(metas, key=lambda m: m[axis])
    xs = [m[axis] for m in ms]
    ys = [m["processing_tps"] for m in ms]
    lo = [min(m["processing_tps_reps"]) for m in ms]
    hi = [max(m["processing_tps_reps"]) for m in ms]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.fill_between(xs, lo, hi, color=BLUE, alpha=0.15)
    ax.plot(xs, ys, "o-", color=BLUE, lw=1.6)
    for x, y in zip(xs, ys):
        ax.text(x, y, f" {y:.0f}", va="bottom", fontsize=8)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("processing TPS (median of k)")
    ax.set_xticks(xs)
    ax.set_title(_title(scn_id, metas, f"throughput vs {xlabel}"))
    ax.grid(True, alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_tps_by_{axis}.png")]


def bits_sweep(pdir, metas, bands, scn_id):
    """Range-proof bit-width sweep (same shielded shape at RP=32/48/64): TPS bars with the k-rep
    spread as error bars, each annotated with the verify (S3S4) time and mean proof size — the
    cost/size dial. Colours go green→orange→red as the proof grows."""
    plt = _plt()
    ms = sorted(metas, key=lambda m: m["bits"])
    x = list(range(len(ms)))
    tps = [m["processing_tps"] for m in ms]
    lo = [t - min(m["processing_tps_reps"]) for t, m in zip(tps, ms)]
    hi = [max(m["processing_tps_reps"]) - t for t, m in zip(tps, ms)]
    cols = [GREEN, ORANGE, RED, PURPLE, BLUE]
    fig, ax = plt.subplots(figsize=(7, 4.6))
    ax.bar(x, tps, width=0.55, color=[cols[i % len(cols)] for i in x],
           yerr=[lo, hi], capsize=4, ecolor="#333")
    ax.set_ylim(0, max(tps) * 1.15)
    for xi, m in zip(x, ms):
        v = m.get("stage_mean_us", {}).get("S3S4", 0.0) / 1000.0
        sz = m.get("size_bytes", 0) / 1024.0
        ax.text(xi, tps[xi], f"{tps[xi]:.0f} tx/s", ha="center", va="bottom", fontsize=9, weight="bold")
        ax.text(xi, tps[xi] * 0.5, f"verify\n{v:.0f} ms\n\n{sz:.1f} KB",
                ha="center", va="center", fontsize=8, color="white", weight="bold")
    ax.set_xticks(x, [f"RP={m['bits']}" for m in ms])
    ax.set_xlabel("range-proof bit-width")
    ax.set_ylabel("processing TPS (median of k)")
    t = metas[0]["title"]
    ax.set_title(f"{t[:1].upper() + t[1:]} — throughput, verify time, tx size")
    ax.grid(True, axis="y", alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_bits_sweep.png")]


def scaling_i(pdir, metas, bands, scn_id):
    return _scaling(pdir, metas, scn_id, "i", "number of inputs")


def scaling_o(pdir, metas, bands, scn_id):
    return _scaling(pdir, metas, scn_id, "o", "number of outputs")


def _split_ts(metas):
    trans = sorted((m for m in metas if not m["shielded"]), key=lambda m: (m["i"], m["o"]))
    shield = sorted((m for m in metas if m["shielded"]), key=lambda m: (m["i"], m["o"]))
    return trans, shield


def compare_ts_bar(pdir, metas, bands, scn_id):
    plt = _plt()
    trans, shield = _split_ts(metas)
    fig, ax = plt.subplots(figsize=(7, 4.8))
    names, vals, colors = [], [], []
    for m in trans:
        names.append(f"transparent\n{m['i']}i{m['o']}o")
        vals.append(m["processing_tps"])
        colors.append(GRAY)
    for m in shield:
        names.append(f"shielded\n{m['i']}i{m['o']}o")
        vals.append(m["processing_tps"])
        colors.append(BLUE)
    bars = ax.bar(names, vals, color=colors)
    ax.bar_label(bars, fmt="%.0f", fontsize=9)
    ax.set_ylabel("processing TPS")
    ax.set_title(_title(scn_id, metas, "processing throughput"))
    ax.grid(True, axis="y", alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_compare_bar.png")]


def compare_ts_lines(pdir, metas, bands, scn_id):
    plt = _plt()
    trans, shield = _split_ts(metas)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    # neutral connectors distinguish type (light=transparent, dark=shielded); markers colour by shape
    for grp, name, line_c, dark in ((trans, "transparent", "#9a9a9a", False),
                                    (shield, "shielded", "#444444", True)):
        if not grp:
            continue
        xs = [f"{m['i']}i{m['o']}o" for m in grp]
        ys = [m["processing_tps"] for m in grp]
        ax.plot(xs, ys, "-", color=line_c, lw=1.4, zorder=1, label=name)
        for xi, m in zip(xs, grp):
            pair = P7_SHAPE_COLORS.get((m["i"], m["o"]))
            c = (pair[0] if dark else pair[1]) if pair else (BLUE if dark else LIGHT)
            ax.plot(xi, m["processing_tps"], "o", ms=10, color=c, mec="black", mew=0.5, zorder=2)
            ax.text(xi, m["processing_tps"], f"  {m['processing_tps']:.0f}", va="bottom", fontsize=8)
    ax.set_xlabel("tx shape (inputs × outputs)")
    ax.set_ylabel("processing TPS")
    ax.set_title(_title(scn_id, metas, "throughput by tx shape"))
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_compare_lines.png")]


def _grid(metas):
    ins = sorted({m["i"] for m in metas})
    outs = sorted({m["o"] for m in metas})
    tps = {(m["i"], m["o"]): m["processing_tps"] for m in metas}
    return ins, outs, tps


def grid_family(pdir, metas, bands, scn_id):
    plt = _plt()
    ins, outs, tps = _grid(metas)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for k, i in enumerate(ins):
        ys = [tps.get((i, o)) for o in outs]
        ax.plot(outs, ys, "o-", color=SERIES[k % len(SERIES)], lw=1.6, label=f"{i} inputs")
    ax.set_xlabel("number of outputs")
    ax.set_ylabel("processing TPS")
    ax.set_xticks(outs)
    ax.set_title(_title(scn_id, metas, "TPS vs outputs, per input count"))
    ax.legend(fontsize=9, title="inputs")
    ax.grid(True, alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_tps_family.png")]


def grid_grouped(pdir, metas, bands, scn_id):
    plt = _plt()
    ins, outs, tps = _grid(metas)
    fig, axes = plt.subplots(1, len(ins), figsize=(3.2 * len(ins), 4.2), sharey=True)
    axes = axes if hasattr(axes, "__len__") else [axes]
    for ax, i in zip(axes, ins):
        vals = [tps.get((i, o), 0.0) for o in outs]
        bars = ax.bar([str(o) for o in outs], vals, color=BLUE)
        ax.bar_label(bars, fmt="%.0f", fontsize=8)
        ax.set_title(f"{i} inputs")
        ax.set_xlabel("outputs")
        ax.grid(True, axis="y", alpha=0.25)
    axes[0].set_ylabel("processing TPS")
    fig.suptitle(_title(scn_id, metas, "grouped by input count"))
    return [_save(fig, pdir, f"{scn_id}_grouped_by_input.png")]


def grid_heatmap(pdir, metas, bands, scn_id):
    plt = _plt()
    ins, outs, tps = _grid(metas)
    grid = [[tps.get((i, o), float("nan")) for o in outs] for i in ins]
    fig, ax = plt.subplots(figsize=(7.2, 5))
    im = ax.imshow(grid, cmap="viridis", aspect="auto", origin="lower")
    ax.set_xticks(range(len(outs)), [str(o) for o in outs])
    ax.set_yticks(range(len(ins)), [str(i) for i in ins])
    ax.set_xlabel("outputs")
    ax.set_ylabel("inputs")
    for a, i in enumerate(ins):
        for b, o in enumerate(outs):
            v = tps.get((i, o))
            if v is not None:
                ax.text(b, a, f"{v:.0f}", ha="center", va="center", color="w", fontsize=9)
    fig.colorbar(im, ax=ax, label="processing TPS")
    ax.set_title(_title(scn_id, metas, "throughput heatmap"))
    return [_save(fig, pdir, f"{scn_id}_heatmap.png")]


def opt_bars(pdir, metas, bands, scn_id):
    plt = _plt()
    by = {m["cell"]: m for m in metas}
    order = [c for c in ("no-opt", "opt") if c in by]
    fig, ax = plt.subplots(figsize=(5, 4.5))
    vals = [by[c]["processing_tps"] for c in order]
    bars = ax.bar(order, vals, color=[GRAY, BLUE][: len(order)])
    ax.bar_label(bars, fmt="%.0f", fontsize=10)
    if "opt" in by and "no-opt" in by and by["no-opt"]["processing_tps"]:
        r = by["opt"]["processing_tps"] / by["no-opt"]["processing_tps"]
        ax.text(0.5, 0.9, f"{r:.2f}× speedup", transform=ax.transAxes, ha="center",
                fontsize=12, color=GREEN, weight="bold")
    ax.set_ylabel("processing TPS")
    ax.set_title(_title(scn_id, metas, "all optimizations on vs off"))
    ax.grid(True, axis="y", alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_opt_bars.png")]


def section_bars(pdir, metas, bands, scn_id):
    plt = _plt()
    by = {m["cell"]: m for m in metas}
    full = by.get("full", {}).get("processing_tps", 0.0)
    order = ["full"] + [c for c in sorted(by) if c.startswith("no-")]
    x = list(range(len(order)))
    fig, ax = plt.subplots(figsize=(8, 4.5))
    vals = [by[c]["processing_tps"] for c in order]
    colors = [GREEN] + [BLUE] * (len(order) - 1)
    bars = ax.bar(x, vals, color=colors)
    ax.bar_label(bars, fmt="%.0f", fontsize=9, padding=2)
    # marginal contribution: dropping section X (rest on) costs full - no_sX tx/s (white, inside bar)
    for xi, c in enumerate(order):
        if c.startswith("no-") and full:
            ax.text(xi, vals[xi] * 0.5, f"Δ{full - vals[xi]:+.0f}", ha="center", va="center",
                    fontsize=8, color="white", weight="bold")
    ax.set_xticks(x, [_pretty_cell(c) for c in order])
    ax.set_ylim(0, max(vals) * 1.12)
    ax.set_ylabel("processing TPS")
    ax.set_title(_title(scn_id, metas, "each section OFF (rest ON); Δ = its contribution"))
    ax.grid(True, axis="y", alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_sections.png")]


def _transition_fig(pdir, metas, bands, scn_id, as_tps: bool):
    """P11: per-tx latency (or its TPS twin) across the continuous two-segment stream, one figure per
    direction (T2S/S2T), overlaying the shapes. Vertical line marks the transition; the legend carries
    each shape's per-segment TPS so the composition shift is quantified."""
    plt = _plt()
    by_dir: dict[str, list] = {}
    for m in metas:
        by_dir.setdefault(m.get("transition", "?"), []).append(m)
    made = []
    for direction, ms in by_dir.items():
        ms = sorted(ms, key=lambda x: (x["i"], x["o"]))
        fig, ax = plt.subplots(figsize=(10, 4.8))
        boundary = ms[0].get("boundary", 0)
        seg_labels = ms[0].get("seg_labels", ["", ""])
        a, b = seg_labels[0][:1].upper(), seg_labels[1][:1].upper()
        dropped = 0
        for k, m in enumerate(ms):
            rows = bands.get(m["cell"])
            if not rows:
                continue
            rows, d = _clip_band(rows)
            dropped += d
            xs = [r[0] for r in rows]
            if as_tps:
                lo = [1e6 / r[3] for r in rows]
                av = [1e6 / r[2] for r in rows]
                hi = [1e6 / r[1] for r in rows]
            else:
                lo, av, hi = [r[1] for r in rows], [r[2] for r in rows], [r[3] for r in rows]
            c = SERIES[k % len(SERIES)]
            st = m.get("seg_tps", [0, 0])
            lab = f"{m['i']}i{m['o']}o  ({a}:{st[0]:.0f}→{b}:{st[1]:.0f} tx/s)"
            ax.fill_between(xs, lo, hi, color=c, alpha=0.12)
            ax.plot(xs, av, lw=1.0, color=c, label=lab)
        ax.axvline(boundary, color="black", ls="--", lw=1.2)
        ax.text(boundary, ax.get_ylim()[1], f"  transition @ {boundary}  →", va="top", fontsize=8)
        ax.set_xlabel("tx index across the continuous stream (no warm-up discarded)")
        ax.set_ylabel("instantaneous TPS = 1/latency (tx/s)" if as_tps else "total latency S1..S6 (µs)")
        metric = "throughput" if as_tps else "latency"
        what = f"{_DIR_LABEL.get(direction, direction)} — {metric} across the transition"
        ax.set_title(_title(scn_id, metas, what))
        ax.legend(fontsize=8, title="shape (segment TPS)")
        _sigma_note(ax, dropped)
        ax.grid(True, alpha=0.25)
        made.append(_save(fig, pdir, f"{scn_id}_transition_{direction}{'_tps' if as_tps else ''}.png"))
    return made


def transition(pdir, metas, bands, scn_id):
    return _transition_fig(pdir, metas, bands, scn_id, as_tps=False)


def transition_tps(pdir, metas, bands, scn_id):
    return _transition_fig(pdir, metas, bands, scn_id, as_tps=True)


_FAMILIES = {fn.__name__: fn for fn in (
    latency_band, tps_band, stage_breakdown, stage_throughput, scaling_i, scaling_o, bits_sweep,
    compare_ts_bar, compare_ts_lines, grid_family, grid_grouped, grid_heatmap, opt_bars, section_bars,
    transition, transition_tps,
)}


def render_scenario(root: Path, scn_id: str, figures_root: Path | None = None) -> list[str]:
    sdir = root / scn_id
    if not sdir.is_dir():
        return []
    metas, bands = _load_scenario(sdir)
    if not metas:
        return []
    pdir = (figures_root / scn_id) if figures_root else (sdir / "plots")
    made = []
    for fam in PLOT_SPECS.get(scn_id, ["latency_band"]):
        made += _FAMILIES[fam](pdir, metas, bands, scn_id)
    print(f"  {scn_id}: {', '.join(made)}")
    return made


WORKLOAD_SHORT = {"1-tip-transparent": "transparent", "capless-full-shielded": "shielded (capless)"}


def _scenario_dirs(root: Path) -> list[str]:
    ids = [p.name for p in root.iterdir() if p.is_dir() and p.name.startswith("P") and p.name[1:].isdigit()]
    return sorted(ids, key=lambda s: int(s[1:]))


def build_summary(root: Path, figures_root: Path | None = None) -> Path:
    """Assemble one summary.md over EVERY scenario present in `root`: a headline table across all
    cells + per-scenario sections embedding the figures. Consumes only the saved meta/plots. When
    `figures_root` is given, figures live in `<figures_root>/<P>/` and the summary is written there."""
    ids = _scenario_dirs(root)
    lines = [f"# TPS benchmark report — {root.name}", "",
             "Generated by `report_data.py` + `report_plots.py`. Values are the **median of k reps**; "
             "the range-proof build cache is enabled for shielded cells (build-only — measured "
             "processing is unaffected, see CP-16). Per-tx-index min/avg/max bands are in the "
             "`*_latency_band.png` figures.", "",
             "## Headline", "",
             "| scn | cell | workload | I×O | bits | TPS | acc | RSS MB | disk MB | FD | energy J | wall s |",
             "|-----|------|----------|-----|-----:|----:|-----|-------:|--------:|---:|---------:|-------:|"]
    sections = []
    for scn_id in ids:
        metas, _ = _load_scenario(root / scn_id)
        if not metas:
            continue
        title = metas[0]["title"]
        for m in metas:
            wl = WORKLOAD_SHORT.get(m["workload"], m["workload"])
            acc = f"{min(m['accepted'])}/{m['n']}"
            lines.append(
                f"| {scn_id} | {m['cell']} | {wl} | {m['i']}×{m['o']} | {m['bits']} | "
                f"{m['processing_tps']:.0f} | {acc} | {m['rss_peak_mb']:.0f} | "
                f"{m['disk_written_mb']:.1f} | {m['fd_peak']} | {m['energy_j']:.1f} | {m['batch_wall_s']:.1f} |")
        pdir = (figures_root / scn_id) if figures_root else (root / scn_id / "plots")
        rel = f"{scn_id}" if figures_root else f"{scn_id}/plots"
        # primary figures first, the per-tx band figures (latency + TPS twin) last
        figs = sorted(pdir.glob("*.png"), key=lambda f: ("band" in f.name, f.name)) \
            if pdir.is_dir() else []
        cfg = metas[0]
        wl_label = " + ".join(WORKLOAD_SHORT.get(w, w) for w in sorted({m["workload"] for m in metas}))
        sec = [f"## {scn_id} — {title}", "",
               f"_{wl_label}, N={cfg['n']} · warm-up={cfg['warmup']} · k={cfg['k']}_", ""]
        sec += [f"![{f.stem}]({rel}/{f.name})" for f in figs] or ["_(no figures)_"]
        sections.append("\n".join(sec))
    md = "\n".join(lines) + "\n\n" + "\n\n".join(sections) + "\n"
    out = (figures_root or root) / "summary.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    return out


def render_report(root: Path, only: list[str] | None = None, figures_root: Path | None = None) -> list[str]:
    ids = only or [p.name for p in sorted(root.iterdir()) if p.is_dir() and p.name.startswith("P")]
    print(f"plots → {figures_root or root}")
    made = []
    for scn_id in ids:
        made += render_scenario(root, scn_id.upper(), figures_root)
    summary = build_summary(root, figures_root)
    print(f"  summary → {summary}")
    return made


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Render report figures (PNG+PDF) from collected data.")
    ap.add_argument("root", type=Path, help="report-data dir (holds <P>/<cell>.meta.json + .band.csv)")
    ap.add_argument("scenarios", nargs="*", help="scenario ids to render, e.g. P1 P8 (default: all)")
    ap.add_argument("--figures", type=Path, default=None,
                    help="write figures + summary.md into this dir (as <dir>/<P>/) instead of alongside data")
    args = ap.parse_args()
    if not args.root.is_dir():
        print(f"not a dir: {args.root}")
        return 2
    only = [a.upper() for a in args.scenarios] or None
    made = render_report(args.root, only, figures_root=args.figures)
    print(f"done: {len(made)} figures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
