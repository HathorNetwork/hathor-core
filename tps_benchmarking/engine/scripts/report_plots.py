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
STAGE_COLORS = {"S1": "#8250df", "S2": "#0969da", "S3S4": "#1f6feb",
                "S5": "#bc4c00", "S6": "#116329"}
SERIES = [BLUE, ORANGE, GREEN, PURPLE, RED, GRAY]

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
}
_DIR_LABEL = {"T2S": "transparent → shielded", "S2T": "shielded → transparent"}


def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def _save(fig, pdir: Path, name: str) -> str:
    pdir.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(pdir / name, dpi=120)
    _plt().close(fig)
    return name


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
    return f"  ·  {'/'.join(map(str, bits))}-bit range proofs" if bits else ""


def _title(scn_id: str, metas: list[dict], what: str) -> str:
    t = metas[0]["title"] if metas else scn_id
    return f"{scn_id}  {t} — {what}{_bits_note(metas)}"


# -- figure families -------------------------------------------------------------------------------
def latency_band(pdir, metas, bands, scn_id):
    plt = _plt()
    fig, ax = plt.subplots(figsize=(9, 4.5))
    for k, m in enumerate(metas):
        rows = bands.get(m["cell"])
        if not rows:
            continue
        xs = [r[0] for r in rows]
        lo, av, hi = [r[1] for r in rows], [r[2] for r in rows], [r[3] for r in rows]
        c = SERIES[k % len(SERIES)]
        ax.fill_between(xs, lo, hi, color=c, alpha=0.15)
        ax.plot(xs, av, lw=1.0, color=c, label=m["cell"])
    ax.set_xlabel("measured tx index (steady state, warm-up discarded)")
    ax.set_ylabel("total latency S1..S6 (µs)")
    ax.set_title(_title(scn_id, metas, "per-tx latency band (min/avg/max over k reps)"))
    ax.legend(fontsize=8, ncol=2)
    ax.grid(True, alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_latency_band.png")]


def tps_band(pdir, metas, bands, scn_id):
    """TPS twin of latency_band: instantaneous throughput (1 / per-tx latency). Latency min/max
    invert to TPS max/min, so the band is the same spread expressed as tx/s."""
    plt = _plt()
    fig, ax = plt.subplots(figsize=(9, 4.5))
    for k, m in enumerate(metas):
        rows = bands.get(m["cell"])
        if not rows:
            continue
        xs = [r[0] for r in rows]
        lo = [1e6 / r[3] for r in rows]   # from MAX latency → MIN tps
        av = [1e6 / r[2] for r in rows]
        hi = [1e6 / r[1] for r in rows]   # from MIN latency → MAX tps
        c = SERIES[k % len(SERIES)]
        ax.fill_between(xs, lo, hi, color=c, alpha=0.15)
        ax.plot(xs, av, lw=1.0, color=c, label=m["cell"])
    ax.set_xlabel("measured tx index (steady state, warm-up discarded)")
    ax.set_ylabel("instantaneous TPS = 1 / per-tx latency (tx/s)")
    ax.set_title(_title(scn_id, metas, "per-tx throughput band (min/avg/max over k reps)"))
    ax.legend(fontsize=8, ncol=2)
    ax.grid(True, alpha=0.25)
    return [_save(fig, pdir, f"{scn_id}_tps_band.png")]


def stage_breakdown(pdir, metas, bands, scn_id):
    plt = _plt()
    n = len(metas)
    fig, ax = plt.subplots(figsize=(max(7.5, 1.6 * n + 3.5), 4.8))
    x = list(range(n))
    labels = [m["cell"] for m in metas]
    bottom = [0.0] * n
    for s in STAGE_ORDER:
        vals = [m.get("stage_mean_us", {}).get(s, 0.0) for m in metas]
        ax.bar(x, vals, width=0.55, bottom=bottom, label=s, color=STAGE_COLORS.get(s, GRAY))
        bottom = [b + v for b, v in zip(bottom, vals)]
    for xi in x:
        ax.text(xi, bottom[xi], f"{metas[xi]['processing_tps']:.0f} tx/s",
                ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x, labels)
    ax.set_xlim(-0.8, n - 0.2)
    ax.set_ylim(0, max(bottom) * 1.15)
    ax.set_ylabel("mean stage wall time (µs)")
    ax.set_title(_title(scn_id, metas, "per-stage breakdown + TPS"))
    ax.legend(fontsize=8, ncol=len(STAGE_ORDER), loc="lower center")
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
        ax.bar(xs, ys, width=width, label=s, color=STAGE_COLORS.get(s, GRAY))
    ax.set_yscale("log")
    ymax = ax.get_ylim()[1]
    for b, m in zip(base, metas):
        ax.text(b, ymax, f"{m['processing_tps']:.0f} tx/s\ntotal", ha="center", va="top", fontsize=8)
    ax.set_xticks(base, [m["cell"] for m in metas])
    ax.set_ylabel("per-stage throughput ceiling = 1 / stage time (tx/s, log)")
    ax.set_title(_title(scn_id, metas, "per-stage throughput ceiling (bottleneck = lowest bar)"))
    ax.legend(fontsize=8, ncol=nst)
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
    for grp, name, c in ((trans, "transparent", GRAY), (shield, "shielded", BLUE)):
        if not grp:
            continue
        xs = [f"{m['i']}i{m['o']}o" for m in grp]
        ys = [m["processing_tps"] for m in grp]
        ax.plot(xs, ys, "o-", color=c, lw=1.6, label=name)
        for x, y in zip(xs, ys):
            ax.text(x, y, f" {y:.0f}", va="bottom", fontsize=8)
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
    fig, ax = plt.subplots(figsize=(8, 4.5))
    vals = [by[c]["processing_tps"] for c in order]
    colors = [GREEN] + [BLUE] * (len(order) - 1)
    bars = ax.bar(order, vals, color=colors)
    ax.bar_label(bars, fmt="%.0f", fontsize=9)
    # marginal contribution: dropping section X (rest on) costs full - no_sX tx/s
    for x, c in enumerate(order):
        if c.startswith("no-") and full:
            ax.text(x, vals[x], f"\nΔ{full - vals[x]:+.0f}", ha="center", va="top",
                    fontsize=8, color=RED)
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
        for k, m in enumerate(ms):
            rows = bands.get(m["cell"])
            if not rows:
                continue
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
        ax.grid(True, alpha=0.25)
        made.append(_save(fig, pdir, f"{scn_id}_transition_{direction}{'_tps' if as_tps else ''}.png"))
    return made


def transition(pdir, metas, bands, scn_id):
    return _transition_fig(pdir, metas, bands, scn_id, as_tps=False)


def transition_tps(pdir, metas, bands, scn_id):
    return _transition_fig(pdir, metas, bands, scn_id, as_tps=True)


_FAMILIES = {fn.__name__: fn for fn in (
    latency_band, tps_band, stage_breakdown, stage_throughput, scaling_i, scaling_o,
    compare_ts_bar, compare_ts_lines, grid_family, grid_grouped, grid_heatmap, opt_bars, section_bars,
    transition, transition_tps,
)}


def render_scenario(root: Path, scn_id: str) -> list[str]:
    sdir = root / scn_id
    if not sdir.is_dir():
        return []
    metas, bands = _load_scenario(sdir)
    if not metas:
        return []
    pdir = sdir / "plots"
    made = []
    for fam in PLOT_SPECS.get(scn_id, ["latency_band"]):
        made += _FAMILIES[fam](pdir, metas, bands, scn_id)
    print(f"  {scn_id}: {', '.join(made)}")
    return made


WORKLOAD_SHORT = {"1-tip-transparent": "transparent", "capless-full-shielded": "shielded (capless)"}


def _scenario_dirs(root: Path) -> list[str]:
    ids = [p.name for p in root.iterdir() if p.is_dir() and p.name.startswith("P") and p.name[1:].isdigit()]
    return sorted(ids, key=lambda s: int(s[1:]))


def build_summary(root: Path) -> Path:
    """Assemble one summary.md over EVERY scenario present in `root`: a headline table across all
    cells + per-scenario sections embedding the figures. Consumes only the saved meta/plots."""
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
        pdir = root / scn_id / "plots"
        # primary figures first, the per-tx band figures (latency + TPS twin) last
        figs = sorted(pdir.glob("*.png"), key=lambda f: ("band" in f.name, f.name)) \
            if pdir.is_dir() else []
        cfg = metas[0]
        wl_label = " + ".join(WORKLOAD_SHORT.get(w, w) for w in sorted({m["workload"] for m in metas}))
        sec = [f"## {scn_id} — {title}", "",
               f"_{wl_label}, N={cfg['n']} · warm-up={cfg['warmup']} · k={cfg['k']}_", ""]
        sec += [f"![{f.stem}]({scn_id}/plots/{f.name})" for f in figs] or ["_(no figures)_"]
        sections.append("\n".join(sec))
    md = "\n".join(lines) + "\n\n" + "\n\n".join(sections) + "\n"
    out = root / "summary.md"
    out.write_text(md, encoding="utf-8")
    return out


def render_report(root: Path, only: list[str] | None = None) -> list[str]:
    ids = only or [p.name for p in sorted(root.iterdir()) if p.is_dir() and p.name.startswith("P")]
    print(f"plots → {root}")
    made = []
    for scn_id in ids:
        made += render_scenario(root, scn_id.upper())
    summary = build_summary(root)
    print(f"  summary → {summary.relative_to(root.parent)}")
    return made


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: report_plots.py <report-data/dir> [P1 P2 ...]")
        return 2
    root = Path(sys.argv[1])
    if not root.is_dir():
        print(f"not a dir: {root}")
        return 2
    only = [a.upper() for a in sys.argv[2:]] or None
    made = render_report(root, only)
    print(f"done: {len(made)} figures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
