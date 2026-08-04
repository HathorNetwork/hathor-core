"""Figure rendering for the UI runs.

Palette is derived from hathor.network (deep navy grounds; lime / indigo / cyan / orange accents)
and was checked with the dataviz validator against these exact surfaces — every ink and series
colour clears 3:1 contrast on both the page and card grounds; the grid is deliberately BELOW that
(1.4:1) so it stays recessive.

Both figures here are SINGLE-SERIES by design, so no categorical palette is needed: the stage
chart's identity is carried by its axis labels, and the throughput chart's second line is a faint
reference of the same measure, not a second entity. Colour therefore encodes ROLE, not rank:

    lime   -> throughput (the headline measure)
    indigo -> latency composition
    muted  -> reference / secondary series

Known deviation from the mark spec: bar data-ends are square rather than 4px-rounded. Rounding in
matplotlib data coordinates distorts badly when the x and y scales differ by 3 orders of magnitude
(µs vs category index); it is a cosmetic refinement, deferred rather than faked.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

PAGE = "#0a0c26"
CARD = "#11143a"
INK = "#fafafa"
MUTED = "#8b93c7"
GRID = "#2a2f5e"
LIME = "#6eff00"
INDIGO = "#536cff"

STAGE_TAGS = {"S1": "ser/de", "S2": "gate", "S3S4": "verify", "S5": "cons.", "S6": "post-cons."}
DPI = 140
CAPTION_COLS = 104      # caption wrap width, so it never runs past the figure's right edge


def _fig(w=8.0, h=3.6):
    fig, ax = plt.subplots(figsize=(w, h), dpi=DPI)
    fig.patch.set_facecolor(CARD)
    ax.set_facecolor(CARD)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
        ax.spines[side].set_linewidth(1.0)
    ax.tick_params(colors=MUTED, labelsize=8.5, length=3, width=1.0)
    return fig, ax


def _caption(meta: dict) -> str:
    on = [s for s, v in meta["opt"].items() if v]
    opt = "all optimizations on" if len(on) == 5 else \
          ("all optimizations off" if not on else "opt: " + ", ".join(on))
    return (f"{meta['workload']} · N={meta['n']} measured (+{meta['warmup']} warm-up) · "
            f"I={meta['i']} O={meta['o']} · seed {meta['seed']} · {opt}")


def _finish(fig, ax, path: Path, title: str, subtitle: str) -> Path:
    """Stack title over caption without collisions, at any figure height.

    The caption is offset in POINTS from the axes' top-left, not in axes fractions: these figures
    size themselves to their row count, so a fractional offset drifts into the title on tall ones.
    The title's pad is then derived from the wrapped caption's line count."""
    lines = textwrap.wrap(subtitle, CAPTION_COLS) or [""]
    ax.set_title(title, color=INK, fontsize=12.5, fontweight="bold", loc="left",
                 pad=10 + 11 * len(lines))
    ax.annotate("\n".join(lines), xy=(0, 1), xycoords="axes fraction",
                xytext=(0, 6), textcoords="offset points",
                ha="left", va="bottom", color=MUTED, fontsize=8.2, linespacing=1.35)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, facecolor=CARD, bbox_inches="tight")
    plt.close(fig)
    return path


def rolling_tps_figure(path: Path, roll_median, roll_mean, head: dict, meta: dict) -> Path:
    """Throughput over the measured window — the transient -> steady-state curve.

    Two lines of the SAME measure: the rolling median (robust; the signal) and the rolling mean
    (kept faint because the ~0.5% RocksDB write-stall spikes drag it down for a whole window).
    A legend is present because there are two lines; the headline rate is direct-labelled."""
    fig, ax = _fig()
    xm = [i for i, _ in roll_mean]
    ax.plot(xm, [v for _, v in roll_mean], color=MUTED, linewidth=1.2, alpha=0.55,
            label="rolling mean (spike-sensitive)", zorder=2)
    xd = [i for i, _ in roll_median]
    yd = [v for _, v in roll_median]
    ax.plot(xd, yd, color=LIME, linewidth=2.0, label="rolling median", zorder=3)

    # The overall rate is a legend entry, not an annotation on the line: any in-plot placement
    # collides with the median curve, which wanders across the whole upper band.
    tps = head["processing_tps"]
    ax.axhline(tps, color=INK, linewidth=1.0, linestyle=(0, (4, 4)), alpha=0.5, zorder=1,
               label=f"overall {tps:,.0f} tx/s")

    ax.grid(axis="y", color=GRID, linewidth=0.8, alpha=0.7)
    ax.set_axisbelow(True)
    ax.set_xlabel("measured transaction index", color=MUTED, fontsize=9)
    ax.set_ylabel("throughput (tx/s)", color=MUTED, fontsize=9)
    ax.set_ylim(bottom=0)
    leg = ax.legend(frameon=False, fontsize=8.5, loc="lower right")
    for t in leg.get_texts():
        t.set_color(MUTED)
    return _finish(fig, ax, path, "Throughput over time", _caption(meta))


def stage_breakdown_figure(path: Path, stages: list[dict], meta: dict) -> Path:
    """Where the per-transaction time goes, in pipeline order S1 -> S6.

    Pipeline order, not sorted by size: the sequence is meaningful. One hue for every bar — the
    axis labels carry identity, so colouring bars individually would encode rank, not entity.
    Every bar is direct-labelled, so the chart is readable without reading the axis."""
    rows = [r for r in stages if r["mean_wall_us"] > 0]
    labels = [f"{r['stage']}  {STAGE_TAGS.get(r['stage'], '')}" for r in rows]
    values = [r["mean_wall_us"] for r in rows]
    shares = [r["share"] for r in rows]

    fig, ax = _fig(h=0.62 * len(rows) + 1.6)
    y = list(range(len(rows)))[::-1]                     # S1 at the top
    ax.barh(y, values, height=0.62, color=INDIGO, zorder=3)

    span = max(values) if values else 1.0
    for yi, v, sh in zip(y, values, shares):
        ax.text(v + span * 0.015, yi, f"{v:,.0f} µs · {sh:.0%}", va="center", ha="left",
                color=INK, fontsize=9)

    ax.set_yticks(y)
    ax.set_yticklabels(labels, color=INK, fontsize=9.5)
    ax.set_xlabel("mean wall time per transaction (µs)", color=MUTED, fontsize=9)
    ax.set_xlim(0, span * 1.36)     # headroom for the direct labels at the bar ends
    ax.grid(axis="x", color=GRID, linewidth=0.8, alpha=0.7)
    ax.set_axisbelow(True)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)

    total = sum(values)
    return _finish(fig, ax, path, "Per-stage cost breakdown",
                   f"{_caption(meta)} · total ≈ {total:,.0f} µs/tx")
