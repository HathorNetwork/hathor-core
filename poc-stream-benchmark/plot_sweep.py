"""
Plot the wallet-scan binding sweep (results_sweep/wallet_scan.csv).

Same visual style as plot_stream.py, but the two overlaid dimensions are the
crypto BINDING (color) and the shielded-output count M (linestyle + marker),
against stream size N on the x axis.

Writes one PNG per metric/view into the plot dir:

LINE plots (x = stream size N, one curve per binding × M):
  - recovery_per_output_ms.png   per-output recovery cost (cross-binding metric:
                                 rust/node = ecdh+rewind+recheck; wasm = bundled)
  - rewind_per_output_ms.png     the rewind primitive alone (wasm = bundled)
  - total_time_s.png             total wall time per stream (rust/node = full
                                 7-phase pass; wasm = recovery-only)
  - per_tx_total_ms.png          per-tx total time
  - range_verify_per_proof_ms.png  range-proof verify (rust-pure vs node-napi;
                                 wasm has no verify surface)

BAR plots:
  - recovery_overhead_bar.png    mean per-output recovery by binding, grouped by M
  - phase_breakdown.png          stacked phase composition of total wall time at
                                 the largest N, one panel per binding

Usage: python3 plot_sweep.py [--csv results_sweep/wallet_scan.csv] [--plot-dir plots_sweep]
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics as st
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')  # headless: savefig only
import matplotlib.pyplot as plt  # noqa: E402

DEFAULT_CSV = 'results_sweep/wallet_scan.csv'
PLOT_DIR = 'plots_sweep'

BINDING_ORDER = ['rust-pure', 'node-napi', 'wasm']
BINDING_COLORS = {'rust-pure': 'tab:green', 'node-napi': 'tab:blue', 'wasm': 'tab:red'}
M_LINESTYLES = {1: '-', 2: '--', 3: '-.', 4: ':'}
M_MARKERS = {1: 'o', 2: 's', 3: '^', 4: 'D'}

# Phase columns -> (label, color) for the stacked breakdown.
PHASES = [
    ('range_verify_s', 'range', 'tab:orange'),
    ('surjection_verify_s', 'surjection', 'tab:purple'),
    ('balance_verify_s', 'balance', 'tab:green'),
    ('ecdh_s', 'ecdh', 'tab:cyan'),
    ('rewind_s', 'rewind', 'tab:red'),
    ('recover_check_s', 'recheck', 'tab:brown'),
    ('balance_update_s', 'update', 'tab:gray'),
]


def _f(x: str) -> float:
    return float(x) if x not in ('', None) else float('nan')


def _load(path: str) -> list[dict]:
    with open(path) as f:
        return list(csv.DictReader(f))


def _recovery_ms(r: dict) -> float:
    """Per-output recovery cost. wasm bundles ecdh+rewind+recheck into rewind."""
    if r['binding'] == 'wasm':
        return _f(r['per_rewind_ms'])
    return _f(r['per_ecdh_ms']) + _f(r['per_rewind_ms']) + _f(r['per_recover_check_ms'])


def _group(rows: list[dict], yfn, bindings: list[str]) -> dict:
    """dict[(binding, M)] -> (xs sorted by N, ys). NaN ys are dropped."""
    by: dict[tuple[str, int], list[tuple[int, float]]] = defaultdict(list)
    for r in rows:
        b = r['binding']
        if b not in bindings:
            continue
        y = yfn(r)
        if y != y:  # NaN (e.g. verify columns for wasm)
            continue
        by[(b, int(r['shielded_outputs']))].append((int(r['n']), y))
    out = {}
    for k, prs in by.items():
        prs.sort()
        out[k] = ([p[0] for p in prs], [p[1] for p in prs])
    return out


def _plot_lines(rows, yfn, title, ylabel, out_path, bindings=None) -> None:
    bindings = bindings or BINDING_ORDER
    grouped = _group(rows, yfn, bindings)
    if not grouped:
        print(f'  (no data for {os.path.basename(out_path)}; skipped)')
        return
    ms_seen = sorted({m for (_, m) in grouped})
    fig, ax = plt.subplots(figsize=(8, 5))
    for b in bindings:
        for m in ms_seen:
            if (b, m) not in grouped:
                continue
            xs, ys = grouped[(b, m)]
            ax.plot(xs, ys, marker=M_MARKERS.get(m, 'o'), markersize=4,
                    color=BINDING_COLORS.get(b, 'k'), linestyle=M_LINESTYLES.get(m, '-'),
                    label=f'{b} · M={m}')
    ax.set_xlabel('Stream size (transactions)')
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=7, ncol=len(bindings), loc='best')
    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    print(f'  wrote {out_path}')


def _plot_recovery_bar(rows, out_path) -> None:
    """Grouped bars: mean per-output recovery (over N) per binding, grouped by M."""
    by: dict[tuple[str, int], list[float]] = defaultdict(list)
    for r in rows:
        by[(r['binding'], int(r['shielded_outputs']))].append(_recovery_ms(r))
    ms = sorted({m for (_, m) in by})
    bindings = [b for b in BINDING_ORDER if any(bb == b for (bb, _) in by)]
    fig, ax = plt.subplots(figsize=(8, 5))
    width = 0.8 / len(bindings)
    x = list(range(len(ms)))
    for i, b in enumerate(bindings):
        vals = [st.mean(by[(b, m)]) for m in ms]
        bars = ax.bar([xx + i * width for xx in x], vals, width=width,
                      color=BINDING_COLORS[b], label=b)
        for rect, v in zip(bars, vals):
            ax.annotate(f'{v:.1f}', (rect.get_x() + rect.get_width() / 2, v),
                        ha='center', va='bottom', fontsize=7)
    ax.set_xticks([xx + width * (len(bindings) - 1) / 2 for xx in x])
    ax.set_xticklabels([f'M={m}' for m in ms])
    ax.set_ylabel('Recovery time (ms / shielded output)')
    ax.set_title('Per-output recovery cost by binding (mean over N)\n'
                 'rust/node = ecdh + rewind + recheck; wasm = bundled rewindFullShieldedOutput')
    ax.grid(True, axis='y', alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    print(f'  wrote {out_path}')


def _plot_phase_breakdown(rows, out_path) -> None:
    """Stacked phase composition of total wall time at the largest N, panel per binding."""
    nmax = max(int(r['n']) for r in rows)
    sub = [r for r in rows if int(r['n']) == nmax]
    cell = {(r['binding'], int(r['shielded_outputs'])): r for r in sub}
    ms = sorted({int(r['shielded_outputs']) for r in sub})
    bindings = [b for b in BINDING_ORDER if any(r['binding'] == b for r in sub)]

    fig, axes = plt.subplots(1, len(bindings), figsize=(4.2 * len(bindings), 5),
                             sharey=True, squeeze=False)
    x = list(range(len(ms)))
    for idx, b in enumerate(bindings):
        ax = axes[0][idx]
        bottom = [0.0] * len(ms)
        for col, lbl, color in PHASES:
            vals = [_f(cell[(b, m)][col]) for m in ms]
            vals = [0.0 if v != v else v for v in vals]
            ax.bar(x, vals, width=0.6, bottom=bottom, color=color, label=lbl)
            bottom = [bt + v for bt, v in zip(bottom, vals)]
        ax.set_xticks(x)
        ax.set_xticklabels([f'M={m}' for m in ms])
        ax.set_title(b, color=BINDING_COLORS.get(b, 'k'))
        ax.set_xlabel('Shielded outputs / tx')
        ax.grid(True, axis='y', alpha=0.3)
        if idx == 0:
            ax.set_ylabel(f'Total wall time at N={nmax} (s)')
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper right', fontsize=8)
    fig.suptitle(f'Phase breakdown of total wall time at N={nmax}  '
                 '(wasm = recovery-only; its rewind is bundled ecdh+rewind+recheck)')
    fig.tight_layout(rect=(0, 0, 0.93, 0.94))
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    print(f'  wrote {out_path}')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--csv', default=DEFAULT_CSV)
    p.add_argument('--plot-dir', default=PLOT_DIR)
    args = p.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(here, args.csv)
    plot_dir = os.path.join(here, args.plot_dir)
    os.makedirs(plot_dir, exist_ok=True)
    if not os.path.exists(csv_path):
        raise SystemExit(f'No CSV at {csv_path}. Run sweep_wallet_scan.py first.')

    rows = _load(csv_path)
    print(f'Reading {csv_path} ({len(rows)} rows) ...')

    _plot_lines(rows, _recovery_ms,
                'Per-output recovery cost vs stream size',
                'Recovery (ms / shielded output)',
                os.path.join(plot_dir, 'recovery_per_output_ms.png'))
    _plot_lines(rows, lambda r: _f(r['per_rewind_ms']),
                'Rewind primitive vs stream size  (wasm = bundled)',
                'Rewind (ms / shielded output)',
                os.path.join(plot_dir, 'rewind_per_output_ms.png'))
    _plot_lines(rows, lambda r: _f(r['total_s']),
                'Total wall time per stream  (rust/node = full pass; wasm = recovery-only)',
                'Total time (s)',
                os.path.join(plot_dir, 'total_time_s.png'))
    _plot_lines(rows, lambda r: _f(r['per_tx_total_ms']),
                'Per-tx total time vs stream size',
                'Per-tx (ms)',
                os.path.join(plot_dir, 'per_tx_total_ms.png'))
    _plot_lines(rows, lambda r: _f(r['per_range_verify_ms']),
                'Range-proof verify vs stream size  (wasm has no verify surface)',
                'Range verify (ms / proof)',
                os.path.join(plot_dir, 'range_verify_per_proof_ms.png'),
                bindings=['rust-pure', 'node-napi'])
    _plot_recovery_bar(rows, os.path.join(plot_dir, 'recovery_overhead_bar.png'))
    _plot_phase_breakdown(rows, os.path.join(plot_dir, 'phase_breakdown.png'))

    print(f'\nAll plots -> {plot_dir}/')


if __name__ == '__main__':
    main()
