"""
Per-mode "shape overlay" plot for stream_time.csv.

For each mode in the CSV (amount_hidden, fully_shielded) writes one PNG to
`plots/` containing two vertically-stacked subplots that share the x axis:

    ┌────────────────────────────────────────────┐
    │ Verification time (s)   2x2 4x4 8x8 16x16  │
    ├────────────────────────────────────────────┤
    │ Proof-creation time (s) 2x2 4x4 8x8 16x16  │
    └────────────────────────────────────────────┘

x = stream size (number of transactions in the sequence)
y = wall-clock seconds for the entire stream

Outputs:
    plots/shapes_amount_hidden.png
    plots/shapes_fully_shielded.png

A `--per-tx` flag swaps the y axis to per-tx milliseconds instead of total
seconds (sometimes easier to read because lines flatten out).
"""

from __future__ import annotations

import argparse
import csv
import os
from collections import defaultdict

import matplotlib.pyplot as plt

DEFAULT_CSV = 'results_time/stream_time.csv'
DEFAULT_PLOT_DIR = 'plots'

SHAPE_ORDER = ['2x2', '4x4', '8x8', '16x16']
SHAPE_COLORS = {
    '2x2': 'tab:blue',
    '4x4': 'tab:green',
    '8x8': 'tab:orange',
    '16x16': 'tab:red',
}
SHAPE_MARKERS = {
    '2x2': 'o',
    '4x4': 's',
    '8x8': '^',
    '16x16': 'D',
}

MODE_TITLES = {
    'amount_hidden': 'Amount-hidden stream',
    'fully_shielded': 'Fully-shielded stream',
}


def _load(path: str) -> list[dict]:
    with open(path) as f:
        return list(csv.DictReader(f))


def _curves(rows: list[dict], mode: str, y_field: str) -> dict[str, tuple[list[int], list[float]]]:
    """Return {shape -> (xs, ys)} for the given mode, sorted by stream_size."""
    by_shape: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for r in rows:
        if r['mode'] != mode:
            continue
        by_shape[r['shape']].append((int(r['stream_size']), float(r[y_field])))
    out: dict[str, tuple[list[int], list[float]]] = {}
    for shape, pairs in by_shape.items():
        pairs.sort()
        out[shape] = ([p[0] for p in pairs], [p[1] for p in pairs])
    return out


def _plot_mode(rows: list[dict], mode: str, plot_dir: str, per_tx: bool, logy: bool) -> None:
    if per_tx:
        verify_field, create_field = 'per_tx_verify_ms', 'per_tx_create_ms'
        ylabel = 'Per-tx time (ms)'
        suffix = '_per_tx'
    else:
        verify_field, create_field = 'verify_total_s', 'create_total_s'
        ylabel = 'Total time (s)'
        suffix = ''

    verify_curves = _curves(rows, mode, verify_field)
    create_curves = _curves(rows, mode, create_field)

    if not verify_curves and not create_curves:
        print(f'  no rows for mode={mode!r}; skipping')
        return

    fig, (ax_v, ax_c) = plt.subplots(2, 1, figsize=(9, 8), sharex=True)

    for shape in SHAPE_ORDER:
        if shape in verify_curves:
            xs, ys = verify_curves[shape]
            ax_v.plot(xs, ys,
                      marker=SHAPE_MARKERS[shape], markersize=5,
                      color=SHAPE_COLORS[shape], linewidth=1.8,
                      label=f'{shape}')
        if shape in create_curves:
            xs, ys = create_curves[shape]
            ax_c.plot(xs, ys,
                      marker=SHAPE_MARKERS[shape], markersize=5,
                      color=SHAPE_COLORS[shape], linewidth=1.8,
                      label=f'{shape}')

    ax_v.set_title('Verification time')
    ax_v.set_ylabel(ylabel)
    ax_v.grid(True, alpha=0.3)
    ax_v.legend(title='shape (inputs × outputs)', fontsize=8, loc='best')
    if logy:
        ax_v.set_yscale('log')

    ax_c.set_title('Proof-creation time')
    ax_c.set_xlabel('Stream size (transactions in sequence)')
    ax_c.set_ylabel(ylabel)
    ax_c.grid(True, alpha=0.3)
    ax_c.legend(title='shape (inputs × outputs)', fontsize=8, loc='best')
    if logy:
        ax_c.set_yscale('log')

    fig.suptitle(MODE_TITLES.get(mode, mode), fontsize=13)
    fig.tight_layout(rect=(0, 0, 1, 0.96))

    out = os.path.join(plot_dir, f'shapes_{mode}{suffix}.png')
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f'  wrote {out}')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--csv', default=DEFAULT_CSV,
                   help=f'path to stream_time.csv (default {DEFAULT_CSV})')
    p.add_argument('--plot-dir', default=DEFAULT_PLOT_DIR)
    p.add_argument('--per-tx', action='store_true',
                   help='plot per-tx ms instead of total seconds')
    p.add_argument('--logy', action='store_true', help='log-scale y axis')
    args = p.parse_args()

    here = os.path.dirname(__file__)
    csv_path = os.path.join(here, args.csv)
    plot_dir = os.path.join(here, args.plot_dir)
    os.makedirs(plot_dir, exist_ok=True)

    if not os.path.exists(csv_path):
        raise SystemExit(f'No CSV at {csv_path}. Run benchmark_stream_time.py first.')

    rows = _load(csv_path)
    modes = sorted({r['mode'] for r in rows})
    print(f'Reading {csv_path} ...')
    print(f'Modes: {modes}')
    for mode in modes:
        _plot_mode(rows, mode, plot_dir, per_tx=args.per_tx, logy=args.logy)
    print(f'\nAll plots -> {plot_dir}/')


if __name__ == '__main__':
    main()
