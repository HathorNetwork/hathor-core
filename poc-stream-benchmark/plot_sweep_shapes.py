"""
Per-binding "M overlay" plot for the wallet-scan sweep (results_sweep/wallet_scan.csv).

The sweep analog of plot_stream_shapes.py: for each binding in the CSV it writes
one PNG with two vertically-stacked subplots that share the x axis (stream size N),
one curve per shielded-output count M:

    ┌─────────────────────────────────────────────┐
    │ Total wall time (s)        M=1 M=2 M=3 M=4   │
    ├─────────────────────────────────────────────┤
    │ Recovery (ms / output)     M=1 M=2 M=3 M=4   │
    └─────────────────────────────────────────────┘

Top = total wall time for the whole stream (rust/node = full 7-phase pass;
wasm = recovery-only). Bottom = per-output recovery cost (rust/node =
ecdh+rewind+recheck; wasm = bundled rewindFullShieldedOutput) — flat in N because
it is a per-output figure, so it reads as a stability/overhead check.

Outputs: plots_sweep/sweep_<binding>.png  (e.g. sweep_rust-pure.png)

Usage: python3 plot_sweep_shapes.py [--csv results_sweep/wallet_scan.csv] [--plot-dir plots_sweep] [--logy]
"""

from __future__ import annotations

import argparse
import csv
import os
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

DEFAULT_CSV = 'results_sweep/wallet_scan.csv'
DEFAULT_PLOT_DIR = 'plots_sweep'

M_ORDER = [1, 2, 3, 4]
M_COLORS = {1: 'tab:blue', 2: 'tab:green', 3: 'tab:orange', 4: 'tab:red'}
M_MARKERS = {1: 'o', 2: 's', 3: '^', 4: 'D'}


def _f(x: str) -> float:
    return float(x) if x not in ('', None) else float('nan')


def _load(path: str) -> list[dict]:
    with open(path) as f:
        return list(csv.DictReader(f))


def _recovery_ms(r: dict) -> float:
    if r['binding'] == 'wasm':
        return _f(r['per_rewind_ms'])
    return _f(r['per_ecdh_ms']) + _f(r['per_rewind_ms']) + _f(r['per_recover_check_ms'])


def _curves(rows, binding, yfn) -> dict[int, tuple[list[int], list[float]]]:
    """{M -> (xs sorted by N, ys)} for one binding."""
    by_m: dict[int, list[tuple[int, float]]] = defaultdict(list)
    for r in rows:
        if r['binding'] != binding:
            continue
        y = yfn(r)
        if y != y:
            continue
        by_m[int(r['shielded_outputs'])].append((int(r['n']), y))
    out = {}
    for m, prs in by_m.items():
        prs.sort()
        out[m] = ([p[0] for p in prs], [p[1] for p in prs])
    return out


def _plot_binding(rows, binding, plot_dir, logy) -> None:
    total_curves = _curves(rows, binding, lambda r: _f(r['total_s']))
    recov_curves = _curves(rows, binding, _recovery_ms)
    if not total_curves and not recov_curves:
        print(f'  no rows for binding={binding!r}; skipping')
        return

    fig, (ax_t, ax_r) = plt.subplots(2, 1, figsize=(9, 8), sharex=True)
    for m in M_ORDER:
        if m in total_curves:
            xs, ys = total_curves[m]
            ax_t.plot(xs, ys, marker=M_MARKERS[m], markersize=5, color=M_COLORS[m],
                      linewidth=1.8, label=f'M={m}')
        if m in recov_curves:
            xs, ys = recov_curves[m]
            ax_r.plot(xs, ys, marker=M_MARKERS[m], markersize=5, color=M_COLORS[m],
                      linewidth=1.8, label=f'M={m}')

    full = 'full 7-phase pass' if binding != 'wasm' else 'recovery-only'
    ax_t.set_title(f'Total wall time per stream ({full})')
    ax_t.set_ylabel('Total time (s)')
    ax_t.grid(True, alpha=0.3)
    ax_t.legend(title='shielded outputs / tx', fontsize=8, loc='best')

    bundled = '' if binding != 'wasm' else ' (bundled)'
    ax_r.set_title(f'Per-output recovery cost{bundled}')
    ax_r.set_xlabel('Stream size (transactions in sequence)')
    ax_r.set_ylabel('Recovery (ms / shielded output)')
    ax_r.grid(True, alpha=0.3)
    ax_r.legend(title='shielded outputs / tx', fontsize=8, loc='best')
    if logy:
        ax_t.set_yscale('log')
        ax_r.set_yscale('log')

    fig.suptitle(f'{binding} — wallet-scan sweep', fontsize=13)
    fig.tight_layout(rect=(0, 0, 1, 0.96))
    out = os.path.join(plot_dir, f'sweep_{binding}.png')
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f'  wrote {out}')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--csv', default=DEFAULT_CSV)
    p.add_argument('--plot-dir', default=DEFAULT_PLOT_DIR)
    p.add_argument('--logy', action='store_true', help='log-scale y axes')
    args = p.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(here, args.csv)
    plot_dir = os.path.join(here, args.plot_dir)
    os.makedirs(plot_dir, exist_ok=True)
    if not os.path.exists(csv_path):
        raise SystemExit(f'No CSV at {csv_path}. Run sweep_wallet_scan.py first.')

    rows = _load(csv_path)
    bindings = [b for b in ('rust-pure', 'node-napi', 'wasm') if any(r['binding'] == b for r in rows)]
    print(f'Reading {csv_path} ...')
    print(f'Bindings: {bindings}')
    for b in bindings:
        _plot_binding(rows, b, plot_dir, logy=args.logy)
    print(f'\nAll plots -> {plot_dir}/')


if __name__ == '__main__':
    main()
