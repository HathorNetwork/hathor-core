"""
Plot stream benchmark results.

Reads:
  results_time/stream_time.csv       (from benchmark_stream_time.py)
  results_memory/stream_memory.csv   (from benchmark_stream_memory.py)

Writes one PNG per (metric, view) into plots/. Each plot overlays the two modes
(amount_hidden vs fully_shielded) on the same axes, with one line per tx shape.

TIME plots (x = stream_size, y = seconds or ms/tx):
  - create_total_s.png        total proof-creation wall time
  - verify_total_s.png        total verification wall time
  - per_tx_create_ms.png      per-tx proof creation
  - per_tx_verify_ms.png      per-tx verification
  - verify_breakdown.png      stacked balance/range/surjection contributions
  - throughput_create.png     tx/s (create)
  - throughput_verify.png     tx/s (verify)

MEMORY plots:
  - payload_total_kib.png         cumulative on-wire bytes
  - per_tx_payload_kib.png        per-tx on-wire bytes
  - payload_breakdown.png         stacked artifact contributions for largest shape
  - rss_peak_build_mib.png        peak process RSS during creation
  - rss_peak_verify_mib.png       peak process RSS during verification
  - tracemalloc_peak_build_mib.png Python-allocated bytes during creation
"""

from __future__ import annotations

import argparse
import csv
import os
from collections import defaultdict

import matplotlib.pyplot as plt

TIME_CSV = 'results_time/stream_time.csv'
MEM_CSV = 'results_memory/stream_memory.csv'
PLOT_DIR = 'plots'

MODE_COLORS = {
    'amount_hidden': 'tab:blue',
    'fully_shielded': 'tab:red',
}
MODE_LABELS = {
    'amount_hidden': 'Amount hidden',
    'fully_shielded': 'Fully shielded',
}
SHAPE_LINESTYLES = {
    '2x2': '-',
    '4x4': '--',
    '8x8': '-.',
    '16x16': ':',
}


def _load(path: str) -> list[dict]:
    with open(path) as f:
        return list(csv.DictReader(f))


def _group(rows: list[dict], metric: str) -> dict:
    """Return dict[(mode, shape)] -> (sorted xs, sorted ys)."""
    by_key: dict[tuple[str, str], list[tuple[int, float]]] = defaultdict(list)
    for r in rows:
        key = (r['mode'], r['shape'])
        by_key[key].append((int(r['stream_size']), float(r[metric])))
    out = {}
    for k, pairs in by_key.items():
        pairs.sort()
        xs = [p[0] for p in pairs]
        ys = [p[1] for p in pairs]
        out[k] = (xs, ys)
    return out


def _plot_metric(
    rows: list[dict],
    metric: str,
    title: str,
    ylabel: str,
    out_path: str,
    scale: float = 1.0,
    logy: bool = False,
) -> None:
    grouped = _group(rows, metric)
    fig, ax = plt.subplots(figsize=(8, 5))

    # Stable ordering: walk modes then shapes
    modes_seen = []
    shapes_seen = []
    for (mode, shape) in grouped:
        if mode not in modes_seen:
            modes_seen.append(mode)
        if shape not in shapes_seen:
            shapes_seen.append(shape)

    # Sort shapes by inputs_per_tx
    shapes_seen.sort(key=lambda s: int(s.split('x')[0]))

    for mode in modes_seen:
        color = MODE_COLORS.get(mode, 'k')
        for shape in shapes_seen:
            key = (mode, shape)
            if key not in grouped:
                continue
            xs, ys = grouped[key]
            ys_scaled = [y * scale for y in ys]
            ax.plot(
                xs, ys_scaled,
                marker='o', markersize=4,
                color=color,
                linestyle=SHAPE_LINESTYLES.get(shape, '-'),
                label=f'{MODE_LABELS.get(mode, mode)} · {shape}',
            )

    ax.set_xlabel('Stream size (transactions)')
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if logy:
        ax.set_yscale('log')
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8, ncol=2, loc='best')

    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    print(f'  wrote {out_path}')


def _plot_verify_breakdown(rows: list[dict], plot_dir: str) -> None:
    """Stacked-bar verify breakdown (balance/range/surjection) per mode × shape."""
    target_size = max(int(r['stream_size']) for r in rows)
    sub = [r for r in rows if int(r['stream_size']) == target_size]
    if not sub:
        return

    by: dict[str, dict[str, tuple[float, float, float]]] = defaultdict(dict)
    for r in sub:
        by[r['mode']][r['shape']] = (
            float(r['verify_balance_s']),
            float(r['verify_range_s']),
            float(r['verify_surjection_s']),
        )

    modes = [m for m in ('amount_hidden', 'fully_shielded') if m in by]
    shapes = sorted({s for m in by for s in by[m]}, key=lambda s: int(s.split('x')[0]))

    fig, axes = plt.subplots(1, len(modes), figsize=(4.5 * len(modes), 5),
                             sharey=True, squeeze=False)
    x = list(range(len(shapes)))

    for idx, mode in enumerate(modes):
        ax = axes[0][idx]
        bals = [by[mode].get(s, (0, 0, 0))[0] for s in shapes]
        rps = [by[mode].get(s, (0, 0, 0))[1] for s in shapes]
        sps = [by[mode].get(s, (0, 0, 0))[2] for s in shapes]
        ax.bar(x, bals, width=0.6, color='tab:green', label='balance')
        ax.bar(x, rps, width=0.6, bottom=bals, color='tab:orange', label='range')
        bottom_sp = [b + r for b, r in zip(bals, rps)]
        ax.bar(x, sps, width=0.6, bottom=bottom_sp, color='tab:purple', label='surjection')
        ax.set_xticks(x)
        ax.set_xticklabels(shapes)
        ax.set_title(MODE_LABELS[mode], color=MODE_COLORS[mode])
        ax.set_xlabel('Tx shape (inputs × outputs)')
        ax.grid(True, axis='y', alpha=0.3)
        if idx == 0:
            ax.set_ylabel('Verify time (seconds)')

    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper right', fontsize=8)
    fig.suptitle(f'Verify-time breakdown at stream_size = {target_size}')
    fig.tight_layout(rect=(0, 0, 0.95, 0.95))
    out = os.path.join(plot_dir, 'verify_breakdown.png')
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f'  wrote {out}')


def _plot_payload_breakdown(rows: list[dict], plot_dir: str) -> None:
    """Stacked bars of per-tx payload bytes by artifact, one panel per mode."""
    target_size = max(int(r['stream_size']) for r in rows)
    sub = [r for r in rows if int(r['stream_size']) == target_size]

    by: dict[str, dict[str, tuple[float, float, float, float]]] = defaultdict(dict)
    for r in sub:
        n = int(r['stream_size'])
        by[r['mode']][r['shape']] = (
            float(r['commitments_bytes']) / n / 1024,
            float(r['blinded_gens_bytes']) / n / 1024,
            float(r['range_proofs_bytes']) / n / 1024,
            float(r['surjection_proofs_bytes']) / n / 1024,
        )

    modes = [m for m in ('amount_hidden', 'fully_shielded') if m in by]
    shapes = sorted({s for m in by for s in by[m]}, key=lambda s: int(s.split('x')[0]))

    fig, axes = plt.subplots(1, len(modes), figsize=(4.5 * len(modes), 5),
                             sharey=True, squeeze=False)
    x = list(range(len(shapes)))

    artifact_colors = {
        'commitments': 'tab:blue',
        'blinded_gens': 'tab:cyan',
        'range_proofs': 'tab:orange',
        'surjection_proofs': 'tab:purple',
    }

    for idx, mode in enumerate(modes):
        ax = axes[0][idx]
        com = [by[mode].get(s, (0, 0, 0, 0))[0] for s in shapes]
        gen = [by[mode].get(s, (0, 0, 0, 0))[1] for s in shapes]
        rp = [by[mode].get(s, (0, 0, 0, 0))[2] for s in shapes]
        sp = [by[mode].get(s, (0, 0, 0, 0))[3] for s in shapes]

        ax.bar(x, com, width=0.6, color=artifact_colors['commitments'], label='commitments')
        ax.bar(x, gen, width=0.6, bottom=com, color=artifact_colors['blinded_gens'],
               label='blinded gens / asset commits')
        bottom2 = [c + g for c, g in zip(com, gen)]
        ax.bar(x, rp, width=0.6, bottom=bottom2, color=artifact_colors['range_proofs'],
               label='range proofs (Borromean)')
        bottom3 = [b + r for b, r in zip(bottom2, rp)]
        ax.bar(x, sp, width=0.6, bottom=bottom3, color=artifact_colors['surjection_proofs'],
               label='surjection proofs')
        ax.set_xticks(x)
        ax.set_xticklabels(shapes)
        ax.set_title(MODE_LABELS[mode], color=MODE_COLORS[mode])
        ax.set_xlabel('Tx shape (inputs × outputs)')
        ax.grid(True, axis='y', alpha=0.3)
        if idx == 0:
            ax.set_ylabel('Per-tx payload (KiB)')

    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper right', fontsize=8)
    fig.suptitle(f'Per-tx payload breakdown at stream_size = {target_size}')
    fig.tight_layout(rect=(0, 0, 0.95, 0.95))
    out = os.path.join(plot_dir, 'payload_breakdown.png')
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f'  wrote {out}')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--time-csv', default=TIME_CSV)
    p.add_argument('--memory-csv', default=MEM_CSV)
    p.add_argument('--plot-dir', default=PLOT_DIR)
    args = p.parse_args()

    here = os.path.dirname(__file__)
    time_csv = os.path.join(here, args.time_csv)
    memory_csv = os.path.join(here, args.memory_csv)
    plot_dir = os.path.join(here, args.plot_dir)
    os.makedirs(plot_dir, exist_ok=True)

    if os.path.exists(time_csv):
        print(f'Reading {time_csv} ...')
        time_rows = _load(time_csv)
        print('Time plots:')
        _plot_metric(time_rows, 'create_total_s', 'Total proof-creation time vs stream size',
                     'Total time (s)', os.path.join(plot_dir, 'create_total_s.png'))
        _plot_metric(time_rows, 'verify_total_s', 'Total verification time vs stream size',
                     'Total time (s)', os.path.join(plot_dir, 'verify_total_s.png'))
        _plot_metric(time_rows, 'per_tx_create_ms', 'Per-tx proof-creation time',
                     'Per-tx (ms)', os.path.join(plot_dir, 'per_tx_create_ms.png'))
        _plot_metric(time_rows, 'per_tx_verify_ms', 'Per-tx verification time',
                     'Per-tx (ms)', os.path.join(plot_dir, 'per_tx_verify_ms.png'))
        _plot_metric(time_rows, 'create_tps', 'Proof-creation throughput',
                     'tx / s', os.path.join(plot_dir, 'throughput_create.png'))
        _plot_metric(time_rows, 'verify_tps', 'Verification throughput',
                     'tx / s', os.path.join(plot_dir, 'throughput_verify.png'))
        _plot_verify_breakdown(time_rows, plot_dir)
    else:
        print(f'No time CSV at {time_csv}; skipping time plots.')

    if os.path.exists(memory_csv):
        print(f'Reading {memory_csv} ...')
        mem_rows = _load(memory_csv)
        print('Memory plots:')
        _plot_metric(mem_rows, 'payload_total_bytes', 'Total on-wire payload vs stream size',
                     'Payload (KiB)', os.path.join(plot_dir, 'payload_total_kib.png'),
                     scale=1.0 / 1024.0)
        _plot_metric(mem_rows, 'per_tx_payload_bytes', 'Per-tx on-wire payload',
                     'Per-tx (KiB)', os.path.join(plot_dir, 'per_tx_payload_kib.png'),
                     scale=1.0 / 1024.0)
        _plot_metric(mem_rows, 'rss_peak_build_kib', 'Peak process RSS during proof creation',
                     'RSS peak (MiB)', os.path.join(plot_dir, 'rss_peak_build_mib.png'),
                     scale=1.0 / 1024.0)
        _plot_metric(mem_rows, 'rss_peak_verify_kib', 'Peak process RSS during verification',
                     'RSS peak (MiB)', os.path.join(plot_dir, 'rss_peak_verify_mib.png'),
                     scale=1.0 / 1024.0)
        _plot_metric(mem_rows, 'rss_delta_peak_build_kib',
                     'Δ peak RSS (build − baseline) vs stream size',
                     'Δ RSS (MiB)', os.path.join(plot_dir, 'rss_delta_peak_build_mib.png'),
                     scale=1.0 / 1024.0)
        _plot_metric(mem_rows, 'tracemalloc_peak_build_kib',
                     'Python tracemalloc peak during proof creation',
                     'Tracemalloc peak (MiB)',
                     os.path.join(plot_dir, 'tracemalloc_peak_build_mib.png'),
                     scale=1.0 / 1024.0)
        _plot_payload_breakdown(mem_rows, plot_dir)
    else:
        print(f'No memory CSV at {memory_csv}; skipping memory plots.')

    print(f'\nAll plots -> {plot_dir}/')


if __name__ == '__main__':
    main()
