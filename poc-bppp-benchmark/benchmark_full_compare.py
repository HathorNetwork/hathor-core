"""
Compare Python-loop vs Rust-time-only for the full benchmark (Pedersen + Surjection).

Runs both `run_benchmark` and `run_benchmark_rust_time` from benchmark_full.py,
then plots side-by-side heatmaps for three groups:
  1. Pedersen (creation + verification)
  2. Surjection (creation + verification)
  3. Total (creation + verification)

Outputs to results_full_compare/.
"""

import csv
import os
import sys

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LogNorm

# -- Make hathor-core importable --
HATHOR_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'hathor-core'))
if HATHOR_CORE not in sys.path:
    sys.path.insert(0, HATHOR_CORE)

from benchmark_full import (
    OUTPUT_DIR,
    RUST_TIME_OUTPUT_DIR,
    run_benchmark,
    run_benchmark_rust_time,
)

COMPARE_DIR = os.path.join(os.path.dirname(__file__), 'results_full_compare')


def load_csv(path: str) -> tuple[list[int], list[int], np.ndarray]:
    with open(path) as f:
        reader = csv.reader(f)
        header = next(reader)
        m_values = [int(x) for x in header[1:]]
        n_values = []
        rows = []
        for row in reader:
            n_values.append(int(row[0]))
            rows.append([float(x) for x in row[1:]])
    return n_values, m_values, np.array(rows)


def plot_heatmap(ax, n_values, m_values, data, title, vmin, vmax):
    data_ms = data * 1000.0
    norm = LogNorm(vmin=max(vmin, 0.01), vmax=vmax)
    im = ax.imshow(data_ms, aspect='auto', origin='lower', norm=norm, cmap='YlOrRd')

    ax.set_xticks(range(len(m_values)))
    ax.set_xticklabels([str(m) for m in m_values], fontsize=8)
    ax.set_yticks(range(len(n_values)))
    ax.set_yticklabels([str(n) for n in n_values], fontsize=8)

    ax.set_xlabel('M (shielded outputs)', fontsize=10)
    ax.set_ylabel('N (shielded inputs)', fontsize=10)
    ax.set_title(title, fontsize=10, fontweight='bold')

    for i in range(len(n_values)):
        for j in range(len(m_values)):
            val = data_ms[i, j]
            if val >= 1000:
                text = f'{val / 1000:.1f}s'
            elif val >= 1:
                text = f'{val:.1f}'
            else:
                text = f'{val:.2f}'

            log_brightness = np.log(val / vmin) / (np.log(vmax / vmin) + 1e-9)
            color = 'white' if log_brightness > 0.55 else 'black'
            ax.text(j, i, text, ha='center', va='center', fontsize=7, color=color)

    return im


def plot_comparison_pair(
    fig, ax_left, ax_cbar, ax_right,
    loop_csv: str, rust_csv: str, metric_label: str,
):
    """Plot one row: loop timing (left), colorbar (center), rust timing (right)."""
    n_loop, m_loop, data_loop = load_csv(loop_csv)
    n_rust, m_rust, data_rust = load_csv(rust_csv)

    all_ms = np.concatenate([data_loop.ravel() * 1000, data_rust.ravel() * 1000])
    vmin = max(all_ms.min(), 0.01)
    vmax = all_ms.max()

    im_left = plot_heatmap(
        ax_left, n_loop, m_loop, data_loop,
        f'{metric_label}\n(Python for-loop)', vmin, vmax,
    )
    im_right = plot_heatmap(
        ax_right, n_rust, m_rust, data_rust,
        f'{metric_label}\n(Rust FFI only)', vmin, vmax,
    )

    cbar = fig.colorbar(im_left, cax=ax_cbar)
    cbar.set_label('ms', fontsize=9)

    return im_left, im_right


# Metric groups: (file_prefix_create, file_prefix_verify, display_name)
GROUPS = [
    ('pedersen',   'Pedersen + Range Proof'),
    ('surjection', 'Asset Surjection'),
    ('total',      'Total (Pedersen + Surjection)'),
]


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Compare Python-loop vs Rust-time for full benchmark')
    parser.add_argument('--max-n', type=int, default=64)
    parser.add_argument('--max-m', type=int, default=64)
    parser.add_argument('--runs', type=int, default=10)
    parser.add_argument('--plot-only', action='store_true',
                        help='Skip benchmarks, just plot from existing CSVs')
    args = parser.parse_args()

    os.makedirs(COMPARE_DIR, exist_ok=True)

    if not args.plot_only:
        print("=" * 60)
        print("Phase 1: run_benchmark (Python for-loop timing)")
        print("=" * 60)
        run_benchmark(max_n=args.max_n, max_m=args.max_m, runs=args.runs)

        print()
        print("=" * 60)
        print("Phase 2: run_benchmark_rust_time (Rust FFI call timing)")
        print("=" * 60)
        run_benchmark_rust_time(max_n=args.max_n, max_m=args.max_m, runs=args.runs)

    # Verify all CSVs exist
    for prefix, _ in GROUPS:
        for phase in ('create', 'verify'):
            for d in (OUTPUT_DIR, RUST_TIME_OUTPUT_DIR):
                path = os.path.join(d, f'{prefix}_{phase}.csv')
                if not os.path.exists(path):
                    print(f"Error: {path} not found. Run without --plot-only first.")
                    sys.exit(1)

    print()
    print("=" * 60)
    print("Plotting comparisons")
    print("=" * 60)

    for prefix, label in GROUPS:
        for phase, phase_label in [('create', 'Creation'), ('verify', 'Verification')]:
            loop_csv = os.path.join(OUTPUT_DIR, f'{prefix}_{phase}.csv')
            rust_csv = os.path.join(RUST_TIME_OUTPUT_DIR, f'{prefix}_{phase}.csv')

            fig, (ax_left, ax_cbar, ax_right) = plt.subplots(
                1, 3, figsize=(22, 8),
                gridspec_kw={'width_ratios': [1, 0.05, 1]},
            )

            plot_comparison_pair(
                fig, ax_left, ax_cbar, ax_right,
                loop_csv, rust_csv,
                f'{label} {phase_label}',
            )

            fig.suptitle(
                f'{label} {phase_label}: Python Loop vs Rust-Only Timing\n'
                f'(avg of {args.runs} runs, shared color scale)',
                fontsize=13, fontweight='bold',
            )
            fig.subplots_adjust(top=0.85, wspace=0.3)

            out_png = os.path.join(COMPARE_DIR, f'{prefix}_{phase}_compare.png')
            fig.savefig(out_png, dpi=150, bbox_inches='tight')
            print(f"Saved: {out_png}")
            plt.close(fig)

    print("Done.")


if __name__ == '__main__':
    main()
