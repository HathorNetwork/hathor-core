"""
Run all three rust-time benchmarks and generate the same plots as the original
plot_results.py, plot_mixed.py, and plot_full.py — but from rust-time-only data.

All outputs go to results_rust_time_all/.
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

from benchmark import run_benchmark_rust_time as run_surjection
from benchmark import RUST_TIME_OUTPUT_DIR as SURJECTION_DIR
from benchmark_mixed import run_benchmark_rust_time as run_mixed
from benchmark_mixed import RUST_TIME_OUTPUT_DIR as MIXED_DIR
from benchmark_full import run_benchmark_rust_time as run_full
from benchmark_full import RUST_TIME_OUTPUT_DIR as FULL_DIR

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results_rust_time_all')
TOTAL_INPUTS_MIXED = 64


# ---------------------------------------------------------------------------
# CSV loading
# ---------------------------------------------------------------------------

def load_csv(path: str) -> tuple[list[int], list[int], np.ndarray]:
    with open(path) as f:
        reader = csv.reader(f)
        header = next(reader)
        col_values = [int(x) for x in header[1:]]
        row_values = []
        rows = []
        for row in reader:
            row_values.append(int(row[0]))
            rows.append([float(x) for x in row[1:]])
    return row_values, col_values, np.array(rows)


# ---------------------------------------------------------------------------
# Heatmap plotting
# ---------------------------------------------------------------------------

def plot_heatmap(
    ax, row_values, col_values, data, title,
    xlabel, ylabel,
    vmin=None, vmax=None,
    row_labels=None,
):
    data_ms = data * 1000.0

    if vmin is None:
        vmin = max(data_ms.min(), 0.01)
    if vmax is None:
        vmax = data_ms.max()

    norm = LogNorm(vmin=max(vmin, 0.01), vmax=vmax)
    im = ax.imshow(data_ms, aspect='auto', origin='lower', norm=norm, cmap='YlOrRd')

    ax.set_xticks(range(len(col_values)))
    ax.set_xticklabels([str(c) for c in col_values], fontsize=8)
    ax.set_yticks(range(len(row_values)))
    if row_labels:
        ax.set_yticklabels(row_labels, fontsize=8)
    else:
        ax.set_yticklabels([str(r) for r in row_values], fontsize=8)

    ax.set_xlabel(xlabel, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.set_title(title, fontsize=11, fontweight='bold')

    for i in range(len(row_values)):
        for j in range(len(col_values)):
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


# ---------------------------------------------------------------------------
# Plot generators (mirroring original scripts)
# ---------------------------------------------------------------------------

def plot_surjection(runs: int):
    """Reproduce plot_results.py style from rust-time data."""
    creation_csv = os.path.join(SURJECTION_DIR, 'creation_times.csv')
    verification_csv = os.path.join(SURJECTION_DIR, 'verification_times.csv')

    n_c, m_c, data_c = load_csv(creation_csv)
    n_v, m_v, data_v = load_csv(verification_csv)

    xl = 'M (shielded outputs)'
    yl = 'N (shielded inputs)'

    # Individual plots
    for label, n_vals, m_vals, data, fname in [
        ('Surjection Proof CREATION Time (Rust-only)', n_c, m_c, data_c, 'surjection_creation_heatmap.png'),
        ('Surjection Proof VERIFICATION Time (Rust-only)', n_v, m_v, data_v, 'surjection_verification_heatmap.png'),
    ]:
        fig, ax = plt.subplots(figsize=(10, 8))
        im = plot_heatmap(ax, n_vals, m_vals, data, label, xl, yl)
        plt.colorbar(im, ax=ax, shrink=0.8).set_label('Time (ms)')
        fig.tight_layout()
        fig.savefig(os.path.join(OUTPUT_DIR, fname), dpi=150)
        print(f"  Saved: {fname}")
        plt.close(fig)

    # Combined
    fig, (ax1, ax_cb, ax2) = plt.subplots(
        1, 3, figsize=(22, 8), gridspec_kw={'width_ratios': [1, 0.05, 1]},
    )
    all_ms = np.concatenate([data_c.ravel() * 1000, data_v.ravel() * 1000])
    vmin, vmax = max(all_ms.min(), 0.01), all_ms.max()

    plot_heatmap(ax1, n_c, m_c, data_c, 'Surjection CREATION', xl, yl, vmin, vmax)
    im = plot_heatmap(ax2, n_v, m_v, data_v, 'Surjection VERIFICATION', xl, yl, vmin, vmax)
    fig.colorbar(im, cax=ax_cb).set_label('Time (ms)')

    fig.suptitle(
        f'Surjection Proof Benchmark (Rust-only timing, avg of {runs} runs)',
        fontsize=13, fontweight='bold',
    )
    fig.subplots_adjust(top=0.88, wspace=0.3)
    fig.savefig(os.path.join(OUTPUT_DIR, 'surjection_combined.png'), dpi=150, bbox_inches='tight')
    print(f"  Saved: surjection_combined.png")
    plt.close(fig)


def plot_mixed(runs: int):
    """Reproduce plot_mixed.py style from rust-time data."""
    creation_csv = os.path.join(MIXED_DIR, 'creation_times.csv')
    verification_csv = os.path.join(MIXED_DIR, 'verification_times.csv')

    s_c, m_c, data_c = load_csv(creation_csv)
    s_v, m_v, data_v = load_csv(verification_csv)

    xl = 'M (shielded outputs)'
    yl = 'Shielded inputs s  (transparent u = 64 - s)'
    row_labels_c = [f's={s}  (u={TOTAL_INPUTS_MIXED - s})' for s in s_c]
    row_labels_v = [f's={s}  (u={TOTAL_INPUTS_MIXED - s})' for s in s_v]

    for label, s_vals, m_vals, data, rlabels, fname in [
        ('Surjection CREATION (mixed inputs, Rust-only)', s_c, m_c, data_c, row_labels_c,
         'mixed_creation_heatmap.png'),
        ('Surjection VERIFICATION (mixed inputs, Rust-only)', s_v, m_v, data_v, row_labels_v,
         'mixed_verification_heatmap.png'),
    ]:
        fig, ax = plt.subplots(figsize=(10, 8))
        im = plot_heatmap(ax, s_vals, m_vals, data, label, xl, yl, row_labels=rlabels)
        plt.colorbar(im, ax=ax, shrink=0.8).set_label('Time (ms)')
        fig.tight_layout()
        fig.savefig(os.path.join(OUTPUT_DIR, fname), dpi=150)
        print(f"  Saved: {fname}")
        plt.close(fig)

    # Combined
    fig, (ax1, ax_cb, ax2) = plt.subplots(
        1, 3, figsize=(22, 8), gridspec_kw={'width_ratios': [1, 0.05, 1]},
    )
    all_ms = np.concatenate([data_c.ravel() * 1000, data_v.ravel() * 1000])
    vmin, vmax = max(all_ms.min(), 0.01), all_ms.max()

    plot_heatmap(ax1, s_c, m_c, data_c, 'Surjection CREATION', xl, yl, vmin, vmax, row_labels_c)
    im = plot_heatmap(ax2, s_v, m_v, data_v, 'Surjection VERIFICATION', xl, yl, vmin, vmax, row_labels_v)
    fig.colorbar(im, cax=ax_cb).set_label('Time (ms)')

    fig.suptitle(
        f'Mixed Input Benchmark (Rust-only timing, avg of {runs} runs)\n'
        f'64 total inputs (u transparent + s shielded)',
        fontsize=13, fontweight='bold',
    )
    fig.subplots_adjust(top=0.85, wspace=0.3)
    fig.savefig(os.path.join(OUTPUT_DIR, 'mixed_combined.png'), dpi=150, bbox_inches='tight')
    print(f"  Saved: mixed_combined.png")
    plt.close(fig)


def plot_full(runs: int):
    """Reproduce plot_full.py style from rust-time data."""
    FULL_METRICS = [
        ('pedersen_create',   'Pedersen + Range Proof\nCREATION'),
        ('surjection_create', 'Asset Surjection\nCREATION'),
        ('total_create',      'Total\nCREATION'),
        ('pedersen_verify',   'Range Proof\nVERIFICATION'),
        ('surjection_verify', 'Asset Surjection\nVERIFICATION'),
        ('total_verify',      'Total\nVERIFICATION'),
    ]

    all_data = {}
    for metric, _ in FULL_METRICS:
        path = os.path.join(FULL_DIR, f'{metric}.csv')
        all_data[metric] = load_csv(path)

    # Global color scale
    all_ms_vals = []
    for metric, _ in FULL_METRICS:
        _, _, data = all_data[metric]
        all_ms_vals.extend((data * 1000.0).ravel().tolist())
    vmin_global = max(min(all_ms_vals), 0.01)
    vmax_global = max(all_ms_vals)

    xl = 'M (shielded outputs)'
    yl = 'N (shielded inputs)'

    # 2x3 grid
    fig, axes = plt.subplots(2, 3, figsize=(22, 13))

    for idx, (metric, title) in enumerate(FULL_METRICS):
        row, col = divmod(idx, 3)
        n_vals, m_vals, data = all_data[metric]
        im = plot_heatmap(
            axes[row, col], n_vals, m_vals, data,
            title, xl, yl, vmin_global, vmax_global,
        )

    cbar = fig.colorbar(im, ax=axes.ravel().tolist(), shrink=0.6, pad=0.02)
    cbar.set_label('Time (ms)', fontsize=11)

    fig.suptitle(
        f'Full Shielded Benchmark (Rust-only timing, avg of {runs} runs)\n'
        f'bppp value commitment + bppp range proof + Asset surjection proof\n'
        f'Cell values in ms (times for ALL M outputs)',
        fontsize=13, fontweight='bold',
    )
    fig.subplots_adjust(left=0.05, right=0.88, top=0.88, bottom=0.06, wspace=0.25, hspace=0.35)
    fig.savefig(os.path.join(OUTPUT_DIR, 'full_all_heatmaps.png'), dpi=150, bbox_inches='tight')
    print(f"  Saved: full_all_heatmaps.png")

    # Individual PNGs
    for metric, title in FULL_METRICS:
        n_vals, m_vals, data = all_data[metric]
        data_ms = data * 1000.0
        local_vmin = max(data_ms.min(), 0.01)
        local_vmax = data_ms.max()

        fig_i, ax_i = plt.subplots(figsize=(10, 8))
        im_i = plot_heatmap(
            ax_i, n_vals, m_vals, data,
            f'{title} (Rust-only)', xl, yl, local_vmin, local_vmax,
        )
        plt.colorbar(im_i, ax=ax_i, shrink=0.8).set_label('Time (ms)')
        fig_i.tight_layout()
        fig_i.savefig(os.path.join(OUTPUT_DIR, f'full_{metric}_heatmap.png'), dpi=150)
        print(f"  Saved: full_{metric}_heatmap.png")
        plt.close(fig_i)

    plt.close('all')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Run all rust-time benchmarks and generate plots')
    parser.add_argument('--max-n', type=int, default=64)
    parser.add_argument('--max-m', type=int, default=64)
    parser.add_argument('--runs', type=int, default=10)
    parser.add_argument('--plot-only', action='store_true',
                        help='Skip benchmarks, just plot from existing CSVs')
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if not args.plot_only:
        print("=" * 60)
        print("1/3  Surjection-only benchmark (Rust-time)")
        print("=" * 60)
        run_surjection(max_n=args.max_n, max_m=args.max_m, runs=args.runs)

        print()
        print("=" * 60)
        print("2/3  Mixed transparent/shielded benchmark (Rust-time)")
        print("=" * 60)
        run_mixed(runs=args.runs)

        print()
        print("=" * 60)
        print("3/3  Full benchmark — Pedersen + Surjection (Rust-time)")
        print("=" * 60)
        run_full(max_n=args.max_n, max_m=args.max_m, runs=args.runs)

    # Verify CSVs exist
    required = [
        os.path.join(SURJECTION_DIR, 'creation_times.csv'),
        os.path.join(SURJECTION_DIR, 'verification_times.csv'),
        os.path.join(MIXED_DIR, 'creation_times.csv'),
        os.path.join(MIXED_DIR, 'verification_times.csv'),
    ]
    for metric in ('pedersen_create', 'surjection_create', 'total_create',
                    'pedersen_verify', 'surjection_verify', 'total_verify'):
        required.append(os.path.join(FULL_DIR, f'{metric}.csv'))

    for path in required:
        if not os.path.exists(path):
            print(f"Error: {path} not found. Run without --plot-only first.")
            sys.exit(1)

    print()
    print("=" * 60)
    print("Plotting")
    print("=" * 60)

    print("Surjection-only plots:")
    plot_surjection(args.runs)

    print("Mixed input plots:")
    plot_mixed(args.runs)

    print("Full benchmark plots:")
    plot_full(args.runs)

    print(f"\nDone. All plots saved to {OUTPUT_DIR}/")


if __name__ == '__main__':
    main()
