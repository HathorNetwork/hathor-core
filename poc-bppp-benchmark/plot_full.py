"""
Plot all 6 heatmaps from benchmark_full.py results.

Layout:
  Row 1: CREATION   — Pedersen | Surjection | Total
  Row 2: VERIFICATION — Pedersen | Surjection | Total
"""

import csv
import os
import sys

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LogNorm

RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results_full')

METRICS = [
    ('pedersen_create',   'Pedersen + Range Proof\nCREATION'),
    ('surjection_create', 'Asset Surjection\nCREATION'),
    ('total_create',      'Total (Pedersen + Surjection)\nCREATION'),
    ('pedersen_verify',   'Range Proof\nVERIFICATION'),
    ('surjection_verify', 'Asset Surjection\nVERIFICATION'),
    ('total_verify',      'Total (Range + Surjection)\nVERIFICATION'),
]


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


def plot_heatmap(ax, n_values, m_values, data, title, vmin_global, vmax_global):
    data_ms = data * 1000.0

    norm = LogNorm(vmin=max(vmin_global, 0.01), vmax=vmax_global)
    im = ax.imshow(data_ms, aspect='auto', origin='lower', norm=norm, cmap='YlOrRd')

    ax.set_xticks(range(len(m_values)))
    ax.set_xticklabels([str(m) for m in m_values], fontsize=8)
    ax.set_yticks(range(len(n_values)))
    ax.set_yticklabels([str(n) for n in n_values], fontsize=8)

    ax.set_xlabel('M (shielded outputs)', fontsize=9)
    ax.set_ylabel('N (shielded inputs)', fontsize=9)
    ax.set_title(title, fontsize=10, fontweight='bold')

    for i in range(len(n_values)):
        for j in range(len(m_values)):
            val = data_ms[i, j]
            if val >= 1000:
                text = f'{val / 1000:.1f}s'
            elif val >= 10:
                text = f'{val:.0f}'
            elif val >= 1:
                text = f'{val:.1f}'
            else:
                text = f'{val:.2f}'

            brightness = np.log(val / vmin_global) / np.log(vmax_global / vmin_global + 1e-9)
            color = 'white' if brightness > 0.55 else 'black'
            ax.text(j, i, text, ha='center', va='center', fontsize=6, color=color)

    return im


def main():
    # Load all 6 metrics
    all_data = {}
    for metric, _ in METRICS:
        path = os.path.join(RESULTS_DIR, f'{metric}.csv')
        if not os.path.exists(path):
            print(f"Error: {path} not found. Run benchmark_full.py first.")
            sys.exit(1)
        all_data[metric] = load_csv(path)

    # Global color scale across all 6 heatmaps
    all_ms = []
    for metric, _ in METRICS:
        _, _, data = all_data[metric]
        all_ms.extend((data * 1000.0).ravel().tolist())
    vmin_global = max(min(all_ms), 0.01)
    vmax_global = max(all_ms)

    # ---- 2×3 grid ----
    fig, axes = plt.subplots(2, 3, figsize=(22, 13))

    for idx, (metric, title) in enumerate(METRICS):
        row, col = divmod(idx, 3)
        n_vals, m_vals, data = all_data[metric]
        im = plot_heatmap(axes[row, col], n_vals, m_vals, data, title, vmin_global, vmax_global)

    # Single colorbar
    cbar = fig.colorbar(im, ax=axes.ravel().tolist(), shrink=0.6, pad=0.02)
    cbar.set_label('Time (ms)', fontsize=11)

    fig.suptitle(
        'Shielded Output Benchmark: N Inputs × M Outputs (all FullShielded)\n'
        'bppp value commitment + bppp range proof + Asset surjection proof  —  avg of 3 runs\n'
        'Cell values in ms (times for ALL M outputs in the transaction)',
        fontsize=13, fontweight='bold',
    )
    fig.subplots_adjust(left=0.05, right=0.88, top=0.88, bottom=0.06, wspace=0.25, hspace=0.35)
    out = os.path.join(RESULTS_DIR, 'all_heatmaps.png')
    fig.savefig(out, dpi=150, bbox_inches='tight')
    print(f"Saved: {out}")

    # ---- Individual PNGs ----
    for metric, title in METRICS:
        n_vals, m_vals, data = all_data[metric]
        data_ms = data * 1000.0
        local_vmin = max(data_ms.min(), 0.01)
        local_vmax = data_ms.max()

        fig_i, ax_i = plt.subplots(figsize=(10, 8))
        im_i = plot_heatmap(ax_i, n_vals, m_vals, data, title, local_vmin, local_vmax)
        cbar_i = plt.colorbar(im_i, ax=ax_i, shrink=0.8)
        cbar_i.set_label('Time (ms)', fontsize=10)
        fig_i.tight_layout()
        out_i = os.path.join(RESULTS_DIR, f'{metric}_heatmap.png')
        fig_i.savefig(out_i, dpi=150)
        print(f"Saved: {out_i}")

    plt.close('all')
    print("Done.")


if __name__ == '__main__':
    main()
