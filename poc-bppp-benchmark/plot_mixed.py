"""
Plot benchmark results for mixed transparent/shielded inputs.

Reads CSVs from results_mixed/ and generates heatmaps where:
  - Y-axis: s (number of shielded inputs out of 64 total)
  - X-axis: M (number of shielded outputs)
  - Cell labels show both the time and the transparent count (u = 64 - s)
"""

import csv
import os
import sys

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LogNorm

RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results_mixed')
TOTAL_INPUTS = 64


def load_csv(path: str) -> tuple[list[int], list[int], np.ndarray]:
    with open(path) as f:
        reader = csv.reader(f)
        header = next(reader)
        m_values = [int(x) for x in header[1:]]

        s_values = []
        rows = []
        for row in reader:
            s_values.append(int(row[0]))
            rows.append([float(x) for x in row[1:]])

    return s_values, m_values, np.array(rows)


def plot_heatmap(
    ax,
    s_values: list[int],
    m_values: list[int],
    data: np.ndarray,
    title: str,
    use_log: bool = True,
):
    data_ms = data * 1000.0

    if use_log and data_ms.min() > 0:
        norm = LogNorm(vmin=max(data_ms.min(), 0.01), vmax=data_ms.max())
    else:
        norm = None

    im = ax.imshow(data_ms, aspect='auto', origin='lower', norm=norm, cmap='YlOrRd')

    ax.set_xticks(range(len(m_values)))
    ax.set_xticklabels([str(m) for m in m_values], fontsize=9)
    ax.set_yticks(range(len(s_values)))
    # Y-axis labels: "s=X (u=Y)"
    ax.set_yticklabels(
        [f's={s}  (u={TOTAL_INPUTS - s})' for s in s_values],
        fontsize=8,
    )

    ax.set_xlabel('M (shielded outputs)', fontsize=10)
    ax.set_ylabel('Shielded inputs s  (transparent u = 64 - s)', fontsize=10)
    ax.set_title(title, fontsize=12, fontweight='bold')

    for i in range(len(s_values)):
        for j in range(len(m_values)):
            val = data_ms[i, j]
            if val >= 1000:
                text = f'{val / 1000:.1f}s'
            elif val >= 1:
                text = f'{val:.1f}'
            else:
                text = f'{val:.2f}'

            brightness = (val - data_ms.min()) / (data_ms.max() - data_ms.min() + 1e-9)
            color = 'white' if brightness > 0.6 else 'black'
            ax.text(j, i, text, ha='center', va='center', fontsize=7, color=color)

    cbar = plt.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label('Time (ms)', fontsize=9)


def main():
    creation_csv = os.path.join(RESULTS_DIR, 'creation_times.csv')
    verification_csv = os.path.join(RESULTS_DIR, 'verification_times.csv')

    if not os.path.exists(creation_csv) or not os.path.exists(verification_csv):
        print(f"Error: CSV files not found in {RESULTS_DIR}/")
        print("Run benchmark_mixed.py first.")
        sys.exit(1)

    s_c, m_c, data_c = load_csv(creation_csv)
    s_v, m_v, data_v = load_csv(verification_csv)

    # --- Individual plots ---
    fig1, ax1 = plt.subplots(figsize=(10, 8))
    plot_heatmap(ax1, s_c, m_c, data_c,
                 'Surjection Proof CREATION Time\n(64 total inputs, varying shielded ratio)')
    fig1.tight_layout()
    fig1.savefig(os.path.join(RESULTS_DIR, 'creation_heatmap.png'), dpi=150)
    print(f"Saved: {RESULTS_DIR}/creation_heatmap.png")

    fig2, ax2 = plt.subplots(figsize=(10, 8))
    plot_heatmap(ax2, s_v, m_v, data_v,
                 'Surjection Proof VERIFICATION Time\n(64 total inputs, varying shielded ratio)')
    fig2.tight_layout()
    fig2.savefig(os.path.join(RESULTS_DIR, 'verification_heatmap.png'), dpi=150)
    print(f"Saved: {RESULTS_DIR}/verification_heatmap.png")

    # --- Combined side-by-side ---
    fig3, (ax3a, ax3b) = plt.subplots(1, 2, figsize=(20, 8))
    plot_heatmap(ax3a, s_c, m_c, data_c, 'Surjection Proof CREATION')
    plot_heatmap(ax3b, s_v, m_v, data_v, 'Surjection Proof VERIFICATION')
    fig3.suptitle(
        'Mixed Input Benchmark: 64 Total Inputs (u transparent + s shielded) × M Shielded Outputs\n'
        '(FullShielded outputs: Pedersen + surjection proof per output, avg of 3 runs)',
        fontsize=13, fontweight='bold', y=1.02,
    )
    fig3.tight_layout()
    fig3.savefig(os.path.join(RESULTS_DIR, 'combined_heatmaps.png'), dpi=150, bbox_inches='tight')
    print(f"Saved: {RESULTS_DIR}/combined_heatmaps.png")

    plt.close('all')
    print("Done.")


if __name__ == '__main__':
    main()
