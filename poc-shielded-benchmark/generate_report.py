"""Generate a PDF report summarizing the shielded-outputs benchmark results.

All figures are rendered inline through matplotlib's PdfPages backend, which
produces true vector pages (no rasterization). Heatmaps live on their own
landscape-oriented page so the (N, M) grid uses the long edge of the paper.
"""
import csv
import os

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.colors import LogNorm

HERE = os.path.dirname(os.path.abspath(__file__))
PDF_PATH = os.path.join(HERE, 'shielded_outputs_report.pdf')

PORTRAIT = (8.5, 11)
LANDSCAPE = (11, 8.5)


def load_csv(path):
    with open(path) as f:
        reader = csv.reader(f)
        header = next(reader)
        col_values = [int(x) for x in header[1:]]
        row_values, rows = [], []
        for row in reader:
            row_values.append(int(row[0]))
            rows.append([float(x) for x in row[1:]])
    return row_values, col_values, np.array(rows)


def wrap(text, width):
    out, cur = [], ''
    for w in text.split():
        if len(cur) + len(w) + 1 > width:
            out.append(cur)
            cur = w
        else:
            cur = (cur + ' ' + w).strip()
    if cur:
        out.append(cur)
    return out or ['']


def text_page(pdf, title, paragraphs, level=1):
    fig = plt.figure(figsize=PORTRAIT)
    size = {1: 18, 2: 14, 3: 12}.get(level, 12)
    fig.text(0.07, 0.95, title, fontsize=size, weight='bold')
    y = 0.90
    for para in paragraphs:
        for line in wrap(para, 95):
            fig.text(0.07, y, line, fontsize=10, family='serif')
            y -= 0.022
        y -= 0.012
    pdf.savefig(fig)
    plt.close(fig)


def heatmap_page(pdf, title, subtitle, csv_path, row_label, col_label, row_fmt=str):
    """Render a single heatmap on its own landscape page."""
    rows, cols, data = load_csv(csv_path)
    data_ms = data * 1000.0

    fig = plt.figure(figsize=LANDSCAPE)
    fig.suptitle(title, fontsize=14, fontweight='bold', y=0.97)
    if subtitle:
        fig.text(0.5, 0.925, subtitle, ha='center', fontsize=10, style='italic')

    ax = fig.add_axes([0.10, 0.08, 0.78, 0.80])
    norm = LogNorm(vmin=max(data_ms.min(), 0.01), vmax=data_ms.max())
    im = ax.imshow(data_ms, aspect='auto', origin='lower', norm=norm, cmap='YlOrRd')

    ax.set_xticks(range(len(cols)))
    ax.set_xticklabels([str(c) for c in cols], fontsize=10)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([row_fmt(r) for r in rows], fontsize=10)
    ax.set_xlabel(col_label, fontsize=11)
    ax.set_ylabel(row_label, fontsize=11)

    vmin, vmax = data_ms.min(), data_ms.max()
    for i in range(len(rows)):
        for j in range(len(cols)):
            v = data_ms[i, j]
            if v >= 1000:
                t = f'{v / 1000:.2f}s'
            elif v >= 10:
                t = f'{v:.1f}'
            elif v >= 1:
                t = f'{v:.2f}'
            else:
                t = f'{v:.3f}'
            brightness = (np.log(v) - np.log(vmin)) / (np.log(vmax) - np.log(vmin) + 1e-9)
            color = 'white' if brightness > 0.55 else 'black'
            ax.text(j, i, t, ha='center', va='center', fontsize=8, color=color)

    cax = fig.add_axes([0.90, 0.10, 0.02, 0.76])
    cbar = fig.colorbar(im, cax=cax)
    cbar.set_label('Time (ms)', fontsize=10)

    pdf.savefig(fig)
    plt.close(fig)


def stats(csv_path):
    """(min_ms, max_ms, mean_ms, ratio_max_min, per_output_at_max_ms)."""
    rows, cols, data = load_csv(csv_path)
    data_ms = data * 1000.0
    flat = data_ms.ravel()
    return {
        'min': flat.min(),
        'max': flat.max(),
        'mean': flat.mean(),
        'ratio': flat.max() / max(flat.min(), 1e-9),
        'rows': rows,
        'cols': cols,
        'matrix': data_ms,
    }


def fmt_ms(v):
    if v >= 100:
        return f'{v:.1f} ms'
    if v >= 10:
        return f'{v:.2f} ms'
    if v >= 1:
        return f'{v:.2f} ms'
    return f'{v * 1000:.1f} us'


def section_for(pdf, section_no, title, csv_path, narrative_paras,
                row_label='N (shielded inputs)',
                col_label='M (shielded outputs)',
                row_fmt=str,
                heatmap_title=None,
                heatmap_subtitle=None):
    """Emit a subsection: text page (stats + narrative) followed by a landscape heatmap."""
    s = stats(csv_path)
    last_row = s['matrix'][-1]
    first_row = s['matrix'][0]
    summary = (
        f'Range: {fmt_ms(s["min"])} (smallest cell) to {fmt_ms(s["max"])} (largest cell), '
        f'a {s["ratio"]:.0f}x spread. Mean across the grid: {fmt_ms(s["mean"])}. '
        f'At the smallest input set the per-output cost grows from {fmt_ms(first_row[0])} '
        f'(M=1) to {fmt_ms(first_row[-1])} (M={s["cols"][-1]}); at the largest input set, '
        f'from {fmt_ms(last_row[0])} to {fmt_ms(last_row[-1])}.'
    )
    text_page(pdf, f'{section_no} {title}', [summary] + narrative_paras, level=2)
    heatmap_page(
        pdf,
        heatmap_title or title,
        heatmap_subtitle or 'Cell values in milliseconds. Color scale is logarithmic.',
        csv_path, row_label, col_label, row_fmt,
    )


def main():
    with PdfPages(PDF_PATH) as pdf:
        # ---- Cover ----
        fig = plt.figure(figsize=PORTRAIT)
        fig.text(0.5, 0.70, 'Shielded Outputs', ha='center', fontsize=28, weight='bold')
        fig.text(0.5, 0.64, 'Cryptography Benchmark Report', ha='center', fontsize=20)
        fig.text(0.5, 0.55, 'Hathor Network — Issue #1603 PoC', ha='center', fontsize=14, style='italic')
        fig.text(0.5, 0.40, 'Pedersen commitments, Bulletproof range proofs,',
                 ha='center', fontsize=11)
        fig.text(0.5, 0.375, 'and asset surjection proofs.', ha='center', fontsize=11)
        fig.text(0.5, 0.08, '2026-04-13', ha='center', fontsize=10)
        pdf.savefig(fig)
        plt.close(fig)

        # ---- 1. Overview ----
        text_page(pdf, '1. Overview', [
            'This report summarizes the performance of the shielded-outputs cryptography '
            'being prototyped for the Hathor Network (issue #1603). It quantifies the cost '
            'of constructing and verifying the cryptographic objects required by a fully '
            'shielded transaction: blinded Pedersen commitments, Bulletproof range proofs, '
            'and asset surjection proofs.',

            'Three benchmark sweeps were run: (a) surjection proofs in isolation across an '
            'NxM grid of shielded inputs and outputs, (b) the full per-output workload '
            '(commitment + range proof + surjection) over the same grid, and (c) a mixed '
            'configuration with a fixed total of 64 inputs split between shielded and '
            'transparent.',

            'Hardware: Intel Core i5-11300H (11th gen Tiger Lake, 4 cores / 8 threads, '
            '3.1 GHz base / ~4.4 GHz boost), 11 GiB RAM, single-threaded execution under '
            'WSL2 (Linux 6.6) on Windows. Cryptography is implemented in Rust and called '
            'from Python via PyO3 bindings (hathor-core / hathor-ct-crypto). Each grid cell '
            'is the average of 3 runs.',

            'Memory consumption was not measured by the benchmark scripts (only wall-clock '
            'time), so the report does not report memory figures. Adding tracemalloc and '
            'getrusage hooks would be a small follow-up.',
        ])

        # ---- 2. Methodology ----
        text_page(pdf, '2. Methodology', [
            'Inputs and outputs are simulated using deterministic 32-byte token UIDs derived '
            'from an integer index. For each input, a raw asset tag is derived, a blinded '
            'generator A = H_token + r_asset * G is constructed via create_asset_commitment, '
            'and a Pedersen commitment over that generator hides the amount.',

            'Outputs reuse a token UID present in the input set so the surjection proof has '
            'a valid pre-image. Surjection construction is probabilistic (random subset '
            'sampling) and may fail; failed attempts are retried up to 5 times.',

            'Times are measured with time.perf_counter() around the full Python loop. A '
            'separate "Rust-only" pass times just the FFI call (excluding Python loop '
            'overhead). The difference is small in this regime, so the report focuses on '
            'the full-loop numbers.',

            'Grid points are taken from the powers of two intersected with [1, max], plus '
            'the boundary value. For the surjection-only and full benchmarks the grid is '
            '7x7 with N, M in {1, 2, 4, 8, 16, 32, 64}. The mixed benchmark sweeps the '
            'shielded input count s in {0, 1, 2, 4, 8, 16, 32, 64} with the remainder '
            '(64 - s) being transparent.',
        ])

        # ---- 3. Surjection proofs (isolated) ----
        text_page(pdf, '3. Surjection Proofs (Isolated)', [
            'This section measures the asset surjection proof in isolation: one proof per '
            'output, with the proof tying that output back to a domain of N input asset '
            'commitments. The Pedersen commitment and range proof are not included here.',
        ], level=2)

        section_for(pdf, '3.1', 'Surjection: Creation Time',
                    os.path.join(HERE, 'results/creation_times.csv'),
                    [
                        'Creation time scales close to linearly in M — each output gets its own '
                        'proof, and per-output cost grows mildly with N because the proof has '
                        'to position the codomain inside a larger domain.',

                        'The N dependence is sublinear: the Borromean ring signature inside the '
                        'proof samples a small subset of the domain, so doubling N raises per-output '
                        'cost by less than 2x. The largest cell (N=64, M=64) builds 64 proofs in '
                        'roughly 32 ms, giving ~0.5 ms per proof at the densest point in the grid.',
                    ])

        section_for(pdf, '3.2', 'Surjection: Verification Time',
                    os.path.join(HERE, 'results/verification_times.csv'),
                    [
                        'Verification follows the same shape as creation but is consistently '
                        'cheaper — typically 1.5x to 2x faster cell for cell. This is the '
                        'expected asymmetry: the prover does the full Borromean ring construction '
                        'while the verifier mostly performs scalar checks against the published '
                        'proof.',

                        'For Hathor the verification side is what matters at network scale: every '
                        'node verifies every transaction. At N=M=64 the full surjection batch '
                        'verifies in ~27 ms.',
                    ])

        # ---- 4. Full per-output workload ----
        text_page(pdf, '4. Full Per-Output Workload', [
            'This section measures the three primitives that a real shielded output requires, '
            'in three pairs (creation, then verification): Pedersen + Bulletproof range proof, '
            'asset surjection, and the total. The range proof is fixed-cost per output (it '
            'does not depend on N), so it dominates at small input sets and gradually loses '
            'relative weight as N grows.',
        ], level=2)

        section_for(pdf, '4.1', 'Pedersen + Range Proof: Creation Time',
                    os.path.join(HERE, 'results_full/pedersen_create.csv'),
                    [
                        'Creation cost is essentially flat in N (the Pedersen commitment and '
                        'range proof do not consult the input set) and grows linearly in M. '
                        'Each per-output Pedersen + Bulletproof costs roughly 1.2 ms to construct '
                        'on this hardware, dominating per-output total cost up to N ~ 16.',
                    ])

        section_for(pdf, '4.2', 'Range Proof: Verification Time',
                    os.path.join(HERE, 'results_full/pedersen_verify.csv'),
                    [
                        'Verification is also flat in N and linear in M. Per-output verify is '
                        'around 0.8 ms — roughly 30% cheaper than creation, again the standard '
                        'prover/verifier asymmetry for Bulletproofs.',
                    ])

        section_for(pdf, '4.3', 'Surjection: Creation Time (Full Workload Run)',
                    os.path.join(HERE, 'results_full/surjection_create.csv'),
                    [
                        'Same primitive as section 3.1, re-measured during the full-workload '
                        'run for consistency. Numbers track section 3.1 closely; minor variation '
                        'comes from the probabilistic retry behavior and run-to-run jitter.',
                    ])

        section_for(pdf, '4.4', 'Surjection: Verification Time (Full Workload Run)',
                    os.path.join(HERE, 'results_full/surjection_verify.csv'),
                    [
                        'Companion to 4.3; same observations as section 3.2. Verification stays '
                        'cheaper than creation across the whole grid.',
                    ])

        section_for(pdf, '4.5', 'Total Per-Output Workload: Creation Time',
                    os.path.join(HERE, 'results_full/total_create.csv'),
                    [
                        'Sum of Pedersen + range proof + surjection. At small N the range proof '
                        'is the dominant cost; at N=64 the surjection overtakes it. The largest '
                        'cell (N=M=64) constructs all three primitives for 64 outputs in roughly '
                        '110 ms total.',
                    ])

        section_for(pdf, '4.6', 'Total Per-Output Workload: Verification Time',
                    os.path.join(HERE, 'results_full/total_verify.csv'),
                    [
                        'Sum of all three verifications. Comfortably under 100 ms even at the '
                        'top of the grid (~83 ms at N=M=64). This is the figure most relevant '
                        'to network throughput, since every node will verify it.',
                    ])

        # ---- 5. Mixed split ----
        text_page(pdf, '5. Mixed Shielded / Transparent Inputs', [
            'A practical Hathor transaction is unlikely to be 100% shielded. This section '
            'fixes the total input count at 64 and sweeps the shielded share s in '
            '{0, 1, 2, 4, 8, 16, 32, 64}, with the remaining 64 - s inputs being transparent. '
            'Transparent inputs participate in the surjection domain via an unblinded '
            'generator (ZERO_TWEAK), so the total domain size stays at 64 regardless of the '
            'split.',
        ], level=2)

        section_for(pdf, '5.1', 'Mixed: Creation Time',
                    os.path.join(HERE, 'results_mixed/creation_times.csv'),
                    [
                        'Creation time is essentially flat across the shielded/transparent split '
                        'for any given M. This confirms the design intent: surjection proof cost '
                        'depends on the total domain size, not on how many domain members are '
                        'blinded. A transaction author can mix shielded and transparent inputs '
                        'freely without paying a per-share penalty.',

                        'The s=0 row (all transparent) is slightly slower for small M, likely '
                        'because the codomain is still being constructed for shielded outputs '
                        'while the domain is fully unblinded. The variation is within noise.',
                    ],
                    row_label='Shielded inputs s  (transparent u = 64 - s)',
                    row_fmt=lambda s: f's={s} (u={64 - s})')

        section_for(pdf, '5.2', 'Mixed: Verification Time',
                    os.path.join(HERE, 'results_mixed/verification_times.csv'),
                    [
                        'Same shape as 5.1: verification is flat in s and linear in M. Holding '
                        'total input count fixed isolates the surjection cost from the '
                        'shielded-share dimension, and the data confirms that the cost truly '
                        'is independent of that share.',
                    ],
                    row_label='Shielded inputs s  (transparent u = 64 - s)',
                    row_fmt=lambda s: f's={s} (u={64 - s})')

        # ---- 6. Conclusions ----
        text_page(pdf, '6. Conclusions', [
            'The shielded-outputs prototype is performant enough for the regimes tested. At '
            'the largest grid point (64 inputs, 64 outputs) the full creation completes in '
            '~110 ms and full verification in ~83 ms on the test machine.',

            'Verification is consistently 30-50% cheaper than creation, a healthy asymmetry '
            'for a network where each transaction is verified by many nodes.',

            'Per-output cost is dominated by the Bulletproof range proof for small input sets '
            'and shifts toward the surjection proof as N grows past ~16. The ZERO_TWEAK trick '
            'for transparent inputs in the surjection domain has negligible cost overhead, '
            'making mixed shielded/transparent transactions cheap relative to fully-shielded '
            'transactions of the same total size.',

            'Memory was not measured. Adding tracemalloc + getrusage instrumentation would '
            'close that gap; expected per-output footprint is small (a few KB of proof bytes '
            'plus transient scratch space inside the Rust library).',
        ])

    print(f'Wrote {PDF_PATH}')


if __name__ == '__main__':
    main()
