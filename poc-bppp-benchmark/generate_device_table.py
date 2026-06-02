"""Generate a styled PDF with estimated shielded-output crypto times across devices.

Times are extrapolated from the i5-11300H baseline (results_full/total_create.csv
and total_verify.csv) using Geekbench 6 single-core score ratios.
"""
import csv
import os

import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.patches import Rectangle

HERE = os.path.dirname(os.path.abspath(__file__))
PDF_PATH = os.path.join(HERE, 'shielded_outputs_device_estimates.pdf')

LANDSCAPE = (16, 10)

# Device, category, SoC, GB6 single-core score (~), color group
DEVICES = [
    ('Intel Core i5-11300H (reference)', 'Reference (this PoC)', '11th-gen Tiger Lake', 1900, 'ref'),
    ('iPhone 16 Pro Max',                'Most powerful',         'Apple A18 Pro',         3400, 'flagship'),
    ('Samsung Galaxy S25 Ultra',         'Most powerful',         'Snapdragon 8 Elite',    3000, 'flagship'),
    ('OnePlus 13',                       'Most powerful',         'Snapdragon 8 Elite',    3000, 'flagship'),
    ('iPhone 15',                        'USA top-3',             'Apple A16 Bionic',      2500, 'america'),
    ('iPhone 14',                        'USA + Europe top-3',    'Apple A15 Bionic',      2300, 'america'),
    ('Samsung Galaxy S23',               'USA top-3',             'Snapdragon 8 Gen 2',    2000, 'america'),
    ('Samsung Galaxy A54',               'Europe + ROW top-3',    'Exynos 1380',           1050, 'europe'),
    ('Xiaomi Redmi Note 12',             'Europe + ROW top-3',    'Snapdragon 685',         920, 'europe'),
    ('Samsung Galaxy A14',               'Rest of World top-3',   'MediaTek Helio G80',     480, 'row'),
    ('Tecno Spark 10',                   'Rest of World top-3',   'MediaTek Helio G88',     500, 'row'),
    ('iPhone 6 (2014)',                  '2014 era',              'Apple A8',               350, 'old'),
    ('Samsung Galaxy S5 (2014)',         '2014 era',              'Snapdragon 801',         280, 'old'),
    ('LG G3 (2014)',                     '2014 era',              'Snapdragon 801',         280, 'old'),
]

CATEGORY_COLORS = {
    'ref':      '#2c3e50',
    'flagship': '#27ae60',
    'america':  '#2980b9',
    'europe':   '#8e44ad',
    'row':      '#d35400',
    'old':      '#7f8c8d',
}

REF_SCORE = 1900
GRID_POINTS = [(1, 1), (2, 2), (4, 4), (8, 8), (16, 16), (32, 32), (64, 64)]


def load_diagonal(csv_path):
    with open(csv_path) as f:
        reader = csv.reader(f)
        header = next(reader)
        m_values = [int(x) for x in header[1:]]
        rows = {}
        for row in reader:
            n = int(row[0])
            rows[n] = [float(x) for x in row[1:]]
    return {n: rows[n][m_values.index(m)] * 1000.0 for (n, m) in GRID_POINTS}


def fmt_cell(val_ms):
    if val_ms >= 1000:
        return f'{val_ms / 1000:.2f} s'
    if val_ms >= 100:
        return f'{val_ms:.0f} ms'
    if val_ms >= 10:
        return f'{val_ms:.1f} ms'
    if val_ms >= 1:
        return f'{val_ms:.2f} ms'
    return f'{val_ms * 1000:.0f} \u00b5s'


def cell_color(val_ms):
    """Heat-color cells from green (fast) to red (slow)."""
    if val_ms < 5:
        return '#d4edda'
    if val_ms < 25:
        return '#fff3cd'
    if val_ms < 100:
        return '#ffe5b4'
    if val_ms < 300:
        return '#f8d7da'
    return '#f5b7b1'


def draw_table(ax, baseline, title, subtitle):
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    n_rows = len(DEVICES) + 1
    n_cols = 3 + len(GRID_POINTS)
    col_widths = [28, 18, 6] + [6.86] * len(GRID_POINTS)
    x_positions = [0]
    for w in col_widths[:-1]:
        x_positions.append(x_positions[-1] + w)

    row_height = 90 / n_rows
    y_top = 92

    headers = ['Device', 'Category', 'SoC \u00d7', 'i5\u00d7'] + ['' for _ in GRID_POINTS]
    headers = ['Device', 'Category', '\u00d7'] + [f'(N={n}, M={m})' for n, m in GRID_POINTS]

    # Header row
    for j, h in enumerate(headers):
        ax.add_patch(Rectangle(
            (x_positions[j], y_top - row_height), col_widths[j], row_height,
            facecolor='#34495e', edgecolor='white', linewidth=1.2,
        ))
        ax.text(
            x_positions[j] + col_widths[j] / 2, y_top - row_height / 2, h,
            ha='center', va='center', color='white', fontsize=9, fontweight='bold',
        )

    for i, (name, category, soc, score, group) in enumerate(DEVICES):
        y = y_top - row_height * (i + 2)
        mult = REF_SCORE / score
        color = CATEGORY_COLORS[group]

        # Device name cell (colored side stripe + bg)
        ax.add_patch(Rectangle(
            (x_positions[0], y), col_widths[0], row_height,
            facecolor='#ecf0f1' if group != 'ref' else '#2c3e50',
            edgecolor='white', linewidth=0.8,
        ))
        ax.add_patch(Rectangle(
            (x_positions[0], y), 0.6, row_height, facecolor=color, edgecolor='none',
        ))
        text_color = 'white' if group == 'ref' else '#2c3e50'
        ax.text(
            x_positions[0] + 1.5, y + row_height / 2, name,
            ha='left', va='center', fontsize=8.5, fontweight='bold', color=text_color,
        )

        # Category
        ax.add_patch(Rectangle(
            (x_positions[1], y), col_widths[1], row_height,
            facecolor='#f4f6f7' if group != 'ref' else '#34495e',
            edgecolor='white', linewidth=0.8,
        ))
        ax.text(
            x_positions[1] + col_widths[1] / 2, y + row_height / 2, category,
            ha='center', va='center', fontsize=7.5,
            color='white' if group == 'ref' else '#555555',
            style='italic',
        )

        # Multiplier
        ax.add_patch(Rectangle(
            (x_positions[2], y), col_widths[2], row_height,
            facecolor='#fdfefe' if group != 'ref' else '#34495e',
            edgecolor='white', linewidth=0.8,
        ))
        ax.text(
            x_positions[2] + col_widths[2] / 2, y + row_height / 2, f'{mult:.2f}\u00d7',
            ha='center', va='center', fontsize=8,
            color='white' if group == 'ref' else '#2c3e50',
            fontweight='bold',
        )

        # Time cells
        for k, (n, m) in enumerate(GRID_POINTS):
            val = baseline[n] * mult
            facecolor = '#34495e' if group == 'ref' else cell_color(val)
            text_color = 'white' if group == 'ref' else '#2c3e50'
            ax.add_patch(Rectangle(
                (x_positions[3 + k], y), col_widths[3 + k], row_height,
                facecolor=facecolor, edgecolor='white', linewidth=0.8,
            ))
            ax.text(
                x_positions[3 + k] + col_widths[3 + k] / 2, y + row_height / 2,
                fmt_cell(val), ha='center', va='center', fontsize=8,
                color=text_color, fontweight='bold' if group == 'ref' else 'normal',
            )

    # Title & subtitle
    ax.text(50, 98, title, ha='center', va='center', fontsize=16, fontweight='bold', color='#2c3e50')
    ax.text(50, 95, subtitle, ha='center', va='center', fontsize=9, style='italic', color='#555555')


def legend_page(pdf):
    fig = plt.figure(figsize=LANDSCAPE)
    fig.text(0.5, 0.94, 'Estimated Shielded-Output Crypto Times Across Devices',
             ha='center', fontsize=20, fontweight='bold', color='#2c3e50')
    fig.text(0.5, 0.90, 'Hathor Network \u2014 Issue #1603 PoC',
             ha='center', fontsize=12, style='italic', color='#555555')

    sections = [
        ('Methodology',
         'Times are extrapolated from a measured baseline on Intel Core i5-11300H (single-threaded, WSL2 '
         'Linux 6.6) by scaling with the ratio of Geekbench 6 single-core scores. The baseline is the '
         'diagonal of the full per-output workload benchmark (results_full/total_create.csv and '
         'results_full/total_verify.csv). Formula: '
         'Time(device) = Time(i5-11300H) \u00d7 (1900 / GB6_single_core_score(device)).'),
        ('Caveats',
         'Real on-device performance can swing \u00b130\u201350% from this estimate. The crypto stack benefits '
         'from SIMD (AVX2 on x86, NEON on ARM) and from secp256k1 hand-tuned assembly; mobile chips also '
         'throttle under sustained load. Treat values as order-of-magnitude. GB6 scores for 2014 devices '
         'are extrapolated from Geekbench 4/5 since GB6 does not run on those iOS/Android versions.'),
    ]

    y = 0.82
    for heading, body in sections:
        fig.text(0.06, y, heading, fontsize=13, fontweight='bold', color='#2c3e50', family='serif')
        y -= 0.04
        for line in wrap_text(body, 130):
            fig.text(0.06, y, line, fontsize=11, family='serif', color='#2c3e50')
            y -= 0.032
        y -= 0.025

    fig.text(0.06, y, 'Color legend (per cell)', fontsize=13, fontweight='bold',
             color='#2c3e50', family='serif')

    legend_items = [
        ('< 5 ms', '#d4edda', 'instant'),
        ('5\u201325 ms', '#fff3cd', 'fast'),
        ('25\u2013100 ms', '#ffe5b4', 'noticeable'),
        ('100\u2013300 ms', '#f8d7da', 'sluggish'),
        ('> 300 ms', '#f5b7b1', 'slow'),
    ]
    x = 0.06
    y_legend = y - 0.08
    for label, color, desc in legend_items:
        fig.add_artist(Rectangle((x, y_legend), 0.025, 0.035, transform=fig.transFigure,
                                 facecolor=color, edgecolor='#2c3e50', linewidth=0.8))
        fig.text(x + 0.032, y_legend + 0.018, f'{label}  \u2014  {desc}',
                 fontsize=10, va='center', color='#2c3e50')
        x += 0.18

    pdf.savefig(fig)
    plt.close(fig)


def wrap_text(text, width):
    out, cur = [], ''
    for w in text.split():
        if len(cur) + len(w) + 1 > width:
            out.append(cur)
            cur = w
        else:
            cur = (cur + ' ' + w).strip()
    if cur:
        out.append(cur)
    return out


def sources_page(pdf):
    fig = plt.figure(figsize=LANDSCAPE)
    fig.text(0.5, 0.95, 'Sources & References',
             ha='center', fontsize=18, fontweight='bold', color='#2c3e50')

    sections = [
        ('Geekbench 6 single-core scores',
         [
             'Primary database: https://browser.geekbench.com/  (search by device or chipset)',
             'Mac/iOS chart:    https://browser.geekbench.com/mac-benchmarks',
             'Android chart:    https://browser.geekbench.com/android-benchmarks',
             'Processor chart:  https://browser.geekbench.com/processor-benchmarks',
             '2014 devices (iPhone 6, Galaxy S5, LG G3) extrapolated from Geekbench 4/5',
             'archives, since GB6 requires iOS 12+ / modern Android.',
         ]),
        ('Device specifications (SoC, model details)',
         [
             'GSMArena device database:           https://www.gsmarena.com/',
             'Apple newsroom & technical specs:   https://www.apple.com/newsroom/  /  https://support.apple.com/specs',
             'Samsung official spec pages:        https://www.samsung.com/global/galaxy/',
             'Qualcomm Snapdragon spec sheets:    https://www.qualcomm.com/products/mobile/snapdragon',
             'MediaTek SoC pages:                 https://www.mediatek.com/products/smartphones',
         ]),
        ('Device popularity / market share',
         [
             'USA top sellers (iPhone 15, iPhone 14, Galaxy S23):',
             '   - Counterpoint Research US smartphone tracker: https://www.counterpointresearch.com/',
             '   - CIRP US iPhone reports: https://cirpllc.com/',
             'Europe top sellers (iPhone 14, Galaxy A54, Redmi Note 12):',
             '   - Canalys EMEA quarterly: https://canalys.com/newsroom',
             '   - IDC Western Europe Mobile Phone Tracker: https://www.idc.com/',
             'Rest of World (Samsung Galaxy A14, Tecno Spark 10, Redmi Note 12):',
             '   - IDC Worldwide Quarterly Mobile Phone Tracker: https://www.idc.com/',
             '   - Canalys Africa & Latin America reports: https://canalys.com/',
             '   - StatCounter GlobalStats vendor share: https://gs.statcounter.com/vendor-market-share/mobile',
         ]),
        ('Most powerful (2025) selection rationale',
         [
             'iPhone 16 Pro Max (A18 Pro), Samsung Galaxy S25 Ultra (Snapdragon 8 Elite),',
             'OnePlus 13 (Snapdragon 8 Elite) selected as the top three single-core performers',
             'on the Geekbench 6 mobile leaderboard at time of writing (April 2026).',
         ]),
        ('Disclaimer',
         [
             'Market-share rankings shift quarter to quarter. The devices chosen here represent',
             'the top of recent reports (2024\u20132025) and are intended as illustrative anchors,',
             'not as a definitive ranking. Multipliers in the table are derived solely from',
             'Geekbench 6 single-core scores; on-device benchmark of the actual hathor-ct-crypto',
             'library on each phone would be required for production-grade numbers.',
         ]),
    ]

    y = 0.88
    for heading, lines in sections:
        fig.text(0.05, y, heading, fontsize=12, fontweight='bold', color='#2c3e50', family='serif')
        y -= 0.032
        for line in lines:
            fig.text(0.07, y, line, fontsize=9.5, family='monospace', color='#2c3e50')
            y -= 0.022
        y -= 0.012

    pdf.savefig(fig)
    plt.close(fig)


def main():
    create_baseline = load_diagonal(os.path.join(HERE, 'results_full/total_create.csv'))
    verify_baseline = load_diagonal(os.path.join(HERE, 'results_full/total_verify.csv'))

    with PdfPages(PDF_PATH) as pdf:
        legend_page(pdf)

        fig = plt.figure(figsize=LANDSCAPE)
        ax = fig.add_axes([0.02, 0.02, 0.96, 0.96])
        draw_table(
            ax, create_baseline,
            'Estimated TOTAL CREATION Time per Transaction',
            'bppp value commitment + bppp (Bulletproofs++) range proof + asset surjection proof, summed across all M outputs.',
        )
        pdf.savefig(fig)
        plt.close(fig)

        fig = plt.figure(figsize=LANDSCAPE)
        ax = fig.add_axes([0.02, 0.02, 0.96, 0.96])
        draw_table(
            ax, verify_baseline,
            'Estimated TOTAL VERIFICATION Time per Transaction',
            'Pedersen commitment + range proof + surjection verification, summed across all M outputs.',
        )
        pdf.savefig(fig)
        plt.close(fig)

        sources_page(pdf)

    print(f'Wrote {PDF_PATH}')


if __name__ == '__main__':
    main()
