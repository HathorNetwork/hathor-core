"""Generate a styled PDF with bandwidth & storage estimates per device.

Reads results_memory/total_payload.csv (produced by benchmark_memory.py) and
extrapolates per-device upload/download times and storage capacity for shielded
transactions across the same N×M diagonal as generate_device_table.py.

Each device carries:
  * typical + peak real-world cellular downlink/uplink (Mbps)
  * typical + peak Wi-Fi downlink/uplink (Mbps)
  * a typical free-storage budget (GB)
  * a typical sequential flash write speed (MB/s)

Tables rendered, all over the diagonal (N=M=1,2,4,8,16,32,64):
  1. Cellular upload time (typical vs peak)
  2. Cellular download time (typical vs peak)
  3. Wi-Fi upload time (typical vs peak)
  4. Storage cost — tx count fitting in the free budget

Peak = best-case real-world burst on good signal / mmWave / unshared Wi-Fi channel,
generally 5–10× the median. Typical = Opensignal/Speedtest median for the device's
modem class. Both figures are illustrative.

Figures are illustrative — see the methodology / caveats / sources pages in the PDF.
"""
import csv
import os

import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.patches import Rectangle

HERE = os.path.dirname(os.path.abspath(__file__))
PDF_PATH = os.path.join(HERE, 'shielded_outputs_bandwidth_estimates.pdf')

LANDSCAPE = (16, 10)

# Each device is a dict. Cellular numbers are real-world Mbps.
#   cell_dl / cell_ul = typical (Opensignal / Speedtest median for that modem class).
#   cell_dl_peak / cell_ul_peak = best-case burst on good signal / mmWave / lightly
#     loaded cell; generally 5–10× the typical.
# Wi-Fi numbers assume the device's max supported Wi-Fi standard on a fast router.
#   wifi_* = sustained; wifi_*_peak = best-case burst on an unshared channel (~2–3×).
# free_gb = typical free space on the most-common SKU after OS + a moderate apps load.
# flash_mbs = sequential write speed of the storage (UFS / NVMe / eMMC per device era).
DEVICES = [
    dict(name='Intel Core i5-11300H (reference)', category='Reference (this PoC)',
         soc='11th-gen Tiger Lake',
         cell_dl=0, cell_ul=0, cell_dl_peak=0, cell_ul_peak=0,
         wifi_dl=900, wifi_ul=300, wifi_dl_peak=1800, wifi_ul_peak=700,
         free_gb=400, flash_mbs=3000, group='ref'),
    dict(name='iPhone 16 Pro Max', category='Most powerful', soc='Apple A18 Pro',
         cell_dl=250, cell_ul=60, cell_dl_peak=1800, cell_ul_peak=220,
         wifi_dl=1500, wifi_ul=700, wifi_dl_peak=3500, wifi_ul_peak=1600,
         free_gb=220, flash_mbs=3500, group='flagship'),
    dict(name='Samsung Galaxy S25 Ultra', category='Most powerful', soc='Snapdragon 8 Elite',
         cell_dl=230, cell_ul=55, cell_dl_peak=1500, cell_ul_peak=200,
         wifi_dl=1800, wifi_ul=800, wifi_dl_peak=4800, wifi_ul_peak=2200,
         free_gb=220, flash_mbs=4000, group='flagship'),
    dict(name='OnePlus 13', category='Most powerful', soc='Snapdragon 8 Elite',
         cell_dl=220, cell_ul=50, cell_dl_peak=1200, cell_ul_peak=180,
         wifi_dl=1800, wifi_ul=800, wifi_dl_peak=4800, wifi_ul_peak=2200,
         free_gb=220, flash_mbs=4000, group='flagship'),
    dict(name='iPhone 15', category='USA top-3', soc='Apple A16 Bionic',
         cell_dl=180, cell_ul=40, cell_dl_peak=1200, cell_ul_peak=150,
         wifi_dl=900, wifi_ul=500, wifi_dl_peak=2400, wifi_ul_peak=1200,
         free_gb=100, flash_mbs=1500, group='america'),
    dict(name='iPhone 14', category='USA + Europe top-3', soc='Apple A15 Bionic',
         cell_dl=150, cell_ul=35, cell_dl_peak=900, cell_ul_peak=120,
         wifi_dl=600, wifi_ul=400, wifi_dl_peak=1200, wifi_ul_peak=800,
         free_gb=100, flash_mbs=1500, group='america'),
    dict(name='Samsung Galaxy S23', category='USA top-3', soc='Snapdragon 8 Gen 2',
         cell_dl=170, cell_ul=40, cell_dl_peak=1000, cell_ul_peak=150,
         wifi_dl=1200, wifi_ul=600, wifi_dl_peak=2400, wifi_ul_peak=1200,
         free_gb=180, flash_mbs=2900, group='america'),
    dict(name='Samsung Galaxy A54', category='Europe + ROW top-3', soc='Exynos 1380',
         cell_dl=90, cell_ul=20, cell_dl_peak=500, cell_ul_peak=80,
         wifi_dl=400, wifi_ul=250, wifi_dl_peak=1200, wifi_ul_peak=600,
         free_gb=90, flash_mbs=500, group='europe'),
    dict(name='Xiaomi Redmi Note 12', category='Europe + ROW top-3', soc='Snapdragon 685',
         cell_dl=50, cell_ul=12, cell_dl_peak=300, cell_ul_peak=50,
         wifi_dl=300, wifi_ul=200, wifi_dl_peak=866, wifi_ul_peak=433,
         free_gb=90, flash_mbs=400, group='europe'),
    dict(name='Samsung Galaxy A14', category='Rest of World top-3', soc='MediaTek Helio G80',
         cell_dl=25, cell_ul=8, cell_dl_peak=150, cell_ul_peak=30,
         wifi_dl=150, wifi_ul=80, wifi_dl_peak=433, wifi_ul_peak=200,
         free_gb=45, flash_mbs=200, group='row'),
    dict(name='Tecno Spark 10', category='Rest of World top-3', soc='MediaTek Helio G88',
         cell_dl=20, cell_ul=6, cell_dl_peak=120, cell_ul_peak=25,
         wifi_dl=120, wifi_ul=60, wifi_dl_peak=300, wifi_ul_peak=150,
         free_gb=90, flash_mbs=200, group='row'),
    dict(name='iPhone 6 (2014)', category='2014 era', soc='Apple A8',
         cell_dl=8, cell_ul=3, cell_dl_peak=60, cell_ul_peak=25,
         wifi_dl=50, wifi_ul=30, wifi_dl_peak=150, wifi_ul_peak=80,
         free_gb=8, flash_mbs=50, group='old'),
    dict(name='Samsung Galaxy S5 (2014)', category='2014 era', soc='Snapdragon 801',
         cell_dl=6, cell_ul=2, cell_dl_peak=50, cell_ul_peak=20,
         wifi_dl=40, wifi_ul=20, wifi_dl_peak=120, wifi_ul_peak=60,
         free_gb=8, flash_mbs=40, group='old'),
    dict(name='LG G3 (2014)', category='2014 era', soc='Snapdragon 801',
         cell_dl=6, cell_ul=2, cell_dl_peak=50, cell_ul_peak=20,
         wifi_dl=40, wifi_ul=20, wifi_dl_peak=120, wifi_ul_peak=60,
         free_gb=12, flash_mbs=40, group='old'),
]

CATEGORY_COLORS = {
    'ref':      '#2c3e50',
    'flagship': '#27ae60',
    'america':  '#2980b9',
    'europe':   '#8e44ad',
    'row':      '#d35400',
    'old':      '#7f8c8d',
}

GRID_POINTS = [(1, 1), (2, 2), (4, 4), (8, 8), (16, 16), (32, 32), (64, 64)]


def load_diagonal_bytes(csv_path):
    """Load `total_payload.csv` and return {(n,m): bytes} for the diagonal points."""
    with open(csv_path) as f:
        reader = csv.reader(f)
        header = next(reader)
        m_values = [int(x) for x in header[1:]]
        rows = {}
        for row in reader:
            n = int(row[0])
            rows[n] = [float(x) for x in row[1:]]
    return {(n, m): rows[n][m_values.index(m)] for (n, m) in GRID_POINTS}


# ---------------------------------------------------------------------------
# Cell formatting

def fmt_time(seconds):
    if seconds is None or seconds <= 0:
        return '—'
    if seconds >= 60:
        return f'{seconds / 60:.1f} min'
    if seconds >= 1:
        return f'{seconds:.2f} s'
    if seconds >= 0.001:
        return f'{seconds * 1000:.1f} ms'
    return f'{seconds * 1_000_000:.0f} \u00b5s'


def fmt_bytes(b):
    if b >= 1024 * 1024:
        return f'{b / (1024 * 1024):.2f} MiB'
    if b >= 1024:
        return f'{b / 1024:.2f} KiB'
    return f'{b:.0f} B'


def fmt_count(n):
    if n >= 1_000_000:
        return f'{n / 1_000_000:.1f}M'
    if n >= 1_000:
        return f'{n / 1_000:.1f}k'
    return f'{n:.0f}'


def time_color(seconds):
    if seconds is None or seconds <= 0:
        return '#ecf0f1'
    if seconds < 0.05:
        return '#d4edda'
    if seconds < 0.25:
        return '#fff3cd'
    if seconds < 1:
        return '#ffe5b4'
    if seconds < 5:
        return '#f8d7da'
    return '#f5b7b1'


def storage_color(slots):
    if slots >= 1_000_000:
        return '#d4edda'
    if slots >= 100_000:
        return '#fff3cd'
    if slots >= 10_000:
        return '#ffe5b4'
    if slots >= 1_000:
        return '#f8d7da'
    return '#f5b7b1'


# ---------------------------------------------------------------------------
# Generic table rendering

def _draw_header_row(ax, x_positions, col_widths, headers, y_top, row_height):
    for j, h in enumerate(headers):
        ax.add_patch(Rectangle(
            (x_positions[j], y_top - row_height), col_widths[j], row_height,
            facecolor='#34495e', edgecolor='white', linewidth=1.2,
        ))
        ax.text(
            x_positions[j] + col_widths[j] / 2, y_top - row_height / 2, h,
            ha='center', va='center', color='white', fontsize=8.5, fontweight='bold',
        )


def _draw_device_meta(ax, device, row_idx, x_positions, col_widths, y_top, row_height):
    name, category = device['name'], device['category']
    group = device['group']
    color = CATEGORY_COLORS[group]
    y = y_top - row_height * (row_idx + 2)

    # Name with side stripe
    ax.add_patch(Rectangle(
        (x_positions[0], y), col_widths[0], row_height,
        facecolor='#ecf0f1' if group != 'ref' else '#2c3e50',
        edgecolor='white', linewidth=0.8,
    ))
    ax.add_patch(Rectangle(
        (x_positions[0], y), 0.5, row_height, facecolor=color, edgecolor='none',
    ))
    text_color = 'white' if group == 'ref' else '#2c3e50'
    ax.text(
        x_positions[0] + 1.2, y + row_height / 2, name,
        ha='left', va='center', fontsize=8, fontweight='bold', color=text_color,
    )

    # Category
    ax.add_patch(Rectangle(
        (x_positions[1], y), col_widths[1], row_height,
        facecolor='#f4f6f7' if group != 'ref' else '#34495e',
        edgecolor='white', linewidth=0.8,
    ))
    ax.text(
        x_positions[1] + col_widths[1] / 2, y + row_height / 2, category,
        ha='center', va='center', fontsize=7,
        color='white' if group == 'ref' else '#555555', style='italic',
    )
    return y, group


def draw_bandwidth_table(
    ax, payload_bytes_by_grid, typ_key, peak_key, title, subtitle, direction,
):
    """Draw a per-(N=M) cell table of times.

    Each time cell shows two lines: 'typical' (upper) and 'peak' (lower, faded).
    The Mbps column also shows 'typ / peak'.
    """
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    n_rows = len(DEVICES) + 1

    name_w, cat_w, mbps_w = 22, 15, 10
    rest_w = 100 - (name_w + cat_w + mbps_w)
    cell_w = rest_w / len(GRID_POINTS)
    col_widths = [name_w, cat_w, mbps_w] + [cell_w] * len(GRID_POINTS)

    x_positions = [0]
    for w in col_widths[:-1]:
        x_positions.append(x_positions[-1] + w)

    row_height = 90 / n_rows
    y_top = 92

    headers = (
        ['Device', 'Category', f'{direction} Mbps\ntyp / peak']
        + [f'(N=M={n})\ntyp / peak' for n, _ in GRID_POINTS]
    )
    _draw_header_row(ax, x_positions, col_widths, headers, y_top, row_height * 1.3)
    # Shift data rows down to account for the larger header
    header_extra = row_height * 0.3
    y_top_data = y_top - header_extra

    for i, device in enumerate(DEVICES):
        y, group = _draw_device_meta(
            ax, device, i, x_positions, col_widths, y_top_data, row_height,
        )
        mbps_typ = device[typ_key]
        mbps_peak = device[peak_key]

        # Mbps cell (typical / peak)
        ax.add_patch(Rectangle(
            (x_positions[2], y), col_widths[2], row_height,
            facecolor='#fdfefe' if group != 'ref' else '#34495e',
            edgecolor='white', linewidth=0.8,
        ))
        mbps_label = (
            f'{mbps_typ:g} / {mbps_peak:g}' if mbps_typ > 0 else '—'
        )
        ax.text(
            x_positions[2] + col_widths[2] / 2, y + row_height / 2, mbps_label,
            ha='center', va='center', fontsize=7,
            color='white' if group == 'ref' else '#2c3e50', fontweight='bold',
        )

        # Time cells (typical / peak)
        for k, (n, m) in enumerate(GRID_POINTS):
            payload_bytes = payload_bytes_by_grid[(n, m)]
            if mbps_typ > 0:
                t_typ = (payload_bytes * 8) / (mbps_typ * 1_000_000)
                t_peak = (payload_bytes * 8) / (mbps_peak * 1_000_000)
                facecolor = '#34495e' if group == 'ref' else time_color(t_typ)
                upper = fmt_time(t_typ)
                lower = fmt_time(t_peak)
            else:
                facecolor = '#34495e' if group == 'ref' else '#ecf0f1'
                upper, lower = '—', '—'
            text_color = 'white' if group == 'ref' else '#2c3e50'
            peak_text_color = 'lightgray' if group == 'ref' else '#7f8c8d'
            ax.add_patch(Rectangle(
                (x_positions[3 + k], y), col_widths[3 + k], row_height,
                facecolor=facecolor, edgecolor='white', linewidth=0.8,
            ))
            ax.text(
                x_positions[3 + k] + col_widths[3 + k] / 2, y + row_height * 0.68,
                upper, ha='center', va='center', fontsize=7,
                color=text_color, fontweight='bold' if group == 'ref' else 'normal',
            )
            ax.text(
                x_positions[3 + k] + col_widths[3 + k] / 2, y + row_height * 0.30,
                lower, ha='center', va='center', fontsize=6.2,
                color=peak_text_color, style='italic',
            )

    ax.text(50, 98, title, ha='center', va='center', fontsize=15, fontweight='bold', color='#2c3e50')
    ax.text(50, 95, subtitle, ha='center', va='center', fontsize=9, style='italic', color='#555555')


def draw_storage_table(ax, payload_bytes_by_grid):
    """Draw the per-device storage table.

    Columns:
      * Free storage (GB)
      * Flash write speed (MB/s)
      * For each (N=M) point: KiB / tx, write time, slots-in-1-GB, slots-in-free-budget
    Compress to: per (N=M) one column showing 'slots in free budget' (the most
    practically interesting).
    """
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    name_w, cat_w, free_w, flash_w = 24, 14, 7, 7
    rest_w = 100 - (name_w + cat_w + free_w + flash_w)
    cell_w = rest_w / len(GRID_POINTS)
    col_widths = [name_w, cat_w, free_w, flash_w] + [cell_w] * len(GRID_POINTS)

    x_positions = [0]
    for w in col_widths[:-1]:
        x_positions.append(x_positions[-1] + w)

    n_rows = len(DEVICES) + 1
    row_height = 90 / n_rows
    y_top = 92

    headers = (
        ['Device', 'Category', 'Free GB', 'MB/s'] +
        [f'(N=M={n})\nslots' for n, _ in GRID_POINTS]
    )
    _draw_header_row(ax, x_positions, col_widths, headers, y_top, row_height)

    for i, device in enumerate(DEVICES):
        y, group = _draw_device_meta(ax, device, i, x_positions, col_widths, y_top, row_height)
        free_gb = device['free_gb']
        flash_mbs = device['flash_mbs']

        # Free GB
        ax.add_patch(Rectangle(
            (x_positions[2], y), col_widths[2], row_height,
            facecolor='#fdfefe' if group != 'ref' else '#34495e',
            edgecolor='white', linewidth=0.8,
        ))
        ax.text(
            x_positions[2] + col_widths[2] / 2, y + row_height / 2, f'{free_gb:g}',
            ha='center', va='center', fontsize=7.5,
            color='white' if group == 'ref' else '#2c3e50', fontweight='bold',
        )
        # Flash MB/s
        ax.add_patch(Rectangle(
            (x_positions[3], y), col_widths[3], row_height,
            facecolor='#fdfefe' if group != 'ref' else '#34495e',
            edgecolor='white', linewidth=0.8,
        ))
        ax.text(
            x_positions[3] + col_widths[3] / 2, y + row_height / 2, f'{flash_mbs:g}',
            ha='center', va='center', fontsize=7.5,
            color='white' if group == 'ref' else '#2c3e50', fontweight='bold',
        )

        for k, (n, m) in enumerate(GRID_POINTS):
            payload_bytes = payload_bytes_by_grid[(n, m)]
            slots = (free_gb * 1024 * 1024 * 1024) / payload_bytes if payload_bytes > 0 else 0
            facecolor = '#34495e' if group == 'ref' else storage_color(slots)
            text_color = 'white' if group == 'ref' else '#2c3e50'
            ax.add_patch(Rectangle(
                (x_positions[4 + k], y), col_widths[4 + k], row_height,
                facecolor=facecolor, edgecolor='white', linewidth=0.8,
            ))
            ax.text(
                x_positions[4 + k] + col_widths[4 + k] / 2, y + row_height / 2,
                fmt_count(slots), ha='center', va='center', fontsize=7.5,
                color=text_color, fontweight='bold' if group == 'ref' else 'normal',
            )

    ax.text(50, 98,
            'Storage Capacity — Shielded Transactions per Free-Space Budget',
            ha='center', va='center', fontsize=15, fontweight='bold', color='#2c3e50')
    ax.text(50, 95,
            'Slots = (Free GB / total bytes per transaction). Free GB is a typical '
            'budget for the most-common SKU after OS + apps.',
            ha='center', va='center', fontsize=9, style='italic', color='#555555')


def draw_size_summary(ax, payload_bytes_by_grid):
    """A small summary table showing the raw payload size + per-output size for each diagonal point."""
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')
    ax.text(50, 96, 'Shielded Payload Size — diagonal of N×M grid',
            ha='center', va='center', fontsize=15, fontweight='bold', color='#2c3e50')
    ax.text(50, 92,
            'Reference values from results_memory/total_payload.csv. '
            'Per-output ≈ 0.66 KiB (bppp range proof is ~541 B; surjection grows with N).',
            ha='center', va='center', fontsize=9, style='italic', color='#555555')

    headers = ['(N=M)', 'Total payload', 'Per output', 'Range proof / out', 'Surjection / out (avg)']
    n_cols = len(headers)
    col_w = 18
    x0 = (100 - col_w * n_cols) / 2

    row_height = 5
    y_top = 84
    # Header
    for j, h in enumerate(headers):
        ax.add_patch(Rectangle(
            (x0 + j * col_w, y_top - row_height), col_w, row_height,
            facecolor='#34495e', edgecolor='white', linewidth=1.2,
        ))
        ax.text(x0 + j * col_w + col_w / 2, y_top - row_height / 2, h,
                ha='center', va='center', color='white', fontsize=10, fontweight='bold')

    # Read range_proofs.csv and surjection_proofs.csv for the per-output detail
    rp = _load_diagonal(os.path.join(HERE, 'results_memory/range_proofs.csv'))
    sp = _load_diagonal(os.path.join(HERE, 'results_memory/surjection_proofs.csv'))

    for i, (n, m) in enumerate(GRID_POINTS):
        y = y_top - row_height * (i + 2)
        row = [
            f'{n}',
            fmt_bytes(payload_bytes_by_grid[(n, m)]),
            fmt_bytes(payload_bytes_by_grid[(n, m)] / m),
            fmt_bytes(rp[(n, m)] / m),
            fmt_bytes(sp[(n, m)] / m),
        ]
        for j, txt in enumerate(row):
            ax.add_patch(Rectangle(
                (x0 + j * col_w, y), col_w, row_height,
                facecolor='#fdfefe', edgecolor='#bdc3c7', linewidth=0.6,
            ))
            ax.text(x0 + j * col_w + col_w / 2, y + row_height / 2, txt,
                    ha='center', va='center', fontsize=9.5, color='#2c3e50')


def _load_diagonal(csv_path):
    with open(csv_path) as f:
        reader = csv.reader(f)
        header = next(reader)
        m_values = [int(x) for x in header[1:]]
        rows = {}
        for row in reader:
            n = int(row[0])
            rows[n] = [float(x) for x in row[1:]]
    return {(n, m): rows[n][m_values.index(m)] for (n, m) in GRID_POINTS}


# ---------------------------------------------------------------------------
# Ranking pages

def _rank_devices_by(metric_fn, label, subtitle, ax, lower_is_better=True):
    """Sort devices and draw a vertical ranking. metric_fn(device) -> (sort_key, display_str)."""
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    scored = []
    for d in DEVICES:
        if d['group'] == 'ref':
            continue
        key, disp = metric_fn(d)
        scored.append((key, disp, d))
    scored.sort(key=lambda row: row[0], reverse=not lower_is_better)

    ax.text(50, 96, label, ha='center', va='center', fontsize=16, fontweight='bold', color='#2c3e50')
    ax.text(50, 92, subtitle, ha='center', va='center', fontsize=10, style='italic', color='#555555')

    n_rows = len(scored)
    row_height = 80 / n_rows
    y_top = 88
    col_widths = [6, 38, 22, 18, 16]
    headers = ['#', 'Device', 'Category', 'Value', 'SoC']
    x_positions = [0]
    for w in col_widths[:-1]:
        x_positions.append(x_positions[-1] + w)

    for j, h in enumerate(headers):
        ax.add_patch(Rectangle(
            (x_positions[j], y_top - row_height), col_widths[j], row_height,
            facecolor='#34495e', edgecolor='white', linewidth=1.0,
        ))
        ax.text(x_positions[j] + col_widths[j] / 2, y_top - row_height / 2, h,
                ha='center', va='center', color='white', fontsize=10, fontweight='bold')

    for rank, (_, disp, device) in enumerate(scored, start=1):
        y = y_top - row_height * (rank + 1)
        color = CATEGORY_COLORS[device['group']]
        ax.add_patch(Rectangle(
            (x_positions[0], y), col_widths[0], row_height,
            facecolor=color, edgecolor='white', linewidth=0.8,
        ))
        ax.text(x_positions[0] + col_widths[0] / 2, y + row_height / 2, str(rank),
                ha='center', va='center', color='white', fontsize=10, fontweight='bold')
        cells = [device['name'], device['category'], disp, device['soc']]
        for j, txt in enumerate(cells, start=1):
            ax.add_patch(Rectangle(
                (x_positions[j], y), col_widths[j], row_height,
                facecolor='#fdfefe', edgecolor='#bdc3c7', linewidth=0.6,
            ))
            ax.text(x_positions[j] + col_widths[j] / 2, y + row_height / 2, txt,
                    ha='center', va='center', color='#2c3e50', fontsize=9)


# ---------------------------------------------------------------------------
# Static pages

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


def legend_page(pdf, payload_bytes_by_grid):
    fig = plt.figure(figsize=LANDSCAPE)
    fig.text(0.5, 0.94,
             'Bandwidth & Storage Estimates for Shielded Outputs',
             ha='center', fontsize=20, fontweight='bold', color='#2c3e50')
    fig.text(0.5, 0.90,
             'Hathor Network — Issue #1603 PoC (per-device extrapolation)',
             ha='center', fontsize=12, style='italic', color='#555555')

    sections = [
        ('Methodology',
         'Per-(N,M) total transaction payload (bytes) is read from '
         'results_memory/total_payload.csv produced by benchmark_memory.py. '
         'For each device we hold a typical real-world cellular and Wi-Fi throughput '
         '(Mbps) and a typical free-storage budget (GB). Upload/download time is '
         'computed as (bytes × 8) / (Mbps × 10⁶); storage slots as '
         '(free_GB × 2³⁰) / payload_bytes. The reference Intel i5-11300H row is '
         'shown only for the ratio context — the device has no cellular modem.'),
        ('What goes in the payload',
         'Per shielded output: 33 B bppp value commitment + 33 B blinded asset generator + '
         '~541 B bppp range proof + ~70–140 B asset surjection proof. The bppp range '
         'proof is ~9× smaller than the Borromean ring-sig variant used in '
         'poc-shielded-benchmark/. With the range proof shrunk, the surjection proof '
         'and the per-input domain bytes become a larger fraction of the payload at '
         'high N.'),
        ('Typical vs peak',
         'Each time cell shows TWO values. The upper bold value is the "typical" case '
         '(Opensignal/Speedtest median for that modem class). The italicized lower '
         'value is the "peak" case (best-case burst on good signal, mmWave where '
         'available, unshared Wi-Fi channel); generally 5–10× faster. The cell '
         'background color is driven by the TYPICAL time. For ranking we compute the '
         '50/50 mix between typical and peak (weighted "realistic" view).'),
        ('Caveats',
         'The 5–10× peak/typical swing follows Opensignal\'s published distributions; '
         'real variance can be wider in either direction. Storage budgets assume the '
         'most-common SKU after OS + moderate apps. Unlike the Borromean variant, '
         'bppp proofs are constant-size for the full u64 range — amount choice has '
         'no effect on payload size.'),
    ]

    y = 0.82
    for heading, body in sections:
        fig.text(0.06, y, heading, fontsize=13, fontweight='bold', color='#2c3e50', family='serif')
        y -= 0.04
        for line in wrap_text(body, 130):
            fig.text(0.06, y, line, fontsize=11, family='serif', color='#2c3e50')
            y -= 0.032
        y -= 0.025

    # Time legend
    fig.text(0.06, y, 'Time-cell color legend', fontsize=12, fontweight='bold',
             color='#2c3e50', family='serif')
    y -= 0.05
    legend_items = [
        ('< 50 ms',     '#d4edda', 'instant'),
        ('50–250 ms',   '#fff3cd', 'fast'),
        ('250 ms – 1 s','#ffe5b4', 'noticeable'),
        ('1 – 5 s',     '#f8d7da', 'slow'),
        ('> 5 s',       '#f5b7b1', 'painful'),
    ]
    x = 0.06
    for label, color, desc in legend_items:
        fig.add_artist(Rectangle((x, y), 0.022, 0.030, transform=fig.transFigure,
                                 facecolor=color, edgecolor='#2c3e50', linewidth=0.8))
        fig.text(x + 0.027, y + 0.015, f'{label} — {desc}',
                 fontsize=9.5, va='center', color='#2c3e50')
        x += 0.16

    pdf.savefig(fig)
    plt.close(fig)


def sources_page(pdf):
    fig = plt.figure(figsize=LANDSCAPE)
    fig.text(0.5, 0.95, 'Sources & References',
             ha='center', fontsize=18, fontweight='bold', color='#2c3e50')
    sections = [
        ('Cellular throughput (typical median real-world)',
         [
             'Opensignal global mobile network experience reports: https://www.opensignal.com/reports',
             'Speedtest Global Index (Ookla):                       https://www.speedtest.net/global-index',
             'Per-modem-class typical UL/DL distilled from the device-class chapters of the above.',
         ]),
        ('Wi-Fi throughput (typical fast home router)',
         [
             'Wi-Fi 7 / 6E / 6 / 5 / 4 device support taken from each device\'s GSMArena spec sheet.',
             'Throughputs assume an unshared 5 GHz / 6 GHz channel at close range — a generous',
             'upper bound for what the modem class can sustain in practice.',
         ]),
        ('Storage budget',
         [
             'Most-common SKU per device (e.g. iPhone 16 Pro Max ≈ 256 GB → ≈220 GB free after iOS + apps).',
             'Apple specs:                  https://support.apple.com/specs',
             'Samsung specs:                https://www.samsung.com/global/galaxy/',
             'Generic OEM specs:            https://www.gsmarena.com/',
         ]),
        ('Flash sequential write speed',
         [
             'UFS 4.0  (S25 Ultra):     ~3500 MB/s — JEDEC UFS 4.0 spec',
             'UFS 3.1  (S23, OnePlus):  ~1500 MB/s',
             'Apple NVMe (iPhone 14+):  ~1500 MB/s sustained sequential write',
             'eMMC 5.1 (mid-range):     150–500 MB/s',
             'eMMC 4.5 (entry/2014):    25–50 MB/s',
         ]),
        ('Payload sizes',
         [
             'Empirically measured by benchmark_memory.py (this repo) using',
             'hathor.crypto.shielded.* (asset_tag, surjection) over hathor-ct-crypto,',
             'and `hathor_bppp` (PyO3 bindings around distributed-lab/bp-pp) for',
             'the value commitment and u64 range proof. The companion folder',
             'poc-shielded-benchmark/ measures the Borromean variant.',
         ]),
        ('Disclaimer',
         [
             'All numbers are illustrative. Throughput depends on network conditions',
             'and routing; flash write speed depends on device thermal state and',
             'flash wear; storage budgets vary widely by SKU. Treat as order-of-magnitude.',
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


# ---------------------------------------------------------------------------
# Main

def main():
    payload_csv = os.path.join(HERE, 'results_memory/total_payload.csv')
    if not os.path.exists(payload_csv):
        raise SystemExit(
            f'Missing {payload_csv}. Run:  python benchmark_memory.py  first.'
        )
    payload_bytes_by_grid = load_diagonal_bytes(payload_csv)

    with PdfPages(PDF_PATH) as pdf:
        legend_page(pdf, payload_bytes_by_grid)

        # Summary of payload sizes themselves
        fig = plt.figure(figsize=LANDSCAPE)
        ax = fig.add_axes([0.02, 0.02, 0.96, 0.96])
        draw_size_summary(ax, payload_bytes_by_grid)
        pdf.savefig(fig)
        plt.close(fig)

        # Table: cellular UPLOAD (typical + peak)
        fig = plt.figure(figsize=LANDSCAPE)
        ax = fig.add_axes([0.02, 0.02, 0.96, 0.96])
        draw_bandwidth_table(
            ax, payload_bytes_by_grid,
            typ_key='cell_ul', peak_key='cell_ul_peak',
            title='Cellular UPLOAD time per shielded transaction',
            subtitle='Upper bold = typical; lower italic = peak (best-case burst). '
                     'Color follows the typical time.',
            direction='UL',
        )
        pdf.savefig(fig)
        plt.close(fig)

        # Table: cellular DOWNLOAD (typical + peak)
        fig = plt.figure(figsize=LANDSCAPE)
        ax = fig.add_axes([0.02, 0.02, 0.96, 0.96])
        draw_bandwidth_table(
            ax, payload_bytes_by_grid,
            typ_key='cell_dl', peak_key='cell_dl_peak',
            title='Cellular DOWNLOAD time per shielded transaction',
            subtitle='Upper bold = typical; lower italic = peak. '
                     'Peak cellular DL benefits most from mmWave 5G.',
            direction='DL',
        )
        pdf.savefig(fig)
        plt.close(fig)

        # Table: Wi-Fi UPLOAD (typical + peak)
        fig = plt.figure(figsize=LANDSCAPE)
        ax = fig.add_axes([0.02, 0.02, 0.96, 0.96])
        draw_bandwidth_table(
            ax, payload_bytes_by_grid,
            typ_key='wifi_ul', peak_key='wifi_ul_peak',
            title='Wi-Fi UPLOAD time per shielded transaction',
            subtitle='Upper bold = typical sustained; lower italic = peak burst '
                     '(unshared channel, short range).',
            direction='UL',
        )
        pdf.savefig(fig)
        plt.close(fig)

        # Table: Wi-Fi DOWNLOAD (typical + peak)
        fig = plt.figure(figsize=LANDSCAPE)
        ax = fig.add_axes([0.02, 0.02, 0.96, 0.96])
        draw_bandwidth_table(
            ax, payload_bytes_by_grid,
            typ_key='wifi_dl', peak_key='wifi_dl_peak',
            title='Wi-Fi DOWNLOAD time per shielded transaction',
            subtitle='Upper bold = typical sustained; lower italic = peak burst.',
            direction='DL',
        )
        pdf.savefig(fig)
        plt.close(fig)

        # Table: storage capacity
        fig = plt.figure(figsize=LANDSCAPE)
        ax = fig.add_axes([0.02, 0.02, 0.96, 0.96])
        draw_storage_table(ax, payload_bytes_by_grid)
        pdf.savefig(fig)
        plt.close(fig)

        # Ranking pages — for the 16x16 mid-grid point
        n_for_rank, m_for_rank = 16, 16
        payload_for_rank = payload_bytes_by_grid[(n_for_rank, m_for_rank)]

        # Rank by typical cellular UL+DL
        def rank_metric_cell_typical(d):
            ul_mbps = d['cell_ul']; dl_mbps = d['cell_dl']
            if ul_mbps <= 0 or dl_mbps <= 0:
                return (float('inf'), '—')
            ul = (payload_for_rank * 8) / (ul_mbps * 1e6)
            dl = (payload_for_rank * 8) / (dl_mbps * 1e6)
            return (ul + dl, f'{fmt_time(ul)} UL + {fmt_time(dl)} DL = {fmt_time(ul + dl)}')

        # Rank by PEAK cellular UL+DL
        def rank_metric_cell_peak(d):
            ul_mbps = d['cell_ul_peak']; dl_mbps = d['cell_dl_peak']
            if ul_mbps <= 0 or dl_mbps <= 0:
                return (float('inf'), '—')
            ul = (payload_for_rank * 8) / (ul_mbps * 1e6)
            dl = (payload_for_rank * 8) / (dl_mbps * 1e6)
            return (ul + dl, f'{fmt_time(ul)} UL + {fmt_time(dl)} DL = {fmt_time(ul + dl)}')

        # Rank by realistic mix (50/50 typical + peak)
        def rank_metric_cell_blended(d):
            if d['cell_ul'] <= 0 or d['cell_dl'] <= 0:
                return (float('inf'), '—')
            ul_t = (payload_for_rank * 8) / (d['cell_ul'] * 1e6)
            dl_t = (payload_for_rank * 8) / (d['cell_dl'] * 1e6)
            ul_p = (payload_for_rank * 8) / (d['cell_ul_peak'] * 1e6)
            dl_p = (payload_for_rank * 8) / (d['cell_dl_peak'] * 1e6)
            typ = ul_t + dl_t
            peak = ul_p + dl_p
            blend = 0.5 * typ + 0.5 * peak
            return (blend, f'typ {fmt_time(typ)} · peak {fmt_time(peak)} · blend {fmt_time(blend)}')

        for metric_fn, label, subtitle in [
            (rank_metric_cell_typical,
             f'Devices ranked by TYPICAL cellular UL+DL at N=M={n_for_rank}',
             f'Median real-world throughput · payload {fmt_bytes(payload_for_rank)}'),
            (rank_metric_cell_peak,
             f'Devices ranked by PEAK cellular UL+DL at N=M={n_for_rank}',
             f'Best-case burst (5G mmWave etc.) · payload {fmt_bytes(payload_for_rank)}'),
            (rank_metric_cell_blended,
             f'Devices ranked by BLENDED cellular UL+DL at N=M={n_for_rank}',
             f'50/50 typical+peak — realistic mixed-condition view · payload {fmt_bytes(payload_for_rank)}'),
        ]:
            fig = plt.figure(figsize=LANDSCAPE)
            ax = fig.add_axes([0.02, 0.02, 0.96, 0.96])
            _rank_devices_by(metric_fn, label, subtitle, ax, lower_is_better=True)
            pdf.savefig(fig)
            plt.close(fig)

        # Rank by storage capacity
        def rank_metric_storage(d):
            free_gb = d['free_gb']; flash_mbs = d['flash_mbs']
            if free_gb <= 0 or flash_mbs <= 0:
                return (-float('inf'), '—')
            slots = (free_gb * 2**30) / payload_for_rank
            write_s = payload_for_rank / (flash_mbs * 1024 * 1024)
            return (slots, f'{fmt_count(slots)} slots, write {fmt_time(write_s)}')

        fig = plt.figure(figsize=LANDSCAPE)
        ax = fig.add_axes([0.02, 0.02, 0.96, 0.96])
        _rank_devices_by(
            rank_metric_storage,
            f'Devices ranked by STORAGE CAPACITY at N=M={n_for_rank} '
            f'({fmt_bytes(payload_for_rank)} payload)',
            'More tx slots in the free-space budget is better; '
            'flash write time is sub-millisecond on every device.',
            ax,
            lower_is_better=False,
        )
        pdf.savefig(fig)
        plt.close(fig)

        sources_page(pdf)

    print(f'Wrote {PDF_PATH}')


if __name__ == '__main__':
    main()
