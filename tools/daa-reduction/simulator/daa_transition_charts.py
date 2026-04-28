#!/usr/bin/env python3
"""
Generate charts from DAA transition simulation results.

Reads simulation results JSON and produces PNG charts.

Usage:
    # From batch-mode results:
    poetry run python tools/daa-reduction/simulator/daa_transition_charts.py

    # From live simulator run files:
    poetry run python tools/daa-reduction/simulator/daa_transition_charts.py --runs-dir tools/daa-reduction/simulator/daa_runs
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print('matplotlib and numpy are required. Install with: pip install matplotlib numpy', file=sys.stderr)
    sys.exit(1)

_SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_PATH = _SCRIPT_DIR / 'daa_simulation_results.json'
OUTPUT_DIR = _SCRIPT_DIR

# Phase colors for vertical lines and shading
PHASE_COLORS = {
    'warmup': '#cccccc',
    'stable': '#e8f5e9',
    'signaling': '#fff3e0',
    'must_signal': '#fce4ec',
    'locked_in': '#e3f2fd',
    'active': '#f3e5f5',
}


def load_results(path: Path) -> dict:
    """Load simulation results from JSON file."""
    with open(path) as f:
        return json.load(f)


def load_runs_dir(runs_dir: Path) -> dict:
    """Load individual run files from a directory into batch-mode format."""
    runs = []
    for fpath in sorted(runs_dir.glob('*.json')):
        with open(fpath) as f:
            data = json.load(f)
        meta = data.get('meta', {})
        blocks = data.get('blocks', [])
        config = data.get('config', {})
        runs.append({
            'hashpower': meta.get('hashpower', config.get('hashpower', 0)),
            'seed': meta.get('seed', config.get('seed', 0)),
            'run_id': meta.get('run_id', fpath.stem),
            'blocks': blocks,
            'summary': meta.get('summary', {}),
        })

    if not runs:
        print(f'No run files found in {runs_dir}', file=sys.stderr)
        sys.exit(1)

    # Infer config from first run's data
    first_run = runs[0]
    activation_height = 600
    for b in first_run['blocks']:
        if b.get('feature_active'):
            activation_height = b['height']
            break

    return {
        'config': {
            'activation_height': activation_height,
            'eval_interval': 100,
            'total_blocks': len(first_run['blocks']),
            'avg_time_before': 30,
            'avg_time_after': 7,
            'n_blocks_daa': 134,
        },
        'runs': runs,
    }


def group_runs_by_hashpower(results: dict) -> dict[int, list[dict]]:
    """Group runs by hashpower level."""
    groups: dict[int, list[dict]] = defaultdict(list)
    for run in results['runs']:
        groups[run['hashpower']].append(run)
    return dict(groups)


def plot_weight_vs_height(results: dict, output_path: Path) -> None:
    """Chart 1: Weight vs height, one subplot per hashrate."""
    groups = group_runs_by_hashpower(results)
    activation_height = results['config']['activation_height']
    n_groups = len(groups)

    fig, axes = plt.subplots(n_groups, 1, figsize=(14, 5 * n_groups), squeeze=False)
    fig.suptitle('Block Weight vs Height (DAA Transition)', fontsize=16, y=1.02)

    for idx, (hp, runs) in enumerate(sorted(groups.items())):
        ax = axes[idx, 0]
        import math
        target_weight = math.log2(hp * 30)

        # Plot window around activation
        window_start = max(0, activation_height - 200)
        window_end = activation_height + 600

        for run in runs:
            heights = [b['height'] for b in run['blocks']
                       if window_start <= b['height'] <= window_end]
            weights = [b['weight'] for b in run['blocks']
                       if window_start <= b['height'] <= window_end]
            ax.plot(heights, weights, alpha=0.25, linewidth=0.8, color='steelblue')

        # Mean line
        all_heights = sorted(set(
            b['height'] for run in runs for b in run['blocks']
            if window_start <= b['height'] <= window_end
        ))
        mean_weights = []
        for h in all_heights:
            vals = []
            for run in runs:
                for b in run['blocks']:
                    if b['height'] == h:
                        vals.append(b['weight'])
                        break
            mean_weights.append(np.mean(vals) if vals else 0)

        ax.plot(all_heights, mean_weights, linewidth=2, color='darkblue', label='Mean')

        # Activation line
        ax.axvline(x=activation_height, color='red', linestyle='--', linewidth=1.5, label='Activation')
        ax.axhline(y=target_weight, color='gray', linestyle=':', alpha=0.5, label=f'Pre-target W={target_weight:.1f}')
        ax.axhline(y=target_weight - 2, color='green', linestyle=':', alpha=0.5,
                    label=f'Post-target W={target_weight - 2:.1f}')

        ax.set_ylabel('Weight')
        ax.set_title(f'Hashpower = {hp:,} (target weight ~{target_weight:.1f})')
        ax.legend(loc='upper right', fontsize=8)
        ax.grid(True, alpha=0.3)

    axes[-1, 0].set_xlabel('Block Height')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  Saved: {output_path}', file=sys.stderr)


def plot_solvetime_vs_height(results: dict, output_path: Path) -> None:
    """Chart 2: Solvetime vs height, one subplot per hashrate."""
    groups = group_runs_by_hashpower(results)
    activation_height = results['config']['activation_height']
    n_groups = len(groups)

    fig, axes = plt.subplots(n_groups, 1, figsize=(14, 5 * n_groups), squeeze=False)
    fig.suptitle('Block Solvetime vs Height (DAA Transition)', fontsize=16, y=1.02)

    for idx, (hp, runs) in enumerate(sorted(groups.items())):
        ax = axes[idx, 0]
        import math
        target_weight = math.log2(hp * 30)

        window_start = max(1, activation_height - 200)
        window_end = activation_height + 600

        for run in runs:
            heights = [b['height'] for b in run['blocks']
                       if window_start <= b['height'] <= window_end and b['solvetime'] > 0]
            solvetimes = [b['solvetime'] for b in run['blocks']
                          if window_start <= b['height'] <= window_end and b['solvetime'] > 0]
            ax.plot(heights, solvetimes, alpha=0.25, linewidth=0.8, color='coral')

        # Mean line
        all_heights = sorted(set(
            b['height'] for run in runs for b in run['blocks']
            if window_start <= b['height'] <= window_end and b['solvetime'] > 0
        ))
        mean_solvetimes = []
        for h in all_heights:
            vals = []
            for run in runs:
                for b in run['blocks']:
                    if b['height'] == h and b['solvetime'] > 0:
                        vals.append(b['solvetime'])
                        break
            mean_solvetimes.append(np.mean(vals) if vals else 0)

        ax.plot(all_heights, mean_solvetimes, linewidth=2, color='darkred', label='Mean')

        # Reference lines
        ax.axvline(x=activation_height, color='red', linestyle='--', linewidth=1.5, label='Activation')
        ax.axhline(y=30, color='gray', linestyle=':', alpha=0.5, label='Target 30s')
        ax.axhline(y=7.5, color='green', linestyle=':', alpha=0.5, label='Target 7.5s')

        ax.set_ylabel('Solvetime (s)')
        ax.set_title(f'Hashpower = {hp:,} (target weight ~{target_weight:.1f})')
        ax.legend(loc='upper right', fontsize=8)
        ax.grid(True, alpha=0.3)
        ax.set_ylim(bottom=0, top=min(200, ax.get_ylim()[1]))

    axes[-1, 0].set_xlabel('Block Height')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  Saved: {output_path}', file=sys.stderr)


def plot_cumulative_time(results: dict, output_path: Path) -> None:
    """Chart 3: Cumulative wall-clock time vs height."""
    groups = group_runs_by_hashpower(results)
    activation_height = results['config']['activation_height']
    n_groups = len(groups)

    fig, axes = plt.subplots(n_groups, 1, figsize=(14, 5 * n_groups), squeeze=False)
    fig.suptitle('Cumulative Time vs Height (DAA Transition)', fontsize=16, y=1.02)

    for idx, (hp, runs) in enumerate(sorted(groups.items())):
        ax = axes[idx, 0]
        import math
        target_weight = math.log2(hp * 30)

        window_start = max(1, activation_height - 200)
        window_end = activation_height + 600

        for run in runs:
            filtered = [b for b in run['blocks']
                        if window_start <= b['height'] <= window_end and b['solvetime'] > 0]
            if not filtered:
                continue
            heights = [b['height'] for b in filtered]
            cum_time = np.cumsum([b['solvetime'] for b in filtered])
            ax.plot(heights, cum_time / 3600, alpha=0.25, linewidth=0.8, color='seagreen')

        ax.axvline(x=activation_height, color='red', linestyle='--', linewidth=1.5, label='Activation')

        ax.set_ylabel('Cumulative Time (hours)')
        ax.set_title(f'Hashpower = {hp:,} (target weight ~{target_weight:.1f})')
        ax.legend(loc='upper left', fontsize=8)
        ax.grid(True, alpha=0.3)

    axes[-1, 0].set_xlabel('Block Height')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  Saved: {output_path}', file=sys.stderr)


def plot_weight_delta(results: dict, output_path: Path) -> None:
    """Chart 4: Weight delta from steady-state (oscillation envelope)."""
    groups = group_runs_by_hashpower(results)
    activation_height = results['config']['activation_height']
    n_groups = len(groups)

    fig, axes = plt.subplots(n_groups, 1, figsize=(14, 5 * n_groups), squeeze=False)
    fig.suptitle('Weight Delta from Steady State (Oscillation Envelope)', fontsize=16, y=1.02)

    for idx, (hp, runs) in enumerate(sorted(groups.items())):
        ax = axes[idx, 0]
        import math
        target_weight = math.log2(hp * 30)

        window_start = max(0, activation_height - 100)
        window_end = activation_height + 600

        # Collect deltas by height
        height_deltas: dict[int, list[float]] = defaultdict(list)

        for run in runs:
            # Determine pre-activation steady weight for this run
            pre_blocks = [b for b in run['blocks']
                          if activation_height - 100 <= b['height'] < activation_height]
            if not pre_blocks:
                continue
            steady_w = np.mean([b['weight'] for b in pre_blocks])

            # Post-activation expected weight is steady_w - 2
            for b in run['blocks']:
                h = b['height']
                if h < window_start or h > window_end:
                    continue
                if h < activation_height:
                    delta = b['weight'] - steady_w
                else:
                    expected = steady_w - 2  # log2(4) = 2
                    delta = b['weight'] - expected
                height_deltas[h].append(delta)

        if not height_deltas:
            continue

        all_h = sorted(height_deltas.keys())
        means = [np.mean(height_deltas[h]) for h in all_h]
        mins = [np.min(height_deltas[h]) for h in all_h]
        maxs = [np.max(height_deltas[h]) for h in all_h]

        ax.fill_between(all_h, mins, maxs, alpha=0.2, color='purple', label='Min/Max envelope')
        ax.plot(all_h, means, linewidth=2, color='purple', label='Mean delta')
        ax.axhline(y=0, color='gray', linestyle='-', alpha=0.3)
        ax.axvline(x=activation_height, color='red', linestyle='--', linewidth=1.5, label='Activation')

        ax.set_ylabel('Weight Delta')
        ax.set_title(f'Hashpower = {hp:,} (target weight ~{target_weight:.1f})')
        ax.legend(loc='upper right', fontsize=8)
        ax.grid(True, alpha=0.3)

    axes[-1, 0].set_xlabel('Block Height')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  Saved: {output_path}', file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate charts from DAA transition simulation results')
    parser.add_argument('--runs-dir', type=Path, default=None,
                        help='Directory containing individual run JSON files (from live simulator)')
    args = parser.parse_args()

    if args.runs_dir:
        if not args.runs_dir.is_dir():
            print(f'Runs directory not found: {args.runs_dir}', file=sys.stderr)
            sys.exit(1)
        print(f'Loading runs from {args.runs_dir}...', file=sys.stderr)
        results = load_runs_dir(args.runs_dir)
    else:
        if not RESULTS_PATH.exists():
            print(f'Results file not found: {RESULTS_PATH}', file=sys.stderr)
            print('Run the simulation first: poetry run python '
                  'tools/daa-reduction/simulator/daa_transition_simulation.py',
                  file=sys.stderr)
            sys.exit(1)
        print('Loading results...', file=sys.stderr)
        results = load_results(RESULTS_PATH)

    n_runs = len(results['runs'])
    print(f'Loaded {n_runs} runs', file=sys.stderr)

    print('Generating charts...', file=sys.stderr)
    plot_weight_vs_height(results, OUTPUT_DIR / 'daa_chart_weight.png')
    plot_solvetime_vs_height(results, OUTPUT_DIR / 'daa_chart_solvetime.png')
    plot_cumulative_time(results, OUTPUT_DIR / 'daa_chart_cumulative_time.png')
    plot_weight_delta(results, OUTPUT_DIR / 'daa_chart_weight_delta.png')

    print('\nAll charts generated.', file=sys.stderr)


if __name__ == '__main__':
    main()
