#!/usr/bin/env python3
"""
DAA Transition Simulation for REDUCE_DAA_TARGET Feature Activation.

Simulates the DAA's transient behavior when the target block time changes from 30s to 7.5s.
Uses the Hathor Simulator with GeometricMiner for realistic mining behavior.

Usage:
    # Batch mode: run all hashpower levels x seeds, write to JSON
    poetry run python tools/daa-reduction/simulator/daa_transition_simulation.py

    # JSONL mode: single run, stream events to stdout
    poetry run python tools/daa-reduction/simulator/daa_transition_simulation.py --jsonl --hashpower 69905 --seed 0

    # Custom parameters
    poetry run python tools/daa-reduction/simulator/daa_transition_simulation.py --total-blocks 2000 --eval-interval 100
"""
from __future__ import annotations

import argparse
import datetime
import json
import math
import os
import sys
import time
from typing import Any, Callable

# Initialize environment before ANY hathor/hathorlib imports
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.environ.setdefault('HATHOR_CONFIG_YAML', os.path.join(
    _project_root, 'hathorlib', 'hathorlib', 'conf', 'unittests.yml'
))

# Configure logging to stderr and suppress verbose output
import logging  # noqa: E402
import structlog  # noqa: E402

logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format='%(message)s')

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
)

from hathor.conf.get_settings import get_global_settings  # noqa: E402
from hathor.feature_activation.feature import Feature  # noqa: E402
from hathor.feature_activation.model.criteria import Criteria  # noqa: E402
from hathor.feature_activation.model.feature_state import FeatureState  # noqa: E402
from hathor.feature_activation.settings import Settings as FeatureSettings  # noqa: E402
from hathor.reactor import initialize_global_reactor  # noqa: E402
from hathor.simulator.simulator import Simulator  # noqa: E402

initialize_global_reactor()

# Default hashpower levels: target steady-state weights of ~21, ~30, ~40
# hashpower = 2^W / T where T=30s
DEFAULT_HASHPOWER_LEVELS = [
    int(2**21 / 30),       # ~69,905 → weight ~21
    int(2**30 / 30),       # ~35,791,394 → weight ~30
    int(2**40 / 30),       # ~36,650,787,635 → weight ~40
]

DEFAULT_SEEDS = list(range(10))
DEFAULT_TOTAL_BLOCKS = 1600
DEFAULT_EVAL_INTERVAL = 100


def make_settings(eval_interval: int) -> Any:
    """Create HathorSettings configured for the REDUCE_DAA_TARGET simulation."""
    # Timeline: signaling starts at 3*ei, timeout at 5*ei, activation at 6*ei
    # This satisfies: timeout >= start + 2*ei, and gives DAA 268+ blocks to stabilize
    start = 3 * eval_interval
    timeout = 5 * eval_interval       # = start + 2*ei (minimum allowed)
    activation = 6 * eval_interval    # one interval after LOCKED_IN

    feature_settings = FeatureSettings(
        evaluation_interval=eval_interval,
        max_signal_bits=4,
        default_threshold=eval_interval * 3 // 4,
        features={
            Feature.REDUCE_DAA_TARGET: Criteria(
                bit=0,
                start_height=start,
                timeout_height=timeout,
                minimum_activation_height=activation,
                lock_in_on_timeout=True,
                version='0.0.0',
            )
        }
    )

    return get_global_settings().model_copy(update={
        'AVG_TIME_BETWEEN_BLOCKS': 30,
        'FEATURE_ACTIVATION': feature_settings,
        'REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X': 75,
        'BLOCK_DIFFICULTY_N_BLOCKS': 134,  # mainnet value (unittests uses 20)
    })


def get_phase(
    in_warmup: bool,
    feature_state: FeatureState,
) -> tuple[str, str]:
    """Determine the simulation phase for a block."""
    if in_warmup:
        return 'warmup', 'Warmup: filling DAA window'
    if feature_state == FeatureState.DEFINED:
        return 'stable', 'DAA stabilized'
    if feature_state == FeatureState.STARTED:
        return 'signaling', 'Feature signaling started'
    if feature_state == FeatureState.MUST_SIGNAL:
        return 'must_signal', 'Must-signal period'
    if feature_state == FeatureState.LOCKED_IN:
        return 'locked_in', 'Feature locked in'
    if feature_state == FeatureState.ACTIVE:
        return 'active', 'Feature ACTIVE - T changed to 7.5s'
    return 'unknown', f'Unknown state: {feature_state}'


def analyze_results(blocks: list[dict], activation_height: int) -> dict:
    """Compute summary statistics from block data."""
    if not blocks:
        return {}

    # Find blocks before and after activation
    pre_activation = [b for b in blocks if b['height'] < activation_height and b['height'] > 268]
    post_activation = [b for b in blocks if b['height'] >= activation_height]

    # Steady-state weight before activation (last 100 blocks before activation)
    pre_weights = [b['weight'] for b in pre_activation[-100:]]
    steady_weight_before = sum(pre_weights) / len(pre_weights) if pre_weights else 0

    # Steady-state weight after activation (last 100 blocks)
    post_weights = [b['weight'] for b in post_activation[-100:]]
    steady_weight_after = sum(post_weights) / len(post_weights) if post_weights else 0

    # Solvetimes
    pre_solvetimes = [b['solvetime'] for b in pre_activation if b['solvetime'] > 0]
    post_solvetimes = [b['solvetime'] for b in post_activation if b['solvetime'] > 0]

    avg_solvetime_before = sum(pre_solvetimes) / len(pre_solvetimes) if pre_solvetimes else 0
    avg_solvetime_after = sum(post_solvetimes) / len(post_solvetimes) if post_solvetimes else 0

    # Max solvetime during transition (first 200 blocks after activation)
    transition = [b for b in post_activation[:200] if b['solvetime'] > 0]
    max_solvetime_transition = max((b['solvetime'] for b in transition), default=0)

    # Weight extremes during transition
    transition_weights = [b['weight'] for b in post_activation[:200]]
    min_weight_transition = min(transition_weights) if transition_weights else 0
    max_weight_transition = max(transition_weights) if transition_weights else 0

    # Convergence: find when rolling avg solvetime is within 20% of target (7.5s)
    target_solvetime = 7.5  # REDUCED_AVG_TIME_BETWEEN_BLOCKS
    window = 20
    convergence_height = None
    for i in range(window, len(post_activation)):
        recent = post_activation[i - window:i]
        avg_st = sum(b['solvetime'] for b in recent) / window
        if abs(avg_st - target_solvetime) / target_solvetime < 0.20:
            convergence_height = post_activation[i]['height']
            break

    convergence_blocks = (convergence_height - activation_height) if convergence_height else None

    # Weight decay detection (exclude genesis/warmup solvetime artifacts)
    decay_triggered = any(b['solvetime'] >= 3600 for b in blocks if b['height'] > 1)

    return {
        'steady_weight_before': round(steady_weight_before, 2),
        'steady_weight_after': round(steady_weight_after, 2),
        'weight_drop': round(steady_weight_before - steady_weight_after, 2),
        'avg_solvetime_before': round(avg_solvetime_before, 2),
        'avg_solvetime_after': round(avg_solvetime_after, 2),
        'max_solvetime_transition': round(max_solvetime_transition, 2),
        'min_weight_transition': round(min_weight_transition, 2),
        'max_weight_transition': round(max_weight_transition, 2),
        'convergence_blocks': convergence_blocks,
        'decay_triggered': decay_triggered,
    }


def run_simulation(
    hashpower: float,
    seed: int,
    total_blocks: int = DEFAULT_TOTAL_BLOCKS,
    eval_interval: int = DEFAULT_EVAL_INTERVAL,
    on_event: Callable[[dict], None] | None = None,
) -> list[dict]:
    """Run a single DAA transition simulation.

    Args:
        hashpower: Miner hashpower (hashes/second).
        seed: Random seed for reproducibility.
        total_blocks: Total blocks to mine.
        eval_interval: Feature activation evaluation interval.
        on_event: Optional callback for real-time event output.

    Returns:
        List of per-block data dicts.
    """
    settings = make_settings(eval_interval)
    activation_height = 6 * eval_interval
    n_blocks_daa = settings.BLOCK_DIFFICULTY_N_BLOCKS

    # Create simulator
    sim = Simulator(seed=seed)
    sim.settings = settings
    sim.start()

    # Create peer with custom settings
    builder = sim.get_default_builder().set_settings(settings)
    artifacts = sim.create_artifacts(builder)
    manager = artifacts.manager
    tx_storage = artifacts.tx_storage
    feature_service = artifacts.feature_service

    # Wire feature_service into the DAA (Simulator creates DAA without it)
    manager.daa._feature_service = feature_service

    # Allow mining without peers (single-node simulation)
    manager.allow_mining_without_peers()

    # Create miner: signal bit 0 for all blocks to support REDUCE_DAA_TARGET
    signal_bits = [0b1] * (total_blocks + 10)

    # Ramp hashpower during warmup so the DAA converges smoothly.
    # Strategy: set hashpower to 2^weight (blocks arrive ~1s) so the DAA steadily
    # increases weight.  Cap at the target hashpower.  Keep ramping until the weight
    # is within 2 of the steady-state target or the minimum warmup period has passed.
    min_warmup_end = n_blocks_daa * 2  # 268
    target_weight = math.log2(hashpower * settings.AVG_TIME_BETWEEN_BLOCKS)
    initial_hashpower = 2 ** settings.MIN_BLOCK_WEIGHT  # blocks at ~1s with MIN_BLOCK_WEIGHT
    miner = sim.create_miner(manager, hashpower=min(initial_hashpower, hashpower), signal_bits=signal_bits)
    miner.start()

    # Mine in batches so we can stream block data between batches
    # Use smaller batches during warmup for finer-grained hashpower adjustments
    WARMUP_BATCH_SIZE = 10
    BATCH_SIZE = 50
    blocks: list[dict] = []
    prev_timestamp: int | None = None
    prev_phase: str | None = None
    next_height = 0
    blocks_mined = 0
    last_weight: float = settings.MIN_BLOCK_WEIGHT

    t0 = time.time()

    in_warmup = True
    while blocks_mined < total_blocks:
        batch_size = WARMUP_BATCH_SIZE if in_warmup else BATCH_SIZE
        batch = min(batch_size, total_blocks - blocks_mined)
        target_found = miner.get_blocks_found() + batch
        miner.pause_after_exactly(n_blocks=batch)
        # Advance clock event-by-event to avoid over-advancing past the last mined block,
        # which would create artificial timestamp gaps between batches.
        while miner.get_blocks_found() < target_found:
            pending = sim._clock.getDelayedCalls()
            if not pending:
                break
            next_time = min(c.getTime() for c in pending)
            sim._clock.advance(max(0, next_time - sim._clock.seconds()))
        blocks_mined += batch

        # Extract and stream all newly available blocks
        while True:
            block = tx_storage.get_block_by_height(next_height)
            if block is None:
                break

            timestamp = block.timestamp
            weight = float(block.weight)
            solvetime = (timestamp - prev_timestamp) if prev_timestamp is not None else 0

            # Get feature state
            try:
                if block.is_genesis:
                    feature_state = FeatureState.DEFINED
                else:
                    feature_state = feature_service.get_state(
                        block=block, feature=Feature.REDUCE_DAA_TARGET
                    )
            except Exception:
                feature_state = FeatureState.DEFINED

            feature_active = feature_state.is_active()
            phase, phase_label = get_phase(in_warmup, feature_state)

            # Emit phase transition
            if phase != prev_phase and on_event:
                on_event({
                    'type': 'phase',
                    'phase': phase,
                    'label': phase_label,
                    'height': next_height,
                })

            block_dict = {
                'type': 'block',
                'height': next_height,
                'weight': round(weight, 4),
                'solvetime': solvetime,
                'timestamp': timestamp,
                'feature_state': feature_state.value,
                'feature_active': feature_active,
                'phase': phase,
                'in_warmup': in_warmup,
                'hashpower': miner._hashpower,
            }
            blocks.append(block_dict)

            if on_event:
                on_event(block_dict)

            prev_phase = phase
            prev_timestamp = timestamp
            next_height += 1

        # Ramp hashpower during warmup: track weight with overshoot so DAA increases weight.
        # The cap at 2^weight keeps blocks at ~1s (avoiding integer timestamp collisions).
        # Once weight converges near target, switch to full hashpower.
        if blocks:
            last_weight = blocks[-1]['weight']
        if in_warmup and next_height > min_warmup_end and last_weight >= target_weight - 2:
            in_warmup = False
        if in_warmup:
            ramp_hp = min(2 ** last_weight, hashpower)
            miner._hashpower = ramp_hp
        else:
            miner._hashpower = hashpower

    sim_duration = time.time() - t0
    print(f'  Mining completed in {sim_duration:.1f}s real time, '
          f'{miner.get_blocks_found()} blocks found', file=sys.stderr)

    # Cleanup
    miner.stop()
    manager.stop()
    sim.stop()

    return blocks


def run_jsonl(args: argparse.Namespace) -> None:
    """Run a single simulation in JSONL streaming mode."""
    hashpower = args.hashpower
    seed = args.seed
    total_blocks = args.total_blocks
    eval_interval = args.eval_interval
    activation_height = 6 * eval_interval
    run_id = f'hp{int(hashpower)}_s{seed}'

    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    t0 = time.time()

    def emit(event: dict) -> None:
        print(json.dumps(event), flush=True)

    emit({
        'type': 'config',
        'activation_height': activation_height,
        'hashpower': hashpower,
        'seed': seed,
        'total_blocks': total_blocks,
        'eval_interval': eval_interval,
        'n_blocks_daa': 134,
        'avg_time_before': 30,
        'avg_time_after': 7.5,
    })

    emit({
        'type': 'run_start',
        'hashpower': hashpower,
        'seed': seed,
        'run_id': run_id,
    })

    blocks = run_simulation(
        hashpower=hashpower,
        seed=seed,
        total_blocks=total_blocks,
        eval_interval=eval_interval,
        on_event=emit,
    )

    summary = analyze_results(blocks, activation_height)

    emit({
        'type': 'run_end',
        'run_id': run_id,
        'summary': summary,
        'started_at': started_at,
        'duration_seconds': round(time.time() - t0, 1),
    })

    emit({'type': 'simulation_end'})


def run_batch(args: argparse.Namespace) -> None:
    """Run all hashpower x seed combinations and save to JSON."""
    total_blocks = args.total_blocks
    eval_interval = args.eval_interval
    activation_height = 6 * eval_interval
    seeds = list(range(args.num_seeds))
    hashpower_levels = DEFAULT_HASHPOWER_LEVELS

    print(f'DAA Transition Simulation (batch mode)', file=sys.stderr)
    print(f'  Total blocks: {total_blocks}', file=sys.stderr)
    print(f'  Eval interval: {eval_interval}', file=sys.stderr)
    print(f'  Activation height: {activation_height}', file=sys.stderr)
    print(f'  Hashpower levels: {len(hashpower_levels)}', file=sys.stderr)
    print(f'  Seeds per level: {len(seeds)}', file=sys.stderr)
    print(f'  Total runs: {len(hashpower_levels) * len(seeds)}', file=sys.stderr)
    print(file=sys.stderr)

    results = {
        'config': {
            'eval_interval': eval_interval,
            'activation_height': activation_height,
            'total_blocks': total_blocks,
            'avg_time_before': 30,
            'avg_time_after': 7.5,
            'n_blocks_daa': 134,
            'hashpower_levels': hashpower_levels,
            'seeds': seeds,
        },
        'runs': [],
    }

    total_runs = len(hashpower_levels) * len(seeds)
    run_count = 0

    for hp in hashpower_levels:
        target_weight = math.log2(hp * 30)
        print(f'Hashpower {hp:,} (target weight ~{target_weight:.1f})', file=sys.stderr)

        for s in seeds:
            run_count += 1
            run_id = f'hp{hp}_s{s}'
            print(f'  [{run_count}/{total_runs}] seed={s} ...', file=sys.stderr, end=' ')

            t0 = time.time()
            blocks = run_simulation(
                hashpower=hp,
                seed=s,
                total_blocks=total_blocks,
                eval_interval=eval_interval,
            )
            duration = time.time() - t0

            summary = analyze_results(blocks, activation_height)
            print(f'done ({duration:.1f}s, {len(blocks)} blocks, '
                  f'convergence={summary.get("convergence_blocks", "N/A")})',
                  file=sys.stderr)

            results['runs'].append({
                'hashpower': hp,
                'seed': s,
                'run_id': run_id,
                'blocks': blocks,
                'summary': summary,
                'duration_seconds': round(duration, 1),
            })

    # Write results
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, 'daa_simulation_results.json')
    with open(output_path, 'w') as f:
        json.dump(results, f)

    print(f'\nResults written to {output_path}', file=sys.stderr)

    # Print summary table
    print('\n=== Summary ===', file=sys.stderr)
    print(f'{"Hashpower":>15} {"Seed":>5} {"W_before":>9} {"W_after":>8} {"Drop":>6} '
          f'{"Avg_ST_pre":>11} {"Avg_ST_post":>12} {"Max_ST":>7} {"Conv":>6} {"Decay":>6}',
          file=sys.stderr)
    print('-' * 100, file=sys.stderr)
    for run in results['runs']:
        s = run['summary']
        print(f'{run["hashpower"]:>15,} {run["seed"]:>5} '
              f'{s["steady_weight_before"]:>9.2f} {s["steady_weight_after"]:>8.2f} '
              f'{s["weight_drop"]:>6.2f} {s["avg_solvetime_before"]:>11.2f} '
              f'{s["avg_solvetime_after"]:>12.2f} {s["max_solvetime_transition"]:>7.1f} '
              f'{str(s["convergence_blocks"]):>6} '
              f'{"YES" if s["decay_triggered"] else "no":>6}',
              file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description='DAA Transition Simulation')
    parser.add_argument('--jsonl', action='store_true',
                        help='JSONL streaming mode (single run)')
    parser.add_argument('--hashpower', type=float, default=DEFAULT_HASHPOWER_LEVELS[0],
                        help=f'Hashpower for single run (default: {DEFAULT_HASHPOWER_LEVELS[0]})')
    parser.add_argument('--seed', type=int, default=0,
                        help='Random seed for single run (default: 0)')
    parser.add_argument('--total-blocks', type=int, default=DEFAULT_TOTAL_BLOCKS,
                        help=f'Total blocks to mine (default: {DEFAULT_TOTAL_BLOCKS})')
    parser.add_argument('--eval-interval', type=int, default=DEFAULT_EVAL_INTERVAL,
                        help=f'Feature evaluation interval (default: {DEFAULT_EVAL_INTERVAL})')
    parser.add_argument('--num-seeds', type=int, default=10,
                        help='Number of seeds for batch mode (default: 10)')

    args = parser.parse_args()

    if args.jsonl:
        run_jsonl(args)
    else:
        run_batch(args)


if __name__ == '__main__':
    main()
