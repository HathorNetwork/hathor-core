#!/usr/bin/env python
# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Measure end-to-end vertex-processing TPS on a REAL reactor (no simulated clock).

This benchmark isolates the *processing time* of the vertex pipeline for plain UTXO
transactions (no nano contracts). A synthetic DAG (blocks confirming spend-chains of
txs) is built once with the DAG Builder, serialized, and then fed to a fresh manager
exactly like p2p block sync does: every vertex is parsed from its wire bytes and every
block is connected through ``vertex_handler.on_new_block(block, deps=txs)``, which runs
full verification, consensus and storage for each dependency tx and the block.

The real reactor means storage is real (temp) RocksDB and the measured number is honest
wall-clock TPS of the connect pipeline. Only the payload section is timed — the
reward-lock base chain and the funding tx are connected first, untimed.

It sweeps a configurable set of inputs/outputs-per-tx (default 1, 2, 4, 8, 16) so the
table shows how throughput scales as transactions get heavier. For each configuration it
runs N times and reports the median, mirroring how we track this per PR.

    python extras/benchmarking/tps/bench_tps.py
    python extras/benchmarking/tps/bench_tps.py --inputs 1,2,4,8,16 --runs 3 --txs 50 --blocks 40
    python extras/benchmarking/tps/bench_tps.py --output tps_results.json
    python extras/benchmarking/tps/bench_tps.py --baseline master_tps.json
"""

from __future__ import annotations

import argparse
import json
import os

# IMPORTANT: the settings must be selected *before* importing any hathor module, because
# most of them read the global settings at import time. We use the same unittests config
# the test suite uses, so that the genesis output script matches the DAG Builder genesis
# wallet and the reward-lock window is small.
from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH

os.environ.setdefault(
    'HATHOR_CONFIG_YAML',
    os.environ.get('HATHOR_TEST_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH),
)

import logging  # noqa: E402
import statistics  # noqa: E402
import time  # noqa: E402
from typing import Any, Generator  # noqa: E402

import structlog  # noqa: E402

# Silence info/debug logging so it neither floods the console nor skews timing (structlog's
# filtering bound logger short-circuits before formatting).
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))

# The global reactor must be initialized before importing the hathor_tests helpers, because
# some of them build wallets at import time.
from hathor.reactor import initialize_global_reactor  # noqa: E402

initialize_global_reactor(use_asyncio_reactor=True)

from twisted.internet.defer import succeed  # noqa: E402

from hathor.conf.get_settings import get_global_settings  # noqa: E402
from hathor.dag_builder.builder import DAGBuilder  # noqa: E402
from hathor.manager import HathorManager  # noqa: E402
from hathor.reactor import get_global_reactor  # noqa: E402
from hathor.simulator.clock import MemoryReactorHeapClock  # noqa: E402
from hathor.simulator.patches import SimulatorCpuMiningService  # noqa: E402
from hathor.simulator.simulator import _build_vertex_verifiers  # noqa: E402
from hathor.transaction import Block, Transaction  # noqa: E402
from hathor.util import Random  # noqa: E402
from hathor_tests.dag_builder.builder import TestDAGBuilder  # noqa: E402
from hathor_tests.unittest import TestBuilder  # noqa: E402

# HathorManager registers an `after shutdown` reactor trigger that calls stop(). This
# benchmark builds and stops many managers under a single reactor run, so that trigger would
# re-stop an already-stopped manager when the reactor shuts down and raise. Patch the class
# method (before any manager is constructed, so the trigger's bound method picks it up) to
# make stop() idempotent.
_orig_manager_stop = HathorManager.stop


def _idempotent_stop(self: HathorManager, *args: Any, **kwargs: Any) -> Any:
    if not self.is_started:
        return succeed(None)
    return _orig_manager_stop(self, *args, **kwargs)


HathorManager.stop = _idempotent_stop  # type: ignore[method-assign]

DEFAULT_INPUTS = (1, 2, 4, 8, 16)
# RNG seeds: the DAG source is built deterministically; the target manager gets its own seed.
SOURCE_SEED = 1234
TARGET_SEED = 5678
# Production nodes run with the tx-storage cache; without it every get falls through to
# weakrefs/RocksDB and the LRU bookkeeping degenerates into pure eviction churn.
TX_STORAGE_CACHE = 100_000


def base_blocks() -> int:
    """Reward-lock window plus two: enough confirmed blocks to spend the funding reward."""
    return get_global_settings().REWARD_SPEND_MIN_BLOCKS + 2


def build_dag_str(*, num_txs: int, num_blocks: int, num_inputs: int) -> str:
    """Blocks x1..xR each confirming a spend-chain group of `num_txs` txs (one dummy-funded
    tx per group keeps the dummy under the 255-output wire limit).

    Each payload tx has exactly `num_inputs` inputs and `num_inputs` outputs: tx t_{i+1}
    spends all `num_inputs` outputs of t_i, so the chain stays resolvable. For num_inputs > 1
    a per-group source `g{r}_s` (one extra confirmed tx) seeds the chain with `num_inputs`
    outputs; the source is funded from the dummy by the builder."""
    base = base_blocks()
    lines = [
        f'blockchain genesis b[1..{base}]',
        f'blockchain b{base} x[1..{num_blocks}]',
        f'b{base - 1} < dummy',
        f'b{base} --> dummy',
        '',
    ]
    for r in range(num_blocks):
        if num_inputs == 1:
            for i in range(num_txs - 1):
                lines.append(f'g{r}_t{i}.out[0] <<< g{r}_t{i + 1}')
        else:
            src = f'g{r}_s'
            for j in range(num_inputs):
                lines.append(f'{src}.out[{j}] = 1 HTR')
            prev = src
            for i in range(num_txs):
                tx = f'g{r}_t{i}'
                for j in range(num_inputs):
                    lines.append(f'{prev}.out[{j}] <<< {tx}')
                for j in range(num_inputs):
                    lines.append(f'{tx}.out[{j}] = 1 HTR')
                prev = tx
        lines.append(f'x{r + 1} --> g{r}_t{num_txs - 1}')
        lines.append('')
    return '\n'.join(lines)


def build_source_manager() -> HathorManager:
    """Bootstrap a started, in-memory (simulated-clock) HathorManager used only to build and
    serialize the synthetic DAG. It is independent of the global reactor."""
    clock = MemoryReactorHeapClock()
    clock.advance(time.time())
    builder = (
        TestBuilder()
        .set_rng(Random(SOURCE_SEED))
        .set_reactor(clock)
        .set_vertex_verifiers_builder(_build_vertex_verifiers)
        .set_cpu_mining_service(SimulatorCpuMiningService())
    )
    artifacts = builder.build()
    manager = artifacts.manager
    manager.start()
    clock.run()
    clock.advance(5)
    return manager


def build_payloads(num_txs: int, num_blocks: int, num_inputs: int) -> dict[str, bytes]:
    """Build the DAG once (throwaway simulated-clock manager) and serialize every vertex."""
    source = build_source_manager()
    dag_str = build_dag_str(num_txs=num_txs, num_blocks=num_blocks, num_inputs=num_inputs)
    builder: DAGBuilder = TestDAGBuilder.from_manager(source)
    artifacts = builder.build_from_str(dag_str)
    return {node.name: bytes(vertex) for node, vertex in artifacts.list}


def build_target() -> HathorManager:
    """A fresh manager on the REAL reactor (real RocksDB temp dir, tx-storage cache on)."""
    builder = (
        TestBuilder()
        .set_rng(Random(TARGET_SEED))
        .set_reactor(get_global_reactor())
        .set_vertex_verifiers_builder(_build_vertex_verifiers)
        .set_cpu_mining_service(SimulatorCpuMiningService())
        .use_tx_storage_cache(TX_STORAGE_CACHE)
    )
    artifacts = builder.build()
    manager = artifacts.manager
    manager.start()
    return manager


def feed(
    manager: HathorManager,
    payloads: dict[str, bytes],
    num_txs: int,
    num_blocks: int,
    num_inputs: int,
) -> Generator[Any, Any, float]:
    """Feed the DAG through the block-sync entrypoint; return the payload-section wall time."""
    parser = manager.vertex_parser
    storage = manager.tx_storage
    base = base_blocks()

    def parse(name: str) -> Any:
        return parser.deserialize(payloads[name], storage=storage)

    # base chain (reward-lock window) + the dummy funding tx — connected first, not measured
    for i in range(1, base + 1):
        block = parse(f'b{i}')
        assert isinstance(block, Block)
        deps: list[Transaction] = []
        if i == base:
            dummy = parse('dummy')
            assert isinstance(dummy, Transaction)
            deps = [dummy]
        ok = yield manager.vertex_handler.on_new_block(block, deps=deps)
        assert ok, f'base block b{i} rejected'

    # payload: the measured section, fed exactly like sync's on_block_complete
    start = time.perf_counter()
    for r in range(num_blocks):
        # the per-group source (num_inputs > 1) is the chain root and must connect first
        names = ([f'g{r}_s'] if num_inputs > 1 else []) + [f'g{r}_t{i}' for i in range(num_txs)]
        txs = [parse(name) for name in names]
        block = parse(f'x{r + 1}')
        assert isinstance(block, Block)
        ok = yield manager.vertex_handler.on_new_block(block, deps=txs)
        assert ok, f'payload block x{r + 1} rejected'
    return time.perf_counter() - start


def run_sweep(
    inputs: list[int],
    *,
    num_txs: int,
    num_blocks: int,
    runs: int,
) -> dict[int, list[float]]:
    """Drive every (inputs x run) measurement under a single reactor run and return, per
    input-count, the list of tx/s for each run."""
    from twisted.internet.defer import inlineCallbacks

    # Built before the reactor runs: the simulated-clock source managers are independent.
    payloads = {n: build_payloads(num_txs, num_blocks, n) for n in inputs}
    total_txs = num_txs * num_blocks
    results: dict[int, list[float]] = {n: [] for n in inputs}
    failure: dict[str, BaseException] = {}
    reactor = get_global_reactor()

    @inlineCallbacks
    def orchestrate() -> Generator[Any, Any, None]:
        try:
            for n in inputs:
                for _ in range(runs):
                    manager = build_target()
                    try:
                        elapsed = yield inlineCallbacks(feed)(
                            manager, payloads[n], num_txs, num_blocks, n)
                    finally:
                        yield manager.stop()
                    results[n].append(total_txs / elapsed)
        except BaseException as e:  # noqa: B902 — record and stop the reactor cleanly
            failure['error'] = e
        finally:
            reactor.stop()

    reactor.callWhenRunning(orchestrate)
    reactor.run()
    if 'error' in failure:
        raise failure['error']
    return results


def _fmt(value: float) -> str:
    return f'{value:,.0f}'


def _pct(value: float, base: float) -> str:
    if base == 0:
        return '—'
    delta = value / base - 1.0
    return f'{delta * 100:+.1f}%'


def render_table(
    medians: dict[int, float],
    *,
    total_txs: int,
    runs: int,
    baseline: dict[int, float] | None,
) -> str:
    """Render the per-input table; columns mirror what we track per PR."""
    inputs = sorted(medians)
    one_in = medians[inputs[0]]
    header = ['inputs/outputs per tx', 'tx/s', 'UTXOs/s (tx/s x N)', 'tx/s vs 1-in']
    if baseline:
        header += ['tx/s (base)', 'vs base']
    rows: list[list[str]] = []
    for n in inputs:
        tps = medians[n]
        row = [str(n), _fmt(tps), _fmt(tps * n), '—' if n == inputs[0] else _pct(tps, one_in)]
        if baseline:
            base_tps = baseline.get(n)
            row += [_fmt(base_tps) if base_tps else '—', _pct(tps, base_tps) if base_tps else '—']
        rows.append(row)

    widths = [max(len(header[c]), *(len(r[c]) for r in rows)) for c in range(len(header))]

    def line(cells: list[str]) -> str:
        return '| ' + ' | '.join(cell.rjust(widths[c]) for c, cell in enumerate(cells)) + ' |'

    sep = '|' + '|'.join('-' * (w + 2) for w in widths) + '|'
    title = f'real reactor, {total_txs:,} txs/config, median of {runs} run(s)'
    out = [title, '', line(header), sep]
    out += [line(r) for r in rows]
    return '\n'.join(out)


def to_bmf(medians: dict[int, float], samples: dict[int, list[float]]) -> dict[str, Any]:
    """Bencher Metric Format: one benchmark per input-count, throughput measure in tx/s.

    Names are zero-padded so Bencher orders them 01, 02, 04, 08, 16 instead of lexically."""
    bmf: dict[str, Any] = {}
    for n in sorted(medians):
        runs = samples[n]
        bmf[f'tps/{n:02d}-in'] = {
            'throughput': {
                'value': round(medians[n], 2),
                'lower_value': round(min(runs), 2),
                'upper_value': round(max(runs), 2),
            }
        }
    return bmf


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--inputs', default=','.join(map(str, DEFAULT_INPUTS)),
                        help='comma-separated inputs/outputs per tx to sweep (default: 1,2,4,8,16)')
    parser.add_argument('--txs', type=int, default=50, help='payload txs per block (default: 50)')
    parser.add_argument('--blocks', type=int, default=40, help='payload blocks (default: 40)')
    parser.add_argument('--runs', type=int, default=3, help='runs per config; median reported (default: 3)')
    parser.add_argument('--output', default=None, help='write Bencher Metric Format JSON to this path')
    parser.add_argument('--baseline', default=None,
                        help='a previous --output JSON to compare against (adds a vs-base column)')
    args = parser.parse_args()

    inputs = [int(x) for x in args.inputs.split(',') if x.strip()]
    assert inputs, 'no inputs to sweep'

    samples = run_sweep(inputs, num_txs=args.txs, num_blocks=args.blocks, runs=args.runs)
    medians = {n: statistics.median(s) for n, s in samples.items()}

    baseline = None
    if args.baseline:
        with open(args.baseline) as fp:
            raw = json.load(fp)
        baseline = {}
        for name, body in raw.items():
            # name is 'tps/NN-in'; recover N and the throughput value
            n = int(name.split('/')[1].split('-')[0])
            baseline[n] = body['throughput']['value']

    print()
    print(render_table(medians, total_txs=args.txs * args.blocks, runs=args.runs, baseline=baseline))
    print()

    if args.output:
        bmf = to_bmf(medians, samples)
        with open(args.output, 'w') as fp:
            json.dump(bmf, fp, indent=2)
        print(f'Bencher Metric Format written to: {args.output}')


if __name__ == '__main__':
    main()
