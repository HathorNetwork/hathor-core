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
transactions (no nano contracts). A synthetic DAG is built once with the DAG Builder,
serialized, and then fed to a fresh manager. The transaction phase and the block phase are
timed separately:

  - transactions are connected through the realtime relay path
    (``vertex_handler.on_new_relayed_vertex``) — parse + full verification + consensus;
  - blocks are then connected (``vertex_handler.on_new_block``), confirming the txs.

Each payload tx spends ``num_inputs`` funding UTXOs and creates ``num_outputs`` outputs;
the two counts are independent. The funding UTXOs come from per-group *feeder* txs (untimed
scaffolding) rather than from a spend-chain, so a tx's output count never constrains the
next tx's input count. Payload txs are linked by *parent* edges (not spends), so a single
block still confirms the whole group through its ancestry while value flows per-tx. The
feeders are connected first, untimed — only the payload txs are measured.

Each phase ends with ``tx_storage.flush()`` so the actual RocksDB write it produced is
inside the measured window (the tx-storage cache otherwise flushes asynchronously). The
real reactor means storage is real (temp) RocksDB, so the number is honest wall-clock
processing time. Only the payload is timed — the reward-lock base chain and the funding
tx are connected first, untimed.

The report shows, per configuration, the transaction throughput (tx/s, from the
transaction phase only) and the three phase times: transactions, blocks, and total. With
``--blocks 0`` there are no confirming blocks, so only the transaction time is measured.

It sweeps a configurable set of inputs-per-tx (default 1, 2, 4, 8, 16) so the table shows
how throughput scales as transactions get heavier. ``--outputs`` is independent: left unset
the output count matches the input count (the diagonal); set it to sweep the full
inputs x outputs matrix. For each configuration it runs N times and reports the median,
mirroring how we track this per PR.

    python extras/benchmarking/tps/bench_tps.py
    python extras/benchmarking/tps/bench_tps.py --inputs 1,2,4,8,16 --runs 3 --txs 2000 --blocks 1
    python extras/benchmarking/tps/bench_tps.py --inputs 2 --outputs 1,2,4,8,16   # sweep outputs
    python extras/benchmarking/tps/bench_tps.py --txs 2000 --blocks 0   # transactions only
    python extras/benchmarking/tps/bench_tps.py --output tps_results.json
    python extras/benchmarking/tps/bench_tps.py --baseline master_tps.json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from pathlib import Path

# Put the repo root on sys.path. CI runs this as a loose script (`python extras/.../bench_tps.py`),
# which only adds this file's directory to sys.path, and installs deps with `--no-root`, so the
# `hathor` package lives in the source tree rather than site-packages. Without this, `import hathor`
# fails with ModuleNotFoundError. The installed `hathorlib` regular package still wins over the repo
# root's namespace dir, so this is safe.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

# IMPORTANT: the settings must be selected *before* importing any hathor module, because
# most of them read the global settings at import time. We use the same unittests config
# the test suite uses, so that the genesis output script matches the DAG Builder genesis
# wallet and the reward-lock window is small.
from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH  # noqa: E402

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
# Each feeder mints up to this many funding outputs; kept under the 255 wire limit. Every
# feeder is funded straight from the dummy tx, so each one also adds a dummy output — the
# total feeder count (groups x feeders-per-group) must stay under the dummy's 255-output cap.
FEEDER_OUTPUTS = 250


def base_blocks() -> int:
    """Reward-lock window plus two: enough confirmed blocks to spend the funding reward."""
    return get_global_settings().REWARD_SPEND_MIN_BLOCKS + 2


def _group_lines(r: int, *, num_txs: int, num_inputs: int, num_outputs: int) -> list[str]:
    """DSL for group r: `num_txs` payload txs, each spending `num_inputs` funding UTXOs and
    creating `num_outputs` terminal outputs. Inputs and outputs are decoupled.

    Funding UTXOs come from per-group feeder txs `g{r}_f*` (untimed scaffolding), not a
    spend-chain, so a tx's output count never constrains the next tx's input count. Each funding
    UTXO is worth `num_outputs` HTR and each payload output is worth `num_inputs` HTR, so every
    payload tx balances exactly (num_inputs * num_outputs HTR in and out) and the filler adds no
    extra inputs/outputs that would skew the counts.

    Payload txs are linked tx_{i} --> tx_{i-1} by *parent* edges (not spends), so a single block
    confirms the whole group through its ancestry while the value flow stays per-tx."""
    lines: list[str] = []
    # feeder outputs: num_txs * num_inputs UTXOs of `num_outputs` HTR each, spread across feeders
    feeder_out: list[tuple[str, int]] = []
    total = num_txs * num_inputs
    m = 0
    while len(feeder_out) < total:
        f = f'g{r}_f{m}'
        cap = min(FEEDER_OUTPUTS, total - len(feeder_out))
        for j in range(cap):
            lines.append(f'{f}.out[{j}] = {num_outputs} HTR')
            feeder_out.append((f, j))
        m += 1
    # payload txs: spend num_inputs feeder UTXOs, emit num_outputs outputs, parent-chain for confirmation
    fi = 0
    for i in range(num_txs):
        tx = f'g{r}_t{i}'
        for _ in range(num_inputs):
            f, j = feeder_out[fi]
            lines.append(f'{f}.out[{j}] <<< {tx}')
            fi += 1
        for j in range(num_outputs):
            lines.append(f'{tx}.out[{j}] = {num_inputs} HTR')
        if i > 0:
            lines.append(f'{tx} --> g{r}_t{i - 1}')
    return lines


def build_dag_str(*, num_txs: int, num_blocks: int, num_inputs: int, num_outputs: int) -> str:
    """Build the DAG DSL.

    For `num_blocks >= 1`: blocks x1..xR, each confirming one group of `num_txs` payload txs.
    For `num_blocks == 0`: a single unconfirmed group of `num_txs` txs and no blocks — the
    transactions-only case, fed through the mempool/relay path with nothing confirming them."""
    base = base_blocks()
    lines = [f'blockchain genesis b[1..{base}]']
    if num_blocks >= 1:
        lines.append(f'blockchain b{base} x[1..{num_blocks}]')
    lines += [f'b{base - 1} < dummy', f'b{base} --> dummy', '']
    groups = range(num_blocks) if num_blocks >= 1 else range(1)
    for r in groups:
        lines += _group_lines(r, num_txs=num_txs, num_inputs=num_inputs, num_outputs=num_outputs)
        if num_blocks >= 1:
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


def build_payloads(num_txs: int, num_blocks: int, num_inputs: int, num_outputs: int) -> dict[str, bytes]:
    """Build the DAG once (throwaway simulated-clock manager) and serialize every vertex."""
    source = build_source_manager()
    dag_str = build_dag_str(num_txs=num_txs, num_blocks=num_blocks,
                            num_inputs=num_inputs, num_outputs=num_outputs)
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
) -> Generator[Any, Any, tuple[float, float]]:
    """Connect the payload, timing transaction-processing and block-processing separately.

    Returns ``(txs_seconds, blocks_seconds)``. Per group, the feeder txs are connected first
    (untimed funding scaffolding), then the payload txs enter through the realtime relay path
    (``on_new_relayed_vertex``) and are timed; blocks are then connected with no deps,
    confirming the already-present txs. Each phase ends with ``tx_storage.flush()`` so the
    RocksDB write it produced is inside its measured window (the cache otherwise flushes
    asynchronously). With ``num_blocks == 0`` there is no block phase, so ``blocks_seconds`` is 0."""
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

    has_blocks = num_blocks >= 1
    groups = range(num_blocks) if has_blocks else range(1)
    txs_seconds = 0.0
    blocks_seconds = 0.0
    for r in groups:
        # feeders fund the payload txs' inputs — connected first, not measured
        for name in (n for n in payloads if n.startswith(f'g{r}_f')):
            ok = manager.vertex_handler.on_new_relayed_vertex(parse(name))
            assert ok, f'feeder {name} rejected'

        # transaction phase: parse + verify + consensus + storage flush
        t0 = time.perf_counter()
        for i in range(num_txs):
            name = f'g{r}_t{i}'
            ok = manager.vertex_handler.on_new_relayed_vertex(parse(name))
            assert ok, f'tx {name} rejected'
        storage.flush()
        txs_seconds += time.perf_counter() - t0

        # block phase: the block confirms this group's txs (already connected)
        if has_blocks:
            block = parse(f'x{r + 1}')
            assert isinstance(block, Block)
            t1 = time.perf_counter()
            ok = yield manager.vertex_handler.on_new_block(block, deps=[])
            assert ok, f'payload block x{r + 1} rejected'
            storage.flush()
            blocks_seconds += time.perf_counter() - t1
    return txs_seconds, blocks_seconds


def run_sweep(
    configs: list[tuple[int, int]],
    *,
    num_txs: int,
    num_blocks: int,
    runs: int,
) -> dict[tuple[int, int], list[tuple[float, float]]]:
    """Drive every (config x run) measurement under a single reactor run and return, per
    (inputs, outputs) config, the list of (txs_seconds, blocks_seconds) for each run."""
    from twisted.internet.defer import inlineCallbacks

    # Built before the reactor runs: the simulated-clock source managers are independent.
    payloads = {c: build_payloads(num_txs, num_blocks, c[0], c[1]) for c in configs}
    results: dict[tuple[int, int], list[tuple[float, float]]] = {c: [] for c in configs}
    failure: dict[str, BaseException] = {}
    reactor = get_global_reactor()

    @inlineCallbacks
    def orchestrate() -> Generator[Any, Any, None]:
        try:
            for c in configs:
                for _ in range(runs):
                    manager = build_target()
                    try:
                        timing = yield inlineCallbacks(feed)(
                            manager, payloads[c], num_txs, num_blocks)
                    finally:
                        yield manager.stop()
                    results[c].append(timing)
        except BaseException as e:  # noqa: B902 — record and stop the reactor cleanly
            failure['error'] = e
        finally:
            reactor.stop()

    reactor.callWhenRunning(orchestrate)
    reactor.run()
    if 'error' in failure:
        raise failure['error']
    return results


def aggregate(
    samples: dict[tuple[int, int], list[tuple[float, float]]],
    *,
    total_txs: int,
) -> dict[tuple[int, int], dict[str, float]]:
    """Per config, reduce the per-run (txs_s, blocks_s) to medians and a tx/s figure.

    `total_txs` is the payload-tx count per run (num_txs x groups), and each `t` is that run's
    total transaction-phase seconds, so `total_txs / t` is the run's throughput. tx/s uses only
    the transaction phase — the headline 'transaction processing' throughput. min/max are kept
    so the report and Bencher can show run-to-run spread."""
    stats: dict[tuple[int, int], dict[str, float]] = {}
    for c, run_list in samples.items():
        txs_t = [t for t, _ in run_list]
        blk_t = [b for _, b in run_list]
        tot_t = [t + b for t, b in run_list]
        tps = [total_txs / t for t in txs_t]
        stats[c] = {
            'tps': statistics.median(tps), 'tps_lo': min(tps), 'tps_hi': max(tps),
            'txs_s': statistics.median(txs_t), 'txs_lo': min(txs_t), 'txs_hi': max(txs_t),
            'blocks_s': statistics.median(blk_t), 'blocks_lo': min(blk_t), 'blocks_hi': max(blk_t),
            'total_s': statistics.median(tot_t), 'total_lo': min(tot_t), 'total_hi': max(tot_t),
        }
    return stats


def _int(value: float) -> str:
    return f'{value:,.0f}'


def _secs(value: float) -> str:
    return f'{value:.3f}'


def _pct(value: float, base: float) -> str:
    if base == 0:
        return '—'
    delta = value / base - 1.0
    return f'{delta * 100:+.1f}%'


def render_table(
    stats: dict[tuple[int, int], dict[str, float]],
    *,
    total_txs: int,
    num_blocks: int,
    runs: int,
    baseline: dict[tuple[int, int], float] | None,
) -> str:
    """Render the per-config table; tx/s is transaction-only, plus the three phase times."""
    configs = sorted(stats)
    first = configs[0]
    first_tps = stats[first]['tps']
    header = ['inputs', 'outputs', 'tx/s', 'in-UTXOs/s (tx/s x in)',
              'txs (s)', 'blocks (s)', 'total (s)', 'tx/s vs first']
    if baseline:
        header += ['tx/s (base)', 'vs base']
    rows: list[list[str]] = []
    for c in configs:
        num_inputs, num_outputs = c
        s = stats[c]
        row = [str(num_inputs), str(num_outputs), _int(s['tps']), _int(s['tps'] * num_inputs),
               _secs(s['txs_s']), _secs(s['blocks_s']), _secs(s['total_s']),
               '—' if c == first else _pct(s['tps'], first_tps)]
        if baseline:
            base_tps = baseline.get(c)
            row += [_int(base_tps) if base_tps else '—', _pct(s['tps'], base_tps) if base_tps else '—']
        rows.append(row)

    widths = [max(len(header[c]), *(len(r[c]) for r in rows)) for c in range(len(header))]

    def line(cells: list[str]) -> str:
        return '| ' + ' | '.join(cell.rjust(widths[c]) for c, cell in enumerate(cells)) + ' |'

    sep = '|' + '|'.join('-' * (w + 2) for w in widths) + '|'
    blocks_desc = f'{num_blocks} block(s)' if num_blocks >= 1 else 'no blocks (txs only)'
    title = f'real reactor, {total_txs:,} txs, {blocks_desc}, median of {runs} run(s)'
    out = [title, '', line(header), sep]
    out += [line(r) for r in rows]
    return '\n'.join(out)


def to_bmf(stats: dict[tuple[int, int], dict[str, float]]) -> dict[str, Any]:
    """Bencher Metric Format: one benchmark per config, with a throughput measure (tx/s)
    and the three phase times in seconds.

    Names are zero-padded (e.g. `tps/02in-04out`) so Bencher orders them numerically rather
    than lexically."""
    bmf: dict[str, Any] = {}
    for c in sorted(stats):
        num_inputs, num_outputs = c
        s = stats[c]
        bmf[f'tps/{num_inputs:02d}in-{num_outputs:02d}out'] = {
            'throughput': {
                'value': round(s['tps'], 2),
                'lower_value': round(s['tps_lo'], 2),
                'upper_value': round(s['tps_hi'], 2),
            },
            'txs-seconds': {
                'value': round(s['txs_s'], 4),
                'lower_value': round(s['txs_lo'], 4),
                'upper_value': round(s['txs_hi'], 4),
            },
            'blocks-seconds': {
                'value': round(s['blocks_s'], 4),
                'lower_value': round(s['blocks_lo'], 4),
                'upper_value': round(s['blocks_hi'], 4),
            },
            'total-seconds': {
                'value': round(s['total_s'], 4),
                'lower_value': round(s['total_lo'], 4),
                'upper_value': round(s['total_hi'], 4),
            },
        }
    return bmf


def describe_environment() -> str:
    """A best-effort one-line hardware/runtime fingerprint, recorded for diagnostics.

    Absolute TPS depends on the machine, so the comparison is only valid across runs on the
    same hardware. Logging this next to the numbers lets a baseline shift be attributed to an
    environment change (e.g. a CI runner gaining or losing cores) rather than to code.

    `cpus` is the number of cores available to this process (honours cgroup/affinity limits on
    Linux) — the relevant figure, not the host's physical core count."""
    # sched_getaffinity (Linux-only) reports cores available to *this* process, honouring
    # cgroup/affinity limits; fall back to the host count elsewhere.
    sched_getaffinity = getattr(os, 'sched_getaffinity', None)
    cpus = len(sched_getaffinity(0)) if sched_getaffinity else (os.cpu_count() or 0)
    cpu_model = platform.processor() or 'unknown'
    mem = 'unknown'
    try:
        with open('/proc/cpuinfo') as fp:
            for line in fp:
                if line.startswith('model name'):
                    cpu_model = line.split(':', 1)[1].strip()
                    break
        with open('/proc/meminfo') as fp:
            for line in fp:
                if line.startswith('MemTotal'):
                    mem = f'{int(line.split()[1]) / (1024 * 1024):.1f} GiB'
                    break
    except OSError:
        pass
    return f"env: cpus={cpus}, cpu='{cpu_model}', mem={mem}, python={platform.python_version()}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--inputs', default=','.join(map(str, DEFAULT_INPUTS)),
                        help='comma-separated inputs per tx to sweep (default: 1,2,4,8,16)')
    parser.add_argument('--outputs', default=None,
                        help='comma-separated outputs per tx; unset = match inputs. When set, '
                             'sweeps the full inputs x outputs matrix (default: match inputs)')
    parser.add_argument('--txs', type=int, default=2000, help='payload txs per group (default: 2000)')
    parser.add_argument('--blocks', type=int, default=1,
                        help='payload blocks, one per group; 0 = transactions only (default: 1)')
    parser.add_argument('--runs', type=int, default=3, help='runs per config; median reported (default: 3)')
    parser.add_argument('--output', default=None, help='write Bencher Metric Format JSON to this path')
    parser.add_argument('--baseline', default=None,
                        help='a previous --output JSON to compare against (adds a vs-base column)')
    args = parser.parse_args()

    inputs = [int(x) for x in args.inputs.split(',') if x.strip()]
    assert inputs, 'no inputs to sweep'
    assert args.blocks >= 0, 'blocks must be >= 0'
    if args.outputs:
        outputs = [int(x) for x in args.outputs.split(',') if x.strip()]
        assert outputs, 'no outputs to sweep'
        configs = [(i, o) for i in inputs for o in outputs]
    else:
        # unset: outputs match inputs (the diagonal), preserving the default sweep
        configs = [(i, i) for i in inputs]

    # each feeder adds one dummy output; keep the total under the dummy's 255-output ceiling
    groups = max(args.blocks, 1)
    max_feeders = groups * max((args.txs * i + FEEDER_OUTPUTS - 1) // FEEDER_OUTPUTS for i in inputs)
    assert max_feeders <= 254, (
        f'too many feeders ({max_feeders}) for the dummy 255-output limit; '
        f'reduce --txs/--inputs/--blocks'
    )

    total_txs = args.txs * groups
    samples = run_sweep(configs, num_txs=args.txs, num_blocks=args.blocks, runs=args.runs)
    stats = aggregate(samples, total_txs=total_txs)

    baseline = None
    if args.baseline:
        with open(args.baseline) as fp:
            raw = json.load(fp)
        baseline = {}
        for name, body in raw.items():
            # name is 'tps/NNin-NNout'; recover the (inputs, outputs) config and throughput value
            key = name.split('/')[1]
            num_inputs = int(key.split('in-')[0])
            num_outputs = int(key.split('in-')[1].split('out')[0])
            baseline[(num_inputs, num_outputs)] = body['throughput']['value']

    print()
    print(describe_environment())
    print(render_table(stats, total_txs=total_txs, num_blocks=args.blocks, runs=args.runs, baseline=baseline))
    print()

    if args.output:
        bmf = to_bmf(stats)
        with open(args.output, 'w') as fp:
            json.dump(bmf, fp, indent=2)
        print(f'Bencher Metric Format written to: {args.output}')


if __name__ == '__main__':
    main()
