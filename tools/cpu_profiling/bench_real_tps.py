#!/usr/bin/env python
"""Measure end-to-end sync TPS on a REAL reactor (no simulated clock).

A synthetic DAG (blocks confirming spend-chains of txs) is built once with the DAG Builder,
serialized, and then fed to a fresh manager exactly like p2p sync does: every vertex enters
through ``verification_service.verify_bytes`` and every block is connected through
``vertex_handler.on_new_block(block, deps=txs)``. The real reactor means the batched
precompute actually runs on the reactor thread pool (deferToThreadPool), storage is real
RocksDB, and the measured number is honest wall-clock TPS of the connect pipeline.

    python tools/cpu_profiling/bench_real_tps.py --arm batched --blocks 40 --txs 50
    python tools/cpu_profiling/bench_real_tps.py --arm no-precompute
    python tools/cpu_profiling/bench_real_tps.py --arm python
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any, Generator

# _common sets HATHOR_CONFIG_YAML + the global reactor at import time, before any hathor import runs
from _common import build_manager, get_dag_builder, reward_lock_blocks

from hathor.manager import HathorManager
from hathor.reactor import get_global_reactor
from hathor.simulator.patches import SimulatorCpuMiningService
from hathor.simulator.simulator import _build_vertex_verifiers
from hathor.transaction import Block, Transaction
from hathor.util import Random
from hathor.verification.script_verification_pool import ScriptVerificationMode
from hathor_tests.unittest import TestBuilder

BASE_BLOCKS = reward_lock_blocks() + 2


def build_dag_str(*, num_txs: int, num_blocks: int, num_inputs: int = 1) -> str:
    """Blocks x1..xR each confirming a spend-chain group of `num_txs` txs (one dummy-funded
    tx per group keeps the dummy under the 255-output wire limit).

    Each payload tx has exactly `num_inputs` inputs and `num_inputs` outputs: tx t_{i+1}
    spends all `num_inputs` outputs of t_i, so the chain stays in-batch-resolvable. For
    num_inputs > 1 a per-group source `g{r}_s` (one extra confirmed tx) seeds the chain with
    `num_inputs` outputs; the source is funded from the dummy by the builder."""
    lines = [
        f'blockchain genesis b[1..{BASE_BLOCKS}]',
        f'blockchain b{BASE_BLOCKS} x[1..{num_blocks}]',
        f'b{BASE_BLOCKS - 1} < dummy',
        f'b{BASE_BLOCKS} --> dummy',
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


def build_payloads(num_txs: int, num_blocks: int, num_inputs: int) -> dict[str, bytes]:
    """Build the DAG once (throwaway simulated-clock manager) and serialize every vertex."""
    source = build_manager(seed=1234)
    dag_str = build_dag_str(num_txs=num_txs, num_blocks=num_blocks, num_inputs=num_inputs)
    artifacts = get_dag_builder(source).build_from_str(dag_str)
    return {node.name: bytes(vertex) for node, vertex in artifacts.list}


def build_target(arm: str, workers: int) -> HathorManager:
    """A fresh manager on the REAL reactor (thread pool available, real RocksDB temp dir)."""
    builder = (
        TestBuilder()
        .set_rng(Random(5678))
        .set_reactor(get_global_reactor())
        .set_vertex_verifiers_builder(_build_vertex_verifiers)
        .set_cpu_mining_service(SimulatorCpuMiningService())
        # production nodes run with the tx-storage cache; without it every get falls through
        # to weakrefs/RocksDB and the LRU bookkeeping degenerates into pure eviction churn
        .use_tx_storage_cache(100_000)
    )
    if arm != 'python':
        builder.set_script_verification_config(
            mode=ScriptVerificationMode.RUST, num_workers=workers, min_inputs=1)
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
    """Feed the DAG through the p2p entrypoints; return the payload-section wall time."""
    service = manager.verification_service
    storage = manager.tx_storage

    def parse(name: str) -> Any:
        return service.verify_bytes(payloads[name], storage=storage)

    # base chain (reward-lock window) + the dummy funding tx, not measured
    for i in range(1, BASE_BLOCKS + 1):
        block = parse(f'b{i}')
        assert isinstance(block, Block)
        deps = []
        if i == BASE_BLOCKS:
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--arm', choices=['batched', 'no-precompute', 'python'], required=True)
    parser.add_argument('--workers', type=int, default=12)
    parser.add_argument('--blocks', type=int, default=40)
    parser.add_argument('--txs', type=int, default=50)
    parser.add_argument('--inputs', type=int, default=1, help='inputs (and outputs) per payload tx')
    args = parser.parse_args()

    if args.arm == 'no-precompute':
        from hathor.verification.rust_verification_service import RustVerificationService
        RustVerificationService.precompute_stateless_batch = (  # type: ignore[method-assign]
            lambda self, vertices, params, **kwargs: None)

    payloads = build_payloads(args.txs, args.blocks, args.inputs)
    manager = build_target(args.arm, args.workers)
    reactor = get_global_reactor()
    exit_code = 1

    from twisted.internet.defer import inlineCallbacks

    @inlineCallbacks
    def run() -> Generator[Any, Any, None]:
        nonlocal exit_code
        try:
            elapsed = yield inlineCallbacks(feed)(manager, payloads, args.txs, args.blocks, args.inputs)
            total = args.blocks * args.txs
            print(f'{args.arm}: {args.inputs}-in/{args.inputs}-out, connected {total} txs '
                  f'(+{args.blocks} blocks) in {elapsed:.2f}s -> {total / elapsed:.0f} tx/s [real reactor]')
            exit_code = 0
        except BaseException as e:
            print(f'{args.arm}: FAILED: {e!r}')
            raise
        finally:
            reactor.stop()

    reactor.callWhenRunning(run)
    reactor.run()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
