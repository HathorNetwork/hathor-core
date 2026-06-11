"""Shared helpers for the CPU profiling scripts in this directory.

These scripts build a synthetic DAG with the DAG Builder, bootstrap an in-memory
HathorManager (the same setup used by the DAG builder unit tests), propagate all
the "setup" vertices and then run ``on_new_tx()`` on the target vertices under
cProfile.

The profiled call goes through the whole vertex-addition pipeline:
deserialization (optional, see below), verification, consensus and index update.
"""

from __future__ import annotations

import os

# IMPORTANT: the settings must be selected *before* importing any hathor module,
# because most of them read the global settings at import time. We use the same
# unittests config the test suite uses, so that the genesis output script matches
# the DAG Builder genesis wallet and the reward-lock window is small.
from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH

os.environ.setdefault(
    'HATHOR_CONFIG_YAML',
    os.environ.get('HATHOR_TEST_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH),
)

import cProfile  # noqa: E402
import logging  # noqa: E402
import pstats  # noqa: E402
import time  # noqa: E402
from typing import Callable, Iterable  # noqa: E402

import structlog  # noqa: E402

# Silence info/debug logging so it neither floods the console nor skews the
# profile (structlog's filtering bound logger short-circuits before formatting).
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))

# The global reactor must be initialized before importing the hathor_tests
# helpers, because some of them build wallets at import time.
from hathor.reactor import initialize_global_reactor  # noqa: E402

initialize_global_reactor(use_asyncio_reactor=True)

from hathor.conf.get_settings import get_global_settings  # noqa: E402
from hathor.manager import HathorManager  # noqa: E402
from hathor.simulator.clock import MemoryReactorHeapClock  # noqa: E402
from hathor.simulator.patches import SimulatorCpuMiningService  # noqa: E402
from hathor.simulator.simulator import _build_vertex_verifiers  # noqa: E402
from hathor.util import Random  # noqa: E402
from hathor_tests.dag_builder.builder import TestDAGBuilder  # noqa: E402
from hathor_tests.unittest import TestBuilder  # noqa: E402


def build_manager(*, seed: int = 1234) -> HathorManager:
    """Bootstrap a started, in-memory HathorManager ready to process vertices.

    The setup mirrors ``DAGBuilderTestCase``: the PoW-skipping simulator verifiers
    and CPU mining service so the synthetic DAG can be built and resolved quickly.
    """
    clock = MemoryReactorHeapClock()
    clock.advance(time.time())

    builder = (
        TestBuilder()
        .set_rng(Random(seed))
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


def get_dag_builder(manager: HathorManager) -> TestDAGBuilder:
    return TestDAGBuilder.from_manager(manager)


def reward_lock_blocks() -> int:
    """Number of blocks required before a block reward can be spent."""
    return get_global_settings().REWARD_SPEND_MIN_BLOCKS


def profile_on_new_tx(
    manager: HathorManager,
    artifacts,
    is_target: Callable[[str], bool],
    *,
    output: str | None,
    sort: str = 'tottime',
    limit: int = 40,
    include_deserialization: bool = True,
) -> list:
    """Propagate the setup vertices and profile ``on_new_tx()`` on the targets.

    ``is_target(name)`` selects which DAG nodes are the profiling targets. Every
    other vertex is propagated first (the "setup" phase) so that, when the targets
    are added, all of their dependencies are already in the storage.

    Targets are profiled in DAG (topological) order, so it is safe for a target to
    depend on a previously-profiled target (e.g. a chain of blocks).

    Returns the list of profiled (name, vertex) targets.
    """
    setup: list = []
    targets: list = []
    for node, vertex in artifacts.list:
        (targets if is_target(node.name) else setup).append((node.name, vertex))

    assert targets, 'no target vertices selected for profiling'

    # Setup phase: add every non-target vertex (not profiled).
    for name, vertex in setup:
        ok = manager.vertex_handler.on_new_relayed_vertex(vertex)
        assert ok, f'setup propagation failed at {name}'

    # Pre-serialize the targets so that, when requested, the deserialization cost
    # is measured *inside* the profiled region (matching the real p2p receive path:
    # parser.deserialize(bytes) -> vertex.storage = tx_storage -> on_new_tx).
    payloads = [(name, vertex, bytes(vertex)) for name, vertex in targets]

    parser = manager.vertex_parser
    tx_storage = manager.tx_storage

    def run() -> None:
        for name, original, data in payloads:
            if include_deserialization:
                vertex = parser.deserialize(data)
                vertex.storage = tx_storage
            else:
                vertex = original
            ok = manager.on_new_tx(vertex, propagate_to_peers=False)
            assert ok, f'on_new_tx failed for {name}'

    profiler = cProfile.Profile()
    wall0 = time.perf_counter()
    cpu0 = time.process_time()
    profiler.enable()
    run()
    profiler.disable()
    cpu_dt = time.process_time() - cpu0
    wall_dt = time.perf_counter() - wall0

    n = len(payloads)
    print()
    print(f'Profiled {n} call(s) to on_new_tx() '
          f'(deserialization {"included" if include_deserialization else "excluded"})')
    print(f'  total CPU time : {cpu_dt * 1000:.3f} ms  ({cpu_dt / n * 1000:.3f} ms/call)')
    print(f'  total wall time: {wall_dt * 1000:.3f} ms  ({wall_dt / n * 1000:.3f} ms/call)')
    print()

    stats = pstats.Stats(profiler)
    stats.strip_dirs().sort_stats(sort).print_stats(limit)

    if output:
        profiler.dump_stats(output)
        print(f'\nRaw cProfile stats written to: {output}')
        print(f'Tip: visualize with  profiles/cprof2pdf {output}')

    return [(name, vertex) for name, vertex, _ in payloads]


def add_common_args(parser) -> None:
    """Add the CLI flags shared by both profiling scripts."""
    parser.add_argument('--seed', type=int, default=1234, help='RNG seed for the manager (default: 1234)')
    parser.add_argument('--sort', default='tottime',
                        help='pstats sort key: tottime, cumulative, ncalls, ... (default: tottime)')
    parser.add_argument('--limit', type=int, default=40,
                        help='number of lines to print in the stats table (default: 40)')
    parser.add_argument('--output', default=None,
                        help='path to dump the raw cProfile stats (.prof) for later analysis')
    parser.add_argument('--no-deserialization', action='store_true',
                        help='do not measure vertex deserialization (profile on_new_tx only)')


def join_lines(lines: Iterable[str]) -> str:
    return '\n'.join(lines)
