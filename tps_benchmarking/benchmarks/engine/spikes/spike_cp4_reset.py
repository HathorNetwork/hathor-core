"""
CP-4 block-reset experiment: is S5's (and S6's) growth mempool-driven and reset by a block?

Drives M txs (watch S5/S6 climb), injects ONE block to confirm the mempool (timing the
block's O(M) cost), then drives M more txs and checks whether S5/S6 drop back toward
their clean-slate values. This validates the M/Tb sustainable-throughput model:
  - if S5 resets -> growth is unconfirmed-mempool-driven, Tb bounds it (model holds);
  - if S6 does NOT reset -> part of it is permanent (storage), a separate bottleneck.

Run:  poetry run python tps_benchmarking/benchmarks/engine/spikes/spike_cp4_reset.py
"""
import os

from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
os.environ.setdefault("HATHOR_CONFIG_YAML", UNITTESTS_SETTINGS_FILEPATH)

from hathor.reactor import initialize_global_reactor
initialize_global_reactor(use_asyncio_reactor=True)

import time

from hathor.simulator.utils import add_new_blocks
from hathor_tests.utils import BURN_ADDRESS

from hathor_tps_bench.driver.runner import _drive_one, build_params
from hathor_tps_bench.node import NodeHarness
from hathor_tps_bench.workload import get_txtype

M = 250  # txs per phase


def mempool_size(manager) -> int:
    return sum(1 for _ in manager.tx_storage.iter_mempool_tips())


def avg(xs):
    return sum(xs) / len(xs) if xs else 0.0


def main():
    harness = NodeHarness(seed=1234).start()
    manager = harness.manager
    vh = manager.vertex_handler
    settings = manager._settings

    prepared = get_txtype("defunct")().build(harness, 2 * M, 1, 2)
    s5, s6 = [], []

    # ---- phase 1: drive M txs (no blocks) ----
    params = build_params(manager)
    for i in range(M):
        rec = _drive_one(manager, vh, settings, params, prepared[i].raw, i)
        s5.append(rec.stages["S5"].wall_ns / 1000)
        s6.append(rec.stages["S6"].wall_ns / 1000)
    mp_before = mempool_size(manager)

    # ---- inject ONE block (confirm the mempool); time its O(M) cost ----
    t0 = time.perf_counter()
    add_new_blocks(manager, 1, address=BURN_ADDRESS)
    block_ms = (time.perf_counter() - t0) * 1000
    mp_after = mempool_size(manager)

    # ---- phase 2: drive M more txs (best_block changed -> rebuild params) ----
    params = build_params(manager)
    for i in range(M, 2 * M):
        rec = _drive_one(manager, vh, settings, params, prepared[i].raw, i)
        s5.append(rec.stages["S5"].wall_ns / 1000)
        s6.append(rec.stages["S6"].wall_ns / 1000)

    harness.stop()

    p1_early, p1_late = slice(5, 15), slice(M - 15, M - 5)
    p2_early, p2_late = slice(M + 5, M + 15), slice(2 * M - 15, 2 * M - 5)

    print(f"mempool tips: before block = {mp_before}, after block = {mp_after}  "
          f"(block confirmed ~{mp_before - mp_after})")
    print(f"block confirm cost: {block_ms:.1f} ms  for M={M}\n")

    print(f"{'stage':4} {'p1 early':>9} {'p1 late':>9} {'p2 early':>9} {'p2 late':>9}   (us)")
    for name, arr in (("S5", s5), ("S6", s6)):
        print(f"{name:4} {avg(arr[p1_early]):9.0f} {avg(arr[p1_late]):9.0f} "
              f"{avg(arr[p2_early]):9.0f} {avg(arr[p2_late]):9.0f}")

    s5_reset = avg(s5[p2_early]) / avg(s5[p1_late]) if avg(s5[p1_late]) else 0
    s6_reset = avg(s6[p2_early]) / avg(s6[p1_late]) if avg(s6[p1_late]) else 0
    print(f"\nS5 reset ratio (p2-early / p1-late): {s5_reset:.2f}  (<<1 => block reset it)")
    print(f"S6 reset ratio (p2-early / p1-late): {s6_reset:.2f}")
    print("\nverdict:",
          "S5 IS mempool-driven & block-resettable -> M/Tb model holds"
          if s5_reset < 0.6 else
          "S5 did NOT reset -> growth is (partly) permanent; model needs rethink")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
