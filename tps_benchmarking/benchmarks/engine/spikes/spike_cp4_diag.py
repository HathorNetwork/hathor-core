"""
CP-4 diagnostic: localise the S5 cost (and the post-block explosion).

Splits S5 (_unsafe_save_and_run_consensus) into its three sub-steps:
  meta   = vertex.update_initial_metadata  (adds tx as a CHILD of each parent)
  save   = tx_storage.save_transaction
  cons   = consensus.unsafe_update
and tracks acceptance / voiding / mempool size, across: phase1 (M) -> block -> phase2 (M).
"""
import os

from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
os.environ.setdefault("HATHOR_CONFIG_YAML", UNITTESTS_SETTINGS_FILEPATH)

from hathor.reactor import initialize_global_reactor
initialize_global_reactor(use_asyncio_reactor=True)

import sys
import time

from hathor.execution_manager import non_critical_code
from hathor.reward_lock import is_spent_reward_locked
from hathor.simulator.utils import add_new_blocks
from hathor_tests.utils import BURN_ADDRESS

from hathor_tps_bench.driver.runner import build_params
from hathor_tps_bench.node import NodeHarness
from hathor_tps_bench.workload import get_txtype

# argv: [tx_type=transparent] [M=250]
TXTYPE = sys.argv[1] if len(sys.argv) > 1 else "transparent"
M = int(sys.argv[2]) if len(sys.argv) > 2 else 250


def mempool_size(manager):
    return sum(1 for _ in manager.tx_storage.iter_mempool_tips())


def confirmed_count(manager, hashes):
    n = 0
    for h in hashes:
        try:
            if manager.tx_storage.get_transaction(h).get_metadata().first_block is not None:
                n += 1
        except Exception:
            pass
    return n


def drive_split(manager, vh, settings, params, raw):
    ns = time.perf_counter_ns
    vtx = manager.vertex_parser.deserialize(raw)
    vtx.storage = manager.tx_storage
    _ = (not manager.tx_storage.transaction_exists(vtx.hash) and not vtx.is_double_spending()
         and not vtx.is_spending_voided_tx() and not is_spent_reward_locked(settings, vtx))
    vh._validate_vertex(vtx, params)
    # ---- S5 split ----
    t = ns(); vtx.update_initial_metadata(save=False); meta_us = (ns() - t) / 1000
    t = ns(); manager.tx_storage.save_transaction(vtx); save_us = (ns() - t) / 1000
    with non_critical_code(vh._log):
        manager.tx_storage.indexes.add_to_non_critical_indexes(vtx)
    t = ns(); events = vh._consensus.unsafe_update(vtx); cons_us = (ns() - t) / 1000
    vh._post_consensus(vtx, params, events, quiet=True)
    voided = bool(vtx.get_metadata().voided_by)
    return vtx.hash, meta_us, save_us, cons_us, voided


def avg(xs, sl):
    xs = xs[sl]
    return sum(xs) / len(xs) if xs else 0.0


def main():
    harness = NodeHarness(seed=1234).start()
    manager, vh, settings = harness.manager, harness.manager.vertex_handler, harness.manager._settings
    prepared = get_txtype(TXTYPE)().build(harness, 2 * M, 1, 2)
    exact = sum(1 for p in prepared if p.n_inputs == 1 and p.n_outputs == 2)
    print(f"workload={TXTYPE!r}  M={M}  exact I/O={exact}/{2 * M}")

    meta, save, cons, voided = [], [], [], 0
    hashes = []

    params = build_params(manager)
    for i in range(M):
        h, m, s, c, v = drive_split(manager, vh, settings, params, prepared[i].raw)
        meta.append(m); save.append(s); cons.append(c); voided += v; hashes.append(h)
    mp_before = mempool_size(manager)

    t0 = time.perf_counter()
    add_new_blocks(manager, 1, address=BURN_ADDRESS)
    block_ms = (time.perf_counter() - t0) * 1000
    mp_after = mempool_size(manager)
    conf = confirmed_count(manager, hashes)

    params = build_params(manager)
    for i in range(M, 2 * M):
        h, m, s, c, v = drive_split(manager, vh, settings, params, prepared[i].raw)
        meta.append(m); save.append(s); cons.append(c); voided += v
    harness.stop()

    e, l = slice(5, 15), slice(M - 15, M - 5)
    e2, l2 = slice(M + 5, M + 15), slice(2 * M - 15, 2 * M - 5)
    print(f"block: confirmed {conf}/{M} phase-1 txs; mempool {mp_before} -> {mp_after}; cost {block_ms:.1f} ms")
    print(f"total voided (both phases): {voided}/{2 * M}\n")
    print(f"{'sub-step':6} {'p1 early':>9} {'p1 late':>9} {'p2 early':>9} {'p2 late':>9}   (us)")
    for name, arr in (("meta", meta), ("save", save), ("cons", cons)):
        print(f"{name:6} {avg(arr, e):9.1f} {avg(arr, l):9.1f} {avg(arr, e2):9.1f} {avg(arr, l2):9.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
