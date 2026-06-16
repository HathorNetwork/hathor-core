"""
CP-4 stage-timing mini-spike: de-risk decomposing tx processing into S1..S6.

Replays VertexHandler._old_on_new_vertex by hand around the real anchor functions,
timing each stage with perf_counter_ns (wall) + process_time_ns (CPU). Confirms every
tx is accepted and that the per-stage split is sane (S3+S4 verify and S6's second
validate_full should dominate).

Run:  poetry run python tps_benchmarking/benchmarks/engine/spikes/spike_cp4_stages.py
"""
import os

from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
os.environ.setdefault("HATHOR_CONFIG_YAML", UNITTESTS_SETTINGS_FILEPATH)

from hathor.reactor import initialize_global_reactor
initialize_global_reactor(use_asyncio_reactor=True)

import time
from statistics import mean

from hathor.feature_activation.utils import Features
from hathor.reward_lock import is_spent_reward_locked
from hathor.verification.verification_params import VerificationParams

from hathor_tps_bench.node import NodeHarness
from hathor_tps_bench.workload import get_txtype

N_TXS = 50
N_INPUTS = 1
N_OUTPUTS = 2
STAGES = ("S1", "S2", "S3S4", "S5", "S6")


def build_params(manager) -> VerificationParams:
    # Reconstruct what VertexHandler.on_new_relayed_vertex builds. best_block is fixed
    # during the timed loop (we add no blocks), so build it once.
    vh = manager.vertex_handler
    best_block = vh._tx_storage.get_best_block()
    features = Features.for_mempool(
        settings=vh._settings, feature_service=vh._feature_service, best_block=best_block
    )
    return VerificationParams(
        reject_locked_reward=True,
        nc_block_root_id=best_block.get_metadata().nc_block_root_id,
        features=features,
    )


def timed(store, key, fn):
    w, c = time.perf_counter_ns(), time.process_time_ns()
    r = fn()
    store[key].append((time.perf_counter_ns() - w, time.process_time_ns() - c))
    return r


def main():
    harness = NodeHarness(seed=1234).start()
    manager = harness.manager
    vh = manager.vertex_handler
    settings = manager._settings
    parser = manager.vertex_parser

    prepared = get_txtype("defunct")().build(harness, N_TXS, N_INPUTS, N_OUTPUTS)
    params = build_params(manager)

    timings = {s: [] for s in STAGES}
    accepted = 0

    for p in prepared:
        raw = p.raw
        vtx = timed(timings, "S1", lambda: parser.deserialize(raw))
        vtx.storage = manager.tx_storage

        ok2 = timed(timings, "S2", lambda: (
            not manager.tx_storage.transaction_exists(vtx.hash)
            and not vtx.is_double_spending()
            and not vtx.is_spending_voided_tx()
            and not is_spent_reward_locked(settings, vtx)
        ))
        valid = timed(timings, "S3S4", lambda: vh._validate_vertex(vtx, params))
        events = timed(timings, "S5", lambda: vh._unsafe_save_and_run_consensus(vtx))
        timed(timings, "S6", lambda: vh._post_consensus(vtx, params, events, quiet=True))

        if ok2 and valid and not vtx.get_metadata().voided_by:
            accepted += 1

    harness.stop()

    print(f"accepted: {accepted}/{N_TXS}\n")
    print(f"{'stage':6} {'mean wall us':>13} {'mean cpu us':>12} {'share':>7}")
    means_w = {s: mean(t[0] for t in timings[s]) / 1000 for s in STAGES}
    total_w = sum(means_w.values())
    for s in STAGES:
        mc = mean(t[1] for t in timings[s]) / 1000
        print(f"{s:6} {means_w[s]:13.1f} {mc:12.1f} {means_w[s] / total_w:7.1%}")
    print(f"{'TOTAL':6} {total_w:13.1f}")
    print(f"\nprocessing TPS (1 / mean per-tx total wall): {1e6 / total_w:.0f} tx/s")

    ok = accepted == N_TXS
    print(f"\nSPIKE RESULT: {'PASS ✓' if ok else 'FAIL ✗'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
