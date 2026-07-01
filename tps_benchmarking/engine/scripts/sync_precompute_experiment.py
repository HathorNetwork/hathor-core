"""Sync-path fused-pipeline experiment (the deferred PR #1729 optimization).

Measures the Rust batch stateless+script precompute (`RustVerificationService.precompute_stateless_batch`
via `htr_lib.verify_tx_from_bytes`) against the standard per-tx path. The fused call does parse +
stateless + sigops + sighash + full script eval for a WHOLE batch in one GIL-released Rust call
(amortized FFI + rayon parallelism); the per-tx verification then consumes the stash.

This is the block-SYNC scenario: vertices arrive as a batch, not one at a time. Both modes run the
identical full pipeline (incl. S5 save+consensus); only the verification work differs.

Run (from hathor-core root):
  PYTHONPATH=. <venv>/bin/python tps_benchmarking/engine/scripts/sync_precompute_experiment.py
"""
from __future__ import annotations

import os
import time

os.environ.setdefault(
    "HATHOR_CONFIG_YAML",
    __import__("hathorlib.conf", fromlist=["UNITTESTS_SETTINGS_FILEPATH"]).UNITTESTS_SETTINGS_FILEPATH,
)
from hathor.reactor import initialize_global_reactor  # noqa: E402

initialize_global_reactor(use_asyncio_reactor=True)

from hathor_tps_bench.driver.runner import build_params  # noqa: E402
from hathor_tps_bench.node import NodeHarness  # noqa: E402
from hathor_tps_bench.workload import get_txtype  # noqa: E402

N, NUM_IN, NUM_OUT, SEED = 300, 3, 2, 17


def _snapshot(manager):
    manager.tx_storage.flush()
    return {
        tx.hash: (tx.get_metadata().validation.name, bytes(tx))
        for tx in manager.tx_storage.get_all_transactions()
    }


def _run(sync_precompute: bool) -> tuple[float, dict, bool]:
    """Build a fresh batch, drive it (with the batch precompute first when sync_precompute),
    timing the verification+processing of the measured txs. Returns (tx/s, stored-state, used_precompute)."""
    h = NodeHarness(seed=SEED, sync_precompute=sync_precompute).start()  # opt defaults all-ON
    manager = h.manager
    prepared = get_txtype("1-tip-transparent")().build(h, N, NUM_IN, NUM_OUT)
    txs = [p.tx for p in prepared]
    params = build_params(manager)
    used_precompute = False

    t0 = time.perf_counter()
    if sync_precompute and h.rust_service is not None:
        # one GIL-released Rust call for the whole batch (parse+stateless+sigops+sighash+scripts)
        h.rust_service.precompute_stateless_batch(txs, params, include_scripts=True)
        used_precompute = h.rust_service._script_verification_pool.has_script_results(
            txs[0]._hash, int(params.features.opcodes_version))
    for tx in txs:
        assert manager.vertex_handler.on_new_relayed_vertex(tx), "tx rejected"
    if sync_precompute and h.rust_service is not None:
        h.rust_service.discard_precomputed(txs)
    elapsed = time.perf_counter() - t0

    state = _snapshot(manager)
    h.stop()
    return N / elapsed, state, used_precompute


def main() -> None:
    print(f"sync-precompute experiment: N={N} I={NUM_IN} O={NUM_OUT}, 1-tip-transparent, all opts ON\n")
    reps = 3
    sync_tps, std_tps = [], []
    state_sync = state_std = None
    used = False
    for _ in range(reps):
        s, st_s, u = _run(True)
        n, st_n, _ = _run(False)
        sync_tps.append(s)
        std_tps.append(n)
        state_sync, state_std = st_s, st_n
        used = used or u

    def med(v):
        return sorted(v)[len(v) // 2]

    ms, mn = med(sync_tps), med(std_tps)
    print(f"  precompute actually ran (stash populated): {used}")
    print(f"  stored-state identical (sync vs standard):  {state_sync == state_std}")
    print(f"  standard per-tx   : {mn:.0f} tx/s  (runs: {[round(x) for x in std_tps]})")
    print(f"  sync precompute   : {ms:.0f} tx/s  (runs: {[round(x) for x in sync_tps]})")
    print(f"  sync / standard   : {ms / mn:.2f}x")


if __name__ == "__main__":
    main()
