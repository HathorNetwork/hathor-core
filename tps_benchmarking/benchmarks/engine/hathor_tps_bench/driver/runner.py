"""The single-thread driver.

For each prepared tx, it replays `VertexHandler._old_on_new_vertex` by hand around the
real anchor functions, timing each stage (S1..S6) with perf_counter_ns (wall) +
process_time_ns (CPU). Funding is already in storage (the workload preloaded it); this
only drives the *target* txs. A background sampler runs alongside, and disk I/O is read
at the batch boundary after a flush.

Stage → anchor (RFC §"The pipeline and its anchor functions"):
  S1   manager.vertex_parser.deserialize(raw)
  S2   manager pre-checks (exists / double-spend / spending-voided / reward-lock)
  S3S4 VertexHandler._validate_vertex            (full verification)
  S5   VertexHandler._unsafe_save_and_run_consensus
  S6   VertexHandler._post_consensus             (incl. the 2nd validate_full)
"""
from __future__ import annotations

import time
from typing import Any

from hathor.feature_activation.utils import Features
from hathor.reward_lock import is_spent_reward_locked
from hathor.verification.verification_params import VerificationParams

from hathor_tps_bench.metrics.collector import RunResult
from hathor_tps_bench.metrics.model import BatchResources, StageTiming, TxRecord
from hathor_tps_bench.probes import procstats, storage_stats
from hathor_tps_bench.probes.sampler import ProcSampler


def build_params(manager: Any) -> VerificationParams:
    """Reconstruct what VertexHandler.on_new_relayed_vertex builds. best_block is fixed
    during the timed loop (we add no blocks), so this is built once per batch."""
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


def _drive_one(manager, vh, settings, params, raw: bytes, index: int) -> TxRecord:
    stages: dict[str, StageTiming] = {}

    def timed(key: str, fn):
        w, c = time.perf_counter_ns(), time.process_time_ns()
        result = fn()
        stages[key] = StageTiming(
            wall_ns=time.perf_counter_ns() - w,
            cpu_ns=time.process_time_ns() - c,
        )
        return result

    vtx = timed("S1", lambda: manager.vertex_parser.deserialize(raw))
    vtx.storage = manager.tx_storage
    timed("S2", lambda: (
        not manager.tx_storage.transaction_exists(vtx.hash)
        and not vtx.is_double_spending()
        and not vtx.is_spending_voided_tx()
        and not is_spent_reward_locked(settings, vtx)
    ))
    valid = timed("S3S4", lambda: vh._validate_vertex(vtx, params))
    events = timed("S5", lambda: vh._unsafe_save_and_run_consensus(vtx))
    timed("S6", lambda: vh._post_consensus(vtx, params, events, quiet=True))

    accepted = bool(valid) and not vtx.get_metadata().voided_by
    return TxRecord(
        index=index,
        tx_id=vtx.hash_hex,
        n_inputs=len(vtx.inputs),
        n_outputs=len(vtx.outputs),
        size_bytes=len(raw),
        accepted=accepted,
        stages=stages,
    )


def run_batch(harness, prepared, *, sampler_interval_s: float = 0.1) -> RunResult:
    manager = harness.manager
    vh = manager.vertex_handler
    settings = manager._settings
    params = build_params(manager)

    io_r0, io_w0 = procstats.read_io()
    rss_start = procstats.read_rss_bytes()
    sampler = ProcSampler(interval_s=sampler_interval_s).start()

    records: list[TxRecord] = []
    w0, c0 = time.perf_counter(), time.process_time()
    for i, p in enumerate(prepared):
        records.append(_drive_one(manager, vh, settings, params, p.raw, i))
        sampler.set_progress(i + 1)
    wall_s = time.perf_counter() - w0
    cpu_s = time.process_time() - c0

    storage_stats.flush(manager)  # realise deferred writes before reading disk I/O
    sampler.stop()

    io_r1, io_w1 = procstats.read_io()
    rss_end = procstats.read_rss_bytes()
    batch = BatchResources(
        wall_s=wall_s,
        cpu_s=cpu_s,
        io_read_bytes=io_r1 - io_r0,
        io_write_bytes=io_w1 - io_w0,
        rss_start_bytes=rss_start,
        rss_peak_bytes=max(sampler.rss_peak, rss_end),
        rss_end_bytes=rss_end,
        fd_peak=sampler.fd_peak,
        sst_bytes=storage_stats.read_sst_bytes(manager),
    )
    return RunResult(records=records, batch=batch, samples=sampler.samples)
