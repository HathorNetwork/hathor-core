"""
Stream memory benchmark for shielded transactions.

Same sweep grid as benchmark_stream_time.py (stream sizes 100..1000, shapes
(2,2)/(4,4)/(8,8)/(16,16), modes amount_hidden vs fully_shielded), but instead
of timing we measure:

  PAYLOAD BYTES (deterministic, per-artifact):
    - commitments_bytes:       sum of Pedersen commitment sizes across outputs
    - blinded_gens_bytes:      sum of blinded asset generator sizes (==asset_commitment in fully_shielded)
    - range_proofs_bytes:      sum of Borromean range-proof sizes across outputs
    - surjection_proofs_bytes: sum of surjection-proof sizes (0 in amount_hidden)
    - payload_total_bytes:     sum of the above across the entire stream
    - per_tx_payload_bytes:    payload_total_bytes / stream_size

  PROCESS MEMORY (sampled with psutil; noisy but reflects real-world cost):
    - rss_baseline_kib:   RSS just before stream construction
    - rss_after_build_kib: RSS once all proofs are built and held in memory
    - rss_peak_build_kib:  peak RSS observed during proof creation
    - rss_after_verify_kib: RSS after the whole stream has been verified
    - rss_peak_verify_kib:  peak RSS during verification

  PYTHON-OBJECT MEMORY (tracemalloc; bytes attributable to Python allocations):
    - tracemalloc_peak_build_kib
    - tracemalloc_peak_verify_kib

Process memory matters because the verifier (full node) must hold the unverified
batch of incoming proofs while it processes them. Payload bytes matter because
they go on the wire and into block storage.

Caveats:
  - The Rust FFI allocates outside Python's tracemalloc, so tracemalloc figures
    are an undercount; psutil RSS is what reflects total cost.
  - RSS is influenced by other processes and Python's own allocator caching;
    we sample peak in a small polling thread to catch transient spikes.
  - We force gc.collect() before sampling baselines.
"""

from __future__ import annotations

import argparse
import csv
import gc
import os
import statistics
import threading
import time
import tracemalloc

import psutil

from stream_common import (
    DEFAULT_SHAPES,
    MODE_FULLY_SHIELDED,
    MODES,
    STREAM_SIZES,
    build_stream,
    parse_shape,
    seal_tx,
    shape_label,
)
from hathor.crypto.shielded.balance import verify_balance
from hathor.crypto.shielded.range_proof import verify_range_proof
from hathor.crypto.shielded.surjection import verify_surjection_proof

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results_memory')


# --------------------------------------------------------------------------
# RSS peak sampler — runs in a background thread, polling rapidly.
# --------------------------------------------------------------------------

class RSSPeakSampler:
    """Polls process RSS in a background thread; .peak_kib is updated live."""

    def __init__(self, interval_s: float = 0.005):
        self.proc = psutil.Process()
        self.interval_s = interval_s
        self.peak_kib = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _sample(self) -> int:
        return self.proc.memory_info().rss // 1024

    def __enter__(self) -> 'RSSPeakSampler':
        self.peak_kib = self._sample()
        self._stop.clear()

        def _loop() -> None:
            while not self._stop.is_set():
                cur = self._sample()
                if cur > self.peak_kib:
                    self.peak_kib = cur
                self._stop.wait(self.interval_s)

        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        # One final sample in case the peak happened between polls.
        cur = self._sample()
        if cur > self.peak_kib:
            self.peak_kib = cur


def _rss_kib() -> int:
    return psutil.Process().memory_info().rss // 1024


# --------------------------------------------------------------------------
# Payload size accounting
# --------------------------------------------------------------------------

def measure_payload(txs: list, mode: str) -> dict:
    com_total = 0
    gen_total = 0
    rp_total = 0
    sp_total = 0
    for tx in txs:
        for out in tx.outputs:
            com_total += len(out.commitment)
            gen_total += len(out.blinded_gen)
            rp_total += len(out.range_proof)
            if mode == MODE_FULLY_SHIELDED and out.surjection_proof is not None:
                sp_total += len(out.surjection_proof)
    payload_total = com_total + gen_total + rp_total + sp_total
    return dict(
        commitments_bytes=com_total,
        blinded_gens_bytes=gen_total,
        range_proofs_bytes=rp_total,
        surjection_proofs_bytes=sp_total,
        payload_total_bytes=payload_total,
        per_tx_payload_bytes=payload_total / len(txs) if txs else 0.0,
    )


# --------------------------------------------------------------------------
# Verification pass (mirrors benchmark_stream_time.py's logic, sans timing)
# --------------------------------------------------------------------------

def verify_stream(txs: list, mode: str) -> None:
    for tx in txs:
        ok = verify_balance(
            transparent_inputs=[],
            shielded_inputs=[inp.commitment for inp in tx.inputs],
            transparent_outputs=[],
            shielded_outputs=[out.commitment for out in tx.outputs],
        )
        assert ok, 'balance verify failed'
        for out in tx.outputs:
            ok = verify_range_proof(out.range_proof, out.commitment, out.blinded_gen)
            assert ok, 'range proof verify failed'
        if mode == MODE_FULLY_SHIELDED:
            domain_verify = [inp.blinded_gen for inp in tx.inputs]
            for out in tx.outputs:
                ok = verify_surjection_proof(
                    proof=out.surjection_proof,
                    codomain=out.blinded_gen,
                    domain=domain_verify,
                )
                assert ok, 'surjection verify failed'


# --------------------------------------------------------------------------
# Per-combo runner
# --------------------------------------------------------------------------

def measure_combo(
    mode: str,
    shape: tuple[int, int],
    stream_size: int,
) -> dict:
    inputs_per_tx, outputs_per_tx = shape

    # Build the stream (only secrets; proofs not yet created).
    gc.collect()
    rss_baseline_kib = _rss_kib()

    # ----- Creation -----
    tracemalloc.start()
    with RSSPeakSampler() as build_sampler:
        txs = build_stream(mode, stream_size, inputs_per_tx, outputs_per_tx)
        for tx in txs:
            seal_tx(tx, mode)
    _, tm_peak_build = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    rss_after_build_kib = _rss_kib()
    rss_peak_build_kib = build_sampler.peak_kib

    payload = measure_payload(txs, mode)

    # ----- Verification -----
    tracemalloc.start()
    with RSSPeakSampler() as verify_sampler:
        verify_stream(txs, mode)
    _, tm_peak_verify = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    rss_after_verify_kib = _rss_kib()
    rss_peak_verify_kib = verify_sampler.peak_kib

    # Drop refs and force collection so the next combo starts clean.
    del txs
    gc.collect()

    return dict(
        rss_baseline_kib=rss_baseline_kib,
        rss_after_build_kib=rss_after_build_kib,
        rss_peak_build_kib=rss_peak_build_kib,
        rss_after_verify_kib=rss_after_verify_kib,
        rss_peak_verify_kib=rss_peak_verify_kib,
        rss_delta_build_kib=rss_after_build_kib - rss_baseline_kib,
        rss_delta_peak_build_kib=rss_peak_build_kib - rss_baseline_kib,
        tracemalloc_peak_build_kib=tm_peak_build // 1024,
        tracemalloc_peak_verify_kib=tm_peak_verify // 1024,
        **payload,
    )


# --------------------------------------------------------------------------
# Main sweep
# --------------------------------------------------------------------------

def run(
    shapes: list[tuple[int, int]],
    stream_sizes: list[int],
    runs: int,
    modes: list[str],
    output_dir: str,
) -> None:
    os.makedirs(output_dir, exist_ok=True)
    rows: list[dict] = []
    total_combos = len(modes) * len(shapes) * len(stream_sizes)
    combo_idx = 0

    print(f"Stream-memory benchmark | shapes={[shape_label(s) for s in shapes]} "
          f"stream_sizes={stream_sizes} runs={runs} modes={modes}")
    print(f"Results -> {output_dir}/")
    print()

    for mode in modes:
        for shape in shapes:
            for stream_size in stream_sizes:
                combo_idx += 1
                samples: list[dict] = []
                for _ in range(runs):
                    samples.append(measure_combo(mode, shape, stream_size))

                # Mean across runs (median for RSS to suppress single outliers).
                def _mean(key: str) -> float:
                    return statistics.mean(s[key] for s in samples)

                def _median(key: str) -> float:
                    return statistics.median(s[key] for s in samples)

                # Payload is deterministic-ish; mean is fine. RSS is noisy; take median.
                row = dict(
                    mode=mode,
                    shape=shape_label(shape),
                    inputs_per_tx=shape[0],
                    outputs_per_tx=shape[1],
                    stream_size=stream_size,
                    runs=runs,
                    commitments_bytes=_mean('commitments_bytes'),
                    blinded_gens_bytes=_mean('blinded_gens_bytes'),
                    range_proofs_bytes=_mean('range_proofs_bytes'),
                    surjection_proofs_bytes=_mean('surjection_proofs_bytes'),
                    payload_total_bytes=_mean('payload_total_bytes'),
                    per_tx_payload_bytes=_mean('per_tx_payload_bytes'),
                    rss_baseline_kib=_median('rss_baseline_kib'),
                    rss_after_build_kib=_median('rss_after_build_kib'),
                    rss_peak_build_kib=_median('rss_peak_build_kib'),
                    rss_after_verify_kib=_median('rss_after_verify_kib'),
                    rss_peak_verify_kib=_median('rss_peak_verify_kib'),
                    rss_delta_build_kib=_median('rss_delta_build_kib'),
                    rss_delta_peak_build_kib=_median('rss_delta_peak_build_kib'),
                    tracemalloc_peak_build_kib=_median('tracemalloc_peak_build_kib'),
                    tracemalloc_peak_verify_kib=_median('tracemalloc_peak_verify_kib'),
                )
                rows.append(row)

                print(
                    f"[{combo_idx:3d}/{total_combos}] {mode:14s} "
                    f"shape={shape_label(shape):>6s} N={stream_size:4d} | "
                    f"payload={row['payload_total_bytes']/1024:8.1f} KiB "
                    f"({row['per_tx_payload_bytes']/1024:6.2f} KiB/tx) | "
                    f"RSS Δpeak={row['rss_delta_peak_build_kib']/1024:6.1f} MiB "
                    f"verify_peak={row['rss_peak_verify_kib']/1024:6.1f} MiB | "
                    f"tracemalloc build={row['tracemalloc_peak_build_kib']/1024:5.1f} MiB"
                )

    csv_path = os.path.join(output_dir, 'stream_memory.csv')
    fieldnames = list(rows[0].keys())
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"\nWrote {len(rows)} rows -> {csv_path}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--runs', type=int, default=1)
    p.add_argument('--shapes', type=str, default=None)
    p.add_argument('--stream-sizes', type=str, default=None)
    p.add_argument('--mode', choices=list(MODES) + ['both'], default='both')
    p.add_argument('--output-dir', default=OUTPUT_DIR)
    args = p.parse_args()

    shapes = (
        [parse_shape(s) for s in args.shapes.split(',')]
        if args.shapes else DEFAULT_SHAPES
    )
    stream_sizes = (
        [int(s) for s in args.stream_sizes.split(',')]
        if args.stream_sizes else STREAM_SIZES
    )
    modes = list(MODES) if args.mode == 'both' else [args.mode]

    run(shapes=shapes, stream_sizes=stream_sizes, runs=args.runs,
        modes=modes, output_dir=args.output_dir)


if __name__ == '__main__':
    main()
