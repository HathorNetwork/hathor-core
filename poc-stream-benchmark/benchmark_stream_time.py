"""
Stream throughput benchmark for shielded transactions.

Sweeps:
  - stream sizes: 100, 200, ..., 1000 transactions
  - tx shapes (inputs_per_tx, outputs_per_tx): (2,2), (4,4), (8,8), (16,16)
  - modes: 'amount_hidden' and 'fully_shielded'

For each (mode, shape, stream_size) combination, the benchmark:

  1. Pre-builds the stream (input secrets + output amounts/blinding factors). This
     prep cost is NOT included in the reported times — it would be done by the
     wallet ahead of time using existing UTXOs.

  2. Times PROOF CREATION: Pedersen commitment + Borromean range proof for every
     output, plus the asset-surjection proof when fully_shielded.

  3. Times VERIFICATION: per-tx homomorphic balance via verify_balance (single
     FFI call over all input/output commitments) + per-output range-proof verify
     + per-output surjection verify (fully_shielded only).

Why these times are the *real* per-tx work:
  - verify_balance batches input+output commitments inside Rust, so we call it
    once per tx — that is the natural batch boundary.
  - The secp256k1-zkp Borromean range proof and the asset-surjection proof do
    NOT expose batched verification (Bulletproofs do, but those aren't the
    primitives in this stack). So the inner loop is genuinely per-output.

Results CSV layout: one row per (mode, shape, stream_size). Columns include
totals and per-tx amortized timings for each phase.
"""

from __future__ import annotations

import argparse
import csv
import os
import time

from stream_common import (
    DEFAULT_SHAPES,
    MODE_AMOUNT_HIDDEN,
    MODE_FULLY_SHIELDED,
    MODES,
    STREAM_SIZES,
    build_stream,
    parse_shape,
    seal_tx,
    shape_label,
)

# Import after stream_common so its sys.path patch is in effect.
from hathor.crypto.shielded.balance import verify_balance
from hathor.crypto.shielded.range_proof import verify_range_proof
from hathor.crypto.shielded.surjection import verify_surjection_proof

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results_time')


def time_creation(txs: list, mode: str) -> float:
    """Time proof creation for the whole stream. Mutates txs (fills .outputs)."""
    t0 = time.perf_counter()
    for tx in txs:
        seal_tx(tx, mode)
    return time.perf_counter() - t0


def time_verification(txs: list, mode: str) -> tuple[float, float, float, float]:
    """Time verification for the whole stream.

    Returns: (total_s, balance_s, range_s, surjection_s).

    Per tx, in order:
      1. verify_balance over (shielded_inputs, shielded_outputs)  ← batch FFI
      2. for each output: verify_range_proof
      3. (fully_shielded) for each output: verify_surjection_proof
    """
    balance_s = 0.0
    range_s = 0.0
    surjection_s = 0.0

    full_total_t0 = time.perf_counter()
    for tx in txs:
        in_commits = [inp.commitment for inp in tx.inputs]
        out_commits = [out.commitment for out in tx.outputs]

        t0 = time.perf_counter()
        ok = verify_balance(
            transparent_inputs=[],
            shielded_inputs=in_commits,
            transparent_outputs=[],
            shielded_outputs=out_commits,
        )
        balance_s += time.perf_counter() - t0
        assert ok, 'balance verify failed (constructed tx should always balance)'

        t0 = time.perf_counter()
        for out in tx.outputs:
            ok = verify_range_proof(out.range_proof, out.commitment, out.blinded_gen)
            assert ok, 'range proof verify failed'
        range_s += time.perf_counter() - t0

        if mode == MODE_FULLY_SHIELDED:
            domain_verify = [inp.blinded_gen for inp in tx.inputs]
            t0 = time.perf_counter()
            for out in tx.outputs:
                ok = verify_surjection_proof(
                    proof=out.surjection_proof,
                    codomain=out.blinded_gen,
                    domain=domain_verify,
                )
                assert ok, 'surjection verify failed'
            surjection_s += time.perf_counter() - t0

    total_s = time.perf_counter() - full_total_t0
    return total_s, balance_s, range_s, surjection_s


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

    print(f"Stream-time benchmark | shapes={[shape_label(s) for s in shapes]} "
          f"stream_sizes={stream_sizes} runs={runs} modes={modes}")
    print(f"Results -> {output_dir}/")
    print()

    for mode in modes:
        for shape in shapes:
            inputs_per_tx, outputs_per_tx = shape
            for stream_size in stream_sizes:
                combo_idx += 1
                create_samples: list[float] = []
                verify_samples: list[float] = []
                balance_samples: list[float] = []
                range_samples: list[float] = []
                surjection_samples: list[float] = []

                for _ in range(runs):
                    txs = build_stream(mode, stream_size, inputs_per_tx, outputs_per_tx)
                    create_s = time_creation(txs, mode)
                    verify_s, balance_s, range_s, surj_s = time_verification(txs, mode)
                    create_samples.append(create_s)
                    verify_samples.append(verify_s)
                    balance_samples.append(balance_s)
                    range_samples.append(range_s)
                    surjection_samples.append(surj_s)

                def _mean(xs: list[float]) -> float:
                    return sum(xs) / len(xs)

                create_s = _mean(create_samples)
                verify_s = _mean(verify_samples)
                balance_s = _mean(balance_samples)
                range_s = _mean(range_samples)
                surj_s = _mean(surjection_samples)

                row = dict(
                    mode=mode,
                    shape=shape_label(shape),
                    inputs_per_tx=inputs_per_tx,
                    outputs_per_tx=outputs_per_tx,
                    stream_size=stream_size,
                    runs=runs,
                    create_total_s=create_s,
                    verify_total_s=verify_s,
                    verify_balance_s=balance_s,
                    verify_range_s=range_s,
                    verify_surjection_s=surj_s,
                    per_tx_create_ms=create_s / stream_size * 1000.0,
                    per_tx_verify_ms=verify_s / stream_size * 1000.0,
                    create_tps=stream_size / create_s if create_s > 0 else 0.0,
                    verify_tps=stream_size / verify_s if verify_s > 0 else 0.0,
                )
                rows.append(row)

                print(
                    f"[{combo_idx:3d}/{total_combos}] {mode:14s} "
                    f"shape={shape_label(shape):>6s} N={stream_size:4d} | "
                    f"create={create_s:7.2f}s ({row['per_tx_create_ms']:6.1f} ms/tx, "
                    f"{row['create_tps']:6.1f} tx/s) | "
                    f"verify={verify_s:7.2f}s ({row['per_tx_verify_ms']:6.1f} ms/tx, "
                    f"{row['verify_tps']:6.1f} tx/s) "
                    f"[bal={balance_s:5.2f}s rp={range_s:5.2f}s sp={surj_s:5.2f}s]"
                )

    # Write a single tidy CSV
    csv_path = os.path.join(output_dir, 'stream_time.csv')
    fieldnames = list(rows[0].keys())
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"\nWrote {len(rows)} rows -> {csv_path}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--runs', type=int, default=1,
                   help='number of independent stream rebuilds per (mode,shape,size); default 1')
    p.add_argument('--shapes', type=str, default=None,
                   help='comma-separated shapes (e.g. "2x2,4x4"); default 2x2,4x4,8x8,16x16')
    p.add_argument('--stream-sizes', type=str, default=None,
                   help='comma-separated stream sizes; default 100,200,...,1000')
    p.add_argument('--mode', choices=list(MODES) + ['both'], default='both',
                   help='which mode to run; default both')
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
