"""
Benchmark: batched range-proof verification, the unique payoff of switching
from secp256k1-zkp mainline (Borromean, no batch) to grin_secp256k1zkp (original
Bulletproofs, with `verify_bullet_proof_multi`).

For each batch size K in `BATCH_SIZES`, measures four things over `RUNS` repeats:

  CREATION
    1. single_create — K serial calls to `create_range_proof` (single-output).
    2. multi_create  — one `multi_create_proofs(values, blindings)` FFI call.
       NOTE: grin_secp256k1zkp 0.7 does NOT expose the C aggregated-prove path,
       so `multi_create_proofs` is internally K single-output prove calls in
       one FFI round-trip. The only thing it saves is Python <-> Rust crossing
       overhead — see hathor-grin-bp/src/lib.rs for the caveat.

  VERIFICATION
    3. serial_verify — K serial calls to `verify_range_proof`.
    4. batch_verify  — one `batch_verify_range_proofs(proofs, commitments)`
       call → real `secp256k1_bulletproof_rangeproof_verify_multi`. This is
       the path the in-tree `hathor-ct-crypto/src/rangeproof.rs:batch_verify_range_proofs`
       only pretends to be (there it's a sequential loop in Rust).

Outputs five CSVs under `results_batch/`:
  - single_create.csv   K, avg_time_s
  - multi_create.csv    K, avg_time_s
  - serial_verify.csv   K, avg_time_s
  - batch_verify.csv    K, avg_time_s
  - speedup.csv         K, serial_verify/batch_verify, single_create/multi_create
"""

import csv
import os
import sys
import time

HATHOR_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'hathor-core'))
if HATHOR_CORE not in sys.path:
    sys.path.insert(0, HATHOR_CORE)

from grin_bp_range_proof import (
    batch_verify_range_proofs,
    create_commitment,
    create_range_proof,
    multi_create_proofs,
    verify_range_proof,
)

BATCH_SIZES = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]
RUNS = 3
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results_batch')


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def _gen_inputs(k: int) -> tuple[list[int], list[bytes], list[bytes]]:
    """Build K (amount, blinding) pairs and the K corresponding commitments."""
    amounts = [(i * 13 + 7) & ((1 << 60) - 1) for i in range(k)]
    blindings = [_random_bytes(32) for _ in range(k)]
    commitments = [create_commitment(a, b) for a, b in zip(amounts, blindings)]
    return amounts, blindings, commitments


def run_benchmark(batch_sizes: list[int] = BATCH_SIZES, runs: int = RUNS):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Batch sweep: K={batch_sizes}, runs={runs}")
    print(f"Results -> {OUTPUT_DIR}/")
    print()

    single_create: dict[int, float] = {}
    multi_create:  dict[int, float] = {}
    serial_verify: dict[int, float] = {}
    batch_verify:  dict[int, float] = {}

    for k in batch_sizes:
        amounts, blindings, commitments = _gen_inputs(k)

        # warm-up: build one proof so the JIT-cache / page-faults don't fall
        # entirely on the first measured run.
        if k > 0:
            _ = create_range_proof(amounts[0], blindings[0])

        sc_times, mc_times, sv_times, bv_times = [], [], [], []

        for _ in range(runs):
            # --- single_create: K serial prove calls ---
            t0 = time.perf_counter()
            single_proofs = [
                create_range_proof(a, b) for a, b in zip(amounts, blindings)
            ]
            sc_times.append(time.perf_counter() - t0)

            # --- multi_create: one FFI call with K values+blinds ---
            t0 = time.perf_counter()
            multi_proofs = multi_create_proofs(amounts, blindings)
            mc_times.append(time.perf_counter() - t0)

            # Sanity check: both proof sets must verify against the commitments.
            assert len(single_proofs) == k
            assert len(multi_proofs) == k

            # --- serial_verify: K serial verify calls ---
            t0 = time.perf_counter()
            for p, c in zip(single_proofs, commitments):
                ok = verify_range_proof(p, c)
                assert ok, f"single-verify failed at K={k}"
            sv_times.append(time.perf_counter() - t0)

            # --- batch_verify: one FFI call across K (proof, commitment) pairs ---
            t0 = time.perf_counter()
            ok = batch_verify_range_proofs(single_proofs, commitments)
            bv_times.append(time.perf_counter() - t0)
            assert ok, f"batch-verify failed at K={k}"

        single_create[k] = sum(sc_times) / runs
        multi_create[k]  = sum(mc_times) / runs
        serial_verify[k] = sum(sv_times) / runs
        batch_verify[k]  = sum(bv_times) / runs

        sc = single_create[k] * 1000
        mc = multi_create[k]  * 1000
        sv = serial_verify[k] * 1000
        bv = batch_verify[k]  * 1000
        v_ratio = sv / bv if bv > 0 else float('inf')
        c_ratio = sc / mc if mc > 0 else float('inf')
        print(
            f"K={k:5d} | create: single={sc:9.1f}ms multi={mc:9.1f}ms  ratio={c_ratio:5.2f}x | "
            f"verify: serial={sv:9.1f}ms batch={bv:9.1f}ms  speedup={v_ratio:5.2f}x"
        )

    _write_one(os.path.join(OUTPUT_DIR, 'single_create.csv'), batch_sizes, single_create)
    _write_one(os.path.join(OUTPUT_DIR, 'multi_create.csv'),  batch_sizes, multi_create)
    _write_one(os.path.join(OUTPUT_DIR, 'serial_verify.csv'), batch_sizes, serial_verify)
    _write_one(os.path.join(OUTPUT_DIR, 'batch_verify.csv'),  batch_sizes, batch_verify)
    _write_speedup(
        os.path.join(OUTPUT_DIR, 'speedup.csv'),
        batch_sizes, single_create, multi_create, serial_verify, batch_verify,
    )
    print(f"\nDone. 5 CSVs saved to {OUTPUT_DIR}/")


def _write_one(path: str, batch_sizes: list[int], data: dict[int, float]) -> None:
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['k', 'avg_seconds'])
        for k in batch_sizes:
            w.writerow([k, f'{data[k]:.6f}'])


def _write_speedup(
    path: str,
    batch_sizes: list[int],
    single_create: dict[int, float],
    multi_create: dict[int, float],
    serial_verify: dict[int, float],
    batch_verify: dict[int, float],
) -> None:
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['k', 'verify_serial_over_batch', 'create_single_over_multi'])
        for k in batch_sizes:
            v = serial_verify[k] / batch_verify[k] if batch_verify[k] > 0 else 0.0
            c = single_create[k] / multi_create[k] if multi_create[k] > 0 else 0.0
            w.writerow([k, f'{v:.4f}', f'{c:.4f}'])


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description='Grin Bulletproofs batch-verify sweep')
    p.add_argument('--runs', type=int, default=RUNS)
    p.add_argument(
        '--sizes', type=str, default=None,
        help='Comma-separated batch sizes (default: 1,2,4,8,16,32,64,128,256,512,1024)',
    )
    args = p.parse_args()
    sizes = (
        [int(x) for x in args.sizes.split(',')]
        if args.sizes
        else BATCH_SIZES
    )
    run_benchmark(batch_sizes=sizes, runs=args.runs)
