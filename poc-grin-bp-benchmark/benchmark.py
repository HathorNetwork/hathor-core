"""
Benchmark: Surjection Proof Creation & Verification for Shielded Outputs (grin BP swap).

For each combination of N shielded inputs (1..MAX_N) × M shielded outputs (1..MAX_M),
measures:
  1. Time to CREATE M surjection proofs (one per output) given N input asset tags.
  2. Time to VERIFY M surjection proofs (one per output) given N input asset tags.

Each (N, M) combination is run RUNS times; the average is stored.
Results are saved to CSV files for plotting.

Range proof / Pedersen commitment use **grin_secp256k1zkp** (original Bulletproofs on
secp256k1) via the `hathor_grin_bp` binding. The asset surjection pipeline still uses
`hathor.crypto.shielded.surjection` (Borromean) — only the range proof + value
commitment have been swapped vs `poc-shielded-benchmark/`.
"""

import csv
import os
import sys
import time

HATHOR_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'hathor-core'))
if HATHOR_CORE not in sys.path:
    sys.path.insert(0, HATHOR_CORE)

from hathor.crypto.shielded.asset_tag import create_asset_commitment, derive_asset_tag, derive_tag
from hathor.crypto.shielded.surjection import create_surjection_proof, verify_surjection_proof
from grin_bp_range_proof import create_commitment, create_range_proof  # noqa: F401  -- grin BP swap

# ---------------------------------------------------------------------------
MAX_N = 64
MAX_M = 64
RUNS = 3
MAX_PROOF_RETRIES = 5
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results')


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def _make_token_uid(index: int) -> bytes:
    return index.to_bytes(32, 'big')


def make_shielded_input(token_index: int) -> dict:
    token_uid = _make_token_uid(token_index)
    tag_raw = derive_tag(token_uid)
    derive_asset_tag(token_uid)  # warm; unused: grin commit uses libsecp's H
    r_asset = _random_bytes(32)
    blinded_gen = create_asset_commitment(tag_raw, r_asset)
    amount = 1000 + token_index
    value_blind = _random_bytes(32)
    commitment = create_commitment(amount, value_blind, blinded_gen)
    return dict(
        token_uid=token_uid, tag_raw=tag_raw, r_asset=r_asset,
        blinded_gen=blinded_gen, value_blind=value_blind,
        commitment=commitment, amount=amount,
    )


def make_shielded_output(token_index: int) -> dict:
    token_uid = _make_token_uid(token_index)
    tag_raw = derive_tag(token_uid)
    r_asset = _random_bytes(32)
    blinded_gen = create_asset_commitment(tag_raw, r_asset)
    amount = 500 + token_index
    value_blind = _random_bytes(32)
    commitment = create_commitment(amount, value_blind, blinded_gen)
    return dict(
        token_uid=token_uid, tag_raw=tag_raw, r_asset=r_asset,
        blinded_gen=blinded_gen, value_blind=value_blind,
        commitment=commitment, amount=amount,
    )


def run_benchmark(max_n: int = MAX_N, max_m: int = MAX_M, runs: int = RUNS):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    creation_csv = os.path.join(OUTPUT_DIR, 'creation_times.csv')
    verification_csv = os.path.join(OUTPUT_DIR, 'verification_times.csv')

    n_values = sorted(set([1, 2, 4, 8, 16, 32, 64, 128, 255]) & set(range(1, max_n + 1)))
    if max_n not in n_values:
        n_values.append(max_n)
        n_values.sort()
    m_values = sorted(set([1, 2, 4, 8, 16, 32, 64, 128, 255]) & set(range(1, max_m + 1)))
    if max_m not in m_values:
        m_values.append(max_m)
        m_values.sort()

    print(f"Benchmark grid: N_inputs={n_values}, M_outputs={m_values}, runs={runs}")
    print(f"Results will be saved to {OUTPUT_DIR}/")
    print()

    creation_results: dict[tuple[int, int], float] = {}
    verification_results: dict[tuple[int, int], float] = {}

    total_combos = len(n_values) * len(m_values)
    combo_idx = 0

    for n_inputs in n_values:
        inputs = [make_shielded_input(i % 256) for i in range(n_inputs)]
        domain_create = [
            (inp['blinded_gen'], inp['tag_raw'], inp['r_asset'])
            for inp in inputs
        ]
        domain_verify = [inp['blinded_gen'] for inp in inputs]

        for m_outputs in m_values:
            combo_idx += 1
            outputs = [make_shielded_output(i % n_inputs) for i in range(m_outputs)]

            creation_times = []
            verification_times = []

            for run_idx in range(runs):
                # --- CREATION ---
                proofs = []
                t0 = time.perf_counter()
                for out in outputs:
                    for attempt in range(MAX_PROOF_RETRIES):
                        try:
                            proof = create_surjection_proof(
                                codomain_tag=out['tag_raw'],
                                codomain_blinding_factor=out['r_asset'],
                                domain=domain_create,
                            )
                            break
                        except ValueError:
                            if attempt == MAX_PROOF_RETRIES - 1:
                                raise
                    proofs.append(proof)
                t1 = time.perf_counter()
                creation_times.append(t1 - t0)

                # --- VERIFICATION ---
                t0 = time.perf_counter()
                for out, proof in zip(outputs, proofs):
                    ok = verify_surjection_proof(
                        proof=proof,
                        codomain=out['blinded_gen'],
                        domain=domain_verify,
                    )
                    assert ok, f"Surjection proof verification failed! n={n_inputs}, m={m_outputs}"
                t1 = time.perf_counter()
                verification_times.append(t1 - t0)

            avg_create = sum(creation_times) / runs
            avg_verify = sum(verification_times) / runs

            creation_results[(n_inputs, m_outputs)] = avg_create
            verification_results[(n_inputs, m_outputs)] = avg_verify

            print(
                f"[{combo_idx:3d}/{total_combos}] "
                f"N={n_inputs:3d} inputs, M={m_outputs:3d} outputs | "
                f"create={avg_create*1000:8.2f}ms  verify={avg_verify*1000:8.2f}ms"
            )

    _write_csv(creation_csv, n_values, m_values, creation_results)
    _write_csv(verification_csv, n_values, m_values, verification_results)
    print(f"\nDone. Results saved to:\n  {creation_csv}\n  {verification_csv}")


RUST_TIME_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results_rust_time')


def run_benchmark_rust_time(max_n: int = MAX_N, max_m: int = MAX_M, runs: int = RUNS):
    """Run the full N×M benchmark grid, timing only the Rust FFI calls."""
    os.makedirs(RUST_TIME_OUTPUT_DIR, exist_ok=True)

    creation_csv = os.path.join(RUST_TIME_OUTPUT_DIR, 'creation_times.csv')
    verification_csv = os.path.join(RUST_TIME_OUTPUT_DIR, 'verification_times.csv')

    n_values = sorted(set([1, 2, 4, 8, 16, 32, 64, 128, 255]) & set(range(1, max_n + 1)))
    if max_n not in n_values:
        n_values.append(max_n)
        n_values.sort()
    m_values = sorted(set([1, 2, 4, 8, 16, 32, 64, 128, 255]) & set(range(1, max_m + 1)))
    if max_m not in m_values:
        m_values.append(max_m)
        m_values.sort()

    print(f"[Rust-time] Benchmark grid: N_inputs={n_values}, M_outputs={m_values}, runs={runs}")
    print(f"Results will be saved to {RUST_TIME_OUTPUT_DIR}/")
    print()

    creation_results: dict[tuple[int, int], float] = {}
    verification_results: dict[tuple[int, int], float] = {}

    total_combos = len(n_values) * len(m_values)
    combo_idx = 0

    for n_inputs in n_values:
        inputs = [make_shielded_input(i % 256) for i in range(n_inputs)]
        domain_create = [
            (inp['blinded_gen'], inp['tag_raw'], inp['r_asset'])
            for inp in inputs
        ]
        domain_verify = [inp['blinded_gen'] for inp in inputs]

        for m_outputs in m_values:
            combo_idx += 1
            outputs = [make_shielded_output(i % n_inputs) for i in range(m_outputs)]

            creation_times = []
            verification_times = []

            for run_idx in range(runs):
                proofs = []
                dt_create = 0.0
                for out in outputs:
                    for attempt in range(MAX_PROOF_RETRIES):
                        try:
                            t0 = time.perf_counter()
                            proof = create_surjection_proof(
                                codomain_tag=out['tag_raw'],
                                codomain_blinding_factor=out['r_asset'],
                                domain=domain_create,
                            )
                            t1 = time.perf_counter()
                            dt_create += t1 - t0
                            break
                        except ValueError:
                            if attempt == MAX_PROOF_RETRIES - 1:
                                raise
                    proofs.append(proof)
                creation_times.append(dt_create)

                dt_verify = 0.0
                for out, proof in zip(outputs, proofs):
                    t0 = time.perf_counter()
                    ok = verify_surjection_proof(
                        proof=proof,
                        codomain=out['blinded_gen'],
                        domain=domain_verify,
                    )
                    t1 = time.perf_counter()
                    dt_verify += t1 - t0
                    assert ok, f"Surjection proof verification failed! n={n_inputs}, m={m_outputs}"
                verification_times.append(dt_verify)

            avg_create = sum(creation_times) / runs
            avg_verify = sum(verification_times) / runs

            creation_results[(n_inputs, m_outputs)] = avg_create
            verification_results[(n_inputs, m_outputs)] = avg_verify

            print(
                f"[{combo_idx:3d}/{total_combos}] "
                f"N={n_inputs:3d} inputs, M={m_outputs:3d} outputs | "
                f"create={avg_create*1000:8.2f}ms  verify={avg_verify*1000:8.2f}ms"
            )

    _write_csv(creation_csv, n_values, m_values, creation_results)
    _write_csv(verification_csv, n_values, m_values, verification_results)
    print(f"\nDone. Results saved to:\n  {creation_csv}\n  {verification_csv}")


def _write_csv(
    path: str,
    n_values: list[int],
    m_values: list[int],
    results: dict[tuple[int, int], float],
) -> None:
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['n_inputs \\ m_outputs'] + [str(m) for m in m_values])
        for n in n_values:
            row = [str(n)] + [f'{results.get((n, m), 0.0):.6f}' for m in m_values]
            writer.writerow(row)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Shielded output surjection proof benchmark (grin BP swap)')
    parser.add_argument('--max-n', type=int, default=MAX_N)
    parser.add_argument('--max-m', type=int, default=MAX_M)
    parser.add_argument('--runs', type=int, default=RUNS)
    args = parser.parse_args()
    run_benchmark(max_n=args.max_n, max_m=args.max_m, runs=args.runs)
