"""
Comprehensive benchmark: Pedersen + Range Proof + Asset Surjection (grin BP swap).

For each (N shielded inputs, M shielded outputs) pair, measures SIX metrics
(all times are for ALL M outputs in the transaction, not per-output):

  CREATION:
    1. pedersen_create   — grin Pedersen commitment + grin Bulletproof for M outputs
    2. surjection_create — Asset surjection proof for M outputs (given N-input domain)
    3. total_create      — Both combined

  VERIFICATION:
    4. pedersen_verify   — grin Bulletproof verification for M outputs (serial)
    5. surjection_verify — Asset surjection proof verification for M outputs
    6. total_verify      — Both combined

Range proof is **original Bulletproofs** (Mimblewimble/Grin fork of secp256k1-zkp)
via `hathor_grin_bp`, NOT the Borromean range proof from secp256k1-zkp mainline
(which is what `poc-shielded-benchmark/` measures) and NOT Bulletproofs++
(which is what `poc-bppp-benchmark/` measures). The metric name `pedersen_create`
is kept for diff-friendliness against the original folder.

For real batch-verify numbers see `benchmark_batch.py` — this script keeps the
verify loop serial so the 6 metrics line up with the other two POC folders.
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
from grin_bp_range_proof import create_commitment, create_range_proof, verify_range_proof  # grin BP swap

# ---------------------------------------------------------------------------
MAX_N = 64
MAX_M = 64
RUNS = 3
MAX_PROOF_RETRIES = 5
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results_full')

METRICS = [
    'pedersen_create',
    'surjection_create',
    'total_create',
    'pedersen_verify',
    'surjection_verify',
    'total_verify',
]


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def _make_token_uid(index: int) -> bytes:
    return index.to_bytes(32, 'big')


def make_shielded_input(token_index: int) -> dict:
    token_uid = _make_token_uid(token_index)
    tag_raw = derive_tag(token_uid)
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


def run_benchmark(max_n: int = MAX_N, max_m: int = MAX_M, runs: int = RUNS):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    n_values = sorted(set([1, 2, 4, 8, 16, 32, 64, 128, 255]) & set(range(1, max_n + 1)))
    if max_n not in n_values:
        n_values.append(max_n)
        n_values.sort()
    m_values = sorted(set([1, 2, 4, 8, 16, 32, 64, 128, 255]) & set(range(1, max_m + 1)))
    if max_m not in m_values:
        m_values.append(max_m)
        m_values.sort()

    print(f"Benchmark grid: N_inputs={n_values}, M_outputs={m_values}, runs={runs}")
    print(f"Metrics: {METRICS}")
    print(f"Results -> {OUTPUT_DIR}/")
    print()

    results: dict[str, dict[tuple[int, int], float]] = {m: {} for m in METRICS}

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

            timings: dict[str, list[float]] = {m: [] for m in METRICS}

            for run_idx in range(runs):
                out_params = []
                for i in range(m_outputs):
                    token_idx = i % n_inputs
                    token_uid = _make_token_uid(token_idx)
                    tag_raw = derive_tag(token_uid)
                    r_asset = _random_bytes(32)
                    value_blind = _random_bytes(32)
                    amount = 500 + i
                    out_params.append(dict(
                        token_uid=token_uid, tag_raw=tag_raw,
                        r_asset=r_asset, value_blind=value_blind, amount=amount,
                    ))

                # ==================== CREATION ====================
                t0 = time.perf_counter()
                pedersen_artifacts = []
                for op in out_params:
                    blinded_gen = create_asset_commitment(op['tag_raw'], op['r_asset'])
                    commitment = create_commitment(op['amount'], op['value_blind'], blinded_gen)
                    range_proof = create_range_proof(
                        op['amount'], op['value_blind'], commitment, blinded_gen,
                    )
                    pedersen_artifacts.append(dict(
                        blinded_gen=blinded_gen, commitment=commitment,
                        range_proof=range_proof,
                    ))
                t1 = time.perf_counter()
                dt_pedersen_create = t1 - t0

                t0 = time.perf_counter()
                surjection_proofs = []
                for op in out_params:
                    for attempt in range(MAX_PROOF_RETRIES):
                        try:
                            proof = create_surjection_proof(
                                codomain_tag=op['tag_raw'],
                                codomain_blinding_factor=op['r_asset'],
                                domain=domain_create,
                            )
                            break
                        except ValueError:
                            if attempt == MAX_PROOF_RETRIES - 1:
                                raise
                    surjection_proofs.append(proof)
                t1 = time.perf_counter()
                dt_surjection_create = t1 - t0

                timings['pedersen_create'].append(dt_pedersen_create)
                timings['surjection_create'].append(dt_surjection_create)
                timings['total_create'].append(dt_pedersen_create + dt_surjection_create)

                # ==================== VERIFICATION ====================
                t0 = time.perf_counter()
                for art in pedersen_artifacts:
                    ok = verify_range_proof(
                        art['range_proof'], art['commitment'], art['blinded_gen'],
                    )
                    assert ok, "Range proof verification failed"
                t1 = time.perf_counter()
                dt_pedersen_verify = t1 - t0

                t0 = time.perf_counter()
                for art, sp in zip(pedersen_artifacts, surjection_proofs):
                    ok = verify_surjection_proof(
                        proof=sp,
                        codomain=art['blinded_gen'],
                        domain=domain_verify,
                    )
                    assert ok, "Surjection proof verification failed"
                t1 = time.perf_counter()
                dt_surjection_verify = t1 - t0

                timings['pedersen_verify'].append(dt_pedersen_verify)
                timings['surjection_verify'].append(dt_surjection_verify)
                timings['total_verify'].append(dt_pedersen_verify + dt_surjection_verify)

            for metric in METRICS:
                results[metric][(n_inputs, m_outputs)] = sum(timings[metric]) / runs

            pc = results['pedersen_create'][(n_inputs, m_outputs)] * 1000
            sc = results['surjection_create'][(n_inputs, m_outputs)] * 1000
            tc = results['total_create'][(n_inputs, m_outputs)] * 1000
            pv = results['pedersen_verify'][(n_inputs, m_outputs)] * 1000
            sv = results['surjection_verify'][(n_inputs, m_outputs)] * 1000
            tv = results['total_verify'][(n_inputs, m_outputs)] * 1000

            print(
                f"[{combo_idx:3d}/{total_combos}] N={n_inputs:3d} M={m_outputs:3d} | "
                f"create: ped={pc:7.1f} surj={sc:7.1f} tot={tc:7.1f}ms | "
                f"verify: ped={pv:7.1f} surj={sv:7.1f} tot={tv:7.1f}ms"
            )

    for metric in METRICS:
        path = os.path.join(OUTPUT_DIR, f'{metric}.csv')
        _write_csv(path, n_values, m_values, results[metric])

    print(f"\nDone. {len(METRICS)} CSVs saved to {OUTPUT_DIR}/")


RUST_TIME_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results_full_rust_time')


def run_benchmark_rust_time(max_n: int = MAX_N, max_m: int = MAX_M, runs: int = RUNS):
    """Run the full N×M benchmark grid, timing only individual Rust FFI calls."""
    os.makedirs(RUST_TIME_OUTPUT_DIR, exist_ok=True)

    n_values = sorted(set([1, 2, 4, 8, 16, 32, 64, 128, 255]) & set(range(1, max_n + 1)))
    if max_n not in n_values:
        n_values.append(max_n)
        n_values.sort()
    m_values = sorted(set([1, 2, 4, 8, 16, 32, 64, 128, 255]) & set(range(1, max_m + 1)))
    if max_m not in m_values:
        m_values.append(max_m)
        m_values.sort()

    print(f"[Rust-time] Benchmark grid: N_inputs={n_values}, M_outputs={m_values}, runs={runs}")
    print(f"Metrics: {METRICS}")
    print(f"Results -> {RUST_TIME_OUTPUT_DIR}/")
    print()

    results: dict[str, dict[tuple[int, int], float]] = {m: {} for m in METRICS}

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

            timings: dict[str, list[float]] = {m: [] for m in METRICS}

            for run_idx in range(runs):
                out_params = []
                for i in range(m_outputs):
                    token_idx = i % n_inputs
                    token_uid = _make_token_uid(token_idx)
                    tag_raw = derive_tag(token_uid)
                    r_asset = _random_bytes(32)
                    value_blind = _random_bytes(32)
                    amount = 500 + i
                    out_params.append(dict(
                        token_uid=token_uid, tag_raw=tag_raw,
                        r_asset=r_asset, value_blind=value_blind, amount=amount,
                    ))

                dt_pedersen_create = 0.0
                pedersen_artifacts = []
                for op in out_params:
                    t0 = time.perf_counter()
                    blinded_gen = create_asset_commitment(op['tag_raw'], op['r_asset'])
                    commitment = create_commitment(op['amount'], op['value_blind'], blinded_gen)
                    range_proof = create_range_proof(
                        op['amount'], op['value_blind'], commitment, blinded_gen,
                    )
                    t1 = time.perf_counter()
                    dt_pedersen_create += t1 - t0
                    pedersen_artifacts.append(dict(
                        blinded_gen=blinded_gen, commitment=commitment,
                        range_proof=range_proof,
                    ))

                dt_surjection_create = 0.0
                surjection_proofs = []
                for op in out_params:
                    for attempt in range(MAX_PROOF_RETRIES):
                        try:
                            t0 = time.perf_counter()
                            proof = create_surjection_proof(
                                codomain_tag=op['tag_raw'],
                                codomain_blinding_factor=op['r_asset'],
                                domain=domain_create,
                            )
                            t1 = time.perf_counter()
                            dt_surjection_create += t1 - t0
                            break
                        except ValueError:
                            if attempt == MAX_PROOF_RETRIES - 1:
                                raise
                    surjection_proofs.append(proof)

                timings['pedersen_create'].append(dt_pedersen_create)
                timings['surjection_create'].append(dt_surjection_create)
                timings['total_create'].append(dt_pedersen_create + dt_surjection_create)

                dt_pedersen_verify = 0.0
                for art in pedersen_artifacts:
                    t0 = time.perf_counter()
                    ok = verify_range_proof(
                        art['range_proof'], art['commitment'], art['blinded_gen'],
                    )
                    t1 = time.perf_counter()
                    dt_pedersen_verify += t1 - t0
                    assert ok, "Range proof verification failed"

                dt_surjection_verify = 0.0
                for art, sp in zip(pedersen_artifacts, surjection_proofs):
                    t0 = time.perf_counter()
                    ok = verify_surjection_proof(
                        proof=sp,
                        codomain=art['blinded_gen'],
                        domain=domain_verify,
                    )
                    t1 = time.perf_counter()
                    dt_surjection_verify += t1 - t0
                    assert ok, "Surjection proof verification failed"

                timings['pedersen_verify'].append(dt_pedersen_verify)
                timings['surjection_verify'].append(dt_surjection_verify)
                timings['total_verify'].append(dt_pedersen_verify + dt_surjection_verify)

            for metric in METRICS:
                results[metric][(n_inputs, m_outputs)] = sum(timings[metric]) / runs

            pc = results['pedersen_create'][(n_inputs, m_outputs)] * 1000
            sc = results['surjection_create'][(n_inputs, m_outputs)] * 1000
            tc = results['total_create'][(n_inputs, m_outputs)] * 1000
            pv = results['pedersen_verify'][(n_inputs, m_outputs)] * 1000
            sv = results['surjection_verify'][(n_inputs, m_outputs)] * 1000
            tv = results['total_verify'][(n_inputs, m_outputs)] * 1000

            print(
                f"[{combo_idx:3d}/{total_combos}] N={n_inputs:3d} M={m_outputs:3d} | "
                f"create: ped={pc:7.1f} surj={sc:7.1f} tot={tc:7.1f}ms | "
                f"verify: ped={pv:7.1f} surj={sv:7.1f} tot={tv:7.1f}ms"
            )

    for metric in METRICS:
        path = os.path.join(RUST_TIME_OUTPUT_DIR, f'{metric}.csv')
        _write_csv(path, n_values, m_values, results[metric])

    print(f"\nDone. {len(METRICS)} CSVs saved to {RUST_TIME_OUTPUT_DIR}/")


def _write_csv(path, n_values, m_values, data):
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['n_inputs \\ m_outputs'] + [str(m) for m in m_values])
        for n in n_values:
            writer.writerow([str(n)] + [f'{data.get((n, m), 0.0):.6f}' for m in m_values])


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description='Full shielded output benchmark (grin BP swap)')
    p.add_argument('--max-n', type=int, default=MAX_N)
    p.add_argument('--max-m', type=int, default=MAX_M)
    p.add_argument('--runs', type=int, default=RUNS)
    args = p.parse_args()
    run_benchmark(max_n=args.max_n, max_m=args.max_m, runs=args.runs)
