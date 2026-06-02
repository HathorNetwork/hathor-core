"""
Benchmark: Surjection Proof with mixed transparent/shielded inputs.

Total inputs is fixed at 64.  We sweep:
  - s  (shielded inputs):  0, 1, 2, 4, 8, 16, 32, 64   (u = 64 - s)
  - M  (shielded outputs): 1, 2, 4, 8, 16, 32, 64

For each (s, M) pair we measure:
  1. Time to CREATE M surjection proofs (one per output).
  2. Time to VERIFY  M surjection proofs.

Each combination is run RUNS times; the average is stored.

Transparent inputs enter the surjection domain as *unblinded* generators
(blinding factor = ZERO_TWEAK), exactly as the real verifier does.
"""

import csv
import os
import sys
import time

# -- Make hathor-core importable --
HATHOR_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'hathor-core'))
if HATHOR_CORE not in sys.path:
    sys.path.insert(0, HATHOR_CORE)

from hathor.crypto.shielded._bindings import _lib
from hathor.crypto.shielded.asset_tag import create_asset_commitment, derive_asset_tag, derive_tag
from hathor.crypto.shielded.commitment import create_commitment
from hathor.crypto.shielded.surjection import create_surjection_proof, verify_surjection_proof

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
TOTAL_INPUTS = 64
RUNS = 3
MAX_PROOF_RETRIES = 5
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results_mixed')

ZERO_TWEAK = _lib.ZERO_TWEAK  # 32 bytes of zeros


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def _make_token_uid(index: int) -> bytes:
    return index.to_bytes(32, 'big')


def make_transparent_input(token_index: int) -> dict:
    """Simulate a transparent (unshielded) input.

    The domain entry uses the *unblinded* generator and ZERO_TWEAK,
    matching what ShieldedTransactionVerifier.verify_surjection_proofs does.
    """
    token_uid = _make_token_uid(token_index)
    tag_raw = derive_tag(token_uid)
    generator = derive_asset_tag(token_uid)  # unblinded, 33B

    return dict(
        token_uid=token_uid,
        tag_raw=tag_raw,
        r_asset=ZERO_TWEAK,           # no asset blinding
        blinded_gen=generator,         # unblinded generator
    )


def make_shielded_input(token_index: int) -> dict:
    """Simulate a shielded input (FullShieldedOutput being spent)."""
    token_uid = _make_token_uid(token_index)
    tag_raw = derive_tag(token_uid)

    r_asset = _random_bytes(32)
    blinded_gen = create_asset_commitment(tag_raw, r_asset)

    return dict(
        token_uid=token_uid,
        tag_raw=tag_raw,
        r_asset=r_asset,
        blinded_gen=blinded_gen,
    )


def make_shielded_output(token_index: int) -> dict:
    """Create a FullShieldedOutput (amount + token hidden)."""
    token_uid = _make_token_uid(token_index)
    tag_raw = derive_tag(token_uid)

    r_asset = _random_bytes(32)
    blinded_gen = create_asset_commitment(tag_raw, r_asset)

    amount = 500 + token_index
    value_blind = _random_bytes(32)
    commitment = create_commitment(amount, value_blind, blinded_gen)

    return dict(
        token_uid=token_uid,
        tag_raw=tag_raw,
        r_asset=r_asset,
        blinded_gen=blinded_gen,
        value_blind=value_blind,
        commitment=commitment,
        amount=amount,
    )


def run_benchmark(runs: int = RUNS):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    creation_csv = os.path.join(OUTPUT_DIR, 'creation_times.csv')
    verification_csv = os.path.join(OUTPUT_DIR, 'verification_times.csv')

    # Sweep values
    s_values = sorted(set([0, 1, 2, 4, 8, 16, 32, 64]) & set(range(0, TOTAL_INPUTS + 1)))
    m_values = [1, 2, 4, 8, 16, 32, 64]

    print(f"Fixed total inputs: {TOTAL_INPUTS}")
    print(f"Shielded input counts (s): {s_values}")
    print(f"Shielded output counts (M): {m_values}")
    print(f"Runs per combination: {runs}")
    print(f"Results will be saved to {OUTPUT_DIR}/")
    print()

    creation_results: dict[tuple[int, int], float] = {}
    verification_results: dict[tuple[int, int], float] = {}

    total_combos = len(s_values) * len(m_values)
    combo_idx = 0

    for s in s_values:
        u = TOTAL_INPUTS - s

        # Build the mixed input set:
        #   u transparent inputs (distinct tokens 0..u-1)
        #   s shielded inputs   (distinct tokens u..u+s-1)
        inputs = []
        for i in range(u):
            inputs.append(make_transparent_input(i))
        for i in range(s):
            inputs.append(make_shielded_input(u + i))

        # Domain for proof creation: (blinded_gen_33B, raw_tag_32B, blinding_factor_32B)
        domain_create = [
            (inp['blinded_gen'], inp['tag_raw'], inp['r_asset'])
            for inp in inputs
        ]

        # Domain for verification: just the 33B generators
        domain_verify = [inp['blinded_gen'] for inp in inputs]

        for m_outputs in m_values:
            combo_idx += 1

            # Each output uses a token that exists in the input set
            n_tokens = TOTAL_INPUTS
            outputs = [make_shielded_output(i % n_tokens) for i in range(m_outputs)]

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
                    assert ok, f"Verification failed! s={s}, M={m_outputs}"
                t1 = time.perf_counter()
                verification_times.append(t1 - t0)

            avg_create = sum(creation_times) / runs
            avg_verify = sum(verification_times) / runs

            creation_results[(s, m_outputs)] = avg_create
            verification_results[(s, m_outputs)] = avg_verify

            print(
                f"[{combo_idx:3d}/{total_combos}] "
                f"u={u:2d} transparent + s={s:2d} shielded inputs, "
                f"M={m_outputs:2d} shielded outputs | "
                f"create={avg_create*1000:8.2f}ms  verify={avg_verify*1000:8.2f}ms"
            )

    # Write CSVs
    _write_csv(creation_csv, s_values, m_values, creation_results)
    _write_csv(verification_csv, s_values, m_values, verification_results)
    print(f"\nDone. Results saved to:\n  {creation_csv}\n  {verification_csv}")


RUST_TIME_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results_mixed_rust_time')


def run_benchmark_rust_time(runs: int = RUNS):
    """Run the mixed benchmark, timing only individual Rust FFI calls."""
    os.makedirs(RUST_TIME_OUTPUT_DIR, exist_ok=True)

    creation_csv = os.path.join(RUST_TIME_OUTPUT_DIR, 'creation_times.csv')
    verification_csv = os.path.join(RUST_TIME_OUTPUT_DIR, 'verification_times.csv')

    s_values = sorted(set([0, 1, 2, 4, 8, 16, 32, 64]) & set(range(0, TOTAL_INPUTS + 1)))
    m_values = [1, 2, 4, 8, 16, 32, 64]

    print(f"[Rust-time] Fixed total inputs: {TOTAL_INPUTS}")
    print(f"Shielded input counts (s): {s_values}")
    print(f"Shielded output counts (M): {m_values}")
    print(f"Runs per combination: {runs}")
    print(f"Results will be saved to {RUST_TIME_OUTPUT_DIR}/")
    print()

    creation_results: dict[tuple[int, int], float] = {}
    verification_results: dict[tuple[int, int], float] = {}

    total_combos = len(s_values) * len(m_values)
    combo_idx = 0

    for s in s_values:
        u = TOTAL_INPUTS - s

        inputs = []
        for i in range(u):
            inputs.append(make_transparent_input(i))
        for i in range(s):
            inputs.append(make_shielded_input(u + i))

        domain_create = [
            (inp['blinded_gen'], inp['tag_raw'], inp['r_asset'])
            for inp in inputs
        ]
        domain_verify = [inp['blinded_gen'] for inp in inputs]

        for m_outputs in m_values:
            combo_idx += 1

            n_tokens = TOTAL_INPUTS
            outputs = [make_shielded_output(i % n_tokens) for i in range(m_outputs)]

            creation_times = []
            verification_times = []

            for run_idx in range(runs):
                # --- CREATION (per-call) ---
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

                # --- VERIFICATION (per-call) ---
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
                    assert ok, f"Verification failed! s={s}, M={m_outputs}"
                verification_times.append(dt_verify)

            avg_create = sum(creation_times) / runs
            avg_verify = sum(verification_times) / runs

            creation_results[(s, m_outputs)] = avg_create
            verification_results[(s, m_outputs)] = avg_verify

            print(
                f"[{combo_idx:3d}/{total_combos}] "
                f"u={u:2d} transparent + s={s:2d} shielded inputs, "
                f"M={m_outputs:2d} shielded outputs | "
                f"create={avg_create*1000:8.2f}ms  verify={avg_verify*1000:8.2f}ms"
            )

    _write_csv(creation_csv, s_values, m_values, creation_results)
    _write_csv(verification_csv, s_values, m_values, verification_results)
    print(f"\nDone. Results saved to:\n  {creation_csv}\n  {verification_csv}")


def _write_csv(
    path: str,
    s_values: list[int],
    m_values: list[int],
    results: dict[tuple[int, int], float],
) -> None:
    """Write CSV: rows = s (shielded inputs), cols = M (shielded outputs)."""
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        header = ['s_shielded_inputs \\ m_outputs'] + [str(m) for m in m_values]
        writer.writerow(header)
        for s in s_values:
            row = [str(s)]
            for m in m_values:
                row.append(f'{results.get((s, m), 0.0):.6f}')
            writer.writerow(row)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='Mixed transparent/shielded input benchmark (total inputs = 64)')
    parser.add_argument('--runs', type=int, default=RUNS, help='Repetitions per combination')
    args = parser.parse_args()
    run_benchmark(runs=args.runs)
