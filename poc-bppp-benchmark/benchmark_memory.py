"""
Size / on-wire-bytes benchmark for the shielded-output payload.

For each (N shielded inputs, M shielded outputs) pair, reports SEVEN metrics
(all are total bytes per transaction across all M outputs unless noted):

  PER-ARTIFACT (sum across M outputs):
    1. commitments       — bppp value commitments            (33 B each)
    2. blinded_gens      — blinded asset generators          (33 B each)
    3. range_proofs      — bppp (Bulletproofs++) range proofs (~541 B each, u64)
    4. surjection_proofs — asset surjection proofs           (grows with N-input domain)

  AGGREGATE:
    5. total_payload     — sum of 1..4 (everything the shielded section adds to the tx)
    6. per_output        — total_payload / M, useful for extrapolation

  PER-INPUT DOMAIN (not summed across outputs; it's the serialized list the verifier needs):
    7. domain_verify     — 33 * N bytes (the list of blinded generators for verification)

NOTE on the primitive: the range proof here is a **Bulletproofs++** (bppp) u64 range
proof, produced by the `hathor_bppp` PyO3 binding around the
[distributed-lab/bp-pp](https://github.com/distributed-lab/bp-pp) Rust crate. This is
the bppp counterpart of the original `poc-shielded-benchmark/` folder, which used the
Borromean ring-signature range proof from secp256k1-zkp.

NOTE on amount choice: bppp always proves the full u64 range — there is no auto-min-bits
shortcut. The constant `AMOUNT_FOR_SIZING` therefore has no effect on the proof size
(unlike the Borromean variant, where small amounts produced much smaller proofs).

Sizes are deterministic for commitments/generators/range proofs; surjection proof
size can vary slightly between calls (random used-input subset), so each (N,M) is
sampled `RUNS` times and the mean is reported.
"""

import csv
import os
import statistics
import sys

HATHOR_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'hathor-core'))
if HATHOR_CORE not in sys.path:
    sys.path.insert(0, HATHOR_CORE)

from hathor.crypto.shielded.asset_tag import create_asset_commitment, derive_tag
from hathor.crypto.shielded.surjection import create_surjection_proof
from bppp_range_proof import create_commitment, create_range_proof  # bppp swap

# ---------------------------------------------------------------------------
MAX_N = 64
MAX_M = 64
RUNS = 3
MAX_PROOF_RETRIES = 5
# bppp always proves the full u64 range, so this value is decoupled from proof size.
# Kept identical to the Borromean benchmark for easy diff against the original folder.
AMOUNT_FOR_SIZING = 10**18
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'results_memory')

METRICS = [
    'commitments',
    'blinded_gens',
    'range_proofs',
    'surjection_proofs',
    'total_payload',
    'per_output',
    'domain_verify',
]


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def _make_token_uid(index: int) -> bytes:
    return index.to_bytes(32, 'big')


def _make_shielded_input(token_index: int) -> dict:
    token_uid = _make_token_uid(token_index)
    tag_raw = derive_tag(token_uid)
    r_asset = _random_bytes(32)
    blinded_gen = create_asset_commitment(tag_raw, r_asset)
    return dict(tag_raw=tag_raw, r_asset=r_asset, blinded_gen=blinded_gen)


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

    print(f"Memory benchmark grid: N_inputs={n_values}, M_outputs={m_values}, runs={runs}")
    print(f"Results -> {OUTPUT_DIR}/")
    print()

    results: dict[str, dict[tuple[int, int], float]] = {m: {} for m in METRICS}

    total_combos = len(n_values) * len(m_values)
    combo_idx = 0

    for n_inputs in n_values:
        inputs = [_make_shielded_input(i % 256) for i in range(n_inputs)]
        domain_create = [
            (inp['blinded_gen'], inp['tag_raw'], inp['r_asset']) for inp in inputs
        ]
        domain_verify_bytes = sum(len(inp['blinded_gen']) for inp in inputs)

        for m_outputs in m_values:
            combo_idx += 1

            samples = {m: [] for m in METRICS if m != 'domain_verify'}

            for _ in range(runs):
                commit_total = 0
                gen_total = 0
                rp_total = 0
                sp_total = 0

                for i in range(m_outputs):
                    token_idx = i % n_inputs
                    token_uid = _make_token_uid(token_idx)
                    tag_raw = derive_tag(token_uid)
                    r_asset = _random_bytes(32)
                    value_blind = _random_bytes(32)
                    amount = AMOUNT_FOR_SIZING

                    blinded_gen = create_asset_commitment(tag_raw, r_asset)
                    commitment = create_commitment(amount, value_blind, blinded_gen)
                    range_proof = create_range_proof(amount, value_blind, commitment, blinded_gen)

                    for attempt in range(MAX_PROOF_RETRIES):
                        try:
                            surjection_proof = create_surjection_proof(
                                codomain_tag=tag_raw,
                                codomain_blinding_factor=r_asset,
                                domain=domain_create,
                            )
                            break
                        except ValueError:
                            if attempt == MAX_PROOF_RETRIES - 1:
                                raise

                    commit_total += len(commitment)
                    gen_total += len(blinded_gen)
                    rp_total += len(range_proof)
                    sp_total += len(surjection_proof)

                total = commit_total + gen_total + rp_total + sp_total

                samples['commitments'].append(commit_total)
                samples['blinded_gens'].append(gen_total)
                samples['range_proofs'].append(rp_total)
                samples['surjection_proofs'].append(sp_total)
                samples['total_payload'].append(total)
                samples['per_output'].append(total / m_outputs)

            for metric, vals in samples.items():
                results[metric][(n_inputs, m_outputs)] = statistics.mean(vals)
            results['domain_verify'][(n_inputs, m_outputs)] = domain_verify_bytes

            r = {k: results[k][(n_inputs, m_outputs)] for k in METRICS}
            print(
                f"[{combo_idx:3d}/{total_combos}] N={n_inputs:3d} M={m_outputs:3d} | "
                f"com={r['commitments']:>6.0f}B  gen={r['blinded_gens']:>6.0f}B  "
                f"rp={r['range_proofs']:>8.0f}B  sp={r['surjection_proofs']:>8.0f}B | "
                f"total={r['total_payload']/1024:>7.2f} KiB  "
                f"per_out={r['per_output']/1024:>5.2f} KiB  "
                f"dom_verify={r['domain_verify']:>5.0f}B"
            )

    for metric in METRICS:
        path = os.path.join(OUTPUT_DIR, f'{metric}.csv')
        _write_csv(path, n_values, m_values, results[metric])

    print(f"\nDone. {len(METRICS)} CSVs saved to {OUTPUT_DIR}/")


def _write_csv(path, n_values, m_values, data):
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['n_inputs \\ m_outputs'] + [str(m) for m in m_values])
        for n in n_values:
            writer.writerow([str(n)] + [f'{data.get((n, m), 0.0):.2f}' for m in m_values])


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description='Shielded-output payload size benchmark (bytes)')
    p.add_argument('--max-n', type=int, default=MAX_N)
    p.add_argument('--max-m', type=int, default=MAX_M)
    p.add_argument('--runs', type=int, default=RUNS)
    args = p.parse_args()
    run_benchmark(max_n=args.max_n, max_m=args.max_m, runs=args.runs)
