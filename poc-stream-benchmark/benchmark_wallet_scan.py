"""
Wallet-scan throughput benchmark for a stream of shielded transactions.

Emulates the work a Hathor wallet does when it scans an incoming stream of N
transactions, recovering and validating the shielded outputs addressed to it.
Each transaction has this (modularizable) shape:

    inputs : Q shielded   + (Q' - Q) transparent      (Q' total,  Q' >= Q >= 0)
    outputs: M shielded    + (M' - M) transparent      (M' total,  M' >= M >= 1)

Shielded outputs are FullShielded (Pedersen commitment + Borromean range proof +
asset commitment + asset-surjection proof) so both amount and token are hidden.
A single token (HTR, token_uid = 32 zero bytes) is used throughout, so the
surjection domain is always representable.

Per transaction the emulated wallet does, in order (this is what we TIME):

  1. RANGE PROOFS — verify every shielded output's range proof (v in [0, 2^k)),
     and, per the requested scenario, every shielded input's too. There is no
     batched range-proof verification available: the Rust `batch_verify_range_proofs`
     is a sequential loop AND is not exposed through the FFI, so this is a
     genuine per-proof loop. (Don't trust the "Bulletproof" docstrings — the
     primitive is secp256k1-zkp's Borromean RangeProof.)
  2. SURJECTION PROOFS — verify every shielded output's surjection proof against
     the domain of input asset generators. Also per-proof (no batch FFI).
  3. BALANCE — sum the Pedersen commitments and check homomorphic consistency
     via a single `verify_balance` call folding all transparent + shielded
     inputs/outputs of the tx.
  4. REWIND — for every shielded output, derive the rewind nonce from the
     wallet's scan key via ECDH (scan_priv * ephemeral_pub), rewind the range
     proof to recover (value, blinding, message), read token_uid || asset_bf
     out of the message, and cross-check it against the asset commitment
     (AUDIT-C015). This is the wallet recovering the hidden value AND token.
  5. BALANCE UPDATE — accumulate the recovered per-token balance across the
     whole stream (shielded outputs via rewind, transparent outputs directly).

MAIN GOAL: total wall time of this scenario, **rewind included**, broken down by
phase. Stream construction (building the txs + proofs) is prep and is NOT timed —
a wallet receives these from the network already built.

The ECDH root secret is a fixed DUMMY scan key (see `_DUMMY_SCAN_SCALAR`); every
shielded output in the stream is assumed addressed to the wallet, so every rewind
succeeds — the heaviest case for the recovery phase.

Bindings: the same scenario can be driven through different crypto bindings to
study FFI/runtime overhead, selected with `--binding` (the CSV's `binding`
column tags each row). All write the same CSV schema, so rows compare directly:
  - `python-ffi` (default): the in-process PyO3 bindings, timed directly here.
  - `node-napi`: delegates the whole run to benchmark_wallet_scan_node.js, which
    mirrors this benchmark using the @hathor/ct-crypto-node NAPI native addon.
    Requires Node >= 18 + `npm install @hathor/ct-crypto-node`.
  - `wasm`: delegates to benchmark_wallet_scan_wasm.js, using the
    @hathor/ct-crypto-wasm browser build. That build has NO verify/create-proof
    surface, so only the recovery phases run — rewind is bundled (ECDH + rewind +
    the internal AUDIT-C015 asset-commitment recheck), and the verify/ecdh/
    recover-check columns are left blank. Requires Node >= 18 + both
    `npm install @hathor/ct-crypto-wasm` (timed recovery) and
    `@hathor/ct-crypto-node` (builds the untimed stream).

A fourth binding, `rust-pure`, comes from the native-Rust baseline
hathor-ct-crypto/examples/wallet_scan_native.rs (run separately via cargo). It
runs this same 7-phase pass with zero FFI/runtime marshalling and appends a
`binding=rust-pure` row to the same CSV — the zero-overhead lower bound that the
other three bindings are measured against.

Modularizable parameters (CLI flags): N, M, M', Q, Q', k.
Defaults: N=150, M=1, M'=2, Q=0, Q'=1, k=64.
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field

HATHOR_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if HATHOR_CORE not in sys.path:
    sys.path.insert(0, HATHOR_CORE)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hathor.crypto.shielded._bindings import _lib
from hathor.crypto.shielded.asset_tag import create_asset_commitment, derive_asset_tag, derive_tag
from hathor.crypto.shielded.balance import compute_balancing_blinding_factor, verify_balance
from hathor.crypto.shielded.commitment import create_commitment
from hathor.crypto.shielded.ecdh import derive_ecdh_shared_secret, derive_rewind_nonce, generate_ephemeral_keypair
from hathor.crypto.shielded.range_proof import create_range_proof, rewind_range_proof, verify_range_proof
from hathor.crypto.shielded.surjection import create_surjection_proof, verify_surjection_proof

ZERO_TWEAK: bytes = _lib.ZERO_TWEAK

# Single-token streams. token_uid = 32 zero bytes is the HTR-like canonical asset.
TOKEN_UID = b'\x00' * 32

# Fixed dummy ECDH root secret for the wallet's scan key. The value is arbitrary;
# it just has to be a valid, non-zero secp256k1 scalar.
_DUMMY_SCAN_SCALAR = 0x4861_7468_6F72_5F77_616C_6C65_745F_7363_616E_5F6B_6579_5F64_756D_6D79_2A2A

# Surjection-proof creation is probabilistic; retry a few times before giving up.
MAX_SURJECTION_RETRIES = 5

DEFAULTS = dict(n=150, m=1, m_prime=2, q=0, q_prime=1, k=64)


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------

def _keypair_from_scalar(scalar: int) -> tuple[bytes, bytes]:
    """Build (priv_32B, compressed_pub_33B) from a fixed secp256k1 scalar."""
    priv = ec.derive_private_key(scalar, ec.SECP256K1())
    pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    return scalar.to_bytes(32, 'big'), pub


SCAN_PRIVKEY, SCAN_PUBKEY = _keypair_from_scalar(_DUMMY_SCAN_SCALAR)


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------

@dataclass
class ShieldedItem:
    """A FullShielded input or output: everything the wallet needs to validate
    and (for outputs) rewind it."""
    amount: int
    value_blind: bytes              # 32B value blinding factor
    r_asset: bytes                  # 32B asset blinding factor
    asset_commitment: bytes         # 33B blinded generator H_token + r_asset*G (== range/rewind generator)
    commitment: bytes               # 33B Pedersen commitment
    range_proof: bytes              # Borromean range proof
    surjection_proof: bytes | None  # set on outputs, None on inputs
    ephemeral_pubkey: bytes | None  # 33B, set on outputs (for ECDH rewind), None on inputs


@dataclass
class WalletTx:
    """One synthetic transaction in the stream, from the wallet's point of view."""
    transparent_inputs: list[tuple[int, bytes]]    # (amount, token_uid)
    shielded_inputs: list[ShieldedItem]
    transparent_outputs: list[tuple[int, bytes]]   # (amount, token_uid)
    shielded_outputs: list[ShieldedItem]
    surjection_domain: list[bytes] = field(default_factory=list)  # input asset generators (verify side)


# --------------------------------------------------------------------------
# Stream construction (NOT timed — this is wallet/network prep)
# --------------------------------------------------------------------------

def _split_amount(total: int, parts: int) -> list[int]:
    """Split `total` into `parts` positive integers summing exactly to `total`.

    Near-equal split; the last part absorbs the remainder. Requires total >= parts
    so every part is >= 1 (range proofs reject zero-value commitments)."""
    base = total // parts
    out = [base] * parts
    out[-1] += total - base * parts
    return out


def _make_surjection_proof(tag_raw: bytes, r_asset: bytes, domain_create: list[tuple[bytes, bytes, bytes]]) -> bytes:
    """Create a surjection proof, retrying the probabilistic creation step."""
    for attempt in range(MAX_SURJECTION_RETRIES):
        try:
            return create_surjection_proof(
                codomain_tag=tag_raw,
                codomain_blinding_factor=r_asset,
                domain=domain_create,
            )
        except ValueError:
            if attempt == MAX_SURJECTION_RETRIES - 1:
                raise
    raise AssertionError('unreachable')


def _build_shielded_input(amount: int) -> ShieldedItem:
    """A pre-existing FullShielded UTXO the wallet owns and is now spending.

    It carries a valid range proof (verified again by the scenario) but no
    surjection proof / ephemeral key of its own — those live on outputs."""
    tag_raw = derive_tag(TOKEN_UID)
    r_asset = _random_bytes(32)
    vbf = _random_bytes(32)
    asset_commitment = create_asset_commitment(tag_raw, r_asset)
    commitment = create_commitment(amount, vbf, asset_commitment)
    range_proof = create_range_proof(amount, vbf, commitment, asset_commitment)  # random nonce; not rewound here
    return ShieldedItem(
        amount=amount, value_blind=vbf, r_asset=r_asset,
        asset_commitment=asset_commitment, commitment=commitment,
        range_proof=range_proof, surjection_proof=None, ephemeral_pubkey=None,
    )


def _seal_shielded_output(
    amount: int,
    vbf: bytes,
    r_asset: bytes,
    domain_create: list[tuple[bytes, bytes, bytes]],
) -> ShieldedItem:
    """Build a FullShielded output addressed to the wallet's scan key.

    The range proof is made rewindable: its nonce is derived from the ECDH
    shared secret (ephemeral_priv * scan_pub) and its message embeds
    token_uid || r_asset, mirroring how PR 1603's wallet recovers the output."""
    tag_raw = derive_tag(TOKEN_UID)
    asset_commitment = create_asset_commitment(tag_raw, r_asset)
    commitment = create_commitment(amount, vbf, asset_commitment)

    eph_priv, eph_pub = generate_ephemeral_keypair()
    shared_secret = derive_ecdh_shared_secret(eph_priv, SCAN_PUBKEY)
    nonce = derive_rewind_nonce(shared_secret)
    message = TOKEN_UID + r_asset  # wallet reads [:32]=token_uid, [32:64]=asset_bf

    range_proof = create_range_proof(amount, vbf, commitment, asset_commitment, message, nonce)
    surjection_proof = _make_surjection_proof(tag_raw, r_asset, domain_create)

    return ShieldedItem(
        amount=amount, value_blind=vbf, r_asset=r_asset,
        asset_commitment=asset_commitment, commitment=commitment,
        range_proof=range_proof, surjection_proof=surjection_proof, ephemeral_pubkey=eph_pub,
    )


def build_tx(m: int, m_prime: int, q: int, q_prime: int, k: int) -> WalletTx:
    """Construct one balanced transaction of the requested shape."""
    total = _pick_budget(k, max(m_prime, q_prime))

    # ---- Inputs ----
    in_values = _split_amount(total, q_prime)
    transparent_in_values = in_values[: q_prime - q]
    shielded_in_values = in_values[q_prime - q:]
    transparent_inputs = [(v, TOKEN_UID) for v in transparent_in_values]
    shielded_inputs = [_build_shielded_input(v) for v in shielded_in_values]

    # Surjection domain = asset generators of ALL inputs (create-side carries the
    # raw tag + blinding factor; verify-side only the 33B generator).
    tag_raw = derive_tag(TOKEN_UID)
    transparent_gen = derive_asset_tag(TOKEN_UID)
    domain_create: list[tuple[bytes, bytes, bytes]] = (
        [(transparent_gen, tag_raw, ZERO_TWEAK)] * len(transparent_inputs)
        + [(inp.asset_commitment, tag_raw, inp.r_asset) for inp in shielded_inputs]
    )
    domain_verify: list[bytes] = (
        [transparent_gen] * len(transparent_inputs)
        + [inp.asset_commitment for inp in shielded_inputs]
    )

    # ---- Outputs ----
    out_values = _split_amount(total, m_prime)
    transparent_out_values = out_values[: m_prime - m]
    shielded_out_values = out_values[m_prime - m:]
    transparent_outputs = [(v, TOKEN_UID) for v in transparent_out_values]

    # Shielded outputs: the first M-1 get fresh random blinding factors; the last
    # one's value blinding factor is computed so the homomorphic equation balances.
    # Only shielded entries feed the balancing computation — transparent entries
    # are zero-blinded and contribute nothing to the blinding-factor sum.
    other_secrets: list[tuple[int, bytes, bytes]] = []  # (value, vbf, r_asset)
    for v in shielded_out_values[:-1]:
        other_secrets.append((v, _random_bytes(32), _random_bytes(32)))

    last_value = shielded_out_values[-1]
    last_r_asset = _random_bytes(32)
    inputs_bf = [(inp.amount, inp.value_blind, inp.r_asset) for inp in shielded_inputs]
    last_vbf = compute_balancing_blinding_factor(
        value=last_value,
        generator_blinding_factor=last_r_asset,
        inputs=inputs_bf,
        other_outputs=other_secrets,
    )

    shielded_outputs: list[ShieldedItem] = [
        _seal_shielded_output(v, vbf, r_asset, domain_create) for (v, vbf, r_asset) in other_secrets
    ]
    shielded_outputs.append(_seal_shielded_output(last_value, last_vbf, last_r_asset, domain_create))

    return WalletTx(
        transparent_inputs=transparent_inputs,
        shielded_inputs=shielded_inputs,
        transparent_outputs=transparent_outputs,
        shielded_outputs=shielded_outputs,
        surjection_domain=domain_verify,
    )


def _pick_budget(k: int, min_parts: int) -> int:
    """A per-tx total value budget that is a k-bit number, i.e. in [2^(k-1), 2^k).

    Every input/output amount is a share of this budget, so all amounts are in
    [1, 2^k) — the range proofs prove v in [0, 2^k) as requested. Must be at
    least `min_parts` so every share is >= 1."""
    lo = 1 << (k - 1)
    hi = (1 << k) - 1
    span = hi - lo + 1
    t = lo + (int.from_bytes(os.urandom(8), 'big') % span if span > 1 else 0)
    if t < min_parts:
        raise ValueError(f'k={k} is too small to split into {min_parts} positive parts')
    return t


def build_stream(n: int, m: int, m_prime: int, q: int, q_prime: int, k: int) -> list[WalletTx]:
    return [build_tx(m, m_prime, q, q_prime, k) for _ in range(n)]


# --------------------------------------------------------------------------
# The wallet pass (TIMED)
# --------------------------------------------------------------------------

@dataclass
class PhaseTimes:
    range_s: float = 0.0
    surjection_s: float = 0.0
    balance_s: float = 0.0
    ecdh_s: float = 0.0           # ECDH shared-secret + rewind-nonce KDF (per shielded output)
    rewind_s: float = 0.0         # rewind_range_proof ONLY (the recovery primitive)
    recover_check_s: float = 0.0  # AUDIT-C015 asset-commitment recheck of recovered secrets
    update_s: float = 0.0
    total_s: float = 0.0


def wallet_pass(txs: list[WalletTx]) -> tuple[PhaseTimes, dict[bytes, int]]:
    """Run + time the full wallet scan over the stream. Returns (timings, balances)."""
    t = PhaseTimes()
    balances: dict[bytes, int] = {}

    wall0 = time.perf_counter()
    for tx in txs:
        # 1. Range proofs — shielded outputs and (per the scenario) shielded inputs.
        #    No batch FFI exists, so this is genuinely one verify call per proof.
        t0 = time.perf_counter()
        for out in tx.shielded_outputs:
            assert verify_range_proof(out.range_proof, out.commitment, out.asset_commitment), 'range verify failed'
        for inp in tx.shielded_inputs:
            assert verify_range_proof(inp.range_proof, inp.commitment, inp.asset_commitment), 'range verify failed'
        t.range_s += time.perf_counter() - t0

        # 2. Surjection proofs — one per shielded output, against the input domain.
        t0 = time.perf_counter()
        for out in tx.shielded_outputs:
            assert verify_surjection_proof(out.surjection_proof, out.asset_commitment, tx.surjection_domain), \
                'surjection verify failed'
        t.surjection_s += time.perf_counter() - t0

        # 3. Balance — single homomorphic check folding all in/out commitments.
        #    Build the commitment lists OUTSIDE the timer so the bucket is the
        #    verify_balance FFI call alone, not the Python list assembly.
        in_commits = [inp.commitment for inp in tx.shielded_inputs]
        out_commits = [out.commitment for out in tx.shielded_outputs]
        t0 = time.perf_counter()
        assert verify_balance(
            transparent_inputs=tx.transparent_inputs,
            shielded_inputs=in_commits,
            transparent_outputs=tx.transparent_outputs,
            shielded_outputs=out_commits,
        ), 'balance verify failed'
        t.balance_s += time.perf_counter() - t0

        # 4. Recover — for each shielded output, the wallet ECDH-derives the rewind
        #    nonce, rewinds the proof to recover (value, token), and re-checks the
        #    recovered token against the asset commitment. Three DISTINCT costs,
        #    timed separately so "rewind" reflects only rewind_range_proof — not
        #    the ECDH key reconstruction (~14% of the bucket) or the recheck.
        recovered: list[tuple[bytes, int]] = []  # (token_uid, value)
        for out in tx.shielded_outputs:
            t0 = time.perf_counter()
            shared_secret = derive_ecdh_shared_secret(SCAN_PRIVKEY, out.ephemeral_pubkey)
            nonce = derive_rewind_nonce(shared_secret)
            t.ecdh_s += time.perf_counter() - t0

            t0 = time.perf_counter()
            value, _blinding, message = rewind_range_proof(
                out.range_proof, out.commitment, nonce, out.asset_commitment,
            )
            t.rewind_s += time.perf_counter() - t0

            t0 = time.perf_counter()
            token_id = bytes(message[:32])
            asset_bf = bytes(message[32:64])
            # AUDIT-C015: reconstruct the asset commitment from recovered secrets.
            assert create_asset_commitment(derive_tag(token_id), asset_bf) == out.asset_commitment, \
                'recovered token UID does not match asset_commitment'
            assert value == out.amount, 'rewound value mismatch'
            t.recover_check_s += time.perf_counter() - t0

            recovered.append((token_id, value))

        # 5. Balance update — accumulate per-token totals over the whole stream.
        t0 = time.perf_counter()
        for token_id, value in recovered:
            balances[token_id] = balances.get(token_id, 0) + value
        for value, token_uid in tx.transparent_outputs:
            balances[token_uid] = balances.get(token_uid, 0) + value
        t.update_s += time.perf_counter() - t0

    t.total_s = time.perf_counter() - wall0
    return t, balances


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def run(n: int, m: int, m_prime: int, q: int, q_prime: int, k: int, runs: int,
        binding: str, output_dir: str) -> None:
    _validate(n, m, m_prime, q, q_prime, k, runs)

    print(f"Wallet-scan benchmark | N={n} M={m} M'={m_prime} Q={q} Q'={q_prime} k={k} "
          f"runs={runs} binding={binding}")
    print(f"  tx shape: {q} shielded + {q_prime - q} transparent inputs -> "
          f"{m} shielded + {m_prime - m} transparent outputs")

    samples: list[PhaseTimes] = []
    for r in range(runs):
        txs = build_stream(n, m, m_prime, q, q_prime, k)   # prep: NOT timed
        timing, _balances = wallet_pass(txs)               # the timed scenario
        samples.append(timing)
        print(f"  run {r + 1}/{runs}: total={timing.total_s:7.3f}s "
              f"[range={timing.range_s:6.3f} surj={timing.surjection_s:6.3f} "
              f"bal={timing.balance_s:6.3f} ecdh={timing.ecdh_s:6.3f} "
              f"rewind={timing.rewind_s:6.3f} recheck={timing.recover_check_s:6.4f} "
              f"update={timing.update_s:6.4f}]")

    def _mean(attr: str) -> float:
        return sum(getattr(s, attr) for s in samples) / len(samples)

    total_s = _mean('total_s')
    range_s = _mean('range_s')
    surj_s = _mean('surjection_s')
    bal_s = _mean('balance_s')
    ecdh_s = _mean('ecdh_s')
    rewind_s = _mean('rewind_s')
    recheck_s = _mean('recover_check_s')
    update_s = _mean('update_s')

    n_range = n * (m + q)
    n_surj = n * m
    n_out = n * m   # per shielded-output phases: ecdh, rewind, recover-check
    n_balance = n

    print()
    print(f"  AVERAGE over {runs} run(s): total {total_s:.3f}s  ({total_s / n * 1000:.3f} ms/tx)")
    print(f"    range       {range_s:8.3f}s  {_safe_ms(range_s, n_range):8.3f} ms/proof  ({n_range} proofs)")
    print(f"    surjection  {surj_s:8.3f}s  {_safe_ms(surj_s, n_surj):8.3f} ms/proof  ({n_surj} proofs)")
    print(f"    balance     {bal_s:8.3f}s  {_safe_ms(bal_s, n_balance):8.3f} ms/tx     ({n_balance} txs)")
    print(f"    ecdh+nonce  {ecdh_s:8.3f}s  {_safe_ms(ecdh_s, n_out):8.3f} ms/output ({n_out} outputs)")
    print(f"    rewind      {rewind_s:8.3f}s  {_safe_ms(rewind_s, n_out):8.3f} ms/output ({n_out} outputs)")
    print(f"    recover-chk {recheck_s:8.3f}s  {_safe_ms(recheck_s, n_out):8.3f} ms/output ({n_out} outputs)")
    print(f"    update      {update_s:8.4f}s")

    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, 'wallet_scan.csv')
    row = dict(
        binding=binding, n=n, shielded_outputs=m, total_outputs=m_prime,
        shielded_inputs=q, total_inputs=q_prime, bits=k, runs=runs,
        total_s=total_s, range_verify_s=range_s, surjection_verify_s=surj_s,
        balance_verify_s=bal_s, ecdh_s=ecdh_s, rewind_s=rewind_s,
        recover_check_s=recheck_s, balance_update_s=update_s,
        per_tx_total_ms=total_s / n * 1000.0,
        num_range_verifs=n_range, num_surjection_verifs=n_surj, num_shielded_outputs=n_out,
        per_range_verify_ms=_safe_ms(range_s, n_range),
        per_surjection_verify_ms=_safe_ms(surj_s, n_surj),
        per_balance_verify_ms=_safe_ms(bal_s, n_balance),
        per_ecdh_ms=_safe_ms(ecdh_s, n_out),
        per_rewind_ms=_safe_ms(rewind_s, n_out),
        per_recover_check_ms=_safe_ms(recheck_s, n_out),
    )
    write_header = not os.path.exists(csv_path)
    with open(csv_path, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if write_header:
            writer.writeheader()
        writer.writerow(row)
    print(f"\n  {'wrote header + 1 row' if write_header else 'appended 1 row'} -> {csv_path}")


def _safe_ms(seconds: float, count: int) -> float:
    return seconds / count * 1000.0 if count else 0.0


def _validate(n: int, m: int, m_prime: int, q: int, q_prime: int, k: int, runs: int) -> None:
    if n < 1:
        raise SystemExit('N must be >= 1')
    if m < 1:
        raise SystemExit('M (shielded outputs) must be >= 1 (need a shielded output to balance and rewind)')
    if m_prime < m:
        raise SystemExit("M' (total outputs) must be >= M")
    if q < 0:
        raise SystemExit('Q (shielded inputs) must be >= 0')
    if q_prime < q:
        raise SystemExit("Q' (total inputs) must be >= Q")
    if q_prime < 1:
        raise SystemExit("Q' must be >= 1 (FullShielded outputs need a non-empty surjection domain)")
    if not (1 <= k <= 64):
        raise SystemExit('k must be in [1, 64] (amounts are u64)')
    if (1 << (k - 1)) < max(m_prime, q_prime):
        raise SystemExit(f"k={k} is too small to give every input/output a positive share")
    if runs < 1:
        raise SystemExit('--runs must be >= 1')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('-N', '--num-txs', type=int, default=DEFAULTS['n'],
                   help=f"N: transactions in the stream (default {DEFAULTS['n']})")
    p.add_argument('-M', '--shielded-outputs', type=int, default=DEFAULTS['m'],
                   help=f"M: shielded outputs per tx (default {DEFAULTS['m']})")
    p.add_argument("--total-outputs", type=int, default=DEFAULTS['m_prime'],
                   help=f"M': total outputs per tx, M' >= M (default {DEFAULTS['m_prime']})")
    p.add_argument('-Q', '--shielded-inputs', type=int, default=DEFAULTS['q'],
                   help=f"Q: shielded inputs per tx (default {DEFAULTS['q']})")
    p.add_argument("--total-inputs", type=int, default=DEFAULTS['q_prime'],
                   help=f"Q': total inputs per tx, Q' >= Q and Q' >= 1 (default {DEFAULTS['q_prime']})")
    p.add_argument('-k', '--bits', type=int, default=DEFAULTS['k'],
                   help=f"k: amount bit-width, v in [0, 2^k) (default {DEFAULTS['k']})")
    p.add_argument('--runs', type=int, default=1, help='independent stream rebuilds, averaged (default 1)')
    p.add_argument('--binding', choices=['python-ffi', 'node-napi', 'wasm'], default='python-ffi',
                   help="crypto binding: 'python-ffi' runs in-process (default); 'node-napi' delegates to "
                        "benchmark_wallet_scan_node.js (@hathor/ct-crypto-node); 'wasm' delegates to "
                        "benchmark_wallet_scan_wasm.js (@hathor/ct-crypto-wasm, recovery-only)")
    p.add_argument('--output-dir', default=os.path.join(os.path.dirname(__file__), 'results_wallet'))
    args = p.parse_args()

    if args.binding in ('node-napi', 'wasm'):
        raise SystemExit(_dispatch_to_node_binding(args))

    run(n=args.num_txs, m=args.shielded_outputs, m_prime=args.total_outputs,
        q=args.shielded_inputs, q_prime=args.total_inputs, k=args.bits,
        runs=args.runs, binding=args.binding, output_dir=args.output_dir)


def _dispatch_to_node_binding(args: argparse.Namespace) -> int:
    """Delegate the run to a Node-hosted binding twin (node-napi or wasm).

    Both twins (benchmark_wallet_scan_node.js / benchmark_wallet_scan_wasm.js)
    append a row with the same CSV schema (tagged with the chosen binding) to the
    same results_wallet/wallet_scan.csv, so all bindings compare directly. Both
    need Node >= 18: node-napi uses @hathor/ct-crypto-node; wasm uses
    @hathor/ct-crypto-wasm for the timed recovery (+ @hathor/ct-crypto-node to
    build the untimed stream). The wasm twin accepts but ignores M'/Q/Q' —
    recovery touches only the M shielded outputs per tx."""
    node = shutil.which('node')
    if node is None:
        raise SystemExit(f"--binding {args.binding} requires Node.js (>= 18) on PATH, but 'node' was not found.")
    script_name = 'benchmark_wallet_scan_wasm.js' if args.binding == 'wasm' else 'benchmark_wallet_scan_node.js'
    script = os.path.join(os.path.dirname(__file__), script_name)
    cmd = [
        node, script,
        '--num-txs', str(args.num_txs),
        '--shielded-outputs', str(args.shielded_outputs),
        '--total-outputs', str(args.total_outputs),
        '--shielded-inputs', str(args.shielded_inputs),
        '--total-inputs', str(args.total_inputs),
        '--bits', str(args.bits),
        '--runs', str(args.runs),
        '--binding', args.binding,
        '--output-dir', args.output_dir,
    ]
    print(f'Delegating to {args.binding} binding:\n  {" ".join(cmd)}\n')
    return subprocess.run(cmd).returncode


if __name__ == '__main__':
    main()
