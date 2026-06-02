"""
Shared transaction-stream construction for the stream benchmarks.

A "stream" is a list of synthetic transactions, each with:
  - INPUTS_PER_TX shielded inputs (their secrets remembered locally — these stand
    in for unspent shielded UTXOs the wallet owns).
  - OUTPUTS_PER_TX shielded outputs whose value blinding factors are chosen so
    that the homomorphic balance equation holds for the tx.

Two modes:
  - 'amount_hidden': each output is an AmountShielded-style output. The asset
    generator is the unblinded token tag H_token (no asset_commitment, no
    surjection proof). Only the amount is hidden.
  - 'fully_shielded': each output additionally carries an asset_commitment
    A = H_token + r_asset*G and a surjection proof over the domain of input
    asset commitments. Both the amount and the token are hidden.

For benchmarking we use a single HTR-like token (token_uid = 32 zero bytes) so
the surjection domain always matches. The surjection codomain tag for an output
is the same token tag the inputs were built over — i.e. all txs are single-token.

Balance is enforced per-tx via `compute_balancing_blinding_factor`, so
`verify_balance` returns True for every constructed tx.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

HATHOR_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if HATHOR_CORE not in sys.path:
    sys.path.insert(0, HATHOR_CORE)

from hathor.crypto.shielded._bindings import _lib
from hathor.crypto.shielded.asset_tag import create_asset_commitment, derive_tag
from hathor.crypto.shielded.balance import compute_balancing_blinding_factor
from hathor.crypto.shielded.commitment import create_commitment
from hathor.crypto.shielded.range_proof import create_range_proof
from hathor.crypto.shielded.surjection import create_surjection_proof

ZERO_TWEAK: bytes = _lib.ZERO_TWEAK

# Single-token streams for benchmarking. token_uid = 32 zero bytes is the HTR-like
# canonical asset. Using a single token keeps the surjection codomain always
# representable in any input domain.
TOKEN_UID = b'\x00' * 32

# Each input has its amount in [INPUT_AMOUNT_LO, INPUT_AMOUNT_HI]. The outputs
# split that amount so the per-tx balance equation holds. We use 64-bit-friendly
# magnitudes so the range proof exercises a realistic bit width.
INPUT_AMOUNT_LO = 10**12
INPUT_AMOUNT_HI = 10**12 + 10**6

MODE_AMOUNT_HIDDEN = 'amount_hidden'
MODE_FULLY_SHIELDED = 'fully_shielded'
MODES = (MODE_AMOUNT_HIDDEN, MODE_FULLY_SHIELDED)

MAX_SURJECTION_RETRIES = 5


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


@dataclass
class ShieldedInput:
    """A pre-built shielded UTXO the wallet 'owns', usable as a tx input."""
    amount: int
    value_blind: bytes              # 32B vbf
    r_asset: bytes                  # 32B asset blinding factor (zeros for amount_hidden)
    tag_raw: bytes                  # 32B raw tag derived from token_uid
    blinded_gen: bytes              # 33B generator: amount_hidden→H_token, fully_shielded→H_token+r_asset*G
    commitment: bytes               # 33B Pedersen commitment


@dataclass
class ShieldedOutputArtifacts:
    """The on-wire artifacts produced when sealing one output."""
    commitment: bytes               # 33B Pedersen commitment
    blinded_gen: bytes              # 33B blinded asset generator (used for verify)
    range_proof: bytes              # variable-length Borromean range proof
    asset_commitment: bytes | None  # 33B asset commitment (fully_shielded only)
    surjection_proof: bytes | None  # variable (fully_shielded only)


@dataclass
class StreamTx:
    """One synthetic transaction in the stream."""
    inputs: list[ShieldedInput]
    output_secrets: list[dict]      # raw materials needed to build proofs
    outputs: list[ShieldedOutputArtifacts] = field(default_factory=list)


def _make_blinded_gen(mode: str, tag_raw: bytes, r_asset: bytes) -> tuple[bytes, bytes]:
    """Return (blinded_gen, effective_r_asset) for the given mode.

    In amount-hidden mode r_asset is ZERO_TWEAK and the generator is the
    unblinded token tag H_token. In fully-shielded mode r_asset is a real
    32B tweak and the generator is the blinded asset commitment H_token + r_asset*G.
    """
    if mode == MODE_AMOUNT_HIDDEN:
        eff_r = ZERO_TWEAK
        gen = create_asset_commitment(tag_raw, eff_r)
        return gen, eff_r
    elif mode == MODE_FULLY_SHIELDED:
        gen = create_asset_commitment(tag_raw, r_asset)
        return gen, r_asset
    else:
        raise ValueError(f'unknown mode: {mode!r}')


def make_shielded_input(mode: str, amount: int) -> ShieldedInput:
    tag_raw = derive_tag(TOKEN_UID)
    r_asset = _random_bytes(32) if mode == MODE_FULLY_SHIELDED else ZERO_TWEAK
    value_blind = _random_bytes(32)
    blinded_gen, eff_r = _make_blinded_gen(mode, tag_raw, r_asset)
    commitment = create_commitment(amount, value_blind, blinded_gen)
    return ShieldedInput(
        amount=amount, value_blind=value_blind, r_asset=eff_r,
        tag_raw=tag_raw, blinded_gen=blinded_gen, commitment=commitment,
    )


def build_stream(
    mode: str,
    stream_size: int,
    inputs_per_tx: int,
    outputs_per_tx: int,
) -> list[StreamTx]:
    """Construct `stream_size` txs of shape (inputs_per_tx, outputs_per_tx).

    Only the *input secrets* and *output target amounts/blinding factors* are
    prepared here. Proof creation is deferred to `seal_tx` so the benchmark can
    time it separately.
    """
    if inputs_per_tx < 1 or outputs_per_tx < 1:
        raise ValueError('inputs_per_tx and outputs_per_tx must be >= 1')

    txs: list[StreamTx] = []
    for tx_idx in range(stream_size):
        # Inputs: deterministic-ish amounts so total is reproducible per-tx.
        in_amounts = [
            INPUT_AMOUNT_LO + ((tx_idx + i) % (INPUT_AMOUNT_HI - INPUT_AMOUNT_LO))
            for i in range(inputs_per_tx)
        ]
        inputs = [make_shielded_input(mode, a) for a in in_amounts]
        total = sum(in_amounts)

        # Split total across outputs_per_tx outputs.
        per = total // outputs_per_tx
        out_amounts = [per] * outputs_per_tx
        out_amounts[-1] += total - per * outputs_per_tx  # absorb rounding

        # Generate output secrets. The LAST output's vbf is the balancing factor.
        out_secrets: list[dict] = []
        tag_raw = derive_tag(TOKEN_UID)

        # We need the blinding factors and generator-bf of ALL inputs / non-last
        # outputs to feed compute_balancing_blinding_factor.
        inputs_bf = [(inp.amount, inp.value_blind, inp.r_asset) for inp in inputs]

        # Generate the first (outputs_per_tx - 1) outputs with fresh random vbfs.
        for i in range(outputs_per_tx - 1):
            r_asset = _random_bytes(32) if mode == MODE_FULLY_SHIELDED else ZERO_TWEAK
            vbf = _random_bytes(32)
            out_secrets.append(dict(
                amount=out_amounts[i], value_blind=vbf, r_asset=r_asset,
                tag_raw=tag_raw, _is_balancing=False,
            ))

        # Last output: compute the balancing vbf so the homomorphic equation holds.
        last_r_asset = _random_bytes(32) if mode == MODE_FULLY_SHIELDED else ZERO_TWEAK
        other_outs_bf = [
            (s['amount'], s['value_blind'], s['r_asset']) for s in out_secrets
        ]
        balancing_vbf = compute_balancing_blinding_factor(
            value=out_amounts[-1],
            generator_blinding_factor=last_r_asset,
            inputs=inputs_bf,
            other_outputs=other_outs_bf,
        )
        out_secrets.append(dict(
            amount=out_amounts[-1], value_blind=balancing_vbf, r_asset=last_r_asset,
            tag_raw=tag_raw, _is_balancing=True,
        ))

        txs.append(StreamTx(inputs=inputs, output_secrets=out_secrets))

    return txs


def seal_tx(tx: StreamTx, mode: str) -> None:
    """Build proofs + commitments for every output of `tx`.

    After this call `tx.outputs` is populated with ShieldedOutputArtifacts.
    Surjection proof creation is probabilistic; retries up to MAX_SURJECTION_RETRIES.
    """
    domain_create: list[tuple[bytes, bytes, bytes]] = []
    if mode == MODE_FULLY_SHIELDED:
        domain_create = [
            (inp.blinded_gen, inp.tag_raw, inp.r_asset) for inp in tx.inputs
        ]

    tx.outputs = []
    for sec in tx.output_secrets:
        blinded_gen, eff_r = _make_blinded_gen(mode, sec['tag_raw'], sec['r_asset'])
        commitment = create_commitment(sec['amount'], sec['value_blind'], blinded_gen)
        range_proof = create_range_proof(
            sec['amount'], sec['value_blind'], commitment, blinded_gen,
        )

        asset_commitment = None
        surjection_proof = None
        if mode == MODE_FULLY_SHIELDED:
            asset_commitment = blinded_gen  # same point in this scheme
            for attempt in range(MAX_SURJECTION_RETRIES):
                try:
                    surjection_proof = create_surjection_proof(
                        codomain_tag=sec['tag_raw'],
                        codomain_blinding_factor=eff_r,
                        domain=domain_create,
                    )
                    break
                except ValueError:
                    if attempt == MAX_SURJECTION_RETRIES - 1:
                        raise

        tx.outputs.append(ShieldedOutputArtifacts(
            commitment=commitment,
            blinded_gen=blinded_gen,
            range_proof=range_proof,
            asset_commitment=asset_commitment,
            surjection_proof=surjection_proof,
        ))


# --------------------------------------------------------------------------
# Stream sweep configuration shared by all stream scripts
# --------------------------------------------------------------------------

STREAM_SIZES = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
DEFAULT_SHAPES = [(2, 2), (4, 4), (8, 8), (16, 16)]


def parse_shape(s: str) -> tuple[int, int]:
    """Parse a shape string like '4x4' or '4,4' into (inputs, outputs)."""
    sep = 'x' if 'x' in s else ','
    a, b = s.split(sep)
    return int(a), int(b)


def shape_label(shape: tuple[int, int]) -> str:
    return f'{shape[0]}x{shape[1]}'
