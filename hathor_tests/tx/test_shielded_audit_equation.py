#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Network-wide supply audit equation for shielded transactions.

Verifies the chain-wide invariant:

    Σ C_utxo  ==  Σ_token (total_supply_token · H_token)

In the current shielded design this holds because per-tx balance
(Σ C_in == Σ C_out + fee · H_HTR, a curve-point equality) forces
Σ r_in = Σ r_out for every shielded tx. Telescoping then gives
Σ r_utxo = 0, and the residual G-component of the audit equation
collapses to zero. See `_designs/03-amount-privacy/100-NETWORK-SUPPLY-AUDIT.md`
for the full derivation.

The tests build small chains using `htr_lib.shielded` directly — real
secp256k1 commitments, no Python-side curve arithmetic.
"""
from __future__ import annotations

from dataclasses import dataclass

from htr_lib import shielded as ctc

ZERO_TWEAK = b'\x00' * 32


@dataclass(frozen=True)
class UTXO:
    """A UTXO entry tracked for the audit equation.

    For transparent UTXOs, `commitment` is the trivial Pedersen commitment
    `v · H_token`. For shielded UTXOs, it is the actual on-chain commitment.
    """
    commitment: bytes
    token_uid: bytes
    value: int        # cleartext value (for supply tracking only; not exposed on-chain for shielded)
    blinding: bytes   # cleartext blinding (for residual computation only)
    is_shielded: bool


def _shield_in_tx(
    transparent_input_value: int,
    shielded_output_values: list[int],
    fee: int,
    token_uid: bytes,
    generator: bytes,
) -> tuple[list[UTXO], list[UTXO]]:
    """Build a shield-in tx: 1 transparent input → N shielded outputs + fee.

    Returns (consumed_utxos, created_utxos). The wallet picks random blindings
    for all shielded outputs except the last, whose blinding is computed as
    the residual to satisfy the per-tx balance equation `e_tx = 0`.
    """
    assert sum(shielded_output_values) + fee == transparent_input_value
    n = len(shielded_output_values)
    assert n >= 1

    # Random blindings for first n-1 outputs.
    other_blindings = [ctc.generate_random_blinding_factor() for _ in range(n - 1)]
    other_outputs = [
        (v, b, ZERO_TWEAK)  # (value, value_blinding, generator_blinding=0 for AmountShielded)
        for v, b in zip(shielded_output_values[:-1], other_blindings)
    ]

    # Last blinding = residual that makes e_tx = 0.
    # Inputs: one transparent input (value, blinding=0, generator_blinding=0).
    # Fees are transparent so they contribute (fee, 0, 0) on the output side.
    last_blinding = ctc.compute_balancing_blinding_factor(
        shielded_output_values[-1],
        ZERO_TWEAK,
        [(transparent_input_value, ZERO_TWEAK, ZERO_TWEAK)],
        other_outputs + [(fee, ZERO_TWEAK, ZERO_TWEAK)],
    )

    blindings = other_blindings + [last_blinding]
    commitments = [
        ctc.create_commitment(v, b, generator)
        for v, b in zip(shielded_output_values, blindings)
    ]

    consumed = [UTXO(
        commitment=ctc.create_trivial_commitment(transparent_input_value, generator),
        token_uid=token_uid,
        value=transparent_input_value,
        blinding=ZERO_TWEAK,
        is_shielded=False,
    )]
    created = [
        UTXO(commitment=c, token_uid=token_uid, value=v, blinding=b, is_shielded=True)
        for c, v, b in zip(commitments, shielded_output_values, blindings)
    ]
    return consumed, created


def _mixed_tx(
    shielded_input: UTXO,
    shielded_output_values: list[int],
    transparent_output_values: list[int],
    fee: int,
    generator: bytes,
) -> tuple[list[UTXO], list[UTXO]]:
    """Build a mixed tx: 1 shielded input → N shielded outputs + M transparent outputs + fee.

    Same residual-blinding pattern: random for first n-1 shielded outputs, last absorbs.
    """
    assert sum(shielded_output_values) + sum(transparent_output_values) + fee == shielded_input.value
    n = len(shielded_output_values)
    assert n >= 1

    other_blindings = [ctc.generate_random_blinding_factor() for _ in range(n - 1)]
    other_outputs_for_residual = [
        (v, b, ZERO_TWEAK)
        for v, b in zip(shielded_output_values[:-1], other_blindings)
    ]
    # Transparent outputs and fee are all (value, 0, 0).
    transparent_entries = [(v, ZERO_TWEAK, ZERO_TWEAK) for v in transparent_output_values]
    transparent_entries.append((fee, ZERO_TWEAK, ZERO_TWEAK))

    last_blinding = ctc.compute_balancing_blinding_factor(
        shielded_output_values[-1],
        ZERO_TWEAK,
        [(shielded_input.value, shielded_input.blinding, ZERO_TWEAK)],
        other_outputs_for_residual + transparent_entries,
    )

    blindings = other_blindings + [last_blinding]
    shielded_commitments = [
        ctc.create_commitment(v, b, generator)
        for v, b in zip(shielded_output_values, blindings)
    ]

    consumed = [shielded_input]
    created_shielded = [
        UTXO(commitment=c, token_uid=shielded_input.token_uid, value=v, blinding=b, is_shielded=True)
        for c, v, b in zip(shielded_commitments, shielded_output_values, blindings)
    ]
    created_transparent = [
        UTXO(
            commitment=ctc.create_trivial_commitment(v, generator),
            token_uid=shielded_input.token_uid,
            value=v,
            blinding=ZERO_TWEAK,
            is_shielded=False,
        )
        for v in transparent_output_values
    ]
    return consumed, created_shielded + created_transparent


def _verify_per_tx_balance(consumed: list[UTXO], created: list[UTXO], fee: int, token_uid: bytes) -> bool:
    """Per-tx consensus check: Σ C_in == Σ C_out + fee · H_HTR.

    Sanity check that each tx in the chain actually balances. The audit equation
    relies on this holding for every tx.
    """
    transparent_inputs = [
        (u.value, u.token_uid) for u in consumed if not u.is_shielded
    ]
    shielded_inputs = [u.commitment for u in consumed if u.is_shielded]
    transparent_outputs = [
        (u.value, u.token_uid) for u in created if not u.is_shielded
    ]
    if fee > 0:
        # Fees are transparent HTR outputs.
        transparent_outputs.append((fee, token_uid))
    shielded_outputs = [u.commitment for u in created if u.is_shielded]
    return ctc.verify_balance(
        transparent_inputs=transparent_inputs,
        shielded_inputs=shielded_inputs,
        transparent_outputs=transparent_outputs,
        shielded_outputs=shielded_outputs,
        excess_blinding_factor=None,
    )


def _audit_supply(utxo_set: list[UTXO], token_supplies: dict[bytes, int]) -> bool:
    """The chain-wide supply audit: Σ C_utxo == Σ_token (supply_token · H_token).

    Both sides are sums of curve points. We use ctc.verify_commitments_sum to
    check the equation, which is a single multi-exp comparison.

    `token_supplies` is the publicly computable expected supply per token,
    derived from cleartext fields: initial + Σ mint − Σ melt − Σ burned_fees.
    """
    utxo_commitments = [u.commitment for u in utxo_set]
    supply_commitments = [
        ctc.create_trivial_commitment(supply, ctc.derive_asset_tag(token_uid))
        for token_uid, supply in token_supplies.items()
        if supply > 0  # skip zero-supply tokens (would create identity point)
    ]
    return ctc.verify_commitments_sum(positive=utxo_commitments, negative=supply_commitments)


# ---------------------------------------------------------------------------
# Tests


HTR_UID = b'\x00' * 32
HTR_GEN = ctc.htr_asset_tag()


class TestSupplyAuditEquation:
    """Σ C_utxo == Σ_token (supply_token · H_token)."""

    def test_audit_holds_after_single_shield_in_tx(self) -> None:
        # Initial: one transparent UTXO with 100 HTR (supply = 100).
        initial_value = 100
        utxo_set: list[UTXO] = [UTXO(
            commitment=ctc.create_trivial_commitment(initial_value, HTR_GEN),
            token_uid=HTR_UID,
            value=initial_value,
            blinding=ZERO_TWEAK,
            is_shielded=False,
        )]

        # Shield-in: spend 100 transparent → 60 + 39 shielded + 1 fee.
        consumed, created = _shield_in_tx(
            transparent_input_value=initial_value,
            shielded_output_values=[60, 39],
            fee=1,
            token_uid=HTR_UID,
            generator=HTR_GEN,
        )
        assert _verify_per_tx_balance(consumed, created, fee=1, token_uid=HTR_UID)

        # Apply tx to UTXO set.
        utxo_set = [u for u in utxo_set if u not in consumed] + created

        # Audit: supply now = 100 − 1 (burned fee) = 99. Σ C_utxo should equal 99 · H_HTR.
        assert _audit_supply(utxo_set, {HTR_UID: 99})

    def test_audit_holds_after_chain_of_two_txs(self) -> None:
        """The worked example from `100-NETWORK-SUPPLY-AUDIT.md` Section 5."""
        # Initial: 100 HTR transparent.
        initial_value = 100
        utxo_set: list[UTXO] = [UTXO(
            commitment=ctc.create_trivial_commitment(initial_value, HTR_GEN),
            token_uid=HTR_UID,
            value=initial_value,
            blinding=ZERO_TWEAK,
            is_shielded=False,
        )]

        # tx1: shield-in 100 → 40+30+29 shielded + 1 fee.
        consumed1, created1 = _shield_in_tx(
            transparent_input_value=initial_value,
            shielded_output_values=[40, 30, 29],
            fee=1,
            token_uid=HTR_UID,
            generator=HTR_GEN,
        )
        assert _verify_per_tx_balance(consumed1, created1, fee=1, token_uid=HTR_UID)
        utxo_set = [u for u in utxo_set if u not in consumed1] + created1

        # tx2: spend the 40-HTR shielded UTXO → 20+10 shielded + 9 transparent + 1 fee.
        spent_shielded = next(u for u in utxo_set if u.is_shielded and u.value == 40)
        consumed2, created2 = _mixed_tx(
            shielded_input=spent_shielded,
            shielded_output_values=[20, 10],
            transparent_output_values=[9],
            fee=1,
            generator=HTR_GEN,
        )
        assert _verify_per_tx_balance(consumed2, created2, fee=1, token_uid=HTR_UID)
        utxo_set = [u for u in utxo_set if u not in consumed2] + created2

        # Audit: supply = 100 − 2 burned fees = 98.
        assert _audit_supply(utxo_set, {HTR_UID: 98})

    def test_audit_holds_with_multiple_tokens(self) -> None:
        """Audit equation as a single curve-point check across tokens."""
        custom_uid = b'\x01' + b'\x00' * 31
        custom_gen = ctc.derive_asset_tag(custom_uid)

        # Initial allocations: 200 HTR + 500 of custom token (cleartext).
        utxo_set: list[UTXO] = [
            UTXO(
                commitment=ctc.create_trivial_commitment(200, HTR_GEN),
                token_uid=HTR_UID,
                value=200,
                blinding=ZERO_TWEAK,
                is_shielded=False,
            ),
            UTXO(
                commitment=ctc.create_trivial_commitment(500, custom_gen),
                token_uid=custom_uid,
                value=500,
                blinding=ZERO_TWEAK,
                is_shielded=False,
            ),
        ]

        # Shield 200 HTR into 150 + 49 shielded + 1 fee.
        consumed_htr, created_htr = _shield_in_tx(
            transparent_input_value=200,
            shielded_output_values=[150, 49],
            fee=1,
            token_uid=HTR_UID,
            generator=HTR_GEN,
        )
        assert _verify_per_tx_balance(consumed_htr, created_htr, fee=1, token_uid=HTR_UID)
        utxo_set = [u for u in utxo_set if u not in consumed_htr] + created_htr

        # Shield 500 custom token into 300 + 200 shielded (no fee for non-HTR shielding;
        # in practice fees are always HTR — we model a cross-token scenario by adding
        # a separate transparent HTR input below for the fee. For simplicity here we
        # do a pure same-token shield with no fee, which is still a valid test of the
        # audit equation.)
        consumed_custom, created_custom = _shield_in_tx(
            transparent_input_value=500,
            shielded_output_values=[300, 200],
            fee=0,
            token_uid=custom_uid,
            generator=custom_gen,
        )
        assert _verify_per_tx_balance(consumed_custom, created_custom, fee=0, token_uid=custom_uid)
        utxo_set = [u for u in utxo_set if u not in consumed_custom] + created_custom

        # Audit: HTR supply = 200 − 1 fee = 199; custom supply = 500.
        assert _audit_supply(utxo_set, {HTR_UID: 199, custom_uid: 500})

    def test_audit_fails_on_simulated_inflation(self) -> None:
        """Sanity check: if we lie about supply, the audit equation fails."""
        utxo_set: list[UTXO] = [UTXO(
            commitment=ctc.create_trivial_commitment(100, HTR_GEN),
            token_uid=HTR_UID,
            value=100,
            blinding=ZERO_TWEAK,
            is_shielded=False,
        )]
        consumed, created = _shield_in_tx(
            transparent_input_value=100,
            shielded_output_values=[60, 39],
            fee=1,
            token_uid=HTR_UID,
            generator=HTR_GEN,
        )
        utxo_set = [u for u in utxo_set if u not in consumed] + created

        # Real supply is 99. Claiming 100 must make the audit fail.
        assert not _audit_supply(utxo_set, {HTR_UID: 100})
        assert not _audit_supply(utxo_set, {HTR_UID: 98})
        # But the correct value passes.
        assert _audit_supply(utxo_set, {HTR_UID: 99})
