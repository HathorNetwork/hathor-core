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

"""Unit tests for ShieldedHeaderVerifier — the methods that do NOT depend on
the native hathor_ct_crypto Rust library.

Scope:
  * calculate_shielded_fee
  * verify_shielded_fee (missing-header case only — sufficient-fee cases need a full FeeHeader build)
  * verify_authority_restriction
  * verify_trivial_commitment_protection
  * verify_no_mint_melt
  * _normalize_token_uid

Deferred to PR 8 (need the native Rust crate):
  * verify_commitments_valid     (validate_commitment / validate_generator)
  * verify_range_proofs          (verify_range_proof)
  * verify_surjection_proofs     (verify_surjection_proof)
  * _get_or_derive_asset_tag     (derive_asset_tag)
  * verify_shielded_balance      (_lib.verify_balance)
"""

import pytest

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import Transaction, TxOutput
from hathor.transaction.exceptions import (
    InvalidShieldedOutputError,
    ShieldedAuthorityError,
    ShieldedMintMeltForbiddenError,
    TrivialCommitmentError,
)
from hathor.transaction.headers import ShieldedOutputsHeader
from hathor.transaction.token_info import TokenInfo, TokenInfoDict, TokenVersion
from hathor.verification.shielded_header_verifier import ShieldedHeaderVerifier
from hathorlib.conf.settings import HATHOR_TOKEN_UID
from hathorlib.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput

# --- fixtures -----------------------------------------------------------------

@pytest.fixture
def verifier() -> ShieldedHeaderVerifier:
    return ShieldedHeaderVerifier(settings=get_global_settings())


def _amount_shielded_output(token_data: int = 0) -> AmountShieldedOutput:
    """Build a minimal AmountShieldedOutput; only `token_data` is meaningful for the Rust-free checks."""
    return AmountShieldedOutput(
        commitment=b'\x00' * 33,
        range_proof=b'',
        script=b'',
        token_data=token_data,
    )


def _full_shielded_output() -> FullShieldedOutput:
    """Build a minimal FullShieldedOutput; only the type matters for the Rust-free checks."""
    return FullShieldedOutput(
        commitment=b'\x00' * 33,
        range_proof=b'',
        script=b'',
        asset_commitment=b'\x00' * 33,
        surjection_proof=b'',
    )


def _tx_with_shielded_outputs(shielded_outputs: list) -> Transaction:
    """Build a Transaction carrying a ShieldedOutputsHeader with the given outputs."""
    tx = Transaction()
    tx.headers = [ShieldedOutputsHeader(shielded_outputs=shielded_outputs)]
    return tx


# --- construction -------------------------------------------------------------

def test_construction(verifier: ShieldedHeaderVerifier) -> None:
    """ShieldedHeaderVerifier instantiates with just settings."""
    assert verifier._settings is get_global_settings()


# --- calculate_shielded_fee ---------------------------------------------------

def test_calculate_shielded_fee_empty(verifier: ShieldedHeaderVerifier) -> None:
    """No shielded outputs → fee is 0."""
    tx = Transaction()
    assert ShieldedHeaderVerifier.calculate_shielded_fee(verifier._settings, tx) == 0


def test_calculate_shielded_fee_amount_only(verifier: ShieldedHeaderVerifier) -> None:
    """N AmountShielded outputs → fee = N * FEE_PER_AMOUNT_SHIELDED_OUTPUT."""
    tx = _tx_with_shielded_outputs([_amount_shielded_output() for _ in range(3)])
    expected = 3 * verifier._settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT
    assert ShieldedHeaderVerifier.calculate_shielded_fee(verifier._settings, tx) == expected


def test_calculate_shielded_fee_full_only(verifier: ShieldedHeaderVerifier) -> None:
    """N FullShielded outputs → fee = N * FEE_PER_FULL_SHIELDED_OUTPUT."""
    tx = _tx_with_shielded_outputs([_full_shielded_output() for _ in range(2)])
    expected = 2 * verifier._settings.FEE_PER_FULL_SHIELDED_OUTPUT
    assert ShieldedHeaderVerifier.calculate_shielded_fee(verifier._settings, tx) == expected


def test_calculate_shielded_fee_mixed(verifier: ShieldedHeaderVerifier) -> None:
    """Mixed outputs → fee is the sum of per-type contributions."""
    outputs = [
        _amount_shielded_output(),
        _full_shielded_output(),
        _amount_shielded_output(),
    ]
    tx = _tx_with_shielded_outputs(outputs)
    expected = (
        2 * verifier._settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT
        + 1 * verifier._settings.FEE_PER_FULL_SHIELDED_OUTPUT
    )
    assert ShieldedHeaderVerifier.calculate_shielded_fee(verifier._settings, tx) == expected


# --- verify_shielded_fee ------------------------------------------------------

def test_verify_shielded_fee_requires_fee_header(verifier: ShieldedHeaderVerifier) -> None:
    """A shielded tx without any FeeHeader is rejected."""
    tx = _tx_with_shielded_outputs([_amount_shielded_output()])
    with pytest.raises(InvalidShieldedOutputError, match='shielded transactions require a fee header'):
        verifier.verify_shielded_fee(tx)


# --- verify_authority_restriction ---------------------------------------------

def test_verify_authority_restriction_no_shielded_outputs(verifier: ShieldedHeaderVerifier) -> None:
    """No shielded outputs → no-op, no raise."""
    tx = Transaction()
    verifier.verify_authority_restriction(tx)


def test_verify_authority_restriction_amount_no_authority_bit(verifier: ShieldedHeaderVerifier) -> None:
    """AmountShielded with token_data lacking the authority bit → accepted."""
    tx = _tx_with_shielded_outputs([_amount_shielded_output(token_data=0)])
    verifier.verify_authority_restriction(tx)


def test_verify_authority_restriction_amount_with_authority_bit(verifier: ShieldedHeaderVerifier) -> None:
    """AmountShielded with the authority bit set → ShieldedAuthorityError."""
    tx = _tx_with_shielded_outputs([_amount_shielded_output(token_data=TxOutput.TOKEN_AUTHORITY_MASK)])
    with pytest.raises(ShieldedAuthorityError, match='authority outputs cannot be shielded'):
        verifier.verify_authority_restriction(tx)


def test_verify_authority_restriction_full_shielded_accepted(verifier: ShieldedHeaderVerifier) -> None:
    """FullShielded has no token_data field, so the authority check is a pass-through."""
    tx = _tx_with_shielded_outputs([_full_shielded_output()])
    verifier.verify_authority_restriction(tx)


# --- verify_trivial_commitment_protection -------------------------------------

def test_verify_trivial_commitment_protection_no_shielded_outputs(verifier: ShieldedHeaderVerifier) -> None:
    """No shielded outputs → no-op (the check only applies when there are any)."""
    tx = Transaction()
    verifier.verify_trivial_commitment_protection(tx)


def test_verify_trivial_commitment_protection_single_output_rejected(verifier: ShieldedHeaderVerifier) -> None:
    """A single shielded output enables trivial brute-forcing of the hidden amount → rejected."""
    tx = _tx_with_shielded_outputs([_amount_shielded_output()])
    with pytest.raises(TrivialCommitmentError, match='at least 2 shielded outputs are required'):
        verifier.verify_trivial_commitment_protection(tx)


def test_verify_trivial_commitment_protection_two_outputs_accepted(verifier: ShieldedHeaderVerifier) -> None:
    """Two or more shielded outputs → accepted."""
    tx = _tx_with_shielded_outputs([_amount_shielded_output(), _amount_shielded_output()])
    verifier.verify_trivial_commitment_protection(tx)


# --- verify_no_mint_melt ------------------------------------------------------

CUSTOM_TOKEN_UID = b'\x01' + b'\x00' * 31


def test_verify_no_mint_melt_empty_dict(verifier: ShieldedHeaderVerifier) -> None:
    """An empty token_dict is trivially fine."""
    verifier.verify_no_mint_melt(TokenInfoDict())


def test_verify_no_mint_melt_native_only_is_skipped(verifier: ShieldedHeaderVerifier) -> None:
    """NATIVE tokens are skipped; even with permissions and a non-zero amount, no raise."""
    token_dict = TokenInfoDict()
    token_dict[HATHOR_TOKEN_UID] = TokenInfo(version=TokenVersion.NATIVE, amount=42, can_mint=True, can_melt=True)
    verifier.verify_no_mint_melt(token_dict)


def test_verify_no_mint_melt_custom_balanced_token_accepted(verifier: ShieldedHeaderVerifier) -> None:
    """Non-native token with zero amount (not minted or melted) → no raise."""
    token_dict = TokenInfoDict()
    token_dict[CUSTOM_TOKEN_UID] = TokenInfo(
        version=TokenVersion.DEPOSIT, amount=0, can_mint=True, can_melt=True
    )
    verifier.verify_no_mint_melt(token_dict)


def test_verify_no_mint_melt_minted_with_authority_rejected(verifier: ShieldedHeaderVerifier) -> None:
    """Non-native with can_mint + positive amount (has_been_minted) → rejected."""
    token_dict = TokenInfoDict()
    token_dict[CUSTOM_TOKEN_UID] = TokenInfo(
        version=TokenVersion.DEPOSIT, amount=100, can_mint=True, can_melt=False
    )
    with pytest.raises(ShieldedMintMeltForbiddenError, match='minting is not allowed'):
        verifier.verify_no_mint_melt(token_dict)


def test_verify_no_mint_melt_melted_with_authority_rejected(verifier: ShieldedHeaderVerifier) -> None:
    """Non-native with can_melt + negative amount (has_been_melted) → rejected."""
    token_dict = TokenInfoDict()
    token_dict[CUSTOM_TOKEN_UID] = TokenInfo(
        version=TokenVersion.DEPOSIT, amount=-100, can_mint=False, can_melt=True
    )
    with pytest.raises(ShieldedMintMeltForbiddenError, match='melting is not allowed'):
        verifier.verify_no_mint_melt(token_dict)


def test_verify_no_mint_melt_minted_without_authority_skipped(verifier: ShieldedHeaderVerifier) -> None:
    """A non-native token with positive amount but no can_mint is NOT rejected by this rule.

    (It WOULD be caught by ForbiddenMint upstream in the transparent token-rule path —
    different rule, different verifier.)
    """
    token_dict = TokenInfoDict()
    token_dict[CUSTOM_TOKEN_UID] = TokenInfo(
        version=TokenVersion.DEPOSIT, amount=100, can_mint=False, can_melt=False
    )
    verifier.verify_no_mint_melt(token_dict)


# --- _normalize_token_uid -----------------------------------------------------

def test_normalize_token_uid_htr(verifier: ShieldedHeaderVerifier) -> None:
    """The HTR sentinel (b'\\x00', 1 byte) is normalized to 32 zero bytes."""
    assert ShieldedHeaderVerifier._normalize_token_uid(HATHOR_TOKEN_UID) == b'\x00' * 32


def test_normalize_token_uid_custom_token_unchanged(verifier: ShieldedHeaderVerifier) -> None:
    """A 32-byte custom token UID passes through untouched."""
    uid = b'\x42' * 32
    assert ShieldedHeaderVerifier._normalize_token_uid(uid) == uid
