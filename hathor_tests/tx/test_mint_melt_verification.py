# Copyright 2026 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Structural verification of MintHeader / MeltHeader (Rules M1–M4).

Each verifier method is exercised in isolation with a mock transaction. The
augmented balance equation (the crypto half) is verified separately in the
shielded-balance verification PR.
"""

from typing import cast
from unittest.mock import MagicMock

import pytest

from hathor.conf.settings import HathorSettings
from hathor.transaction import Transaction
from hathor.transaction.exceptions import (
    ForbiddenMelt,
    ForbiddenMint,
    InvalidMintMeltHeaderError,
    InvalidToken,
    ShieldedMintMeltForbiddenError,
)
from hathor.transaction.headers import MeltHeader, MintHeader, MintMeltEntry
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenInfo, TokenInfoDict, TokenVersion
from hathor.verification.token_creation_transaction_verifier import TokenCreationTransactionVerifier
from hathor.verification.transaction_verifier import TransactionVerifier

TOKEN_A = b'\xaa' * 32
TOKEN_B = b'\xbb' * 32


def _verifier() -> TransactionVerifier:
    return TransactionVerifier(
        settings=MagicMock(spec=HathorSettings), daa_factory=MagicMock(), feature_service=MagicMock()
    )


def _tx(
    *,
    mint: list[MintMeltEntry] | None = None,
    melt: list[MintMeltEntry] | None = None,
    shielded: bool = True,
    tokens: tuple[bytes, ...] = (TOKEN_A,),
    nano_actions: list[bytes] | None = None,
) -> Transaction:
    tx = MagicMock()
    tx.has_mint_header.return_value = mint is not None
    tx.has_melt_header.return_value = melt is not None
    tx.get_mint_header.return_value = MintHeader(entries=list(mint or []))
    tx.get_melt_header.return_value = MeltHeader(entries=list(melt or []))
    tx.has_shielded_outputs.return_value = shielded
    tx.has_unshield_balance_header.return_value = False
    tx.is_nano_contract.return_value = nano_actions is not None
    tx.tokens = list(tokens)
    tx.get_token_uid.side_effect = lambda idx: tokens[idx - 1]
    if nano_actions is not None:
        nano_header = MagicMock()
        nano_header.get_actions.return_value = [MagicMock(token_uid=uid) for uid in nano_actions]
        tx.get_nano_header.return_value = nano_header
    return cast(Transaction, tx)


def _authority_input(token_uid: bytes, *, can_mint: bool, can_melt: bool) -> MagicMock:
    spent = MagicMock()
    out = MagicMock()
    out.is_token_authority.return_value = True
    out.get_token_index.return_value = 1
    out.can_mint_token.return_value = can_mint
    out.can_melt_token.return_value = can_melt
    spent.outputs = [out]
    spent.get_token_uid.side_effect = lambda idx: token_uid
    return spent


# --- Rule M1: requires shielded ---------------------------------------------

def test_requires_shielded_rejects_transparent() -> None:
    tx = _tx(mint=[MintMeltEntry(1, 100)], shielded=False)
    with pytest.raises(ShieldedMintMeltForbiddenError):
        _verifier().verify_mint_melt_requires_shielded(tx)


def test_requires_shielded_ok_with_shielded_or_unshield() -> None:
    _verifier().verify_mint_melt_requires_shielded(_tx(mint=[MintMeltEntry(1, 100)], shielded=True))
    tx = _tx(mint=[MintMeltEntry(1, 100)], shielded=False)
    cast(MagicMock, tx).has_unshield_balance_header.return_value = True
    _verifier().verify_mint_melt_requires_shielded(tx)
    # no headers: always fine
    _verifier().verify_mint_melt_requires_shielded(_tx(shielded=False))


# --- Rule M3 + bounds: well-formed ------------------------------------------

def test_well_formed_token_index_exceeds_tokens() -> None:
    tx = _tx(mint=[MintMeltEntry(2, 100)], tokens=(TOKEN_A,))
    with pytest.raises(InvalidMintMeltHeaderError, match='exceeds'):
        _verifier().verify_mint_melt_headers_well_formed(tx)


def test_well_formed_rejects_token_in_both_headers() -> None:
    tx = _tx(mint=[MintMeltEntry(1, 100)], melt=[MintMeltEntry(1, 50)], tokens=(TOKEN_A,))
    with pytest.raises(InvalidMintMeltHeaderError, match='both'):
        _verifier().verify_mint_melt_headers_well_formed(tx)


def test_well_formed_ok_disjoint_tokens() -> None:
    tx = _tx(mint=[MintMeltEntry(1, 100)], melt=[MintMeltEntry(2, 50)], tokens=(TOKEN_A, TOKEN_B))
    _verifier().verify_mint_melt_headers_well_formed(tx)


# --- nano compatibility -----------------------------------------------------

def test_nano_compatibility_rejects_same_token() -> None:
    tx = _tx(mint=[MintMeltEntry(1, 100)], tokens=(TOKEN_A,), nano_actions=[TOKEN_A])
    with pytest.raises(InvalidMintMeltHeaderError, match='single channel'):
        _verifier().verify_mint_melt_nano_compatibility(tx)


def test_nano_compatibility_ok_cross_token_and_non_nano() -> None:
    _verifier().verify_mint_melt_nano_compatibility(
        _tx(mint=[MintMeltEntry(1, 100)], tokens=(TOKEN_A,), nano_actions=[TOKEN_B])
    )
    _verifier().verify_mint_melt_nano_compatibility(_tx(mint=[MintMeltEntry(1, 100)]))  # not nano


# --- Rule M2: authority inputs ----------------------------------------------

def test_authority_inputs_missing_mint_authority() -> None:
    tx = _tx(mint=[MintMeltEntry(1, 100)], tokens=(TOKEN_A,))
    mock = cast(MagicMock, tx)
    mock.inputs = []
    mock.storage = MagicMock()
    with pytest.raises(ForbiddenMint):
        _verifier().verify_mint_melt_authority_inputs(tx)


def test_authority_inputs_present_mint_authority() -> None:
    tx = _tx(mint=[MintMeltEntry(1, 100)], tokens=(TOKEN_A,))
    mock = cast(MagicMock, tx)
    mock.inputs = [MagicMock(tx_id=b'p', index=0)]
    mock.storage = MagicMock()
    mock.storage.get_transaction.return_value = _authority_input(TOKEN_A, can_mint=True, can_melt=False)
    _verifier().verify_mint_melt_authority_inputs(tx)


def test_authority_inputs_missing_melt_authority() -> None:
    tx = _tx(melt=[MintMeltEntry(1, 100)], tokens=(TOKEN_A,))
    mock = cast(MagicMock, tx)
    mock.inputs = [MagicMock(tx_id=b'p', index=0)]
    mock.storage = MagicMock()
    mock.storage.get_transaction.return_value = _authority_input(TOKEN_A, can_mint=True, can_melt=False)
    with pytest.raises(ForbiddenMelt):
        _verifier().verify_mint_melt_authority_inputs(tx)


# --- Rule M4: undeclared mint/melt ------------------------------------------

def _token_dict(token_uid: bytes, *, amount: int, can_mint: bool, can_melt: bool) -> TokenInfoDict:
    td = TokenInfoDict()
    td[token_uid] = TokenInfo(version=TokenVersion.DEPOSIT, amount=amount, can_mint=can_mint, can_melt=can_melt)
    return td


def test_no_undeclared_mint_rejected() -> None:
    td = _token_dict(TOKEN_A, amount=100, can_mint=True, can_melt=False)  # minted (amount > 0)
    tx = _tx(shielded=True, tokens=(TOKEN_A,))  # no MintHeader declaring it
    with pytest.raises(ShieldedMintMeltForbiddenError, match='undeclared mint'):
        _verifier().verify_no_undeclared_mint_melt(tx, td)


def test_no_undeclared_mint_ok_when_declared() -> None:
    td = _token_dict(TOKEN_A, amount=100, can_mint=True, can_melt=False)
    tx = _tx(mint=[MintMeltEntry(1, 100)], tokens=(TOKEN_A,))
    _verifier().verify_no_undeclared_mint_melt(tx, td)


def test_no_undeclared_native_token_ignored() -> None:
    td = TokenInfoDict()
    td[TOKEN_A] = TokenInfo(version=TokenVersion.NATIVE, amount=100, can_mint=True)
    _verifier().verify_no_undeclared_mint_melt(_tx(shielded=True, tokens=(TOKEN_A,)), td)


# --- TCT: shielded initial supply via MintHeader ----------------------------

def _tct_verifier() -> TokenCreationTransactionVerifier:
    return TokenCreationTransactionVerifier(settings=MagicMock(spec=HathorSettings))


def _tct(*, shielded: bool, mint: list[MintMeltEntry] | None, melt: list[MintMeltEntry] | None = None) -> MagicMock:
    tx = MagicMock(spec=TokenCreationTransaction)
    tx.is_shielded.return_value = shielded
    tx.has_mint_header.return_value = mint is not None
    tx.has_melt_header.return_value = melt is not None
    tx.get_mint_header.return_value = MintHeader(entries=list(mint or []))
    tx.get_melt_header.return_value = MeltHeader(entries=list(melt or []))
    return tx


def test_tct_shielded_requires_mint_header() -> None:
    tx = _tct(shielded=True, mint=None)
    with pytest.raises(InvalidToken, match='must declare initial supply'):
        _tct_verifier().verify_minted_tokens(cast(TokenCreationTransaction, tx), TokenInfoDict())


def test_tct_shielded_ok_with_new_token_mint_entry() -> None:
    tx = _tct(shielded=True, mint=[MintMeltEntry(1, 1000)])
    _tct_verifier().verify_minted_tokens(cast(TokenCreationTransaction, tx), TokenInfoDict())


def test_tct_shielded_cannot_melt_new_token() -> None:
    tx = _tct(shielded=True, mint=[MintMeltEntry(1, 1000)], melt=[MintMeltEntry(1, 1)])
    with pytest.raises(InvalidToken, match='cannot melt the new token'):
        _tct_verifier().verify_minted_tokens(cast(TokenCreationTransaction, tx), TokenInfoDict())
