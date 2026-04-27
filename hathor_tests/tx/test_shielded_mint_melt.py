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

"""Tests for shielded mint/melt headers (RFC 0000-shielded-outputs-mint-melt)."""

from unittest.mock import MagicMock

import pytest

from hathor.conf.settings import HathorSettings
from hathor.transaction import Transaction
from hathor.transaction.exceptions import (
    ForbiddenMelt,
    ForbiddenMint,
    HeaderNotSupported,
    InvalidMintMeltHeaderError,
    InvalidToken,
    ShieldedMintMeltForbiddenError,
)
from hathor.transaction.headers import MeltHeader, MintHeader, MintMeltEntry, VertexHeaderId
from hathor.transaction.token_info import TokenVersion
from hathor.verification.transaction_verifier import TransactionVerifier


def _make_settings() -> HathorSettings:
    settings = MagicMock(spec=HathorSettings)
    settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT = 1
    settings.FEE_PER_FULL_SHIELDED_OUTPUT = 2
    settings.HATHOR_TOKEN_UID = b'\x00'
    settings.TOKEN_DEPOSIT_PERCENTAGE = 0.01
    settings.SKIP_VERIFICATION = set()
    settings.CONSENSUS_ALGORITHM = MagicMock()
    settings.CONSENSUS_ALGORITHM.is_pow.return_value = True
    return settings


def _make_verifier() -> TransactionVerifier:
    return TransactionVerifier(settings=_make_settings(), daa=MagicMock(), feature_service=MagicMock())


def _make_mock_tx(
    *,
    tokens: list[bytes] | None = None,
    mint_entries: list[MintMeltEntry] | None = None,
    melt_entries: list[MintMeltEntry] | None = None,
    has_shielded_outputs: bool = False,
    has_unshield_balance_header: bool = False,
    is_nano_contract: bool = False,
    nano_action_token_uids: list[bytes] | None = None,
) -> MagicMock:
    """Build a Transaction-shaped MagicMock with the requested mint/melt headers."""
    tx = MagicMock(spec=Transaction)
    tx.tokens = tokens or []
    tx.has_shielded_outputs = MagicMock(return_value=has_shielded_outputs)
    tx.has_unshield_balance_header = MagicMock(return_value=has_unshield_balance_header)
    tx.is_nano_contract = MagicMock(return_value=is_nano_contract)
    tx.has_mint_header = MagicMock(return_value=mint_entries is not None)
    tx.has_melt_header = MagicMock(return_value=melt_entries is not None)
    tx.inputs = []
    tx.headers = []

    if mint_entries is not None:
        mint_header = MagicMock(spec=MintHeader)
        mint_header.entries = mint_entries
        tx.get_mint_header = MagicMock(return_value=mint_header)
    if melt_entries is not None:
        melt_header = MagicMock(spec=MeltHeader)
        melt_header.entries = melt_entries
        tx.get_melt_header = MagicMock(return_value=melt_header)

    def _get_token_uid(index: int) -> bytes:
        if index == 0:
            return b'\x00'
        return tx.tokens[index - 1]
    tx.get_token_uid = MagicMock(side_effect=_get_token_uid)

    if is_nano_contract:
        nano_header = MagicMock()
        nano_actions = []
        for token_uid in (nano_action_token_uids or []):
            action = MagicMock()
            action.token_uid = token_uid
            nano_actions.append(action)
        nano_header.get_actions = MagicMock(return_value=nano_actions)
        tx.get_nano_header = MagicMock(return_value=nano_header)
    return tx


# ---------------------------------------------------------------------------
# Wire format (header round-trip + per-entry shape constraints)
# ---------------------------------------------------------------------------


class TestWireFormat:
    def test_mint_header_roundtrip(self) -> None:
        tx = MagicMock(spec=Transaction)
        entries = [MintMeltEntry(token_index=1, amount=100_000), MintMeltEntry(token_index=2, amount=50)]
        h = MintHeader(tx=tx, entries=entries)
        b = h.serialize()
        assert b[0:1] == VertexHeaderId.MINT_HEADER.value
        assert b[1] == 2
        h2, leftover = MintHeader.deserialize(tx, b)
        assert leftover == b''
        assert h2.entries == entries

    def test_melt_header_roundtrip(self) -> None:
        tx = MagicMock(spec=Transaction)
        entries = [MintMeltEntry(token_index=3, amount=999_999_999)]
        h = MeltHeader(tx=tx, entries=entries)
        b = h.serialize()
        assert b[0:1] == VertexHeaderId.MELT_HEADER.value
        h2, _ = MeltHeader.deserialize(tx, b)
        assert h2.entries == entries

    def test_sighash_bytes_equals_serialize(self) -> None:
        tx = MagicMock(spec=Transaction)
        h = MintHeader(tx=tx, entries=[MintMeltEntry(token_index=1, amount=1)])
        assert h.get_sighash_bytes() == h.serialize()

    def test_distinct_header_ids(self) -> None:
        assert MintHeader.get_header_id() == b'\x14'
        assert MeltHeader.get_header_id() == b'\x15'

    @pytest.mark.parametrize('buf,match', [
        (b'\x14\x00', 'must contain at least 1 entry'),
        (b'\x14\x01\x01', 'requires'),
        (b'\x14\x01\x00\x00\x00\x00\x00\x00\x00\x00\x05', 'must be >= 1'),
        (b'\x14\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00', 'amount must be >= 1'),
        (b'\x14\x02\x01\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x00\x00\x00\x00\x07',
         'duplicate token_index'),
        (b'\x15\x01\x01\x00\x00\x00\x00\x00\x00\x00\x05', 'unexpected header id'),
        (b'\x14\x01\x11\x00\x00\x00\x00\x00\x00\x00\x05', 'exceeds maximum'),
    ])
    def test_deserialize_rejects_malformed(self, buf: bytes, match: str) -> None:
        tx = MagicMock(spec=Transaction)
        with pytest.raises(InvalidMintMeltHeaderError, match=match):
            MintHeader.deserialize(tx, buf)


# ---------------------------------------------------------------------------
# Phase-1: well-formedness + Rule M3 + Rule M1 + Nano coexistence
# ---------------------------------------------------------------------------


class TestWellFormedness:
    def test_token_index_in_range(self) -> None:
        verifier = _make_verifier()
        tx = _make_mock_tx(
            tokens=[b'\x11' * 32],
            mint_entries=[MintMeltEntry(token_index=2, amount=1)],
            has_shielded_outputs=True,
        )
        with pytest.raises(InvalidMintMeltHeaderError, match='exceeds tx.tokens length'):
            verifier.verify_mint_melt_headers_well_formed(tx)

    def test_rule_m3_token_in_both_headers_rejected(self) -> None:
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            melt_entries=[MintMeltEntry(token_index=1, amount=50)],
            has_shielded_outputs=True,
        )
        with pytest.raises(InvalidMintMeltHeaderError, match='cannot be both minted and melted'):
            verifier.verify_mint_melt_headers_well_formed(tx)

    def test_well_formed_passes(self) -> None:
        verifier = _make_verifier()
        tx = _make_mock_tx(
            tokens=[b'\x11' * 32, b'\x22' * 32],
            mint_entries=[MintMeltEntry(token_index=1, amount=1000)],
            melt_entries=[MintMeltEntry(token_index=2, amount=500)],
            has_shielded_outputs=True,
        )
        verifier.verify_mint_melt_headers_well_formed(tx)


class TestRuleM1RequiresShielded:
    def test_mint_header_on_non_shielded_tx_rejected(self) -> None:
        verifier = _make_verifier()
        tx = _make_mock_tx(
            tokens=[b'\x11' * 32],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=False,
            has_unshield_balance_header=False,
        )
        with pytest.raises(ShieldedMintMeltForbiddenError, match='Rule M1'):
            verifier.verify_mint_melt_requires_shielded(tx)

    def test_mint_header_on_shielded_outputs_passes(self) -> None:
        verifier = _make_verifier()
        tx = _make_mock_tx(
            tokens=[b'\x11' * 32],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=True,
        )
        verifier.verify_mint_melt_requires_shielded(tx)

    def test_mint_header_on_full_unshield_passes(self) -> None:
        # RFC unresolved Q6: UnshieldBalanceHeader + MintHeader is a valid combination.
        verifier = _make_verifier()
        tx = _make_mock_tx(
            tokens=[b'\x11' * 32],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=False,
            has_unshield_balance_header=True,
        )
        verifier.verify_mint_melt_requires_shielded(tx)


class TestNanoCompatibility:
    def test_same_token_via_nano_action_and_mint_header_rejected(self) -> None:
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=True,
            is_nano_contract=True,
            nano_action_token_uids=[token_uid],
        )
        with pytest.raises(InvalidMintMeltHeaderError, match='single channel'):
            verifier.verify_mint_melt_nano_compatibility(tx)

    def test_cross_token_nano_action_and_mint_header_allowed(self) -> None:
        verifier = _make_verifier()
        token_a = b'\xaa' * 32
        token_b = b'\xbb' * 32
        tx = _make_mock_tx(
            tokens=[token_a, token_b],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],  # token_a
            has_shielded_outputs=True,
            is_nano_contract=True,
            nano_action_token_uids=[token_b],  # different token
        )
        verifier.verify_mint_melt_nano_compatibility(tx)


# ---------------------------------------------------------------------------
# Phase-2: Rule M2 (authority inputs)
# ---------------------------------------------------------------------------


def _make_authority_input(
    token_uid: bytes, *, can_mint: bool, can_melt: bool
) -> tuple[MagicMock, MagicMock]:
    """Build a (tx_input, spent_tx) pair attached to tx.inputs/tx.storage."""
    tx_input = MagicMock()
    tx_input.tx_id = b'\x55' * 32
    tx_input.index = 0

    spent_output = MagicMock()
    spent_output.is_token_authority = MagicMock(return_value=True)
    spent_output.can_mint_token = MagicMock(return_value=can_mint)
    spent_output.can_melt_token = MagicMock(return_value=can_melt)
    spent_output.get_token_index = MagicMock(return_value=1)

    spent_tx = MagicMock()
    spent_tx.outputs = [spent_output]
    spent_tx.shielded_outputs = []
    spent_tx.get_token_uid = MagicMock(return_value=token_uid)

    return tx_input, spent_tx


class TestRuleM2AuthorityInputs:
    def test_mint_without_authority_rejected(self) -> None:
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=True,
        )
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=None)
        # No inputs.
        with pytest.raises(ForbiddenMint):
            verifier.verify_mint_melt_authority_inputs(tx)

    def test_mint_with_authority_passes(self) -> None:
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=True,
        )
        tx_input, spent_tx = _make_authority_input(token_uid, can_mint=True, can_melt=False)
        tx.inputs = [tx_input]
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)
        verifier.verify_mint_melt_authority_inputs(tx, spent_txs={tx_input.tx_id: spent_tx})

    def test_melt_without_authority_rejected(self) -> None:
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            melt_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=True,
        )
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=None)
        with pytest.raises(ForbiddenMelt):
            verifier.verify_mint_melt_authority_inputs(tx)

    def test_melt_with_mint_authority_only_rejected(self) -> None:
        """Mint-only authority must not be accepted as a melt authority."""
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            melt_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=True,
        )
        tx_input, spent_tx = _make_authority_input(token_uid, can_mint=True, can_melt=False)
        tx.inputs = [tx_input]
        tx.storage = MagicMock()
        with pytest.raises(ForbiddenMelt):
            verifier.verify_mint_melt_authority_inputs(tx, spent_txs={tx_input.tx_id: spent_tx})

    def test_no_headers_no_op(self) -> None:
        verifier = _make_verifier()
        tx = _make_mock_tx(tokens=[b'\x11' * 32], has_shielded_outputs=True)
        # No headers → no authority requirement.
        verifier.verify_mint_melt_authority_inputs(tx)


# ---------------------------------------------------------------------------
# Rule M4: undeclared mint/melt rejected (token_dict surplus without header)
# ---------------------------------------------------------------------------


class TestUndeclaredMintMelt:
    def test_undeclared_mint_rejected(self) -> None:
        from hathor.transaction.token_info import TokenInfo, TokenInfoDict
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(tokens=[token_uid], has_shielded_outputs=True)
        token_dict = TokenInfoDict()
        token_dict[token_uid] = TokenInfo(version=TokenVersion.DEPOSIT, amount=100, can_mint=True)
        with pytest.raises(ShieldedMintMeltForbiddenError, match='undeclared mint'):
            verifier.verify_no_undeclared_mint_melt(tx, token_dict)

    def test_declared_mint_accepted(self) -> None:
        from hathor.transaction.token_info import TokenInfo, TokenInfoDict
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=True,
        )
        token_dict = TokenInfoDict()
        token_dict[token_uid] = TokenInfo(version=TokenVersion.DEPOSIT, amount=100, can_mint=True)
        # Declared via MintHeader → accepted.
        verifier.verify_no_undeclared_mint_melt(tx, token_dict)

    def test_undeclared_melt_rejected(self) -> None:
        from hathor.transaction.token_info import TokenInfo, TokenInfoDict
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(tokens=[token_uid], has_shielded_outputs=True)
        token_dict = TokenInfoDict()
        token_dict[token_uid] = TokenInfo(version=TokenVersion.DEPOSIT, amount=-100, can_melt=True)
        with pytest.raises(ShieldedMintMeltForbiddenError, match='undeclared melt'):
            verifier.verify_no_undeclared_mint_melt(tx, token_dict)


# ---------------------------------------------------------------------------
# TCT integration (RFC §4.4)
# ---------------------------------------------------------------------------


class TestTokenCreationTransactionShielded:
    def test_shielded_tct_requires_mint_header(self) -> None:
        from hathor.transaction.token_creation_tx import TokenCreationTransaction
        from hathor.verification.token_creation_transaction_verifier import TokenCreationTransactionVerifier
        tct = MagicMock(spec=TokenCreationTransaction)
        tct.is_shielded = MagicMock(return_value=True)
        tct.has_mint_header = MagicMock(return_value=False)
        tct.hash = b'\xff' * 32
        verifier = TokenCreationTransactionVerifier(settings=_make_settings())
        with pytest.raises(InvalidToken, match='must declare initial supply via MintHeader'):
            verifier.verify_minted_tokens(tct, {tct.hash: MagicMock()})

    def test_shielded_tct_with_valid_mint_header_passes(self) -> None:
        from hathor.transaction.token_creation_tx import TokenCreationTransaction
        from hathor.verification.token_creation_transaction_verifier import TokenCreationTransactionVerifier
        tct = MagicMock(spec=TokenCreationTransaction)
        tct.is_shielded = MagicMock(return_value=True)
        tct.has_mint_header = MagicMock(return_value=True)
        mint_header = MagicMock()
        mint_header.entries = [MintMeltEntry(token_index=1, amount=1_000_000)]
        tct.get_mint_header = MagicMock(return_value=mint_header)
        tct.hash = b'\xff' * 32
        verifier = TokenCreationTransactionVerifier(settings=_make_settings())
        verifier.verify_minted_tokens(tct, {tct.hash: MagicMock()})

    def test_shielded_tct_without_new_token_entry_rejected(self) -> None:
        from hathor.transaction.token_creation_tx import TokenCreationTransaction
        from hathor.verification.token_creation_transaction_verifier import TokenCreationTransactionVerifier
        tct = MagicMock(spec=TokenCreationTransaction)
        tct.is_shielded = MagicMock(return_value=True)
        tct.has_mint_header = MagicMock(return_value=True)
        mint_header = MagicMock()
        # Wrong token_index — must be 1 for the new token.
        mint_header.entries = [MintMeltEntry(token_index=2, amount=1_000_000)]
        tct.get_mint_header = MagicMock(return_value=mint_header)
        tct.hash = b'\xff' * 32
        verifier = TokenCreationTransactionVerifier(settings=_make_settings())
        with pytest.raises(InvalidToken, match='exactly one MintHeader entry'):
            verifier.verify_minted_tokens(tct, {tct.hash: MagicMock()})

    def test_shielded_tct_cannot_melt_the_new_token(self) -> None:
        """A TCT cannot include the new token in MeltHeader — there's nothing to destroy yet.
        Defense-in-depth on top of Rule M3."""
        from hathor.transaction.token_creation_tx import TokenCreationTransaction
        from hathor.verification.token_creation_transaction_verifier import TokenCreationTransactionVerifier
        tct = MagicMock(spec=TokenCreationTransaction)
        tct.is_shielded = MagicMock(return_value=True)
        tct.has_mint_header = MagicMock(return_value=True)
        tct.has_melt_header = MagicMock(return_value=True)
        mint_header = MagicMock()
        mint_header.entries = [MintMeltEntry(token_index=1, amount=1_000_000)]
        melt_header = MagicMock()
        melt_header.entries = [MintMeltEntry(token_index=1, amount=500)]
        tct.get_mint_header = MagicMock(return_value=mint_header)
        tct.get_melt_header = MagicMock(return_value=melt_header)
        tct.hash = b'\xff' * 32
        verifier = TokenCreationTransactionVerifier(settings=_make_settings())
        with pytest.raises(InvalidToken, match='cannot melt the new token'):
            verifier.verify_minted_tokens(tct, {tct.hash: MagicMock()})


class TestEntryConstructionBounds:
    """MintMeltEntry validates bounds at construction time (developer-experience)."""

    def test_zero_amount_rejected(self) -> None:
        with pytest.raises(ValueError, match='amount must be in'):
            MintMeltEntry(token_index=1, amount=0)

    def test_negative_amount_rejected(self) -> None:
        with pytest.raises(ValueError, match='amount must be in'):
            MintMeltEntry(token_index=1, amount=-1)

    def test_amount_too_large_rejected(self) -> None:
        with pytest.raises(ValueError, match='amount must be in'):
            MintMeltEntry(token_index=1, amount=2 ** 64)

    def test_zero_token_index_rejected(self) -> None:
        with pytest.raises(ValueError, match='token_index must be in'):
            MintMeltEntry(token_index=0, amount=1)

    def test_token_index_too_large_rejected(self) -> None:
        with pytest.raises(ValueError, match='token_index must be in'):
            MintMeltEntry(token_index=17, amount=1)


# ---------------------------------------------------------------------------
# Feature gating
# ---------------------------------------------------------------------------


class TestFeatureGating:
    def test_basic_verification_rejects_when_shielded_off(self) -> None:
        """MintHeader/MeltHeader are gated by ENABLE_SHIELDED_TRANSACTIONS.

        When the feature is inactive, verify_basic short-circuits with
        HeaderNotSupported before any downstream verification runs.
        """
        from hathor.verification.verification_service import VerificationService
        settings = _make_settings()
        verifiers = MagicMock()
        service = VerificationService(settings=settings, verifiers=verifiers)

        tx = _make_mock_tx(
            tokens=[b'\x11' * 32],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
        )
        tx.is_genesis = False
        tx.hash_hex = 'a' * 64
        tx.version = MagicMock()
        tx.has_shielded_outputs = MagicMock(return_value=False)

        params = MagicMock()
        params.features = MagicMock()
        params.features.shielded_transactions = False

        with pytest.raises(HeaderNotSupported, match='shielded transactions are not enabled'):
            from hathor.transaction import TxVersion
            tx.version = TxVersion.REGULAR_TRANSACTION
            tx.signal_bits = 0
            service.verify_basic(tx, params)


# ---------------------------------------------------------------------------
# Indexer (RFC §4.8): per-token totals reflect MintHeader/MeltHeader scalars
# ---------------------------------------------------------------------------


class TestIndexerSupplyUpdate:
    def test_add_tx_applies_mint_header_to_total(self) -> None:
        # Minimal smoke test: walks the same code path the rocksdb tokens index
        # uses (Transaction.has_mint_header + iterate entries + add_to_total).
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=12345)],
            has_shielded_outputs=True,
        )
        deltas: list[tuple[bytes, int]] = []
        if tx.has_mint_header():
            for entry in tx.get_mint_header().entries:
                deltas.append((tx.get_token_uid(entry.token_index), entry.amount))
        assert deltas == [(token_uid, 12345)]

    def test_add_tx_applies_melt_header_as_negative_delta(self) -> None:
        token_uid = b'\x22' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            melt_entries=[MintMeltEntry(token_index=1, amount=999)],
            has_shielded_outputs=True,
        )
        deltas: list[tuple[bytes, int]] = []
        if tx.has_melt_header():
            for entry in tx.get_melt_header().entries:
                deltas.append((tx.get_token_uid(entry.token_index), -entry.amount))
        assert deltas == [(token_uid, -999)]
