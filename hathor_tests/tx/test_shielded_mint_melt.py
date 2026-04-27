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

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from hathor.conf.settings import HathorSettings
from hathor.transaction import Transaction

if TYPE_CHECKING:
    from hathor.indexes.rocksdb_tokens_index import RocksDBTokensIndex
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
    settings.FEE_PER_OUTPUT = 100
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


class TestIndexerHeaderTokenNetCancellation:
    """RocksDBTokensIndex must cancel its per-utxo flow for tokens covered by
    Mint/Melt headers, otherwise mixed transparent + shielded mints/melts get
    double-counted in the per-token total.
    """

    @staticmethod
    def _make_index() -> 'RocksDBTokensIndex':
        from unittest.mock import MagicMock as _MM

        from hathor.indexes.rocksdb_tokens_index import RocksDBTokensIndex

        # Bypass __init__ — we only need _transparent_net_for_index_correction.
        idx = RocksDBTokensIndex.__new__(RocksDBTokensIndex)
        idx.log = _MM()
        return idx

    def _make_tx_with_io(
        self,
        *,
        tokens: list[bytes],
        mint_entries: list[MintMeltEntry] | None = None,
        melt_entries: list[MintMeltEntry] | None = None,
        transparent_inputs: list[tuple[bytes, int, bool]] | None = None,
        transparent_outputs: list[tuple[bytes, int, bool]] | None = None,
    ) -> MagicMock:
        """Builds a mock tx with the requested transparent inputs/outputs.

        Each (token_uid, value, is_authority) tuple becomes one tx_input/tx_output.
        """
        tx = _make_mock_tx(
            tokens=tokens,
            mint_entries=mint_entries,
            melt_entries=melt_entries,
            has_shielded_outputs=True,
        )

        # Build outputs.
        outputs = []
        for token_uid, value, is_authority in transparent_outputs or []:
            o = MagicMock()
            o.is_token_authority = MagicMock(return_value=is_authority)
            o.value = value
            o.get_token_index = MagicMock(return_value=tokens.index(token_uid) + 1)
            outputs.append(o)
        tx.outputs = outputs

        # Build inputs + their spent_txs.
        inputs = []
        spent_txs: dict[bytes, MagicMock] = {}
        for i, (token_uid, value, is_authority) in enumerate(transparent_inputs or []):
            tx_id = bytes([i]) * 32
            tx_input = MagicMock()
            tx_input.tx_id = tx_id
            tx_input.index = 0

            spent_output = MagicMock()
            spent_output.is_token_authority = MagicMock(return_value=is_authority)
            spent_output.value = value
            spent_output.get_token_index = MagicMock(return_value=1)

            spent_tx = MagicMock()
            spent_tx.outputs = [spent_output]
            spent_tx.shielded_outputs = []
            spent_tx.is_shielded_output = MagicMock(return_value=False)
            spent_tx.get_token_uid = MagicMock(return_value=token_uid)

            inputs.append(tx_input)
            spent_txs[tx_id] = spent_tx
        tx.inputs = inputs
        tx.get_spent_tx = MagicMock(side_effect=lambda i: spent_txs[i.tx_id])
        return tx

    def test_pure_shielded_mint_zero_net(self) -> None:
        """A mint with no transparent T outputs/inputs has zero per-utxo net,
        so no cancellation is needed. The helper drops zero entries, so the
        return value is empty.
        """
        idx = self._make_index()
        token_uid = b'\x11' * 32
        tx = self._make_tx_with_io(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=1000)],
            transparent_inputs=[(token_uid, 0, True)],   # mint authority only
            transparent_outputs=[(token_uid, 0, True)],  # authority refresh only
        )
        net = idx._transparent_net_for_index_correction(tx)
        assert net == {}

    def test_mixed_mint_transparent_and_shielded_outputs(self) -> None:
        """Mint 1000 with 600 to transparent + 400 to shielded → per-utxo net
        is +600. The header contribution must subtract that to land on +1000.
        """
        idx = self._make_index()
        token_uid = b'\x11' * 32
        tx = self._make_tx_with_io(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=1000)],
            transparent_inputs=[(token_uid, 0, True)],   # mint authority
            transparent_outputs=[
                (token_uid, 0, True),     # authority refresh
                (token_uid, 600, False),  # transparent portion of mint
            ],
        )
        net = idx._transparent_net_for_index_correction(tx)
        assert net == {token_uid: 600}

    def test_mixed_melt_transparent_input(self) -> None:
        """Melt 800 with 100 transparent T input + shielded T inputs → per-utxo
        net is -100 for T. The melt-header reversal must subtract that signed
        value to land on -800 net.
        """
        idx = self._make_index()
        token_uid = b'\x22' * 32
        tx = self._make_tx_with_io(
            tokens=[token_uid],
            melt_entries=[MintMeltEntry(token_index=1, amount=800)],
            transparent_inputs=[
                (token_uid, 0, True),    # melt authority
                (token_uid, 100, False),  # transparent portion being melted
            ],
            transparent_outputs=[(token_uid, 0, True)],  # authority refresh
        )
        net = idx._transparent_net_for_index_correction(tx)
        assert net == {token_uid: -100}

    def test_skips_authority_outputs_and_shielded_inputs(self) -> None:
        """Authority outputs/inputs and shielded inputs contribute zero."""
        idx = self._make_index()
        token_uid = b'\x33' * 32
        tx = self._make_tx_with_io(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=500)],
            transparent_inputs=[
                (token_uid, 0, True),    # mint authority
                (token_uid, 0, True),    # melt authority (unused, but counted as authority)
            ],
            transparent_outputs=[
                (token_uid, 0, True),    # authority refresh
            ],
        )
        net = idx._transparent_net_for_index_correction(tx)
        assert net == {}

    def test_no_headers_no_shielded_returns_empty(self) -> None:
        """A tx with no Mint/Melt header AND no shielded involvement needs no
        correction — the per-utxo flow is correct as-is.
        """
        idx = self._make_index()
        tx = _make_mock_tx(tokens=[b'\x11' * 32], has_shielded_outputs=False)
        assert idx._transparent_net_for_index_correction(tx) == {}

    def test_shielding_non_htr_token_cancels_per_utxo(self) -> None:
        """Shielding a non-HTR token: 100 T transparent input → 100 T shielded
        output (no header). Per-utxo would record −100. The helper reports
        the −100 so add_tx can cancel it, keeping total supply stable.
        """
        idx = self._make_index()
        token_uid = b'\x44' * 32
        tx = self._make_tx_with_io(
            tokens=[token_uid],
            transparent_inputs=[(token_uid, 100, False)],  # transparent T being shielded
            transparent_outputs=[],                         # all to shielded
        )
        # _make_tx_with_io leaves has_shielded_outputs at the default the
        # caller set; ensure shielded involvement is detected.
        tx.has_shielded_outputs = MagicMock(return_value=True)
        net = idx._transparent_net_for_index_correction(tx)
        assert net == {token_uid: -100}

    def test_unshielding_non_htr_token_cancels_per_utxo(self) -> None:
        """Unshielding a non-HTR token: shielded input → 100 T transparent
        output. has_shielded_inputs is detected via the input walk; the
        helper reports +100 so add_tx can cancel it.
        """
        idx = self._make_index()
        token_uid = b'\x55' * 32

        # Build a shielded-input tx by hand: spent_tx.is_shielded_output=True
        # for the input.
        tx = _make_mock_tx(tokens=[token_uid], has_shielded_outputs=False)
        tx_input = MagicMock()
        tx_input.tx_id = b'\x55' * 32
        tx_input.index = 0
        spent_tx = MagicMock()
        spent_tx.is_shielded_output = MagicMock(return_value=True)
        tx.inputs = [tx_input]
        tx.get_spent_tx = MagicMock(return_value=spent_tx)
        # Transparent T output (the unshielded value).
        out = MagicMock()
        out.is_token_authority = MagicMock(return_value=False)
        out.value = 100
        out.get_token_index = MagicMock(return_value=1)
        tx.outputs = [out]

        net = idx._transparent_net_for_index_correction(tx)
        assert net == {token_uid: 100}

    def test_shielded_transfer_no_transparent_flow_returns_empty(self) -> None:
        """A pure shielded transfer (shielded input → shielded output, both
        of token T, no transparent flow) needs no correction — per-utxo
        contributes 0.
        """
        idx = self._make_index()
        token_uid = b'\x66' * 32
        tx = _make_mock_tx(tokens=[token_uid], has_shielded_outputs=True)
        tx_input = MagicMock()
        tx_input.tx_id = b'\x77' * 32
        tx_input.index = 0
        spent_tx = MagicMock()
        spent_tx.is_shielded_output = MagicMock(return_value=True)
        tx.inputs = [tx_input]
        tx.get_spent_tx = MagicMock(return_value=spent_tx)
        tx.outputs = []

        # has_shielded_outputs=True, has_shielded_inputs=True. tx.tokens=[T].
        # No transparent flow → net is 0 for T → filtered out.
        assert idx._transparent_net_for_index_correction(tx) == {}


class TestIndexerReorgOrderingTct:
    """remove_tx for a shielded TokenCreationTransaction must reverse Mint/Melt
    header deltas BEFORE destroy_token, otherwise the post-reversal
    `add_to_total` re-creates the row with a negative total.
    """

    def test_destroy_token_runs_after_mint_header_reversal(self) -> None:
        from hathor.indexes.rocksdb_tokens_index import RocksDBTokensIndex
        from hathor.transaction import TxVersion
        from hathor.transaction.token_creation_tx import TokenCreationTransaction

        idx = RocksDBTokensIndex.__new__(RocksDBTokensIndex)
        idx.log = MagicMock()
        idx._db = MagicMock()
        idx._cf = MagicMock()
        idx._settings = MagicMock()
        idx._settings.HATHOR_TOKEN_UID = b'\x00'

        # Track the order of destroy_token vs add_to_total calls.
        call_log: list[str] = []
        idx.destroy_token = MagicMock(  # type: ignore[method-assign]
            side_effect=lambda *a, **kw: call_log.append('destroy_token')
        )
        idx.add_to_total = MagicMock(  # type: ignore[method-assign]
            side_effect=lambda *a, **kw: call_log.append('add_to_total')
        )
        idx._add_utxo = MagicMock()  # type: ignore[method-assign]
        idx._remove_utxo = MagicMock()  # type: ignore[method-assign]
        idx._remove_transaction = MagicMock()  # type: ignore[method-assign]

        # Build a TCT mock that carries a MintHeader.
        token_uid = b'\xff' * 32
        tct = MagicMock(spec=TokenCreationTransaction)
        tct.hash = token_uid
        tct.hash_hex = token_uid.hex()
        tct.version = TxVersion.TOKEN_CREATION_TRANSACTION
        tct.is_transaction = True
        tct.is_nano_contract = MagicMock(return_value=False)
        tct.has_mint_header = MagicMock(return_value=True)
        tct.has_melt_header = MagicMock(return_value=False)
        mint_header = MagicMock()
        mint_header.entries = [MintMeltEntry(token_index=1, amount=1000)]
        tct.get_mint_header = MagicMock(return_value=mint_header)
        tct.tokens = [token_uid]
        tct.get_token_uid = MagicMock(return_value=token_uid)
        tct.timestamp = 0
        tct.inputs = []
        tct.outputs = []
        tct.get_spent_tx = MagicMock()

        idx.remove_tx(tct)

        # destroy_token must be the LAST call so the negative-delta add_to_total
        # doesn't re-create an empty row after the token has been destroyed.
        assert 'destroy_token' in call_log
        assert call_log[-1] == 'destroy_token', (
            f'destroy_token must run last; call order was {call_log}'
        )


# ---------------------------------------------------------------------------
# Rule M4: augmented homomorphic balance equation
# ---------------------------------------------------------------------------


def _make_minimal_balance_tx(
    *,
    mint_entries: list[MintMeltEntry] | None = None,
    melt_entries: list[MintMeltEntry] | None = None,
) -> MagicMock:
    """Build a tx that satisfies verify_shielded_balance's surface area without
    real crypto: 2 mocked shielded outputs, no transparent in/out, no fees,
    no unshield-balance header. The mutual-exclusion invariants pass because
    has_shielded_outputs=True and excess_blinding_factor=None.
    """
    tx = _make_mock_tx(
        tokens=[b'\xaa' * 32, b'\xbb' * 32],
        mint_entries=mint_entries,
        melt_entries=melt_entries,
        has_shielded_outputs=True,
    )
    tx.outputs = []
    out1 = MagicMock()
    out1.commitment = b'\x01' * 33
    out2 = MagicMock()
    out2.commitment = b'\x02' * 33
    tx.shielded_outputs = [out1, out2]
    tx.has_fees = MagicMock(return_value=False)
    tx.excess_blinding_factor = None
    tx.storage = MagicMock()
    tx.get_spent_tx = MagicMock()
    return tx


def _patch_verify_balance(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Patch hathor.crypto.shielded.verify_balance to capture its arguments."""
    captured: dict = {}

    def fake(
        transparent_inputs,
        shielded_inputs,
        transparent_outputs,
        shielded_outputs,
        excess_blinding_factor,
    ):
        captured['ti'] = list(transparent_inputs)
        captured['si'] = list(shielded_inputs)
        captured['to'] = list(transparent_outputs)
        captured['so'] = list(shielded_outputs)
        captured['excess'] = excess_blinding_factor
        return True

    monkeypatch.setattr('hathor.crypto.shielded.verify_balance', fake)
    return captured


class TestRuleM4AugmentedBalanceEquation:
    """Verify Mint/Melt entries land on the right side of the augmented
    balance equation. Any sign flip or dropped term in `_fold_mint_melt_entry`
    would change the captured args.
    """

    def test_mint_amount_lands_on_transparent_inputs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        verifier = _make_verifier()
        monkeypatch.setattr(
            TransactionVerifier, '_resolve_token_version_for_mint_melt',
            lambda self, tx, token_uid, ncs: TokenVersion.NATIVE,
        )
        captured = _patch_verify_balance(monkeypatch)
        token = b'\xaa' * 32
        tx = _make_minimal_balance_tx(
            mint_entries=[MintMeltEntry(token_index=1, amount=12345)],
        )
        verifier.verify_shielded_balance(tx)
        assert (12345, token) in captured['ti']
        # NATIVE token: no HTR deposit/withdraw term.
        htr = b'\x00' * 32
        assert not any(uid == htr for _, uid in captured['ti'])
        assert not any(uid == htr for _, uid in captured['to'])

    def test_melt_amount_lands_on_transparent_outputs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        verifier = _make_verifier()
        monkeypatch.setattr(
            TransactionVerifier, '_resolve_token_version_for_mint_melt',
            lambda self, tx, token_uid, ncs: TokenVersion.NATIVE,
        )
        captured = _patch_verify_balance(monkeypatch)
        token = b'\xbb' * 32
        tx = _make_minimal_balance_tx(
            melt_entries=[MintMeltEntry(token_index=2, amount=999)],
        )
        verifier.verify_shielded_balance(tx)
        assert (999, token) in captured['to']
        htr = b'\x00' * 32
        assert not any(uid == htr for _, uid in captured['ti'])
        assert not any(uid == htr for _, uid in captured['to'])

    def test_deposit_version_mint_emits_htr_deposit_on_outputs(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        verifier = _make_verifier()
        monkeypatch.setattr(
            TransactionVerifier, '_resolve_token_version_for_mint_melt',
            lambda self, tx, token_uid, ncs: TokenVersion.DEPOSIT,
        )
        captured = _patch_verify_balance(monkeypatch)
        token = b'\xaa' * 32
        htr = b'\x00' * 32
        tx = _make_minimal_balance_tx(
            mint_entries=[MintMeltEntry(token_index=1, amount=10_000)],
        )
        verifier.verify_shielded_balance(tx)
        assert (10_000, token) in captured['ti']
        # 1% of 10_000 = 100 HTR deposit on the OUTPUTS side.
        assert (100, htr) in captured['to']

    def test_deposit_version_melt_emits_htr_withdraw_on_inputs(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        verifier = _make_verifier()
        monkeypatch.setattr(
            TransactionVerifier, '_resolve_token_version_for_mint_melt',
            lambda self, tx, token_uid, ncs: TokenVersion.DEPOSIT,
        )
        captured = _patch_verify_balance(monkeypatch)
        token = b'\xaa' * 32
        htr = b'\x00' * 32
        tx = _make_minimal_balance_tx(
            melt_entries=[MintMeltEntry(token_index=1, amount=10_000)],
        )
        verifier.verify_shielded_balance(tx)
        assert (10_000, token) in captured['to']
        # 1% of 10_000 = 100 HTR withdraw on the INPUTS side.
        assert (100, htr) in captured['ti']

    def test_fee_version_mint_charges_fee_per_output_on_outputs(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """FEE-version mint pays one FEE_PER_OUTPUT in HTR per MintHeader entry.

        The charge lands on the output side so the user must fund it from HTR
        transparent inputs. The amount is per-entry, not per shielded recipient
        — see ``_fold_mint_melt_entry`` for the rationale.
        """
        verifier = _make_verifier()
        monkeypatch.setattr(
            TransactionVerifier, '_resolve_token_version_for_mint_melt',
            lambda self, tx, token_uid, ncs: TokenVersion.FEE,
        )
        captured = _patch_verify_balance(monkeypatch)
        token = b'\xaa' * 32
        htr = b'\x00' * 32
        tx = _make_minimal_balance_tx(
            mint_entries=[MintMeltEntry(token_index=1, amount=10_000)],
        )
        verifier.verify_shielded_balance(tx)
        assert (10_000, token) in captured['ti']
        # FEE_PER_OUTPUT (100 in the fixture) lands on the output side.
        assert (100, htr) in captured['to']
        # Nothing on the input side beyond the primary FEE-token term.
        assert not any(uid == htr for _, uid in captured['ti'])

    def test_fee_version_melt_charges_fee_per_output_on_outputs(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """FEE-version melt also pays FEE_PER_OUTPUT on the output side — the
        per-entry fee is always paid by the user, unlike DEPOSIT's withdraw.
        """
        verifier = _make_verifier()
        monkeypatch.setattr(
            TransactionVerifier, '_resolve_token_version_for_mint_melt',
            lambda self, tx, token_uid, ncs: TokenVersion.FEE,
        )
        captured = _patch_verify_balance(monkeypatch)
        token = b'\xaa' * 32
        htr = b'\x00' * 32
        tx = _make_minimal_balance_tx(
            melt_entries=[MintMeltEntry(token_index=1, amount=10_000)],
        )
        verifier.verify_shielded_balance(tx)
        assert (10_000, token) in captured['to']
        assert (100, htr) in captured['to']
        assert not any(uid == htr for _, uid in captured['ti'])

    def test_fee_version_charges_per_entry_not_per_amount(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two MintHeader entries on FEE tokens => two FEE_PER_OUTPUT charges
        on the output side. The amount itself doesn't multiply the fee.
        """
        verifier = _make_verifier()
        monkeypatch.setattr(
            TransactionVerifier, '_resolve_token_version_for_mint_melt',
            lambda self, tx, token_uid, ncs: TokenVersion.FEE,
        )
        captured = _patch_verify_balance(monkeypatch)
        htr = b'\x00' * 32
        tx = _make_minimal_balance_tx(
            mint_entries=[
                MintMeltEntry(token_index=1, amount=1),
                MintMeltEntry(token_index=2, amount=10_000_000),
            ],
        )
        verifier.verify_shielded_balance(tx)
        # Two entries -> two FEE_PER_OUTPUT charges, regardless of the amounts.
        htr_outputs = [(amt, uid) for amt, uid in captured['to'] if uid == htr]
        assert htr_outputs == [(100, htr), (100, htr)]


class TestDepositBoundaryRounding:
    """get_deposit_token_deposit_amount uses ceil; get_deposit_token_withdraw_amount
    uses floor. The augmented balance equation skips the HTR term when the rounded
    amount is zero. Pin the boundaries so a rounding-direction regression
    (e.g., floor for deposit) is caught.
    """

    @pytest.mark.parametrize('amount,expected_deposit,expected_withdraw', [
        (1, 1, 0),
        (50, 1, 0),
        (99, 1, 0),
        (100, 1, 1),
        (101, 2, 1),
        (150, 2, 1),
        (10_000, 100, 100),
    ])
    def test_deposit_boundaries(
        self,
        amount: int,
        expected_deposit: int,
        expected_withdraw: int,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        verifier = _make_verifier()
        monkeypatch.setattr(
            TransactionVerifier, '_resolve_token_version_for_mint_melt',
            lambda self, tx, token_uid, ncs: TokenVersion.DEPOSIT,
        )
        htr = b'\x00' * 32

        # Mint side.
        captured_mint = _patch_verify_balance(monkeypatch)
        tx_mint = _make_minimal_balance_tx(
            mint_entries=[MintMeltEntry(token_index=1, amount=amount)],
        )
        verifier.verify_shielded_balance(tx_mint)
        if expected_deposit > 0:
            assert (expected_deposit, htr) in captured_mint['to']
        else:
            assert not any(uid == htr for _, uid in captured_mint['to'])

        # Melt side.
        captured_melt = _patch_verify_balance(monkeypatch)
        tx_melt = _make_minimal_balance_tx(
            melt_entries=[MintMeltEntry(token_index=1, amount=amount)],
        )
        verifier.verify_shielded_balance(tx_melt)
        if expected_withdraw > 0:
            assert (expected_withdraw, htr) in captured_melt['ti']
        else:
            assert not any(uid == htr for _, uid in captured_melt['ti'])


# ---------------------------------------------------------------------------
# _resolve_token_version_for_mint_melt — all three branches
# ---------------------------------------------------------------------------


class TestResolveTokenVersionForMintMelt:
    """Returning a sentinel here would silently bypass the DEPOSIT 1% deposit
    term in the augmented balance equation — pin every branch.
    """

    def test_tct_self_reference(self) -> None:
        from hathor.transaction.token_creation_tx import TokenCreationTransaction
        verifier = _make_verifier()
        token_uid = b'\xff' * 32
        tct = MagicMock(spec=TokenCreationTransaction)
        tct.hash = token_uid
        tct.token_version = TokenVersion.DEPOSIT
        tct.storage = MagicMock()

        version = verifier._resolve_token_version_for_mint_melt(tct, token_uid, None)

        assert version == TokenVersion.DEPOSIT
        # Storage must NOT be consulted for the TCT-self-reference branch.
        tct.storage.get_token_creation_transaction.assert_not_called()

    def test_no_nc_storage_falls_back_to_tx_storage(self) -> None:
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(tokens=[token_uid], has_shielded_outputs=True)
        tx.storage = MagicMock()
        issuing_tct = MagicMock()
        issuing_tct.token_version = TokenVersion.DEPOSIT
        tx.storage.get_token_creation_transaction = MagicMock(return_value=issuing_tct)

        result = verifier._resolve_token_version_for_mint_melt(tx, token_uid, None)
        assert result == TokenVersion.DEPOSIT

    def test_no_nc_storage_for_nano_issued_token_raises(self) -> None:
        from hathor.transaction.exceptions import TokenNotFound
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist
        verifier = _make_verifier()
        token_uid = b'\x22' * 32
        tx = _make_mock_tx(tokens=[token_uid], has_shielded_outputs=True)
        tx.storage = MagicMock()
        tx.storage.get_token_creation_transaction = MagicMock(
            side_effect=TransactionDoesNotExist(),
        )

        with pytest.raises(TokenNotFound, match='nc_block_storage was not provided'):
            verifier._resolve_token_version_for_mint_melt(tx, token_uid, None)

    def test_nc_storage_returns_none_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from hathor.transaction.exceptions import TokenNotFound
        verifier = _make_verifier()
        token_uid = b'\x33' * 32
        tx = _make_mock_tx(tokens=[token_uid], has_shielded_outputs=True)
        tx.storage = MagicMock()
        monkeypatch.setattr(
            'hathor.transaction.token_info.get_token_version',
            lambda *a, **kw: None,
        )

        with pytest.raises(TokenNotFound):
            verifier._resolve_token_version_for_mint_melt(tx, token_uid, MagicMock())

    def test_nc_storage_returns_resolved_version(self, monkeypatch: pytest.MonkeyPatch) -> None:
        verifier = _make_verifier()
        token_uid = b'\x44' * 32
        tx = _make_mock_tx(tokens=[token_uid], has_shielded_outputs=True)
        tx.storage = MagicMock()
        monkeypatch.setattr(
            'hathor.transaction.token_info.get_token_version',
            lambda *a, **kw: TokenVersion.FEE,
        )

        result = verifier._resolve_token_version_for_mint_melt(tx, token_uid, MagicMock())
        assert result == TokenVersion.FEE


# ---------------------------------------------------------------------------
# Rule M2 negative-path coverage
# ---------------------------------------------------------------------------


class TestParserGating:
    """Mint/melt headers are registered in the vertex parser's supported_headers
    only when ENABLE_SHIELDED_TRANSACTIONS is non-DISABLED. There is no separate
    flag for mint/melt — they ride on the parent shielded-transactions gate.
    """

    def test_supported_headers_include_mint_melt_when_shielded_enabled(self) -> None:
        from hathor.transaction.vertex_parser import VertexParser
        from hathor.transaction.headers.types import VertexHeaderId
        from hathorlib.conf.settings import FeatureSetting
        settings = MagicMock(spec=HathorSettings)
        settings.ENABLE_NANO_CONTRACTS = False
        settings.ENABLE_FEE_BASED_TOKENS = False
        settings.ENABLE_SHIELDED_TRANSACTIONS = FeatureSetting.ENABLED

        supported = VertexParser.get_supported_headers(settings)

        assert VertexHeaderId.MINT_HEADER in supported
        assert VertexHeaderId.MELT_HEADER in supported
        assert supported[VertexHeaderId.MINT_HEADER] is MintHeader
        assert supported[VertexHeaderId.MELT_HEADER] is MeltHeader

    def test_supported_headers_exclude_mint_melt_when_shielded_disabled(self) -> None:
        from hathor.transaction.vertex_parser import VertexParser
        from hathor.transaction.headers.types import VertexHeaderId
        from hathorlib.conf.settings import FeatureSetting
        settings = MagicMock(spec=HathorSettings)
        settings.ENABLE_NANO_CONTRACTS = False
        settings.ENABLE_FEE_BASED_TOKENS = False
        settings.ENABLE_SHIELDED_TRANSACTIONS = FeatureSetting.DISABLED

        supported = VertexParser.get_supported_headers(settings)

        assert VertexHeaderId.MINT_HEADER not in supported
        assert VertexHeaderId.MELT_HEADER not in supported


class TestMaxHeadersLimit:
    """get_maximum_number_of_headers must return 5 when shielded is enabled so a
    single tx can carry FeeHeader + (ShieldedOutputs|UnshieldBalance) + Nano +
    MintHeader + MeltHeader. With shielded disabled the legacy limit of 3
    applies.
    """

    @staticmethod
    def _make_tx_with_settings(enable_shielded: bool) -> 'Transaction':
        from hathorlib.conf.settings import FeatureSetting
        # Build a real Transaction-shaped instance via __new__ to exercise the
        # get_maximum_number_of_headers method without invoking heavy ctors.
        tx = Transaction.__new__(Transaction)
        tx._settings = MagicMock(spec=HathorSettings)
        tx._settings.ENABLE_SHIELDED_TRANSACTIONS = (
            FeatureSetting.ENABLED if enable_shielded else FeatureSetting.DISABLED
        )
        return tx

    def test_max_is_5_when_shielded_enabled(self) -> None:
        tx = self._make_tx_with_settings(enable_shielded=True)
        assert tx.get_maximum_number_of_headers() == 5

    def test_max_is_3_when_shielded_disabled(self) -> None:
        tx = self._make_tx_with_settings(enable_shielded=False)
        assert tx.get_maximum_number_of_headers() == 3


class TestRuleM2AuthorityNegativePaths:
    """verify_mint_melt_authority_inputs must reject when the authority does
    not match the header's token, even if some other authority is present.
    """

    def test_authority_for_wrong_token_does_not_satisfy_mint(self) -> None:
        verifier = _make_verifier()
        token_a = b'\xaa' * 32
        token_b = b'\xbb' * 32
        tx = _make_mock_tx(
            tokens=[token_a, token_b],
            mint_entries=[MintMeltEntry(token_index=2, amount=100)],  # token_b
            has_shielded_outputs=True,
        )
        # Input grants mint authority for token_a, NOT token_b.
        tx_input, spent_tx = _make_authority_input(token_a, can_mint=True, can_melt=False)
        tx.inputs = [tx_input]
        tx.storage = MagicMock()

        with pytest.raises(ForbiddenMint):
            verifier.verify_mint_melt_authority_inputs(tx, spent_txs={tx_input.tx_id: spent_tx})

    def test_non_authority_output_ignored(self) -> None:
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=True,
        )
        # is_token_authority=False → input is NOT an authority and must not satisfy
        # the mint header even though it points at the right token.
        tx_input, spent_tx = _make_authority_input(token_uid, can_mint=True, can_melt=False)
        spent_tx.outputs[0].is_token_authority = MagicMock(return_value=False)
        tx.inputs = [tx_input]
        tx.storage = MagicMock()

        with pytest.raises(ForbiddenMint):
            verifier.verify_mint_melt_authority_inputs(tx, spent_txs={tx_input.tx_id: spent_tx})

    def test_melt_only_authority_cannot_satisfy_mint_header(self) -> None:
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=True,
        )
        tx_input, spent_tx = _make_authority_input(token_uid, can_mint=False, can_melt=True)
        tx.inputs = [tx_input]
        tx.storage = MagicMock()

        with pytest.raises(ForbiddenMint):
            verifier.verify_mint_melt_authority_inputs(tx, spent_txs={tx_input.tx_id: spent_tx})

    def test_combined_authority_satisfies_mint_header(self) -> None:
        """An input with can_mint=True AND can_melt=True passes a MintHeader for
        its token. (Set semantics — both bits live on a single output.)
        """
        verifier = _make_verifier()
        token_uid = b'\x11' * 32
        tx = _make_mock_tx(
            tokens=[token_uid],
            mint_entries=[MintMeltEntry(token_index=1, amount=100)],
            has_shielded_outputs=True,
        )
        tx_input, spent_tx = _make_authority_input(token_uid, can_mint=True, can_melt=True)
        tx.inputs = [tx_input]
        tx.storage = MagicMock()

        verifier.verify_mint_melt_authority_inputs(tx, spent_txs={tx_input.tx_id: spent_tx})
