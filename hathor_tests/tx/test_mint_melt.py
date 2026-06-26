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
    pass

from hathor.transaction.exceptions import (
    ForbiddenMelt,
    ForbiddenMint,
    InvalidMintMeltHeaderError,
    InvalidToken,
    ShieldedMintMeltForbiddenError,
)
from hathor.transaction.headers import MeltHeader, MintHeader, MintMeltEntry, VertexHeaderId
from hathor.transaction.token_info import TokenVersion
from hathor.transaction.vertex_parser._mint_melt_header import deserialize_melt_header, deserialize_mint_header
from hathor.verification.transaction_verifier import TransactionVerifier
from hathorlib.serialization import Deserializer


def _make_settings() -> HathorSettings:
    settings = MagicMock(spec=HathorSettings)
    settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT = 1
    settings.FEE_PER_FULL_SHIELDED_OUTPUT = 2
    settings.FEE_PER_OUTPUT_V1 = 100
    settings.HATHOR_TOKEN_UID = b'\x00'
    settings.TOKEN_DEPOSIT_PERCENTAGE = 0.01
    settings.SKIP_VERIFICATION = set()
    settings.CONSENSUS_ALGORITHM = MagicMock()
    settings.CONSENSUS_ALGORITHM.is_pow.return_value = True
    return settings


def _make_verifier() -> TransactionVerifier:
    return TransactionVerifier(settings=_make_settings(), daa_factory=MagicMock(), feature_service=MagicMock())


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
        entries = [MintMeltEntry(token_index=1, amount=100_000), MintMeltEntry(token_index=2, amount=50)]
        h = MintHeader(entries=entries)
        b = h.serialize()
        assert b[0:1] == VertexHeaderId.MINT_HEADER.value
        assert b[1] == 2
        deserializer = Deserializer.build_bytes_deserializer(b)
        entries2 = deserialize_mint_header(deserializer)
        assert bytes(deserializer.read_all()) == b''
        assert entries2 == entries

    def test_melt_header_roundtrip(self) -> None:
        entries = [MintMeltEntry(token_index=3, amount=999_999_999)]
        h = MeltHeader(entries=entries)
        b = h.serialize()
        assert b[0:1] == VertexHeaderId.MELT_HEADER.value
        entries2 = deserialize_melt_header(Deserializer.build_bytes_deserializer(b))
        assert entries2 == entries

    def test_sighash_bytes_equals_serialize(self) -> None:
        h = MintHeader(entries=[MintMeltEntry(token_index=1, amount=1)])
        assert h.get_sighash_bytes() == h.serialize()

    def test_distinct_header_ids(self) -> None:
        assert VertexHeaderId.MINT_HEADER.value == b'\x14'
        assert VertexHeaderId.MELT_HEADER.value == b'\x15'
        assert VertexHeaderId.MINT_HEADER.value != VertexHeaderId.MELT_HEADER.value

    @pytest.mark.parametrize('buf,match', [
        (b'\x14\x00', 'must contain at least 1 entry'),
        (b'\x14\x01\x01', 'malformed'),
        (b'\x14\x01\x00\x00\x00\x00\x00\x00\x00\x00\x05', 'token_index must be in'),
        (b'\x14\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00', 'amount must be in'),
        (b'\x14\x02\x01\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x00\x00\x00\x00\x07',
         'duplicate token_index'),
        (b'\x15\x01\x01\x00\x00\x00\x00\x00\x00\x00\x05', 'unexpected header id'),
        (b'\x14\x01\x11\x00\x00\x00\x00\x00\x00\x00\x05', 'token_index must be in'),
    ])
    def test_deserialize_rejects_malformed(self, buf: bytes, match: str) -> None:
        with pytest.raises(InvalidMintMeltHeaderError, match=match):
            deserialize_mint_header(Deserializer.build_bytes_deserializer(buf))


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


class TestParserGating:
    """Mint/melt headers are registered in the vertex parser's supported_headers
    only when ENABLE_SHIELDED_TRANSACTIONS is non-DISABLED. There is no separate
    flag for mint/melt — they ride on the parent shielded-transactions gate.
    """

    def test_supported_headers_include_mint_melt_when_shielded_enabled(self) -> None:
        from hathor.transaction.headers.types import VertexHeaderId
        from hathor.transaction.vertex_parser import VertexParser
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
        from hathor.transaction.headers.types import VertexHeaderId
        from hathor.transaction.vertex_parser import VertexParser
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
