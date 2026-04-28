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

"""Hathor-core-side tests for the shielded header surface.

The deep wire-format coverage lives in `hathorlib/tests/test_shielded_headers.py`
since the wire format is owned by hathorlib. These tests cover the
hathor-core-specific surface: the GenericVertex defaults, the Transaction
accessors, the @override on shielded_outputs, and parser registration
gating on `ENABLE_SHIELDED_TRANSACTIONS`.
"""

from __future__ import annotations

import pytest

from hathor.transaction import Transaction, TxOutput
from hathor.transaction.headers import (
    MeltHeader,
    MintHeader,
    MintMeltEntry,
    ShieldedOutputsHeader,
    UnshieldBalanceHeader,
    VertexHeaderId,
)
from hathor.transaction.vertex_parser import VertexParser
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.conf.settings import FeatureSetting
from hathorlib.transaction.shielded_tx_output import (
    ASSET_COMMITMENT_SIZE,
    COMMITMENT_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
    AmountShieldedOutput,
    FullShieldedOutput,
)


def _amount_output(token_data: int = 1) -> AmountShieldedOutput:
    return AmountShieldedOutput(
        commitment=b'\x09' + b'\x01' * (COMMITMENT_SIZE - 1),
        range_proof=b'\xab' * 64,
        script=b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac',
        token_data=token_data,
        ephemeral_pubkey=b'\x02' + b'\x03' * (EPHEMERAL_PUBKEY_SIZE - 1),
    )


class TestGenericVertexShieldedDefaults:
    """The empty-by-default behavior on any vertex without shielded headers."""

    def test_shielded_outputs_default_empty(self) -> None:
        tx = Transaction()
        assert tx.shielded_outputs == []

    def test_is_shielded_output_false_for_in_range_index(self) -> None:
        tx = Transaction(outputs=[TxOutput(value=1, script=b'')])
        assert tx.is_shielded_output(0) is False

    def test_is_shielded_output_false_for_out_of_range_index(self) -> None:
        tx = Transaction(outputs=[TxOutput(value=1, script=b'')])
        # Past the transparent outputs, but no shielded outputs either.
        assert tx.is_shielded_output(1) is False
        assert tx.is_shielded_output(99) is False


class TestTransactionShieldedAccessors:
    """Header-presence accessors on the Transaction subclass."""

    def test_no_headers(self) -> None:
        tx = Transaction()
        assert tx.has_shielded_outputs() is False
        assert tx.has_unshield_balance_header() is False
        assert tx.is_shielded() is False
        with pytest.raises(ValueError):
            tx.get_shielded_outputs_header()
        with pytest.raises(ValueError):
            tx.get_unshield_balance_header()

    def test_shielded_outputs_header_present(self) -> None:
        tx = Transaction()
        out = _amount_output()
        # Cross-ABC: shielded headers extend hathorlib's VertexBaseHeader,
        # which is a parallel class to hathor-core's. Runtime is duck-typed.
        header = ShieldedOutputsHeader(tx=tx, shielded_outputs=[out])  # type: ignore[arg-type]
        tx.headers.append(header)  # type: ignore[arg-type]

        assert tx.has_shielded_outputs() is True
        assert tx.has_unshield_balance_header() is False
        assert tx.is_shielded() is True
        assert tx.get_shielded_outputs_header() is header
        # The Transaction.shielded_outputs override surfaces the inner list.
        assert tx.shielded_outputs == [out]
        # is_shielded_output is true for the index past the transparent ones.
        assert tx.is_shielded_output(0) is True

    def test_unshield_balance_header_present(self) -> None:
        tx = Transaction()
        header = UnshieldBalanceHeader(tx=tx, excess_blinding_factor=b'\x00' * 32)  # type: ignore[arg-type]
        tx.headers.append(header)  # type: ignore[arg-type]

        assert tx.has_shielded_outputs() is False
        assert tx.has_unshield_balance_header() is True
        assert tx.is_shielded() is True
        assert tx.get_unshield_balance_header() is header

    def test_both_headers_present(self) -> None:
        # A partial-unshield tx (shielded inputs + shielded outputs) carries both.
        tx = Transaction()
        outs_header = ShieldedOutputsHeader(tx=tx, shielded_outputs=[_amount_output()])  # type: ignore[arg-type]
        unshield_header = UnshieldBalanceHeader(tx=tx, excess_blinding_factor=b'\x00' * 32)  # type: ignore[arg-type]
        tx.headers.append(outs_header)  # type: ignore[arg-type]
        tx.headers.append(unshield_header)  # type: ignore[arg-type]

        assert tx.has_shielded_outputs() is True
        assert tx.has_unshield_balance_header() is True
        assert tx.is_shielded() is True


class TestVertexParserShieldedGating:
    """The four shielded headers are admitted only when the flag is non-DISABLED."""

    def _settings_with(self, value: FeatureSetting):  # type: ignore[no-untyped-def]
        from hathor.conf.settings import HathorSettings
        return HathorSettings(
            NETWORK_NAME='unittests',
            P2PKH_VERSION_BYTE=b'\x28',
            MULTISIG_VERSION_BYTE=b'\x64',
            ENABLE_SHIELDED_TRANSACTIONS=value,
        )

    def test_disabled_omits_shielded_headers(self) -> None:
        settings = self._settings_with(FeatureSetting.DISABLED)
        supported = VertexParser.get_supported_headers(settings)
        for header_id in (
            VertexHeaderId.SHIELDED_OUTPUTS_HEADER,
            VertexHeaderId.UNSHIELD_BALANCE_HEADER,
            VertexHeaderId.MINT_HEADER,
            VertexHeaderId.MELT_HEADER,
        ):
            assert header_id not in supported
        with pytest.raises(ValueError, match='Header type not supported'):
            VertexParser.get_header_parser(b'\x12', settings)
        with pytest.raises(ValueError, match='Header type not supported'):
            VertexParser.get_header_parser(b'\x15', settings)

    def test_enabled_admits_shielded_headers(self) -> None:
        settings = self._settings_with(FeatureSetting.ENABLED)
        supported = VertexParser.get_supported_headers(settings)
        assert supported[VertexHeaderId.SHIELDED_OUTPUTS_HEADER] is ShieldedOutputsHeader
        assert supported[VertexHeaderId.UNSHIELD_BALANCE_HEADER] is UnshieldBalanceHeader
        assert supported[VertexHeaderId.MINT_HEADER] is MintHeader


def _amount_shielded_output(token_data: int = 1) -> AmountShieldedOutput:
    return AmountShieldedOutput(
        commitment=b'\x09' + b'\x01' * (COMMITMENT_SIZE - 1),
        range_proof=b'\xab' * 64,
        script=b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac',
        token_data=token_data,
        ephemeral_pubkey=b'\x02' + b'\x03' * (EPHEMERAL_PUBKEY_SIZE - 1),
    )


def _full_shielded_output() -> FullShieldedOutput:
    return FullShieldedOutput(
        commitment=b'\x09' + b'\x02' * (COMMITMENT_SIZE - 1),
        range_proof=b'\xcd' * 96,
        script=b'\x76\xa9\x14' + b'\x11' * 20 + b'\x88\xac',
        asset_commitment=b'\x0a' + b'\x04' * (ASSET_COMMITMENT_SIZE - 1),
        surjection_proof=b'\xee' * 32,
        ephemeral_pubkey=b'\x02' + b'\x05' * (EPHEMERAL_PUBKEY_SIZE - 1),
    )


class ShieldedHeadersWireRoundTripTest(unittest.TestCase):
    """End-to-end wire round-trip via hathor-core's VertexParser.

    Builds a real, hash-stable Transaction with the DAG builder, attaches
    each shielded header type, serializes to bytes, then parses back through
    `VertexParser.deserialize`. This exercises the cross-package integration
    seam (hathor-core's vertex_parser._headers orchestrator → hathorlib's
    deserialize_header dispatcher → per-header helper) — the seam where
    earlier bugs would have silently passed every other test.
    """

    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..12]
            b10 < dummy
            b11 --> tx1
        """)
        artifacts.propagate_with(self.manager, up_to='dummy')
        self.tx_template = artifacts.get_typed_vertex('tx1', Transaction)

    def _round_trip(self, tx: Transaction) -> Transaction:
        """Re-hash the tx, serialize via VertexParser, then parse it back."""
        tx.update_hash()
        raw = bytes(tx)
        parsed = self.manager.vertex_parser.deserialize(raw)
        assert isinstance(parsed, Transaction)
        return parsed

    def test_shielded_outputs_header_round_trip(self) -> None:
        outs = [_amount_shielded_output(token_data=1), _full_shielded_output()]
        header = ShieldedOutputsHeader(tx=self.tx_template, shielded_outputs=outs)  # type: ignore[arg-type]
        self.tx_template.headers.append(header)  # type: ignore[arg-type]

        parsed = self._round_trip(self.tx_template)
        assert parsed.has_shielded_outputs()
        assert parsed.shielded_outputs == outs
        assert parsed.hash == self.tx_template.hash

    def test_unshield_balance_header_round_trip(self) -> None:
        excess = bytes(range(32))
        header = UnshieldBalanceHeader(tx=self.tx_template, excess_blinding_factor=excess)  # type: ignore[arg-type]
        self.tx_template.headers.append(header)  # type: ignore[arg-type]

        parsed = self._round_trip(self.tx_template)
        assert parsed.has_unshield_balance_header()
        assert parsed.get_unshield_balance_header().excess_blinding_factor == excess
        assert parsed.hash == self.tx_template.hash

    def test_mint_header_round_trip(self) -> None:
        entries = [
            MintMeltEntry(token_index=1, amount=42),
            MintMeltEntry(token_index=2, amount=2 ** 32),
        ]
        header = MintHeader(tx=self.tx_template, entries=entries)  # type: ignore[arg-type]
        self.tx_template.headers.append(header)  # type: ignore[arg-type]

        parsed = self._round_trip(self.tx_template)
        parsed_mint = next(h for h in parsed.headers if isinstance(h, MintHeader))
        assert parsed_mint.entries == entries  # type: ignore[attr-defined]
        assert parsed.hash == self.tx_template.hash

    def test_melt_header_round_trip(self) -> None:
        entries = [MintMeltEntry(token_index=3, amount=99)]
        header = MeltHeader(tx=self.tx_template, entries=entries)  # type: ignore[arg-type]
        self.tx_template.headers.append(header)  # type: ignore[arg-type]

        parsed = self._round_trip(self.tx_template)
        parsed_melt = next(h for h in parsed.headers if isinstance(h, MeltHeader))
        assert parsed_melt.entries == entries  # type: ignore[attr-defined]
        assert parsed.hash == self.tx_template.hash
