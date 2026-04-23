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

"""Tests for UnshieldBalanceHeader and the verifier integration for full-unshield txs."""

import os
from unittest.mock import MagicMock

import hathor_ct_crypto as lib
import pytest

from hathor.conf.settings import HathorSettings
from hathor.transaction.exceptions import InvalidShieldedOutputError, ShieldedBalanceMismatchError
from hathor.transaction.headers import UnshieldBalanceHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.headers.unshield_balance_header import EXCESS_BLINDING_FACTOR_SIZE
from hathor.verification.transaction_verifier import TransactionVerifier
from hathor.verification.vertex_verifier import VertexVerifier


def _make_settings() -> HathorSettings:
    settings = MagicMock(spec=HathorSettings)
    settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT = 1
    settings.FEE_PER_FULL_SHIELDED_OUTPUT = 2
    return settings


def _make_verifier() -> TransactionVerifier:
    return TransactionVerifier(settings=_make_settings(), daa=MagicMock(), feature_service=MagicMock())


class TestUnshieldBalanceHeaderUnit:
    """Header class: construction, size validation, ser/deser, sighash."""

    def _fake_tx(self) -> MagicMock:
        from hathor.transaction.transaction import Transaction
        return MagicMock(spec=Transaction)

    def test_construction_rejects_wrong_size(self) -> None:
        tx = self._fake_tx()
        with pytest.raises(InvalidShieldedOutputError, match='must be 32 bytes'):
            UnshieldBalanceHeader(tx=tx, excess_blinding_factor=b'\x01' * 16)
        with pytest.raises(InvalidShieldedOutputError, match='must be 32 bytes'):
            UnshieldBalanceHeader(tx=tx, excess_blinding_factor=b'\x01' * 33)

    def test_construction_accepts_32_bytes(self) -> None:
        tx = self._fake_tx()
        scalar = os.urandom(EXCESS_BLINDING_FACTOR_SIZE)
        header = UnshieldBalanceHeader(tx=tx, excess_blinding_factor=scalar)
        assert header.excess_blinding_factor == scalar

    def test_header_id_byte(self) -> None:
        assert UnshieldBalanceHeader.get_header_id() == b'\x13'
        assert VertexHeaderId.UNSHIELD_BALANCE_HEADER.value == b'\x13'

    def test_serialization_round_trip(self) -> None:
        tx = self._fake_tx()
        scalar = os.urandom(EXCESS_BLINDING_FACTOR_SIZE)
        header = UnshieldBalanceHeader(tx=tx, excess_blinding_factor=scalar)
        raw = header.serialize()
        assert len(raw) == 1 + EXCESS_BLINDING_FACTOR_SIZE
        assert raw[0:1] == VertexHeaderId.UNSHIELD_BALANCE_HEADER.value
        assert raw[1:] == scalar

        rehydrated, leftover = UnshieldBalanceHeader.deserialize(tx, raw)
        assert leftover == b''
        assert rehydrated.excess_blinding_factor == scalar

    def test_deserialize_returns_leftover(self) -> None:
        """Extra bytes after the header should be returned as leftover."""
        tx = self._fake_tx()
        scalar = os.urandom(EXCESS_BLINDING_FACTOR_SIZE)
        raw = VertexHeaderId.UNSHIELD_BALANCE_HEADER.value + scalar + b'TRAILING'
        header, leftover = UnshieldBalanceHeader.deserialize(tx, raw)
        assert header.excess_blinding_factor == scalar
        assert leftover == b'TRAILING'

    def test_deserialize_rejects_short_buffer(self) -> None:
        tx = self._fake_tx()
        short = VertexHeaderId.UNSHIELD_BALANCE_HEADER.value + b'\x00' * 16
        with pytest.raises(InvalidShieldedOutputError, match='requires 33 bytes'):
            UnshieldBalanceHeader.deserialize(tx, short)

    def test_deserialize_rejects_wrong_header_id(self) -> None:
        tx = self._fake_tx()
        # ShieldedOutputsHeader id followed by 32 bytes
        raw = VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value + os.urandom(EXCESS_BLINDING_FACTOR_SIZE)
        with pytest.raises(InvalidShieldedOutputError, match='unexpected header id'):
            UnshieldBalanceHeader.deserialize(tx, raw)

    def test_sighash_binds_scalar(self) -> None:
        """Mutating the scalar must change the sighash bytes — signatures must
        reject the mutated tx."""
        tx = self._fake_tx()
        scalar = os.urandom(EXCESS_BLINDING_FACTOR_SIZE)
        header = UnshieldBalanceHeader(tx=tx, excess_blinding_factor=scalar)
        original_sighash = header.get_sighash_bytes()

        mutated = bytearray(scalar)
        mutated[0] ^= 0xFF
        header_mut = UnshieldBalanceHeader(tx=tx, excess_blinding_factor=bytes(mutated))
        assert header_mut.get_sighash_bytes() != original_sighash


class TestVertexVerifierAllowedHeaders:
    """`verify_headers` must accept an UnshieldBalanceHeader on REGULAR_TRANSACTION
    when the shielded_transactions feature is active, and reject it otherwise.

    Regression for a bug where `get_allowed_headers` whitelisted only
    `ShieldedOutputsHeader` under `params.features.shielded_transactions`,
    so a real full-unshield tx would be rejected by the verifier even though
    the parser, DAG builder, and balance checker all accepted it.
    """

    def _make_vertex_verifier(self) -> VertexVerifier:
        return VertexVerifier(settings=_make_settings(), reactor=MagicMock(), feature_service=MagicMock())

    def _make_tx_with_unshield_header(self) -> MagicMock:
        from hathor.transaction import TxVersion
        tx = MagicMock()
        tx.version = TxVersion.REGULAR_TRANSACTION
        tx.get_maximum_number_of_headers = MagicMock(return_value=8)
        tx.headers = [UnshieldBalanceHeader(tx=tx, excess_blinding_factor=os.urandom(32))]
        return tx

    def _make_params(self, *, shielded: bool) -> MagicMock:
        features = MagicMock()
        features.nanocontracts = False
        features.fee_tokens = False
        features.shielded_transactions = shielded
        params = MagicMock()
        params.features = features
        return params

    def test_unshield_header_allowed_when_feature_active(self) -> None:
        verifier = self._make_vertex_verifier()
        tx = self._make_tx_with_unshield_header()
        params = self._make_params(shielded=True)

        allowed = verifier.get_allowed_headers(tx, params)
        assert UnshieldBalanceHeader in allowed
        # Must not raise — a real full-unshield tx would carry exactly this header.
        verifier.verify_headers(tx, params)

    def test_unshield_header_rejected_when_feature_disabled(self) -> None:
        from hathor.transaction.exceptions import HeaderNotSupported
        verifier = self._make_vertex_verifier()
        tx = self._make_tx_with_unshield_header()
        params = self._make_params(shielded=False)

        with pytest.raises(HeaderNotSupported, match='UnshieldBalanceHeader'):
            verifier.verify_headers(tx, params)


class TestVerifyShieldedBalanceUnshield:
    """Integration: verify_shielded_balance with the new header wired in.

    Builds real shielded input commitments and drives the verifier through a
    MagicMock tx that exposes `excess_blinding_factor` (the property pattern
    that real Transaction instances expose via the UnshieldBalanceHeader).
    """

    def _build_tx_and_excess(
        self,
        amount: int,
        token_uid: bytes = bytes(32),
        fee_amount: int = 0,
    ) -> tuple[MagicMock, bytes]:
        """Build a MagicMock unshielding tx (shielded in -> transparent out) and
        return it alongside the correct excess blinding factor."""
        from hathor.transaction.headers.fee_header import FeeEntry

        gen = lib.htr_asset_tag() if token_uid == bytes(32) else lib.derive_asset_tag(token_uid)
        vbf = os.urandom(32)
        commitment = lib.create_commitment(amount, vbf, gen)

        spent_tx = MagicMock()
        spent_tx.outputs = []
        shielded_out = MagicMock()
        shielded_out.commitment = commitment
        spent_tx.shielded_outputs = [shielded_out]
        spent_tx.get_token_uid = MagicMock(return_value=token_uid)

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 0  # references the shielded output at index 0

        transparent_out_value = amount - fee_amount
        tx_output = MagicMock()
        tx_output.value = transparent_out_value
        tx_output.get_token_index = MagicMock(return_value=0)
        tx_output.is_token_authority = MagicMock(return_value=False)

        # Compute the correct excess = sum(r_in) − sum(r_out). All outputs are
        # transparent (vbf = 0), so excess == vbf.
        other_outputs: list[tuple[int, bytes, bytes]] = [(transparent_out_value, bytes(32), bytes(32))]
        if fee_amount > 0:
            other_outputs.append((fee_amount, bytes(32), bytes(32)))
        excess = lib.compute_balancing_blinding_factor(
            0,
            bytes(32),
            [(amount, vbf, bytes(32))],
            other_outputs,
        )

        tx = MagicMock()
        tx.inputs = [tx_input]
        tx.outputs = [tx_output]
        tx.shielded_outputs = []
        tx.has_shielded_outputs = MagicMock(return_value=False)
        tx.get_token_uid = MagicMock(return_value=token_uid)
        tx.excess_blinding_factor = excess
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        if fee_amount > 0:
            fee_header = MagicMock()
            fee_header.get_fees = MagicMock(return_value=[
                FeeEntry(token_uid=token_uid, amount=fee_amount),
            ])
            tx.has_fees = MagicMock(return_value=True)
            tx.get_fee_header = MagicMock(return_value=fee_header)
        else:
            tx.has_fees = MagicMock(return_value=False)

        return tx, excess

    def test_full_unshield_passes_with_correct_excess(self) -> None:
        """Shielded 1000 HTR in -> transparent 1000 HTR out: passes with excess."""
        verifier = _make_verifier()
        tx, _ = self._build_tx_and_excess(amount=1000)
        verifier.verify_shielded_balance(tx)

    def test_full_unshield_with_fee_passes(self) -> None:
        """Shielded 1000 HTR in -> transparent 900 HTR out + 100 HTR fee."""
        verifier = _make_verifier()
        tx, _ = self._build_tx_and_excess(amount=1000, fee_amount=100)
        verifier.verify_shielded_balance(tx)

    def test_full_unshield_without_header_rejected(self) -> None:
        """Removing the excess (setting to None) must cause the invariant to reject."""
        verifier = _make_verifier()
        tx, _ = self._build_tx_and_excess(amount=1000)
        tx.excess_blinding_factor = None
        with pytest.raises(ShieldedBalanceMismatchError, match='must carry an unshield balance header'):
            verifier.verify_shielded_balance(tx)

    def test_full_unshield_with_wrong_excess_rejected(self) -> None:
        """A mismatched excess must fail the cryptographic balance check."""
        verifier = _make_verifier()
        tx, _ = self._build_tx_and_excess(amount=1000)
        tx.excess_blinding_factor = os.urandom(32)
        with pytest.raises(ShieldedBalanceMismatchError, match='shielded balance equation does not hold'):
            verifier.verify_shielded_balance(tx)

    def test_excess_with_shielded_outputs_rejected(self) -> None:
        """Mutual-exclusion: excess + shielded outputs is rejected."""
        verifier = _make_verifier()
        tx, _ = self._build_tx_and_excess(amount=1000)
        # Attach a bogus shielded output while keeping the excess.
        shielded_out = MagicMock()
        shielded_out.commitment = b'\x02' + bytes(32)
        tx.shielded_outputs = [shielded_out]
        tx.has_shielded_outputs = MagicMock(return_value=True)
        with pytest.raises(ShieldedBalanceMismatchError, match='cannot carry both'):
            verifier.verify_shielded_balance(tx)

    def test_excess_without_shielded_inputs_rejected(self) -> None:
        """Excess with no shielded inputs is meaningless and rejected."""
        verifier = _make_verifier()
        token_uid = bytes(32)

        spent_tx = MagicMock()
        spent_output = MagicMock()
        spent_output.value = 1000
        spent_output.get_token_index = MagicMock(return_value=0)
        spent_output.is_token_authority = MagicMock(return_value=False)
        spent_tx.outputs = [spent_output]
        spent_tx.shielded_outputs = []
        spent_tx.get_token_uid = MagicMock(return_value=token_uid)

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 0

        tx_output = MagicMock()
        tx_output.value = 1000
        tx_output.get_token_index = MagicMock(return_value=0)
        tx_output.is_token_authority = MagicMock(return_value=False)

        tx = MagicMock()
        tx.inputs = [tx_input]
        tx.outputs = [tx_output]
        tx.shielded_outputs = []
        tx.has_shielded_outputs = MagicMock(return_value=False)
        tx.get_token_uid = MagicMock(return_value=token_uid)
        tx.has_fees = MagicMock(return_value=False)
        tx.excess_blinding_factor = os.urandom(32)  # stray excess, no shielded input
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        with pytest.raises(ShieldedBalanceMismatchError, match='requires at least one shielded input'):
            verifier.verify_shielded_balance(tx)

    def test_multi_token_full_unshield_passes(self) -> None:
        """Shielded HTR + shielded custom-token -> transparent both, with excess."""
        verifier = _make_verifier()
        htr = bytes(32)
        custom = b'\x07' * 32

        gen_htr = lib.htr_asset_tag()
        gen_custom = lib.derive_asset_tag(custom)
        vbf_htr = os.urandom(32)
        vbf_custom = os.urandom(32)
        c_htr = lib.create_commitment(500, vbf_htr, gen_htr)
        c_custom = lib.create_commitment(300, vbf_custom, gen_custom)

        # spent tx for HTR input (index 0)
        spent_htr = MagicMock()
        spent_htr.outputs = []
        htr_shielded = MagicMock()
        htr_shielded.commitment = c_htr
        spent_htr.shielded_outputs = [htr_shielded]
        spent_htr.get_token_uid = MagicMock(return_value=htr)

        spent_custom = MagicMock()
        spent_custom.outputs = []
        custom_shielded = MagicMock()
        custom_shielded.commitment = c_custom
        spent_custom.shielded_outputs = [custom_shielded]
        spent_custom.get_token_uid = MagicMock(return_value=custom)

        input_htr = MagicMock()
        input_htr.tx_id = b'\x01' * 32
        input_htr.index = 0
        input_custom = MagicMock()
        input_custom.tx_id = b'\x02' * 32
        input_custom.index = 0

        out_htr = MagicMock()
        out_htr.value = 500
        out_htr.get_token_index = MagicMock(return_value=0)
        out_htr.is_token_authority = MagicMock(return_value=False)
        out_custom = MagicMock()
        out_custom.value = 300
        out_custom.get_token_index = MagicMock(return_value=1)
        out_custom.is_token_authority = MagicMock(return_value=False)

        excess = lib.compute_balancing_blinding_factor(
            0,
            bytes(32),
            [(500, vbf_htr, bytes(32)), (300, vbf_custom, bytes(32))],
            [(500, bytes(32), bytes(32)), (300, bytes(32), bytes(32))],
        )

        def get_token_uid(idx: int) -> bytes:
            return htr if idx == 0 else custom

        def get_spent(tx_id: bytes) -> MagicMock:
            return spent_htr if tx_id == b'\x01' * 32 else spent_custom

        tx = MagicMock()
        tx.inputs = [input_htr, input_custom]
        tx.outputs = [out_htr, out_custom]
        tx.shielded_outputs = []
        tx.has_shielded_outputs = MagicMock(return_value=False)
        tx.get_token_uid = MagicMock(side_effect=get_token_uid)
        tx.excess_blinding_factor = excess
        tx.has_fees = MagicMock(return_value=False)
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(side_effect=get_spent)

        verifier.verify_shielded_balance(tx)
