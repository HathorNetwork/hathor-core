# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""On-wire encode/decode of output values and the token-amount version bit. Consensus-critical wire-format.

An output value is serialized in the enclosing vertex's token amount version: V1 is a fixed 4-or-8-byte
signed-integer field, V2 is a length-prefixed varint (a length byte followed by that many big-endian payload
bytes). The version is carried by the LSB of `signal_bits` and is committed in the sighash, so the two
encodings are not self-describing out of band; the parser assigns `signal_bits` before decoding the outputs
it governs. Nano action and fee-header amounts follow the same per-vertex version as the outputs.
"""

from __future__ import annotations

import re

import pytest
from htr_lib import UnsignedAmount

from hathor.transaction import Transaction
from hathor.transaction.base_transaction import TxOutput
from hathor.transaction.headers import FeeHeader, NanoHeader
from hathor.transaction.headers.fee_header import FeeHeaderEntry
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.nanocontracts.types import NCActionType
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.encoding.output_value import (
    decode_output_value_v1,
    decode_output_value_v2,
    encode_output_value_v1,
    encode_output_value_v2,
    get_max_output_value_v2,
)
from hathorlib.serialization.exceptions import BadDataError, OutOfDataError
from hathorlib.token_amount_version import TokenAmountVersion

# Fixed wire-format golden vectors for V1 output values, spanning the 4-byte/8-byte boundary. Computed once
# from the current encoder and hard-coded so any drift in the V1 encoding fails the backward-compat anchor.
# 2**31 - 1 is the largest value that still fits in 4 bytes; 2**31 is the first to spill into 8 bytes.
V1_GOLDEN: list[tuple[int, str]] = [
    (1, '00000001'),
    (100, '00000064'),
    (2 ** 31 - 1, '7fffffff'),
    (2 ** 31, 'ffffffff80000000'),
    (2 ** 63, '8000000000000000'),
]

# Fixed wire-format golden vectors for V2 output values, spanning the length-prefix from 1 to 15 payload bytes.
# Each entry is a length byte equal to the payload byte count, followed by the big-endian payload.
V2_GOLDEN: list[tuple[int, str]] = [
    (1, '0101'),
    (0xff, '01ff'),
    (0x100, '020100'),
    (0xff00, '02ff00'),
    (0xc0ffee, '03c0ffee'),
    (256 ** 14, '0f010000000000000000000000000000'),
    (2 ** 113, '0f020000000000000000000000000000'),
    (get_max_output_value_v2(), '0f11c37937e080000000000000000000'),
]


def _encode_v1(value: int) -> bytes:
    """Encode `value` as a standalone V1 output-value field."""
    serializer = Serializer.build_bytes_serializer()
    encode_output_value_v1(serializer, UnsignedAmount.from_v1(value))
    return bytes(serializer.finalize())


def _encode_v2(value: int) -> bytes:
    """Encode `value` as a standalone V2 length-prefixed output-value field."""
    serializer = Serializer.build_bytes_serializer()
    encode_output_value_v2(serializer, UnsignedAmount.from_v2(value))
    return bytes(serializer.finalize())


def _decode_v1(data: bytes) -> UnsignedAmount:
    """Decode `data` as a single V1 output value, consuming it exactly."""
    deserializer = Deserializer.build_bytes_deserializer(data)
    amount = decode_output_value_v1(deserializer)
    deserializer.finalize()
    return amount


def _decode_v2(data: bytes) -> UnsignedAmount:
    """Decode `data` as a single V2 output value, consuming it exactly."""
    deserializer = Deserializer.build_bytes_deserializer(data)
    amount = decode_output_value_v2(deserializer)
    deserializer.finalize()
    return amount


class TestSerializationV1V2(unittest.TestCase):
    """On-wire encode/decode of output values and the version bit. Consensus-critical wire-format coverage."""

    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    # -- helpers ------------------------------------------------------------------------------------------

    def _p2pkh_script(self) -> bytes:
        """Return a standard P2PKH output script, sourced from a propagated HTR transaction."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            b1.out[0] <<< tx
            tx.out[0] = 1.00 HTR

            b11 < tx
            tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        return artifacts.get_typed_vertex('tx', Transaction).outputs[0].script

    def _minimal_tx(self, outputs: list[TxOutput], *, signal_bits: int, tokens: list[bytes] | None = None
                    ) -> Transaction:
        """Build a hashed, input-less transaction carrying `outputs`, for direct serialization round-trips."""
        tx = Transaction(
            weight=1,
            timestamp=int(self.clock.seconds()),
            parents=[],
            inputs=[],
            outputs=outputs,
            tokens=tokens or [],
            storage=self.manager.tx_storage,
            signal_bits=signal_bits,
        )
        tx.update_hash()
        return tx

    def _build_v1_tx(self) -> Transaction:
        """Build and propagate a V1 HTR transaction with several outputs."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            b1.out[0] <<< tx
            tx.out[0] = 0.50 HTR
            tx.out[1] = 0.30 HTR
            tx.out[2] = 0.20 HTR

            b11 < tx
            tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        return artifacts.get_typed_vertex('tx', Transaction)

    def _build_v2_tx(self) -> Transaction:
        """Build and propagate a V2 HTR transaction."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            b1.out[0] <<< tx
            tx.out[0] = 1.00 HTR
            tx.token_amount_version = V2

            b11 < tx
            tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        return artifacts.get_typed_vertex('tx', Transaction)

    # -- byte-level output value encoding -----------------------------------------------------------------

    def test_v1_wire_format_unchanged(self) -> None:
        """Round-trip a set of V1 output values spanning the 4-byte/8-byte boundary and assert byte-for-byte
        equality against fixed golden vectors. The backward-compatibility anchor: any drift in V1 encoding breaks
        consensus."""
        for value, expected_hex in V1_GOLDEN:
            assert _encode_v1(value).hex() == expected_hex
            decoded = _decode_v1(bytes.fromhex(expected_hex))
            assert decoded.raw() == value
            assert decoded.is_v1()

    def test_v2_output_value_round_trips(self) -> None:
        """Round-trip V2 output values across length-prefix boundaries (1, 0xff, 0x100, ..., near
        `get_max_output_value_v2()`); assert decode returns an equal V2 amount and the length byte equals the
        payload byte count. Pins the length-prefixed varint layout."""
        for value, expected_hex in V2_GOLDEN:
            data = _encode_v2(value)
            assert data.hex() == expected_hex
            # the first byte is the length prefix; it must equal the number of payload bytes that follow.
            assert data[0] == len(data) - 1
            decoded = _decode_v2(data)
            assert decoded == UnsignedAmount.from_v2(value)
            assert decoded.raw() == value
            assert decoded.is_v2()

    def test_v2_decode_rejects_non_canonical_and_oversized(self) -> None:
        """Decoding a V2 payload with a leading zero byte raises `ValueError('non-canonical encoding ...')`; a length
        byte > 15 raises `ValueError('length is too big ...')`; an in-range length but over-max value raises
        `ValueError('value is too big ...')`. Pins the anti-malleability and bound guards."""
        # length 1, payload 0x00: the value 0 would also encode as the empty '00', so the leading zero is rejected.
        with pytest.raises(ValueError, match=re.escape('non-canonical encoding, leading zero byte: 00')):
            _decode_v2(bytes.fromhex('0100'))

        # a length prefix of 16 exceeds the 15-byte ceiling of the max V2 value.
        with pytest.raises(ValueError, match=re.escape('length is too big; max is 15, got: 16')):
            _decode_v2(bytes.fromhex('10'))

        # an in-range 15-byte length whose payload is one past the maximum value.
        max_value = get_max_output_value_v2()
        over = max_value + 1
        oversized = bytes([15]) + over.to_bytes(15, byteorder='big')
        with pytest.raises(ValueError, match=re.escape(f'value is too big; max is {max_value}, got: {over}')):
            _decode_v2(oversized)

    def test_v2_decode_truncated_raises_out_of_data(self) -> None:
        """Decoding a V2 output whose length byte over-promises the payload raises `OutOfDataError`, distinct from
        V1's `BadDataError`. Pins the truncation behavior and exact exception type."""
        # length byte promises 3 payload bytes but only 2 are present.
        with pytest.raises(OutOfDataError) as v2_exc:
            _decode_v2(bytes.fromhex('03ffff'))
        assert v2_exc.type is OutOfDataError

        # a V1 field promises 4 bytes but only 2 are present; V1 truncation surfaces as a different type.
        with pytest.raises(BadDataError) as v1_exc:
            _decode_v1(bytes.fromhex('0101'))
        assert v1_exc.type is BadDataError

        # the two truncation exceptions are unrelated types, so a handler cannot conflate the encodings.
        assert not issubclass(OutOfDataError, BadDataError)
        assert not issubclass(BadDataError, OutOfDataError)

    # -- full vertex round-trips --------------------------------------------------------------------------

    def test_full_v1_transaction_round_trip_byte_for_byte(self) -> None:
        """Build a V1 tx with several outputs, serialize, `create_from_struct`, and assert object equality,
        byte-identical re-serialization, and unchanged hash. The regression anchor that the parser refactor left V1
        vertices on the wire untouched."""
        tx = self._build_v1_tx()
        assert tx.get_token_amount_version() == TokenAmountVersion.V1
        assert len(tx.outputs) >= 3

        parsed = Transaction.create_from_struct(tx.get_struct())
        assert parsed == tx
        assert parsed.get_struct() == tx.get_struct()
        assert parsed.hash == tx.hash
        assert parsed.signal_bits == tx.signal_bits
        for output in parsed.outputs:
            assert output.value.is_v1()

    def test_full_v2_transaction_round_trip(self) -> None:
        """Build a V2 tx whose outputs are V2 amounts (small and near max), round-trip through `create_from_struct`,
        and assert equality, byte-identical re-serialization, `get_token_amount_version() == V2`, every output is
        V2, and `signal_bits` is preserved."""
        tx = self._build_v2_tx()
        script = tx.outputs[0].script
        tx.outputs = [
            TxOutput(UnsignedAmount.from_v2(1), script, 0),
            TxOutput(UnsignedAmount.from_v2(get_max_output_value_v2()), script, 0),
        ]
        tx.update_hash()

        parsed = Transaction.create_from_struct(tx.get_struct())
        assert parsed == tx
        assert parsed.get_struct() == tx.get_struct()
        assert parsed.get_token_amount_version() == TokenAmountVersion.V2
        assert parsed.signal_bits == tx.signal_bits
        assert parsed.outputs[0].value.raw() == 1
        assert parsed.outputs[1].value.raw() == get_max_output_value_v2()
        for output in parsed.outputs:
            assert output.value.is_v2()

    def test_full_v2_token_creation_transaction_round_trip(self) -> None:
        """Same for a `TokenCreationTransaction` with V2 outputs; additionally assert token name/symbol/version and
        the mint/melt authority outputs survive. Pins V2 encoding composes with the token-info trailer."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            tx_v2.out[0] = 100 TK2
            tx_v2.token_amount_version = V2
            TK2.token_amount_version = V2

            b11 < tx_v2
            tx_v2 <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        token_creation_tx = artifacts.get_typed_vertex('TK2', TokenCreationTransaction)
        assert token_creation_tx.get_token_amount_version() == TokenAmountVersion.V2

        parsed = TokenCreationTransaction.create_from_struct(token_creation_tx.get_struct())
        assert parsed == token_creation_tx
        assert parsed.get_struct() == token_creation_tx.get_struct()
        assert parsed.get_token_amount_version() == TokenAmountVersion.V2
        assert parsed.token_name == token_creation_tx.token_name
        assert parsed.token_symbol == token_creation_tx.token_symbol

        mint_outputs = [output for output in parsed.outputs if output.can_mint_token()]
        melt_outputs = [output for output in parsed.outputs if output.can_melt_token()]
        assert len(mint_outputs) == 1
        assert len(melt_outputs) == 1
        for output in parsed.outputs:
            if not output.is_token_authority():
                assert output.value.is_v2()

    def test_deserialize_sets_signal_bits_before_decoding_outputs(self) -> None:
        """Regression guard: round-trip a V2 tx whose first output requires V2 decoding and assert it parses (it
        would raise on a V1 mis-decode if the parser read outputs before assigning `signal_bits`). Names the
        invariant that the version field precedes the outputs it governs."""
        tx = self._build_v2_tx()
        script = tx.outputs[0].script
        # A single raw V2 unit has no V1 representation, so decoding this output under V1 would not reproduce it:
        # the round-trip only succeeds because `signal_bits` is assigned before the outputs are decoded.
        tx.outputs = [TxOutput(UnsignedAmount.from_v2(1), script, 0)]
        tx.update_hash()

        parsed = Transaction.create_from_struct(tx.get_struct())
        assert parsed == tx
        assert parsed.signal_bits == tx.signal_bits
        assert parsed.get_token_amount_version() == TokenAmountVersion.V2
        assert parsed.outputs[0].value.is_v2()
        assert parsed.outputs[0].value.raw() == 1

    def test_authority_output_round_trips_using_raw_under_v2(self) -> None:
        """Round-trip V2 authority outputs (mint/melt/both) and assert `can_mint_token()`/`can_melt_token()` are
        preserved because the bitmask is read via `.raw()` (not the normalized value). Pins authority semantics
        over the V2 wire."""
        script = self._p2pkh_script()
        authority_token_data = TxOutput.TOKEN_AUTHORITY_MASK | 1
        tx = self._minimal_tx(
            outputs=[
                TxOutput(UnsignedAmount.from_v2(TxOutput.TOKEN_MINT_MASK), script, authority_token_data),
                TxOutput(UnsignedAmount.from_v2(TxOutput.TOKEN_MELT_MASK), script, authority_token_data),
                TxOutput(UnsignedAmount.from_v2(TxOutput.ALL_AUTHORITIES), script, authority_token_data),
            ],
            signal_bits=0b1,
            tokens=[b'\x11' * 32],
        )

        parsed = Transaction.create_from_struct(tx.get_struct())
        assert parsed == tx
        assert parsed.get_struct() == tx.get_struct()
        assert parsed.get_token_amount_version() == TokenAmountVersion.V2

        mint_only, melt_only, both = parsed.outputs
        assert mint_only.can_mint_token() and not mint_only.can_melt_token()
        assert melt_only.can_melt_token() and not melt_only.can_mint_token()
        assert both.can_mint_token() and both.can_melt_token()
        assert both.value.raw() == TxOutput.ALL_AUTHORITIES

    def test_nano_and_fee_header_amounts_follow_tx_version(self) -> None:
        """Serialize/deserialize a tx carrying both a nano header (deposit/withdrawal actions) and a fee header,
        under V1 and under V2; assert all header amounts encode in the enclosing tx's version and round-trip. Pins
        header amount encoding parity with outputs."""
        script = self._p2pkh_script()
        deposit_raw = {TokenAmountVersion.V1: 5, TokenAmountVersion.V2: 5 * 10 ** 16}
        withdrawal_raw = {TokenAmountVersion.V1: 3, TokenAmountVersion.V2: 3 * 10 ** 16}
        fee_raw = {TokenAmountVersion.V1: 2, TokenAmountVersion.V2: 2 * 10 ** 16}

        for version, signal_bits in [(TokenAmountVersion.V1, 0b0), (TokenAmountVersion.V2, 0b1)]:
            deposit = UnsignedAmount.from_version(deposit_raw[version], version=int(version))
            withdrawal = UnsignedAmount.from_version(withdrawal_raw[version], version=int(version))
            fee = UnsignedAmount.from_version(fee_raw[version], version=int(version))

            tx = self._minimal_tx(outputs=[TxOutput(deposit, script, 0)], signal_bits=signal_bits)
            tx.headers = [
                NanoHeader(
                    tx=tx,
                    nc_seqnum=0,
                    nc_id=b'\x00' * 32,
                    nc_method='my_method',
                    nc_args_bytes=b'',
                    nc_actions=[
                        NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=0, amount=deposit),
                        NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=0, amount=withdrawal),
                    ],
                    nc_address=b'\x00' * 25,
                    nc_script=b'',
                ),
                FeeHeader(
                    settings=self.manager._settings,
                    tx=tx,
                    fees=[FeeHeaderEntry(token_index=0, amount=fee)],
                ),
            ]
            tx.update_hash()

            parsed = Transaction.create_from_struct(tx.get_struct())
            assert parsed == tx
            assert parsed.get_struct() == tx.get_struct()
            assert parsed.get_token_amount_version() == version

            nano_header = parsed.get_nano_header()
            deposit_action, withdrawal_action = nano_header.nc_actions
            assert deposit_action.amount == deposit
            assert deposit_action.amount.raw() == deposit_raw[version]
            assert withdrawal_action.amount.raw() == withdrawal_raw[version]
            fee_entry, = parsed.get_fee_header().fees
            assert fee_entry.amount.raw() == fee_raw[version]
            if version == TokenAmountVersion.V1:
                assert deposit_action.amount.is_v1()
                assert withdrawal_action.amount.is_v1()
                assert fee_entry.amount.is_v1()
            else:
                assert deposit_action.amount.is_v2()
                assert withdrawal_action.amount.is_v2()
                assert fee_entry.amount.is_v2()

    def test_version_bit_is_committed_in_sighash_and_hash(self) -> None:
        """Flip only the `signal_bits` LSB (and re-encode outputs into the matching variant) and assert both the
        sighash bytes and the vertex hash change. Pins that the token-amount version is committed data; outputs
        cannot be re-encoded under a different version without invalidating the signature/PoW."""
        tx = self._build_v1_tx()
        assert tx.get_token_amount_version() == TokenAmountVersion.V1
        original_sighash = tx.get_sighash_all()
        original_hash = tx.hash

        tx.signal_bits |= 0b1
        for output in tx.outputs:
            output.value = output.value.to_v2()
        tx.clear_sighash_cache()
        tx.update_hash()

        assert tx.get_token_amount_version() == TokenAmountVersion.V2
        assert tx.get_sighash_all() != original_sighash
        assert tx.hash != original_hash

    def test_v1_and_v2_bytes_are_not_self_describing(self) -> None:
        """Decode V1 bytes as V2 (and vice versa) and assert it either errors or misparses to a different value.
        Pins that the encodings are ambiguous out-of-band, justifying why the version MUST come from `signal_bits`."""
        # V1 bytes read under V2: the 4-byte field's leading 0x00 is read as a zero length prefix and rejected.
        v1_bytes = _encode_v1(100)
        assert v1_bytes.hex() == '00000064'
        with pytest.raises(ValueError, match=re.escape('value must not be zero')):
            _decode_v2(v1_bytes)

        # V2 bytes read under V1: `03c0ffee` is a length-prefixed 0xc0ffee, but V1 reads all four bytes as one
        # integer, silently yielding a different value.
        v2_bytes = _encode_v2(0xc0ffee)
        assert v2_bytes.hex() == '03c0ffee'
        misparsed = _decode_v1(v2_bytes)
        assert misparsed.raw() == 0x03c0ffee
        assert misparsed.raw() != 0xc0ffee
        assert misparsed.normalized() != UnsignedAmount.from_v2(0xc0ffee).normalized()

    def test_malformed_v2_output_propagates_at_vertex_level(self) -> None:
        """Hand-craft a V2 tx whose first output is non-canonical/truncated and assert `create_from_struct`
        propagates the `ValueError`/`OutOfDataError` (the V2 path is not wrapped as `InvalidOutputValue` the way V1
        struct failures are). Pins the end-to-end error behavior and the wrapping asymmetry."""
        script = self._p2pkh_script()

        # The funds prefix is signal_bits(1) + version(1) + tokens_len(1) + inputs_len(1) + outputs_len(1), so with
        # no tokens and no inputs the first output value begins at byte 5. A V2 `from_v2(1)` encodes as `01 01`.
        non_canonical_tx = self._minimal_tx(
            outputs=[TxOutput(UnsignedAmount.from_v2(1), script, 0)],
            signal_bits=0b1,
        )
        non_canonical = bytearray(non_canonical_tx.get_struct())
        assert non_canonical[5] == 0x01 and non_canonical[6] == 0x01
        non_canonical[6] = 0x00  # length 1 with a zero payload byte -> non-canonical
        with pytest.raises(ValueError, match=re.escape('non-canonical encoding, leading zero byte: 00')):
            Transaction.create_from_struct(bytes(non_canonical))

        # A V2 `from_v2(0xc0ffee)` encodes as `03 c0ffee`; cutting the struct right after the length byte leaves the
        # payload unreadable, and the truncation surfaces as OutOfDataError rather than an InvalidOutputValue.
        truncated_tx = self._minimal_tx(
            outputs=[TxOutput(UnsignedAmount.from_v2(0xc0ffee), script, 0)],
            signal_bits=0b1,
        )
        truncated = bytes(truncated_tx.get_struct())
        assert truncated[5] == 0x03
        with pytest.raises(OutOfDataError):
            Transaction.create_from_struct(truncated[:6])
