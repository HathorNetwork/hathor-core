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

"""Round-trip + wire-format tests for the four new headers introduced for
shielded transactions: ShieldedOutputsHeader (0x12), UnshieldBalanceHeader
(0x13), MintHeader (0x14), MeltHeader (0x15)."""

import unittest

from hathorlib.headers import (
    MAX_MINT_MELT_ENTRIES,
    MeltHeader,
    MintHeader,
    MintMeltEntry,
    ShieldedOutputsHeader,
    UnshieldBalanceHeader,
    VertexHeaderId,
)
from hathorlib.serialization import OutOfDataError
from hathorlib.transaction import Transaction
from hathorlib.transaction.shielded_tx_output import (
    ASSET_COMMITMENT_SIZE,
    COMMITMENT_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
    AmountShieldedOutput,
    FullShieldedOutput,
)


def _amount_output(token_data: int = 1, ephemeral: bytes | None = None) -> AmountShieldedOutput:
    return AmountShieldedOutput(
        commitment=b'\x09' + b'\x01' * (COMMITMENT_SIZE - 1),
        range_proof=b'\xab' * 64,
        script=b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac',
        token_data=token_data,
        ephemeral_pubkey=ephemeral if ephemeral is not None else b'\x02' + b'\x03' * (EPHEMERAL_PUBKEY_SIZE - 1),
    )


def _full_output() -> FullShieldedOutput:
    return FullShieldedOutput(
        commitment=b'\x09' + b'\x02' * (COMMITMENT_SIZE - 1),
        range_proof=b'\xcd' * 96,
        script=b'\x76\xa9\x14' + b'\x11' * 20 + b'\x88\xac',
        asset_commitment=b'\x0a' + b'\x04' * (ASSET_COMMITMENT_SIZE - 1),
        surjection_proof=b'\xee' * 32,
        ephemeral_pubkey=b'\x02' + b'\x05' * (EPHEMERAL_PUBKEY_SIZE - 1),
    )


class UnshieldBalanceHeaderTest(unittest.TestCase):
    def test_round_trip(self):
        tx = Transaction()
        excess = bytes(range(32))
        header = UnshieldBalanceHeader(tx=tx, excess_blinding_factor=excess)

        # Wire format: header_id(1) | excess_blinding_factor(32)
        wire = header.serialize()
        self.assertEqual(len(wire), 33)
        self.assertEqual(wire[:1], VertexHeaderId.UNSHIELD_BALANCE_HEADER.value)
        self.assertEqual(wire[:1], b'\x13')
        self.assertEqual(wire[1:], excess)

        parsed, leftover = UnshieldBalanceHeader.deserialize(tx, wire)
        self.assertEqual(leftover, b'')
        self.assertEqual(parsed.excess_blinding_factor, excess)

        # sighash bytes equal the full wire form (signature-bound).
        self.assertEqual(header.get_sighash_bytes(), wire)

    def test_trailing_bytes_returned_as_leftover(self):
        tx = Transaction()
        excess = bytes(range(32))
        wire = UnshieldBalanceHeader(tx=tx, excess_blinding_factor=excess).serialize()
        trailing = b'\xde\xad\xbe\xef'

        parsed, leftover = UnshieldBalanceHeader.deserialize(tx, wire + trailing)
        self.assertEqual(leftover, trailing)
        self.assertEqual(parsed.excess_blinding_factor, excess)

    def test_invalid_scalar_length_rejected(self):
        tx = Transaction()
        with self.assertRaises(ValueError):
            UnshieldBalanceHeader(tx=tx, excess_blinding_factor=b'\x00' * 31)

    def test_truncated_buffer_rejected(self):
        tx = Transaction()
        wire = UnshieldBalanceHeader(tx=tx, excess_blinding_factor=b'\x00' * 32).serialize()
        with self.assertRaises(OutOfDataError):
            UnshieldBalanceHeader.deserialize(tx, wire[:20])

    def test_wrong_header_id_rejected(self):
        tx = Transaction()
        with self.assertRaises(ValueError):
            UnshieldBalanceHeader.deserialize(tx, b'\x99' + b'\x00' * 32)


class ShieldedOutputsHeaderTest(unittest.TestCase):
    def test_round_trip_amount_only(self):
        tx = Transaction()
        out1 = _amount_output(token_data=1)
        out2 = _amount_output(token_data=2)
        header = ShieldedOutputsHeader(tx=tx, shielded_outputs=[out1, out2])

        wire = header.serialize()
        # header_id(1) | num_outputs(1) | ...
        self.assertEqual(wire[:1], VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value)
        self.assertEqual(wire[:1], b'\x12')
        self.assertEqual(wire[1], 2)

        parsed, leftover = ShieldedOutputsHeader.deserialize(tx, wire)
        self.assertEqual(leftover, b'')
        self.assertEqual(len(parsed.shielded_outputs), 2)
        self.assertEqual(parsed.shielded_outputs, [out1, out2])

    def test_round_trip_full(self):
        tx = Transaction()
        full = _full_output()
        header = ShieldedOutputsHeader(tx=tx, shielded_outputs=[full])

        wire = header.serialize()
        parsed, leftover = ShieldedOutputsHeader.deserialize(tx, wire)
        self.assertEqual(leftover, b'')
        self.assertEqual(parsed.shielded_outputs, [full])

    def test_mixed_outputs_round_trip(self):
        tx = Transaction()
        outs = [_amount_output(token_data=1), _full_output(), _amount_output(token_data=2)]
        header = ShieldedOutputsHeader(tx=tx, shielded_outputs=outs)

        parsed, leftover = ShieldedOutputsHeader.deserialize(tx, header.serialize())
        self.assertEqual(leftover, b'')
        self.assertEqual(parsed.shielded_outputs, outs)

    def test_zero_outputs_rejected(self):
        tx = Transaction()
        empty = ShieldedOutputsHeader(tx=tx, shielded_outputs=[])
        wire = empty.serialize()
        # Wire is well-formed (header_id + count=0) but deserialize rejects count<1.
        with self.assertRaises(ValueError):
            ShieldedOutputsHeader.deserialize(tx, wire)

    def test_trailing_bytes_returned_as_leftover(self):
        tx = Transaction()
        wire = ShieldedOutputsHeader(tx=tx, shielded_outputs=[_amount_output()]).serialize()
        trailing = b'\xde\xad\xbe\xef'
        parsed, leftover = ShieldedOutputsHeader.deserialize(tx, wire + trailing)
        self.assertEqual(leftover, trailing)
        self.assertEqual(len(parsed.shielded_outputs), 1)

    def test_wrong_header_id_rejected(self):
        tx = Transaction()
        wire = ShieldedOutputsHeader(tx=tx, shielded_outputs=[_amount_output()]).serialize()
        bad = b'\x99' + wire[1:]
        with self.assertRaises(ValueError):
            ShieldedOutputsHeader.deserialize(tx, bad)


class MintMeltHeaderTest(unittest.TestCase):
    """MintHeader and MeltHeader share the same wire-format implementation, so
    one test class covers both via parametrization."""

    def _headers(self):
        return [
            (MintHeader, VertexHeaderId.MINT_HEADER.value, b'\x14'),
            (MeltHeader, VertexHeaderId.MELT_HEADER.value, b'\x15'),
        ]

    def test_round_trip_single_entry(self):
        tx = Transaction()
        for cls, _id_value, raw_id in self._headers():
            with self.subTest(header=cls.__name__):
                entries = [MintMeltEntry(token_index=1, amount=42)]
                header = cls(tx=tx, entries=entries)

                wire = header.serialize()
                # header_id(1) | num_entries(1) | (token_index(1) | amount(8))
                self.assertEqual(wire[:1], raw_id)
                self.assertEqual(len(wire), 1 + 1 + 9)
                self.assertEqual(wire[1], 1)

                parsed, leftover = cls.deserialize(tx, wire)
                self.assertEqual(leftover, b'')
                self.assertEqual(parsed.entries, entries)
                # sighash bytes equal the full wire form.
                self.assertEqual(header.get_sighash_bytes(), wire)

    def test_round_trip_multiple_entries(self):
        tx = Transaction()
        for cls, _id_value, _raw_id in self._headers():
            with self.subTest(header=cls.__name__):
                entries = [
                    MintMeltEntry(token_index=1, amount=100),
                    MintMeltEntry(token_index=3, amount=2 ** 32),
                    MintMeltEntry(token_index=16, amount=2 ** 63),
                ]
                wire = cls(tx=tx, entries=entries).serialize()
                parsed, leftover = cls.deserialize(tx, wire)
                self.assertEqual(leftover, b'')
                self.assertEqual(parsed.entries, entries)

    def test_trailing_bytes_returned_as_leftover(self):
        tx = Transaction()
        for cls, _id_value, _raw_id in self._headers():
            with self.subTest(header=cls.__name__):
                wire = cls(tx=tx, entries=[MintMeltEntry(token_index=1, amount=1)]).serialize()
                trailing = b'\xde\xad\xbe\xef'
                _parsed, leftover = cls.deserialize(tx, wire + trailing)
                self.assertEqual(leftover, trailing)

    def test_zero_amount_rejected(self):
        with self.assertRaises(ValueError):
            MintMeltEntry(token_index=1, amount=0)

    def test_token_index_zero_rejected(self):
        # HTR (token_index=0) is forbidden in mint/melt headers.
        with self.assertRaises(ValueError):
            MintMeltEntry(token_index=0, amount=1)

    def test_token_index_above_max_rejected(self):
        with self.assertRaises(ValueError):
            MintMeltEntry(token_index=MAX_MINT_MELT_ENTRIES + 1, amount=1)

    def test_duplicate_token_index_rejected_at_deserialize(self):
        tx = Transaction()
        for cls, _id_value, raw_id in self._headers():
            with self.subTest(header=cls.__name__):
                # Construct a wire payload that bypasses the entry constructor's
                # uniqueness check: two entries with the same token_index.
                import struct
                payload = (
                    raw_id
                    + bytes([2])  # num_entries
                    + bytes([5]) + struct.pack('!Q', 10)
                    + bytes([5]) + struct.pack('!Q', 20)
                )
                with self.assertRaises(ValueError):
                    cls.deserialize(tx, payload)

    def test_too_many_entries_rejected(self):
        tx = Transaction()
        for cls, _id_value, raw_id in self._headers():
            with self.subTest(header=cls.__name__):
                import struct
                # 17 entries with distinct indexes — exceeds MAX_MINT_MELT_ENTRIES (16).
                payload = raw_id + bytes([MAX_MINT_MELT_ENTRIES + 1])
                # Provide enough data so the failure comes from the count check, not truncation.
                for i in range(MAX_MINT_MELT_ENTRIES + 1):
                    payload += bytes([i + 1]) + struct.pack('!Q', 1)
                with self.assertRaises(ValueError):
                    cls.deserialize(tx, payload)

    def test_wrong_header_id_rejected(self):
        tx = Transaction()
        for cls, _id_value, _raw_id in self._headers():
            with self.subTest(header=cls.__name__):
                with self.assertRaises(ValueError):
                    cls.deserialize(tx, b'\x99' + bytes([1]) + bytes([1]) + b'\x00' * 8)


if __name__ == '__main__':
    unittest.main()
