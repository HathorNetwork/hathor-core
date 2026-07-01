from typing import Any

from hathor.serialization import Deserializer, Serializer
from hathor.transaction import Transaction
from hathor.transaction.headers.fee_header import FeeEntry, FeeHeader, FeeHeaderEntry
from hathor.transaction.util import VerboseCallback
from hathor.transaction.vertex_parser._fee_header import deserialize_fee_header, serialize_fee_header
from hathor.transaction.vertex_parser._headers import get_header_sighash_bytes
from hathor.types import TokenUid
from hathor_tests import unittest
from hathor_tests.token_amount import UnsignedAmount


def _serialize_fee_header(header: FeeHeader) -> bytes:
    serializer = Serializer.build_bytes_serializer()
    serialize_fee_header(serializer, header, token_amount_version=header.tx.get_token_amount_version())
    return bytes(serializer.finalize())


def _deserialize_fee_header(
    tx: Transaction,
    buf: bytes,
    *,
    verbose: VerboseCallback = None,
) -> tuple[FeeHeader, bytes]:
    deserializer = Deserializer.build_bytes_deserializer(buf)
    fees = deserialize_fee_header(deserializer, token_amount_version=tx.get_token_amount_version(), verbose=verbose)
    header = FeeHeader(settings=tx._settings, tx=tx, fees=fees)
    return header, bytes(deserializer.read_all())


class FeeHeaderTest(unittest.TestCase):

    def test_fee_header_round_trip(self) -> None:
        """Test FeeHeader serialization and deserialization round-trip."""
        tx = Transaction()
        tx.tokens = [TokenUid(b'test' * 8)]  # Add a custom token at index 1

        # Basic round trip serialization test
        header_round_trip = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[
                FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v1(100)),  # HTR paying
                FeeHeaderEntry(token_index=1, amount=UnsignedAmount.from_v1(200)),  # Custom token paying
            ],
        )
        serialized = _serialize_fee_header(header_round_trip)
        deserialized, remaining = _deserialize_fee_header(tx, serialized)
        assert len(remaining) == 0
        assert deserialized.fees == header_round_trip.fees

        # Verbose callback functionality test
        verbose_calls: list[tuple[str, Any]] = []

        def verbose_callback(name: str, value: Any) -> None:
            verbose_calls.append((name, value))

        header_verbose = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v1(300))],  # HTR paying
        )
        serialized_verbose = _serialize_fee_header(header_verbose)
        deserialized_verbose, remaining = _deserialize_fee_header(tx, serialized_verbose, verbose=verbose_callback)

        # Check that verbose callback was called for all expected values
        assert len(verbose_calls) == 2  # header_id, fees_len
        call_names = [call[0] for call in verbose_calls]
        assert 'header_id' in call_names
        assert 'fees_len' in call_names

        assert len(remaining) == 0
        assert deserialized_verbose.fees == header_verbose.fees

        # get_sighash_bytes functionality test
        header_sighash = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v1(500))],  # HTR paying
        )
        sighash_bytes = get_header_sighash_bytes(header_sighash, token_amount_version=tx.get_token_amount_version())
        serialized_bytes = _serialize_fee_header(header_sighash)

        # The fee header sighash bytes are identical to its full serialization.
        assert sighash_bytes == serialized_bytes

    def test_fee_header_get_fees(self) -> None:
        """Test FeeHeader.get_fees() method that converts to FeeEntry objects."""
        tx = Transaction()
        token1_uid = TokenUid(b'token1' + b'\x00' * 26)
        tx.tokens = [token1_uid]

        # Test with HTR and custom token paying fees
        header = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[
                FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v1(100)),  # HTR
                FeeHeaderEntry(token_index=1, amount=UnsignedAmount.from_v1(200)),  # token1 (must be multiple of 100)
            ],
        )
        fees = header.get_fees()

        assert len(fees) == 2
        assert fees[0] == FeeEntry(token_uid=tx.get_token_uid(0), amount=UnsignedAmount.from_v1(100))  # HTR
        assert fees[1] == FeeEntry(token_uid=token1_uid, amount=UnsignedAmount.from_v1(200))  # token1

        # Test with single fee
        header_single = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v1(300))],  # HTR only
        )
        fees_single = header_single.get_fees()
        assert len(fees_single) == 1
        assert fees_single[0] == FeeEntry(token_uid=tx.get_token_uid(0), amount=UnsignedAmount.from_v1(300))

    def test_fee_header_edge_cases(self) -> None:
        """Test FeeHeader edge cases and comprehensive scenarios."""
        tx = Transaction()

        # Test with many tokens
        many_tokens = [TokenUid(f'token{i}'.encode() + b'\x00' * (32 - len(f'token{i}'))) for i in range(5)]
        tx.tokens = many_tokens

        # Test complex scenario with multiple fees
        header_complex = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[
                FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v1(100)),  # HTR
                FeeHeaderEntry(token_index=2, amount=UnsignedAmount.from_v1(50)),  # token2
                FeeHeaderEntry(token_index=4, amount=UnsignedAmount.from_v1(25)),  # token4
            ],
        )
        serialized_complex = _serialize_fee_header(header_complex)
        deserialized_complex, remaining = _deserialize_fee_header(tx, serialized_complex)

        assert len(remaining) == 0
        assert len(deserialized_complex.fees) == 3
        assert deserialized_complex.fees[0].token_index == 0
        assert deserialized_complex.fees[0].amount == UnsignedAmount.from_v1(100)
        assert deserialized_complex.fees[1].token_index == 2
        assert deserialized_complex.fees[1].amount == UnsignedAmount.from_v1(50)
        assert deserialized_complex.fees[2].token_index == 4
        assert deserialized_complex.fees[2].amount == UnsignedAmount.from_v1(25)

        # Test max values
        header_max = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v1(2 ** 63 - 1))],  # Max amount
        )
        serialized_max = _serialize_fee_header(header_max)
        deserialized_max, remaining = _deserialize_fee_header(tx, serialized_max)
        assert len(remaining) == 0
        assert deserialized_max.fees[0].amount == UnsignedAmount.from_v1(2 ** 63 - 1)

        # Test single fee
        header_single = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[FeeHeaderEntry(token_index=1, amount=UnsignedAmount.from_v1(42))],  # Single custom token fee
        )
        serialized_single = _serialize_fee_header(header_single)
        deserialized_single, remaining = _deserialize_fee_header(tx, serialized_single)
        assert len(remaining) == 0
        assert len(deserialized_single.fees) == 1
        assert deserialized_single.fees[0].token_index == 1
        assert deserialized_single.fees[0].amount == UnsignedAmount.from_v1(42)

    def test_to_json_includes_fees(self) -> None:
        """Test that Transaction.to_json() includes fee header data when present."""
        tx = Transaction()
        token1_uid = TokenUid(b'token1' + b'\x00' * 26)
        tx.tokens = [token1_uid]

        fee_header = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[
                FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v1(100)),
                FeeHeaderEntry(token_index=1, amount=UnsignedAmount.from_v1(200)),
            ],
        )
        tx.headers = [fee_header]

        json = tx.to_json()

        assert 'fees' in json
        assert len(json['fees']) == 2
        assert json['fees'][0] == {
            'token_uid': tx.get_token_uid(0).hex(),
            'amount': 100,
            'amount_str': '1.0',
        }
        assert json['fees'][1] == {
            'token_uid': token1_uid.hex(),
            'amount': 200,
            'amount_str': '2.0',
        }

    def test_to_json_without_fees(self) -> None:
        """Test that Transaction.to_json() does not include fees key when no fee header."""
        tx = Transaction()
        json = tx.to_json()
        assert 'fees' not in json

    def test_to_json_single_htr_fee(self) -> None:
        """Test to_json with a single HTR fee entry."""
        tx = Transaction()

        fee_header = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v1(50))],
        )
        tx.headers = [fee_header]

        json = tx.to_json()

        assert len(json['fees']) == 1
        assert json['fees'][0]['token_uid'] == self._settings.HATHOR_TOKEN_UID.hex()
        assert json['fees'][0]['amount'] == 50
