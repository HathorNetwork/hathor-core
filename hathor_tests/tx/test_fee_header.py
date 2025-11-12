from typing import Any

from hathor.transaction import Transaction
from hathor.transaction.headers.fee_header import FeeEntry, FeeHeader, FeeHeaderEntry
from hathor.types import TokenUid
from hathor_tests import unittest


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
                FeeHeaderEntry(token_index=0, amount=100),  # HTR paying
                FeeHeaderEntry(token_index=1, amount=200),  # Custom token paying
            ],
        )
        serialized = header_round_trip.serialize()
        deserialized, remaining = FeeHeader.deserialize(tx, serialized)
        assert len(remaining) == 0
        assert deserialized.fees == header_round_trip.fees

        # Verbose callback functionality test
        verbose_calls: list[tuple[str, Any]] = []

        def verbose_callback(name: str, value: Any) -> None:
            verbose_calls.append((name, value))

        header_verbose = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[FeeHeaderEntry(token_index=0, amount=300)],  # HTR paying
        )
        serialized_verbose = header_verbose.serialize()
        deserialized_verbose, remaining = FeeHeader.deserialize(tx, serialized_verbose, verbose=verbose_callback)

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
            fees=[FeeHeaderEntry(token_index=0, amount=500)],  # HTR paying
        )
        sighash_bytes = header_sighash.get_sighash_bytes()
        serialized_bytes = header_sighash.serialize()

        # get_sighash_bytes should return the same as serialize()
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
                FeeHeaderEntry(token_index=0, amount=100),  # HTR
                FeeHeaderEntry(token_index=1, amount=200),  # token1 (must be multiple of 100)
            ],
        )
        fees = header.get_fees()

        assert len(fees) == 2
        assert fees[0] == FeeEntry(token_uid=tx.get_token_uid(0), amount=100)  # HTR
        assert fees[1] == FeeEntry(token_uid=token1_uid, amount=200)  # token1

        # Test with single fee
        header_single = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[FeeHeaderEntry(token_index=0, amount=300)],  # HTR only
        )
        fees_single = header_single.get_fees()
        assert len(fees_single) == 1
        assert fees_single[0] == FeeEntry(token_uid=tx.get_token_uid(0), amount=300)

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
                FeeHeaderEntry(token_index=0, amount=100),  # HTR
                FeeHeaderEntry(token_index=2, amount=50),  # token2
                FeeHeaderEntry(token_index=4, amount=25),  # token4
            ],
        )
        serialized_complex = header_complex.serialize()
        deserialized_complex, remaining = FeeHeader.deserialize(tx, serialized_complex)

        assert len(remaining) == 0
        assert len(deserialized_complex.fees) == 3
        assert deserialized_complex.fees[0].token_index == 0
        assert deserialized_complex.fees[0].amount == 100
        assert deserialized_complex.fees[1].token_index == 2
        assert deserialized_complex.fees[1].amount == 50
        assert deserialized_complex.fees[2].token_index == 4
        assert deserialized_complex.fees[2].amount == 25

        # Test max values
        header_max = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[FeeHeaderEntry(token_index=0, amount=2 ** 63 - 1)],  # Max amount
        )
        serialized_max = header_max.serialize()
        deserialized_max, remaining = FeeHeader.deserialize(tx, serialized_max)
        assert len(remaining) == 0
        assert deserialized_max.fees[0].amount == 2 ** 63 - 1

        # Test single fee
        header_single = FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=[FeeHeaderEntry(token_index=1, amount=42)],  # Single custom token fee
        )
        serialized_single = header_single.serialize()
        deserialized_single, remaining = FeeHeader.deserialize(tx, serialized_single)
        assert len(remaining) == 0
        assert len(deserialized_single.fees) == 1
        assert deserialized_single.fees[0].token_index == 1
        assert deserialized_single.fees[0].amount == 42
