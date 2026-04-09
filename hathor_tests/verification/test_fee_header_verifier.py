import pytest

from hathor.transaction import Transaction
from hathor.transaction.exceptions import FeeHeaderTokenNotFound, InvalidFeeAmount, InvalidFeeHeader
from hathor.transaction.headers.fee_header import FeeHeader, FeeHeaderEntry
from hathor.types import TokenUid
from hathor.verification.fee_header_verifier import MAX_FEES_LEN, FeeHeaderVerifier
from hathor_tests import unittest


class TestFeeHeaderVerifier(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

    def _create_transaction_with_tokens(self, num_tokens: int) -> Transaction:
        """Helper method to create a transaction with specified number of custom tokens.

        Args:
            num_tokens: Number of custom tokens to add (excludes HTR which is always at index 0)

        Returns:
            Transaction with the specified tokens
        """
        tx = Transaction()
        if num_tokens > 0:
            tx.tokens = [TokenUid(f'token{i:02d}'.encode().ljust(32, b'\x00')) for i in range(num_tokens)]
        return tx

    def _create_fee_header(self, tx: Transaction, fees: list[FeeHeaderEntry]) -> FeeHeader:
        """Helper method to create FeeHeader with given fees.

        Args:
            tx: Transaction to associate with the header
            fees: List of fee entries

        Returns:
            FeeHeader configured with the given fees
        """
        return FeeHeader(
            settings=self._settings,
            tx=tx,
            fees=fees
        )

    def test_verify_without_storage_valid_cases(self) -> None:
        """Test valid scenarios for verify_without_storage."""
        # Single fee entry
        tx = self._create_transaction_with_tokens(1)  # Custom token at index 1
        fees = [FeeHeaderEntry(token_index=0, amount=100)]  # HTR fee
        header = self._create_fee_header(tx, fees)

        FeeHeaderVerifier.verify_fee_list(header, tx)  # +1 for HTR

        # Multiple fee entries with different tokens
        tx = self._create_transaction_with_tokens(2)  # Custom tokens at indices 1,2
        fees = [
            FeeHeaderEntry(token_index=0, amount=3),  # HTR
            FeeHeaderEntry(token_index=1, amount=200),  # Custom token 1
        ]
        header = self._create_fee_header(tx, fees)

        FeeHeaderVerifier.verify_fee_list(header, tx)

    def test_verify_without_storage_invalid_fee_amounts(self) -> None:
        """Test valid scenarios for verify_without_storage."""
        # Single fee entry
        tx = self._create_transaction_with_tokens(1)  # Custom token at index 1

        # Invalid zero amount
        with pytest.raises(InvalidFeeAmount, match="fees should be a positive integer, got 0"):
            fees = [FeeHeaderEntry(token_index=0, amount=0)]  # HTR fee
            header = self._create_fee_header(tx, fees)
            FeeHeaderVerifier.verify_fee_list(header, tx)

        # Invalid negative amount
        with pytest.raises(InvalidFeeAmount, match="fees should be a positive integer, got -50"):
            fees = [FeeHeaderEntry(token_index=0, amount=-50)]  # HTR fee
            header = self._create_fee_header(tx, fees)
            FeeHeaderVerifier.verify_fee_list(header, tx)

        # Invalid non-multiple of 100
        with pytest.raises(InvalidFeeAmount,
                           match="fees using deposit custom tokens should be a multiple of 100, got 150"):
            fees = [FeeHeaderEntry(token_index=1, amount=150)]
            header = self._create_fee_header(tx, fees)
            FeeHeaderVerifier.verify_fee_list(header, tx)

    def test_verify_fee_list_size_empty(self) -> None:
        """Test that empty fees list raises InvalidFeeHeader."""
        tx = self._create_transaction_with_tokens(1)
        header = self._create_fee_header(tx, [])

        with pytest.raises(InvalidFeeHeader, match="fees cannot be empty"):
            FeeHeaderVerifier.verify_fee_list(header, tx)

    def test_verify_fee_list_size_exceeds_max(self) -> None:
        """Test that fees list exceeding MAX_FEES_LEN raises InvalidFeeHeader."""
        tx = self._create_transaction_with_tokens(MAX_FEES_LEN + 1)
        # Create MAX_FEES_LEN + 1 fees to exceed the limit
        fees = [FeeHeaderEntry(token_index=i, amount=100) for i in range(MAX_FEES_LEN + 1)]
        header = self._create_fee_header(tx, fees)

        expected_msg = f"more fees than the max allowed: {MAX_FEES_LEN + 1} > {MAX_FEES_LEN}"
        with pytest.raises(InvalidFeeHeader, match=expected_msg):
            FeeHeaderVerifier.verify_fee_list(header, tx)

    def test_verify_fee_list_size_at_max(self) -> None:
        """Test that fees list exactly at MAX_FEES_LEN is valid."""
        tx = self._create_transaction_with_tokens(MAX_FEES_LEN)
        # Create exactly MAX_FEES_LEN fees
        fees = [FeeHeaderEntry(token_index=i, amount=100) for i in range(MAX_FEES_LEN)]
        header = self._create_fee_header(tx, fees)

        # Should not raise any exception
        FeeHeaderVerifier.verify_fee_list(header, tx)

    def test_duplicate_token_indexes_in_fees(self) -> None:
        """Test that duplicate token indices in fees raise InvalidFeeHeader."""
        tx = self._create_transaction_with_tokens(1)
        fees = [
            FeeHeaderEntry(token_index=0, amount=100),
            FeeHeaderEntry(token_index=0, amount=200),  # Duplicate HTR fee
        ]
        header = self._create_fee_header(tx, fees)

        with pytest.raises(InvalidFeeHeader, match="duplicate token indexes in fees list"):
            FeeHeaderVerifier.verify_fee_list(header, tx)

    def test_invalid_token_indexes_out_of_bounds(self) -> None:
        """Test that token indices out of bounds raise FeeHeaderTokenNotFound."""
        tx = self._create_transaction_with_tokens(1)  # Only custom token at index 1
        fees = [FeeHeaderEntry(token_index=5, amount=100)]  # Index 5 doesn't exist
        header = self._create_fee_header(tx, fees)

        with pytest.raises(FeeHeaderTokenNotFound,
                           match="fees contains token index 5 which is not in tokens list"):
            FeeHeaderVerifier.verify_fee_list(header, tx)

    def test_invalid_token_index_greater_than_tx_tokens_len(self) -> None:
        """Test that token index greater than tx_tokens_len raises FeeHeaderTokenNotFound."""
        tx = self._create_transaction_with_tokens(1)  # tx_tokens_len = 2 (HTR + 1 custom)
        fees = [FeeHeaderEntry(token_index=2, amount=100)]  # Index 2 > tx_tokens_len (1)
        header = self._create_fee_header(tx, fees)

        with pytest.raises(FeeHeaderTokenNotFound,
                           match="fees contains token index 2 which is not in tokens list"):
            FeeHeaderVerifier.verify_fee_list(header, tx)
