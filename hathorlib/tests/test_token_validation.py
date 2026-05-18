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

import unittest
from unittest.mock import MagicMock

from hathorlib.exceptions import InvalidFeeAmount, TransactionDataError
from hathorlib.utils.token_validation import validate_fee_amount, validate_token_name_and_symbol


class TestValidateTokenNameAndSymbol(unittest.TestCase):
    def _get_settings(self) -> MagicMock:
        settings = MagicMock()
        settings.MAX_LENGTH_TOKEN_NAME = 30
        settings.MAX_LENGTH_TOKEN_SYMBOL = 5
        settings.HATHOR_TOKEN_NAME = 'Hathor'
        settings.HATHOR_TOKEN_SYMBOL = 'HTR'
        return settings

    def test_valid_name_and_symbol(self) -> None:
        settings = self._get_settings()
        # Should not raise
        validate_token_name_and_symbol(settings, 'MyToken', 'MTK')

    def test_empty_name(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(TransactionDataError):
            validate_token_name_and_symbol(settings, '', 'MTK')

    def test_name_too_long(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(TransactionDataError):
            validate_token_name_and_symbol(settings, 'A' * 31, 'MTK')

    def test_empty_symbol(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(TransactionDataError):
            validate_token_name_and_symbol(settings, 'MyToken', '')

    def test_symbol_too_long(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(TransactionDataError):
            validate_token_name_and_symbol(settings, 'MyToken', 'TOOLONG')

    def test_hathor_name_rejected(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(TransactionDataError):
            validate_token_name_and_symbol(settings, 'Hathor', 'MTK')

    def test_hathor_name_case_insensitive(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(TransactionDataError):
            validate_token_name_and_symbol(settings, 'hathor', 'MTK')

    def test_hathor_symbol_rejected(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(TransactionDataError):
            validate_token_name_and_symbol(settings, 'MyToken', 'HTR')

    def test_hathor_symbol_case_insensitive(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(TransactionDataError):
            validate_token_name_and_symbol(settings, 'MyToken', 'htr')


class TestValidateFeeAmount(unittest.TestCase):
    def _get_settings(self) -> MagicMock:
        settings = MagicMock()
        settings.HATHOR_TOKEN_UID = b'\x00'
        settings.FEE_DIVISOR = 100
        return settings

    def test_valid_htr_fee(self) -> None:
        settings = self._get_settings()
        # HTR token: any positive amount is valid
        validate_fee_amount(settings, b'\x00', 1)
        validate_fee_amount(settings, b'\x00', 50)

    def test_zero_amount_raises(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(InvalidFeeAmount):
            validate_fee_amount(settings, b'\x00', 0)

    def test_negative_amount_raises(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(InvalidFeeAmount):
            validate_fee_amount(settings, b'\x00', -10)

    def test_custom_token_valid_multiple(self) -> None:
        settings = self._get_settings()
        # Custom token: amount must be multiple of FEE_DIVISOR
        validate_fee_amount(settings, b'\x01', 100)
        validate_fee_amount(settings, b'\x01', 200)

    def test_custom_token_not_multiple_raises(self) -> None:
        settings = self._get_settings()
        with self.assertRaises(InvalidFeeAmount):
            validate_fee_amount(settings, b'\x01', 50)
