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

from hathorlib.conf import HathorSettings
from hathorlib.token_amount import UnsignedAmount
from hathorlib.utils import (
    bytes_to_int,
    clean_token_string,
    get_deposit_token_deposit_amount,
    get_deposit_token_withdraw_amount,
    int_to_bytes,
    not_none,
    unpack,
    unpack_len,
)


class TestIntBytes(unittest.TestCase):
    def test_int_to_bytes(self) -> None:
        self.assertEqual(int_to_bytes(256, 2), b'\x01\x00')
        self.assertEqual(int_to_bytes(0, 1), b'\x00')

    def test_int_to_bytes_signed(self) -> None:
        self.assertEqual(int_to_bytes(-1, 1, signed=True), b'\xff')

    def test_bytes_to_int(self) -> None:
        self.assertEqual(bytes_to_int(b'\x01\x00'), 256)
        self.assertEqual(bytes_to_int(b'\x00'), 0)

    def test_bytes_to_int_signed(self) -> None:
        self.assertEqual(bytes_to_int(b'\xff', signed=True), -1)

    def test_roundtrip(self) -> None:
        for val in [0, 1, 127, 255, 65535]:
            result = bytes_to_int(int_to_bytes(val, 2))
            self.assertEqual(result, val)


class TestUnpack(unittest.TestCase):
    def test_unpack(self) -> None:
        import struct
        data = struct.pack('!I', 42) + b'rest'
        (value,), remaining = unpack('!I', data)
        self.assertEqual(value, 42)
        self.assertEqual(remaining, b'rest')

    def test_unpack_len(self) -> None:
        data = b'helloworld'
        head, tail = unpack_len(5, data)
        self.assertEqual(head, b'hello')
        self.assertEqual(tail, b'world')


class TestCleanTokenString(unittest.TestCase):
    def test_basic(self) -> None:
        self.assertEqual(clean_token_string('hathor'), 'HATHOR')

    def test_strips_whitespace(self) -> None:
        self.assertEqual(clean_token_string('  hathor  '), 'HATHOR')

    def test_collapses_double_spaces(self) -> None:
        self.assertEqual(clean_token_string('my  token'), 'MY TOKEN')


class TestNotNone(unittest.TestCase):
    def test_with_value(self) -> None:
        self.assertEqual(not_none(42), 42)
        self.assertEqual(not_none('hello'), 'hello')

    def test_with_none(self) -> None:
        with self.assertRaises(AssertionError):
            not_none(None)

    def test_custom_message(self) -> None:
        with self.assertRaises(AssertionError) as cm:
            not_none(None, 'custom error')
        self.assertIn('custom error', str(cm.exception))


class TestDepositFunctions(unittest.TestCase):
    # Both helpers consume and produce TokenAmounts. Arg values are V2 atomic units
    # (10**18 = 1 HTR, 10**16 = 1 HTR cent). Return values are always cent-aligned.

    def setUp(self) -> None:
        super().setUp()
        self.settings = HathorSettings()

    def test_deposit_amount_one_htr_mint(self) -> None:
        # 1% of 1 HTR = 0.01 HTR = exactly 1 cent.
        result = get_deposit_token_deposit_amount(self.settings, UnsignedAmount.from_v2(100 * 10**16))
        assert result.normalized() == 10**16

    def test_deposit_amount_ceils_to_next_cent(self) -> None:
        # 1% of 1.01 HTR = 0.0101 HTR, ceiled up to 2 cents.
        result = get_deposit_token_deposit_amount(self.settings, UnsignedAmount.from_v2(101 * 10**16))
        assert result.normalized() == 2 * 10**16

    def test_deposit_amount_enforces_minimum(self) -> None:
        # 1% of a sub-cent mint still requires the 1-cent minimum.
        result = get_deposit_token_deposit_amount(self.settings, UnsignedAmount.from_v2(1))
        assert result.normalized() == 10**16

    def test_withdraw_amount_one_htr_melt(self) -> None:
        # 1% of 1 HTR = 0.01 HTR = exactly 1 cent.
        result = get_deposit_token_withdraw_amount(self.settings, UnsignedAmount.from_v2(100 * 10**16))
        assert result.normalized() == 10**16

    def test_withdraw_amount_floors_to_previous_cent(self) -> None:
        # 1% of 1.99 HTR = 0.0199 HTR, floored down to 1 cent.
        result = get_deposit_token_withdraw_amount(self.settings, UnsignedAmount.from_v2(199 * 10**16))
        assert result.normalized() == 10**16

    def test_withdraw_amount_below_one_cent_returns_zero(self) -> None:
        # Sub-cent withdrawals are kept by the system.
        result = get_deposit_token_withdraw_amount(self.settings, UnsignedAmount.from_v2(1))
        assert result.normalized() == 0
