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
    def test_deposit_amount(self) -> None:
        from hathorlib.conf import HathorSettings
        settings = HathorSettings()
        result = get_deposit_token_deposit_amount(settings, 100)
        self.assertIsInstance(result, int)
        self.assertGreater(result, 0)

    def test_withdraw_amount(self) -> None:
        from hathorlib.conf import HathorSettings
        settings = HathorSettings()
        result = get_deposit_token_withdraw_amount(settings, 100)
        self.assertIsInstance(result, int)
        self.assertGreater(result, 0)
