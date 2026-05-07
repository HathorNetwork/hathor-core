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

from hathorlib.utils.leb128 import decode_signed, decode_unsigned, encode_signed, encode_unsigned


class TestEncodeUnsigned(unittest.TestCase):
    def test_zero(self) -> None:
        self.assertEqual(encode_unsigned(0), bytes([0x00]))

    def test_small_value(self) -> None:
        self.assertEqual(encode_unsigned(624485), bytes([0xE5, 0x8E, 0x26]))

    def test_max_bytes_ok(self) -> None:
        result = encode_unsigned(624485, max_bytes=3)
        self.assertEqual(result, bytes([0xE5, 0x8E, 0x26]))

    def test_max_bytes_exceeded(self) -> None:
        with self.assertRaises(ValueError) as cm:
            encode_unsigned(624485, max_bytes=2)
        self.assertIn('cannot encode more than 2 bytes', str(cm.exception))


class TestEncodeSigned(unittest.TestCase):
    def test_zero(self) -> None:
        self.assertEqual(encode_signed(0), bytes([0x00]))

    def test_positive(self) -> None:
        self.assertEqual(encode_signed(624485), bytes([0xE5, 0x8E, 0x26]))

    def test_negative(self) -> None:
        self.assertEqual(encode_signed(-123456), bytes([0xC0, 0xBB, 0x78]))

    def test_max_bytes_exceeded(self) -> None:
        with self.assertRaises(ValueError):
            encode_signed(-123456, max_bytes=2)


class TestDecodeUnsigned(unittest.TestCase):
    def test_basic(self) -> None:
        value, remaining = decode_unsigned(bytes([0x00]) + b'test')
        self.assertEqual(value, 0)
        self.assertEqual(remaining, b'test')

    def test_multi_byte(self) -> None:
        value, remaining = decode_unsigned(bytes([0xE5, 0x8E, 0x26]) + b'rest')
        self.assertEqual(value, 624485)
        self.assertEqual(remaining, b'rest')

    def test_max_bytes_ok(self) -> None:
        value, remaining = decode_unsigned(bytes([0xE5, 0x8E, 0x26]) + b'rest', max_bytes=3)
        self.assertEqual(value, 624485)

    def test_max_bytes_exceeded(self) -> None:
        with self.assertRaises(ValueError) as cm:
            decode_unsigned(bytes([0xE5, 0x8E, 0x26]) + b'rest', max_bytes=2)
        self.assertIn('cannot decode more than 2 bytes', str(cm.exception))


class TestDecodeSigned(unittest.TestCase):
    def test_zero(self) -> None:
        value, remaining = decode_signed(bytes([0x00]) + b'test')
        self.assertEqual(value, 0)
        self.assertEqual(remaining, b'test')

    def test_positive(self) -> None:
        value, remaining = decode_signed(bytes([0xE5, 0x8E, 0x26]) + b'test')
        self.assertEqual(value, 624485)

    def test_negative(self) -> None:
        value, remaining = decode_signed(bytes([0xC0, 0xBB, 0x78]) + b'test')
        self.assertEqual(value, -123456)

    def test_max_bytes_exceeded(self) -> None:
        with self.assertRaises(ValueError):
            decode_signed(bytes([0xC0, 0xBB, 0x78]) + b'test', max_bytes=2)


class TestRoundTrip(unittest.TestCase):
    def test_unsigned_roundtrip(self) -> None:
        for val in [0, 1, 127, 128, 255, 16384, 624485, 2**20]:
            encoded = encode_unsigned(val)
            decoded, remaining = decode_unsigned(encoded)
            self.assertEqual(decoded, val)
            self.assertEqual(remaining, b'')

    def test_signed_roundtrip(self) -> None:
        for val in [0, 1, -1, 127, -128, 624485, -123456]:
            encoded = encode_signed(val)
            decoded, remaining = decode_signed(encoded)
            self.assertEqual(decoded, val)
            self.assertEqual(remaining, b'')
