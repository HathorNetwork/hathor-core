#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import unittest

from hathor.utils.hex import HASH32_HEX_LEN, parse_hash32


class ParseHash32Test(unittest.TestCase):
    def test_valid_lowercase_round_trip(self) -> None:
        value = 'ab' * 32
        self.assertEqual(parse_hash32(value), bytes.fromhex(value))
        self.assertEqual(len(parse_hash32(value)), 32)

    def test_valid_uppercase_round_trip(self) -> None:
        value = 'AB' * 32
        self.assertEqual(parse_hash32(value), bytes.fromhex(value))

    def test_mixed_case_accepted(self) -> None:
        value = 'aB' * 32
        self.assertEqual(parse_hash32(value), bytes.fromhex(value))

    def test_too_short_raises(self) -> None:
        with self.assertRaises(ValueError) as cm:
            parse_hash32('ab' * 31)
        self.assertIn(str(HASH32_HEX_LEN), str(cm.exception))

    def test_too_long_raises(self) -> None:
        with self.assertRaises(ValueError) as cm:
            parse_hash32('ab' * 33)
        self.assertIn(str(HASH32_HEX_LEN), str(cm.exception))

    def test_empty_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_hash32('')

    def test_non_hex_chars_raise(self) -> None:
        # 64 chars but contains non-hex letter 'g'
        value = 'g' * 64
        with self.assertRaises(ValueError):
            parse_hash32(value)

    def test_embedded_whitespace_rejected(self) -> None:
        # 64 chars where two of them are spaces; bytes.fromhex would skip the
        # whitespace and decode 31 bytes, the length check must reject this.
        value = 'a' * 62 + '  '
        self.assertEqual(len(value), HASH32_HEX_LEN)
        with self.assertRaises(ValueError) as cm:
            parse_hash32(value)
        self.assertIn('whitespace', str(cm.exception))

    def test_embedded_tab_rejected(self) -> None:
        value = 'a' * 62 + '\t\t'
        self.assertEqual(len(value), HASH32_HEX_LEN)
        with self.assertRaises(ValueError):
            parse_hash32(value)
