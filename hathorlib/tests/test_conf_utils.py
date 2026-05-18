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

from hathorlib.conf.utils import parse_hex_str


class TestParseHexStr(unittest.TestCase):
    def test_from_str(self) -> None:
        result = parse_hex_str('deadbeef')
        self.assertEqual(result, b'\xde\xad\xbe\xef')

    def test_from_str_with_x_prefix(self) -> None:
        result = parse_hex_str('xdeadbeef')
        self.assertEqual(result, b'\xde\xad\xbe\xef')

    def test_from_bytes(self) -> None:
        result = parse_hex_str(b'\x01\x02')
        self.assertEqual(result, b'\x01\x02')

    def test_invalid_type(self) -> None:
        with self.assertRaises(ValueError):
            parse_hex_str(123)  # type: ignore
