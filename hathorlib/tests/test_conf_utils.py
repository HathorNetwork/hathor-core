# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
