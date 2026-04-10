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

from hathorlib.utils.pydantic import BaseModel, Hex, _bytes_to_hex, _hex_to_bytes


class TestHexHelpers(unittest.TestCase):
    def test_hex_to_bytes_from_bytes(self) -> None:
        self.assertEqual(_hex_to_bytes(b'\xde\xad'), b'\xde\xad')

    def test_hex_to_bytes_from_str(self) -> None:
        self.assertEqual(_hex_to_bytes('dead'), b'\xde\xad')

    def test_hex_to_bytes_invalid_type(self) -> None:
        with self.assertRaises(ValueError):
            _hex_to_bytes(123)

    def test_bytes_to_hex(self) -> None:
        self.assertEqual(_bytes_to_hex(b'\xde\xad'), 'dead')


class TestHexType(unittest.TestCase):
    def test_hex_model(self) -> None:
        class MyModel(BaseModel):
            data: Hex[bytes]

        # From hex string
        m = MyModel(data='deadbeef')
        self.assertEqual(m.data, b'\xde\xad\xbe\xef')

        # Serialization to JSON should produce hex
        json_str = m.model_dump_json()
        self.assertIn('deadbeef', json_str)

    def test_hex_model_from_bytes(self) -> None:
        class MyModel(BaseModel):
            data: Hex[bytes]

        m = MyModel(data=b'\x01\x02')
        self.assertEqual(m.data, b'\x01\x02')


class TestBaseModel(unittest.TestCase):
    def test_extra_forbid(self) -> None:
        class MyModel(BaseModel):
            x: int

        with self.assertRaises(Exception):
            MyModel(x=1, y=2)  # type: ignore

    def test_frozen(self) -> None:
        class MyModel(BaseModel):
            x: int

        m = MyModel(x=1)
        with self.assertRaises(Exception):
            m.x = 2  # type: ignore

    def test_json_dumpb(self) -> None:
        class MyModel(BaseModel):
            x: int

        m = MyModel(x=42)
        result = m.json_dumpb()
        self.assertIsInstance(result, bytes)
        self.assertIn(b'42', result)
