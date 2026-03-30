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

from hathorlib.exceptions import InvalidAddress
from hathorlib.nanocontracts.types import HATHOR_TOKEN_UID, Address, NCFee, TokenUid
from hathorlib.utils.address import get_address_b58_from_public_key, get_public_key_from_bytes_compressed


class TestAddressType(unittest.TestCase):
    def _get_valid_address_b58(self) -> str:
        pubkey_bytes = bytes.fromhex('037fe80ee4f43df6a778b383fbc9ba9a09b8b64c9dc42ad01cfa4b40073bcd4f29')
        pubkey = get_public_key_from_bytes_compressed(pubkey_bytes)
        return get_address_b58_from_public_key(pubkey)

    def test_from_str(self) -> None:
        b58 = self._get_valid_address_b58()
        addr = Address.from_str(b58)
        self.assertIsInstance(addr, Address)
        self.assertIsInstance(addr, bytes)
        self.assertEqual(len(addr), 25)

    def test_str(self) -> None:
        b58 = self._get_valid_address_b58()
        addr = Address.from_str(b58)
        self.assertEqual(str(addr), b58)

    def test_repr(self) -> None:
        b58 = self._get_valid_address_b58()
        addr = Address.from_str(b58)
        self.assertIn('Address.from_str', repr(addr))
        self.assertIn(b58, repr(addr))

    def test_from_str_invalid_type(self) -> None:
        with self.assertRaises(TypeError):
            Address.from_str(123)  # type: ignore

    def test_from_str_invalid_address(self) -> None:
        with self.assertRaises(InvalidAddress):
            Address.from_str('invalidaddress')


class TestNCFee(unittest.TestCase):
    def test_htr_fee_value(self) -> None:
        from hathorlib.conf import HathorSettings
        settings = HathorSettings()
        fee = NCFee(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=100)
        self.assertEqual(fee.get_htr_value(settings), 100)

    def test_custom_token_fee_value(self) -> None:
        from hathorlib.conf import HathorSettings
        settings = HathorSettings()
        fee = NCFee(token_uid=TokenUid(b'\x01' * 32), amount=1000)
        # For custom token, it converts using deposit percentage
        result = fee.get_htr_value(settings)
        self.assertIsInstance(result, int)
        self.assertGreater(result, 0)
