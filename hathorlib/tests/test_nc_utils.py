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

import hashlib
import unittest

from hathorlib.nanocontracts.types import (
    NCMethodType,
    BlueprintId,
    ContractId,
    TokenUid,
    VertexId,
    NC_METHOD_TYPE_ATTR,
)
from hathorlib.nanocontracts.utils import (
    CHILD_CONTRACT_ID_PREFIX,
    CHILD_TOKEN_ID_PREFIX,
    derive_child_contract_id,
    derive_child_token_id,
    is_nc_fallback_method,
    is_nc_public_method,
    is_nc_view_method,
    json_dumps,
    sha3,
)


class TestIsMethodType(unittest.TestCase):
    def test_is_nc_public_method(self) -> None:
        def my_func() -> None:
            pass

        self.assertFalse(is_nc_public_method(my_func))
        setattr(my_func, NC_METHOD_TYPE_ATTR, NCMethodType.PUBLIC)
        self.assertTrue(is_nc_public_method(my_func))

    def test_is_nc_view_method(self) -> None:
        def my_func() -> None:
            pass

        self.assertFalse(is_nc_view_method(my_func))
        setattr(my_func, NC_METHOD_TYPE_ATTR, NCMethodType.VIEW)
        self.assertTrue(is_nc_view_method(my_func))

    def test_is_nc_fallback_method(self) -> None:
        def my_func() -> None:
            pass

        self.assertFalse(is_nc_fallback_method(my_func))
        setattr(my_func, NC_METHOD_TYPE_ATTR, NCMethodType.FALLBACK)
        self.assertTrue(is_nc_fallback_method(my_func))

    def test_not_matching_type(self) -> None:
        def my_func() -> None:
            pass

        setattr(my_func, NC_METHOD_TYPE_ATTR, NCMethodType.VIEW)
        self.assertFalse(is_nc_public_method(my_func))
        self.assertFalse(is_nc_fallback_method(my_func))


class TestDeriveChildIds(unittest.TestCase):
    def test_derive_child_contract_id(self) -> None:
        parent_id = ContractId(VertexId(b'\x01' * 32))
        salt = b'my_salt'
        blueprint_id = BlueprintId(VertexId(b'\x02' * 32))

        result = derive_child_contract_id(parent_id, salt, blueprint_id)

        # Verify it's deterministic
        result2 = derive_child_contract_id(parent_id, salt, blueprint_id)
        self.assertEqual(result, result2)

        # Verify the hash is computed correctly
        h = hashlib.sha256()
        h.update(CHILD_CONTRACT_ID_PREFIX)
        h.update(parent_id)
        h.update(salt)
        h.update(blueprint_id)
        self.assertEqual(result, ContractId(VertexId(h.digest())))

        # Different salt produces different result
        result3 = derive_child_contract_id(parent_id, b'other_salt', blueprint_id)
        self.assertNotEqual(result, result3)

    def test_derive_child_token_id(self) -> None:
        parent_id = ContractId(VertexId(b'\x01' * 32))
        token_symbol = 'TKN'

        result = derive_child_token_id(parent_id, token_symbol)

        # Verify it's deterministic
        result2 = derive_child_token_id(parent_id, token_symbol)
        self.assertEqual(result, result2)

        # Verify the hash
        h = hashlib.sha256()
        h.update(CHILD_TOKEN_ID_PREFIX)
        h.update(parent_id)
        h.update(b'')  # default salt
        h.update(token_symbol.encode('utf-8'))
        self.assertEqual(result, TokenUid(VertexId(h.digest())))

    def test_derive_child_token_id_with_salt(self) -> None:
        parent_id = ContractId(VertexId(b'\x01' * 32))
        result1 = derive_child_token_id(parent_id, 'TKN', salt=b'salt1')
        result2 = derive_child_token_id(parent_id, 'TKN', salt=b'salt2')
        self.assertNotEqual(result1, result2)


class TestSha3(unittest.TestCase):
    def test_sha3(self) -> None:
        data = b'hello world'
        result = sha3(data)
        expected = hashlib.sha3_256(data).digest()
        self.assertEqual(result, expected)
        self.assertEqual(len(result), 32)


class TestJsonDumps(unittest.TestCase):
    def test_basic_dict(self) -> None:
        result = json_dumps({'key': 'value'})
        self.assertEqual(result, '{"key":"value"}')

    def test_bytes_converted_to_hex(self) -> None:
        result = json_dumps({'data': b'\xde\xad\xbe\xef'})
        self.assertEqual(result, '{"data":"deadbeef"}')

    def test_nested_bytes(self) -> None:
        result = json_dumps({'items': [b'\x01\x02', b'\x03\x04']})
        self.assertIn('0102', result)
        self.assertIn('0304', result)

    def test_sort_keys(self) -> None:
        result = json_dumps({'b': 1, 'a': 2}, sort_keys=True)
        self.assertEqual(result, '{"a":2,"b":1}')

    def test_indent(self) -> None:
        result = json_dumps({'a': 1}, indent=2, separators=(',', ': '))
        self.assertIn('\n', result)

    def test_non_serializable_raises(self) -> None:
        with self.assertRaises(TypeError):
            json_dumps({'data': object()})
