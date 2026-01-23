#  Copyright 2025 Hathor Labs
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

import hashlib

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_public_key_bytes_compressed
from hathor.nanocontracts import Blueprint, Context, NCFail, public, utils as nc_utils, view
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @view
    def test_sha3(self, data: bytes) -> bytes:
        return nc_utils.sha3(data)

    @view
    def test_verify_ecdsa(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        return nc_utils.verify_ecdsa(public_key, data, signature)

    @view
    def test_json_dumps(self) -> str:
        obj = dict(a=[1, 2, 3], b=123, c='abc')
        return nc_utils.json_dumps(obj)


class TestUtilsFunctions(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id = self.gen_random_contract_id()
        self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context())

    def test_sha3(self) -> None:
        data = b'abc'
        expected = hashlib.sha3_256(data).digest()
        result = self.runner.call_view_method(self.contract_id, 'test_sha3', data)

        assert result == expected

    def test_verify_ecdsa_not_compressed(self) -> None:
        with pytest.raises(NCFail, match='public_key is not compressed'):
            self.runner.call_view_method(self.contract_id, 'test_verify_ecdsa', b'', b'', b'')

    def test_verify_ecdsa_not_valid(self) -> None:
        fake_public_key = b'\x02'
        with pytest.raises(NCFail, match='public_key is invalid'):
            self.runner.call_view_method(self.contract_id, 'test_verify_ecdsa', fake_public_key, b'', b'')

    def test_verify_ecdsa_fail(self) -> None:
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = get_public_key_bytes_compressed(private_key.public_key())

        assert not self.runner.call_view_method(self.contract_id, 'test_verify_ecdsa', public_key, b'', b'')

    def test_verify_ecdsa_success(self) -> None:
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = get_public_key_bytes_compressed(private_key.public_key())
        data = b'abc'
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

        assert self.runner.call_view_method(self.contract_id, 'test_verify_ecdsa', public_key, data, signature)

    def test_json_dumps(self) -> None:
        result = self.runner.call_view_method(self.contract_id, 'test_json_dumps')

        assert result == '{"a":[1,2,3],"b":123,"c":"abc"}'
