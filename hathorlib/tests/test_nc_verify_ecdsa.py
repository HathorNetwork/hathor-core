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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathorlib.nanocontracts.exception import NCFail
from hathorlib.nanocontracts.utils import verify_ecdsa
from hathorlib.utils.address import get_public_key_bytes_compressed


class TestVerifyEcdsa(unittest.TestCase):
    def _generate_keypair(self) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()
        compressed = get_public_key_bytes_compressed(public_key)
        return private_key, compressed

    def test_valid_signature(self) -> None:
        private_key, compressed_pubkey = self._generate_keypair()
        data = b'hello world'
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

        self.assertTrue(verify_ecdsa(compressed_pubkey, data, signature))

    def test_invalid_signature(self) -> None:
        _, compressed_pubkey = self._generate_keypair()
        data = b'hello world'
        bad_signature = b'\x00' * 64

        self.assertFalse(verify_ecdsa(compressed_pubkey, data, bad_signature))

    def test_uncompressed_pubkey_raises(self) -> None:
        # Uncompressed pubkey starts with 0x04
        uncompressed = b'\x04' + b'\x01' * 64
        with self.assertRaises(NCFail):
            verify_ecdsa(uncompressed, b'data', b'sig')

    def test_invalid_pubkey_raises(self) -> None:
        # Valid prefix but invalid point
        bad_pubkey = b'\x02' + b'\x00' * 32
        with self.assertRaises(NCFail):
            verify_ecdsa(bad_pubkey, b'data', b'sig')

    def test_wrong_data(self) -> None:
        private_key, compressed_pubkey = self._generate_keypair()
        data = b'hello world'
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

        # Verify with different data should fail
        self.assertFalse(verify_ecdsa(compressed_pubkey, b'different data', signature))
