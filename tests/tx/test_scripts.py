import unittest
import os
import json
import base64

from hathor.transaction.scripts import HathorScript, op_pushdata, DATA_TO_SIGN, \
                                       op_pushdata1, op_dup, op_equalverify, op_checksig, op_hash160
from hathor.transaction.exceptions import OutOfData, MissingStackItems, EqualVerifyFailed
from hathor.crypto.util import get_private_key_from_bytes, get_public_key_from_bytes, \
                               get_public_key_bytes_compressed, get_hash160

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


class BasicTransaction(unittest.TestCase):
    def test_pushdata(self):
        stack = []
        random_bytes = b'a' * 50
        s = HathorScript()
        s.pushData(random_bytes)

        op_pushdata(0, s.data, stack)

        self.assertEqual(random_bytes, stack.pop())

        with self.assertRaises(OutOfData):
            op_pushdata(0, s.data[:-1], stack)

    def test_pushdata1(self):
        stack = []
        random_bytes = b'a' * 100
        s = HathorScript()
        s.pushData(random_bytes)

        op_pushdata1(0, s.data, stack)

        self.assertEqual(random_bytes, stack.pop())

        with self.assertRaises(OutOfData):
            op_pushdata1(0, s.data[:-1], stack)

    def test_dup(self):
        with self.assertRaises(MissingStackItems):
            op_dup([])

        stack = [1]
        op_dup(stack)
        self.assertEqual(stack[-1], stack[-2])

    def test_equalverify(self):
        elem = b'a'
        with self.assertRaises(MissingStackItems):
            op_equalverify([elem])

        op_equalverify([elem, elem])

        with self.assertRaises(EqualVerifyFailed):
            op_equalverify([elem, b'aaaa'])

    def test_checksig(self):
        filepath = os.path.join(os.getcwd(), 'hathor/wallet/genesis_keys.json')
        dict_data = None
        with open(filepath, 'r') as json_file:
            dict_data = json.loads(json_file.read())
        b64_private_key = dict_data['private_key']
        b64_public_key = dict_data['public_key']
        private_key_bytes = base64.b64decode(b64_private_key)
        public_key_bytes = base64.b64decode(b64_public_key)
        genesis_private_key = get_private_key_from_bytes(private_key_bytes)
        genesis_public_key = get_public_key_from_bytes(public_key_bytes)

        with self.assertRaises(MissingStackItems):
            op_checksig([1])

        signature = genesis_private_key.sign(DATA_TO_SIGN, ec.ECDSA(hashes.SHA256()))
        pubkey_bytes = get_public_key_bytes_compressed(genesis_public_key)
        stack = [signature, pubkey_bytes]
        op_checksig(stack)
        self.assertEqual(1, stack.pop())

        stack = [b'aaaaaaaaa', pubkey_bytes]
        op_checksig(stack)
        self.assertEqual(0, stack.pop())

    def test_hash160(self):
        with self.assertRaises(MissingStackItems):
            op_checksig([])

        elem = b'aaaaaaaa'
        hash160 = get_hash160(elem)
        stack = [elem]
        op_hash160(stack)
        self.assertEqual(hash160, stack.pop())


if __name__ == '__main__':
    unittest.main()
