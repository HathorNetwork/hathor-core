import unittest
import json
import base64
import base58
import hashlib

from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import NanoContractMatchValues, NanoContractMatchInterval, \
                                       P2PKH, script_eval
from hathor.crypto.util import get_hash160
from tests.utils import create_private_key

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


class NanoContracts(unittest.TestCase):
    def setUp(self):
        pass

    def test_match_values(self):
        pubkey_hash = '6o6ul2c+sqAariBVW+CwNaSJb9w='
        pubkey = 'Awmloohhey8WhajdDURgvbk1z3JHX2vxDSBjz9uG9wEp'
        # ./hathor-cli oracle-encode-data str:some_id int:1543974403 int:100
        oracle_data = 'B3NvbWVfaWQEXAcuAwFk'
        oracle_signature = 'MEYCIQC5cyg1tOY4oyPZ5KY7ugWJGRShrsSPxr8AxxyuvO5PYwIhAOxHBDMid7aRXe' \
                           '+85rIaDPI2ussIcw54avaFWfT9svSp'

        address = base58.b58decode('1Pa4MMsr5DMRAeU1PzthFXyEJeVNXsMHoz')

        # they should be the same
        nc = NanoContractMatchValues(base64.b64decode(pubkey_hash), 1543970403,
                                     'some_id'.encode('utf-8'), {address: 100})
        script = nc.create_output_script()
        nc2 = NanoContractMatchValues.parse_script(script)
        self.assertEqual(json.dumps(nc.to_human_readable()), json.dumps(nc2.to_human_readable()))

        # if we add some more bytes, parsing should not match
        script2 = script + b'00'
        nc3 = NanoContractMatchValues.parse_script(script2)
        self.assertIsNone(nc3)

        # test script eval is true
        input_data = NanoContractMatchValues.create_input_data(
            base64.b64decode(oracle_data), base64.b64decode(oracle_signature), base64.b64decode(pubkey)
        )
        txin = TxInput(b'aa', 0, input_data)
        spent_tx = Transaction(outputs=[TxOutput(20, script)])
        tx = Transaction(outputs=[TxOutput(20, P2PKH.create_output_script(address))])
        script_eval(tx, txin, spent_tx)

    def test_match_interval(self):
        privkey, pubkey_bytes = create_private_key()
        pubkey_hash = get_hash160(pubkey_bytes)
        # ./hathor-cli oracle-encode-data str:some_id int:1543974403 int:100
        oracle_data = 'B3NvbWVfaWQEXAcuAwFk'
        oracle_signature = 'MEYCIQC5cyg1tOY4oyPZ5KY7ugWJGRShrsSPxr8AxxyuvO5PYwIhAOxHBDMid7aRXe' \
                           '+85rIaDPI2ussIcw54avaFWfT9svSp'
        oracle_pubkey = 'Awmloohhey8WhajdDURgvbk1z3JHX2vxDSBjz9uG9wEp'
        oracle_pubkey_hash = '6o6ul2c+sqAariBVW+CwNaSJb9w='

        address = base58.b58decode('1Pa4MMsr5DMRAeU1PzthFXyEJeVNXsMHoz')

        pubkeys = [b'pubkey1', b'pubkey2', b'pubkey3', pubkey_hash]
        values = [1, 50, 90]

        # they should be the same
        # oracle_pubkey_hash, min_timestamp, oracle_data_id, pubkey_list, value_list
        nc = NanoContractMatchInterval(base64.b64decode(oracle_pubkey_hash), 1543970403,
                                       'some_id'.encode('utf-8'), pubkeys, values)
        script = nc.create_output_script()
        nc2 = NanoContractMatchInterval.parse_script(script)
        self.assertEqual(json.dumps(nc.to_human_readable()), json.dumps(nc2.to_human_readable()))

        # if we add some more bytes, parsing should not match
        script2 = script + b'00'
        nc3 = NanoContractMatchInterval.parse_script(script2)
        self.assertIsNone(nc3)

        # test script eval is true
        txin = TxInput(b'aa', 0, b'')
        spent_tx = Transaction(outputs=[TxOutput(20, script)])
        tx = Transaction(inputs=[txin], outputs=[TxOutput(20, P2PKH.create_output_script(address))])
        # create input
        data_to_sign = tx.get_sighash_all()
        hashed_data = hashlib.sha256(data_to_sign).digest()
        signature = privkey.sign(hashed_data, ec.ECDSA(hashes.SHA256()))
        input_data = NanoContractMatchInterval.create_input_data(
            signature, pubkey_bytes, base64.b64decode(oracle_data),
            base64.b64decode(oracle_signature), base64.b64decode(oracle_pubkey)
        )
        tx.inputs[0].data = input_data
        script_eval(tx, txin, spent_tx)


if __name__ == '__main__':
    unittest.main()
