import unittest
import json
import base64
import base58

from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import NanoContractMatchValues, P2PKH, script_eval


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
        self.assertIsNotNone(nc2)
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


if __name__ == '__main__':
    unittest.main()
