import urllib.parse

from hathor.cli.mining import create_parser as create_parser_mining, execute as execute_mining
from hathor.cli.tx_generator import create_parser as create_parser_tx, execute as execute_tx
from tests import unittest
from tests.utils import request_server, run_server


class GenerateTxTest(unittest.TestCase):
    def setUp(self):
        self.process = run_server()

        self.parser_mining = create_parser_mining()
        self.parser_tx = create_parser_tx()
        self.host = 'http://localhost:8085'

    def tearDown(self):
        self.process.terminate()

    def test_generate_many_tx_blocks(self):
        # Check number of txs (for now we have only the genesis)
        tx_payload = {b'count': 20, b'type': b'tx'}
        response = request_server('transaction', 'GET', data=tx_payload)
        last_len_tx = len(response['transactions'])
        self.assertEqual(last_len_tx, 2)

        # Check number of blocks (for now we have only the genesis)
        block_payload = {b'count': 20, b'type': b'block'}
        response = request_server('transaction', 'GET', data=block_payload)
        last_len_block = len(response['transactions'])
        self.assertEqual(last_len_block, 1)

        # Unlock wallet to start mining
        request_server('wallet/unlock', 'POST', data={'passphrase': '123'})

        # Start mining process
        args = self.parser_mining.parse_args([urllib.parse.urljoin(self.host, 'mining'), '--count', '3'])
        execute_mining(args)

        response = request_server('transaction', 'GET', data=block_payload)
        self.assertEqual(len(response['transactions']), last_len_block + 3)

        # Generate txs
        args = self.parser_tx.parse_args([self.host, '--count', '4'])
        execute_tx(args)

        response = request_server('transaction', 'GET', data=tx_payload)
        self.assertEqual(len(response['transactions']), last_len_tx + 4)

    def test_generate_tx(self):
        # Check balance
        response_balance = request_server('wallet/balance/', 'GET')
        self.assertEqual(response_balance['balance'], {'locked': 0, 'available': 0})

        # Check number of txs (for now we have only the genesis)
        tx_payload = {b'count': 20, b'type': b'tx'}
        response = request_server('transaction', 'GET', data=tx_payload)
        last_len_tx = len(response['transactions'])
        self.assertEqual(last_len_tx, 2)

        # Check number of blocks (for now we have only the genesis)
        block_payload = {b'count': 20, b'type': b'block'}
        response = request_server('transaction', 'GET', data=block_payload)
        last_len_block = len(response['transactions'])
        self.assertEqual(last_len_block, 1)

        # Unlock wallet to start mining
        request_server('wallet/unlock', 'POST', data={'passphrase': '123'})

        # Start mining process
        args = self.parser_mining.parse_args([urllib.parse.urljoin(self.host, 'mining'), '--count', '1'])
        execute_mining(args)

        response = request_server('transaction', 'GET', data=block_payload)
        last_len_block = len(response['transactions'])
        self.assertEqual(last_len_block, 2)

        # Chech if balance is right
        mining_balance = request_server('wallet/balance/', 'GET')
        self.assertEqual(mining_balance['balance']['available'], 2000)

        # Now we will generate txs inside the wallet
        args = self.parser_tx.parse_args([self.host, '--count', '1'])
        execute_tx(args)

        response = request_server('transaction', 'GET', data=tx_payload)
        last_len_tx = len(response['transactions'])
        self.assertEqual(last_len_tx, 3)

        # Balance must be equal because all txs were generated to inside the wallet
        tx_balance = request_server('wallet/balance/', 'GET')
        self.assertEqual(tx_balance['balance']['available'], 2000)

        value = 100
        # Now we will generate txs to outside the wallet
        args = self.parser_tx.parse_args([
            self.host, '--address', '15d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH', '--value', '{}'.format(value), '--count', '1'
        ])
        execute_tx(args)

        response = request_server('transaction', 'GET', data=tx_payload)
        last_len_tx = len(response['transactions'])
        self.assertEqual(last_len_tx, 4)

        tx_balance = request_server('wallet/balance/', 'GET')
        # Now we have lost some tokens because the tx have sent tokens outside the wallet
        self.assertEqual(tx_balance['balance']['available'], 2000 - value)

        # generate tx with timestamp set on client
        args = self.parser_tx.parse_args([self.host, '--count', '1', '--timestamp', 'client'])
        execute_tx(args)

        response = request_server('transaction', 'GET', data=tx_payload)
        last_len_tx = len(response['transactions'])
        self.assertEqual(last_len_tx, 5)

        # generate tx with timestamp set on server
        args = self.parser_tx.parse_args([self.host, '--count', '1', '--timestamp', 'server'])
        execute_tx(args)

        response = request_server('transaction', 'GET', data=tx_payload)
        last_len_tx = len(response['transactions'])
        self.assertEqual(last_len_tx, 6)
