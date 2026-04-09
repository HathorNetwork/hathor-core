import pytest

import hathor.util
from hathor_tests import unittest
from hathor_tests.utils import execute_mining, execute_tx_gen, request_server, run_server


class GenerateTxTest(unittest.TestCase):
    def setUp(self):
        self.process = run_server()

    def tearDown(self):
        self.process.terminate()

    @pytest.mark.skip(reason='broken')
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
        execute_mining(count=15)

        response = request_server('transaction', 'GET', data=block_payload)
        self.assertEqual(len(response['transactions']), last_len_block + 15)

        # Generate txs
        execute_tx_gen(count=4)

        response = request_server('transaction', 'GET', data=tx_payload)
        self.assertEqual(len(response['transactions']), last_len_tx + 4)

    @pytest.mark.skip(reason='broken')
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
        execute_mining(count=1)

        response = request_server('transaction', 'GET', data=block_payload)
        last_len_block = len(response['transactions'])
        self.assertEqual(last_len_block, 2)

        # expected total token rewards
        rewarded = hathor.util._get_tokens_issued_per_block(1)

        # Chech if balance is right
        mining_balance = request_server('wallet/balance/', 'GET')
        self.assertEqual(mining_balance['balance']['available'], rewarded)

        # Now we will generate txs inside the wallet
        execute_tx_gen(count=1)

        response = request_server('transaction', 'GET', data=tx_payload)
        last_len_tx = len(response['transactions'])
        self.assertEqual(last_len_tx, 3)

        # Balance must be equal because all txs were generated to inside the wallet
        tx_balance = request_server('wallet/balance/', 'GET')
        self.assertEqual(tx_balance['balance']['available'], rewarded)

        value = 100
        # Now we will generate txs to outside the wallet
        execute_tx_gen(address=self.get_address(0), value=value, count=1)

        response = request_server('transaction', 'GET', data=tx_payload)
        last_len_tx = len(response['transactions'])
        self.assertEqual(last_len_tx, 4)

        tx_balance = request_server('wallet/balance/', 'GET')
        # Now we have lost some tokens because the tx have sent tokens outside the wallet
        self.assertEqual(tx_balance['balance']['available'], rewarded - value)

        # generate tx with timestamp set on client
        execute_tx_gen(count=1, timestamp='client')

        response = request_server('transaction', 'GET', data=tx_payload)
        last_len_tx = len(response['transactions'])
        self.assertEqual(last_len_tx, 5)

        # generate tx with timestamp set on server
        execute_tx_gen(count=1, timestamp='server')

        response = request_server('transaction', 'GET', data=tx_payload)
        last_len_tx = len(response['transactions'])
        self.assertEqual(last_len_tx, 6)
