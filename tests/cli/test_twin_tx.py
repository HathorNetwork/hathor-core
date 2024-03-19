from contextlib import redirect_stdout
from io import StringIO

import pytest
from structlog.testing import capture_logs

from hathor.cli.twin_tx import create_parser, execute
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction, TransactionMetadata
from hathor.util import json_loadb
from tests import unittest
from tests.utils import (
    add_blocks_unlock_reward,
    add_new_transactions,
    execute_mining,
    execute_tx_gen,
    request_server,
    run_server,
)


class BaseTwinTxTest(unittest.TestCase):
    __test__ = False

    async def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

        await add_new_blocks(self.manager, 1, advance_clock=1)
        await add_blocks_unlock_reward(self.manager)
        txs = await add_new_transactions(self.manager, 1, advance_clock=1)
        self.tx = txs[0]

        self.parser = create_parser()

    async def test_twin(self) -> None:
        # Normal twin
        params = ['--raw_tx', self.tx.get_struct().hex()]
        args = self.parser.parse_args(params)

        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args)

        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        twin_tx = Transaction.create_from_struct(bytes.fromhex(output[0]))
        # Parents are the same but in different order
        self.assertEqual(twin_tx.parents[0], self.tx.parents[1])
        self.assertEqual(twin_tx.parents[1], self.tx.parents[0])

        # Testing metadata creation from json
        meta_before_conflict = self.tx.get_metadata()
        meta_before_conflict_json = meta_before_conflict.to_json()
        del meta_before_conflict_json['conflict_with']
        del meta_before_conflict_json['voided_by']
        del meta_before_conflict_json['twins']
        new_meta = TransactionMetadata.create_from_json(meta_before_conflict_json)
        self.assertEqual(meta_before_conflict, new_meta)

        await self.manager.propagate_tx(twin_tx)

        # Validate they are twins
        meta = self.tx.get_metadata(force_reload=True)
        self.assertEqual(meta.twins, [twin_tx.hash])

        meta2 = twin_tx.get_metadata()
        self.assertFalse(meta == meta2)

    @pytest.mark.skip(reason='broken?')
    def test_twin_different(self):
        server = run_server()

        # Unlock wallet to start mining
        request_server('wallet/unlock', 'POST', data={'passphrase': '123'})

        # Mining
        execute_mining(count=2)

        # Generating txs
        execute_tx_gen(count=4)

        response = request_server('transaction', 'GET', data={b'count': 4, b'type': 'tx'})
        tx = response['transactions'][-1]

        response = request_server('transaction', 'GET', data={b'id': tx['tx_id']})
        tx = response['tx']

        # Twin different weight and parents
        host = 'http://localhost:8085/{}/'.format(self._settings.API_VERSION_PREFIX)
        params = ['--url', host, '--hash', tx['hash'], '--parents', '--weight', '14']
        args = self.parser.parse_args(params)

        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args)

        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        twin_tx = Transaction.create_from_struct(bytes.fromhex(output[0]))
        # Parents are differents
        self.assertNotEqual(twin_tx.parents[0], tx['parents'][0])
        self.assertNotEqual(twin_tx.parents[0], tx['parents'][1])
        self.assertNotEqual(twin_tx.parents[1], tx['parents'][0])
        self.assertNotEqual(twin_tx.parents[1], tx['parents'][1])

        self.assertNotEqual(twin_tx.weight, tx['weight'])
        self.assertEqual(twin_tx.weight, 14.0)

        server.terminate()

    def test_twin_human(self):
        # Twin in human form
        params = ['--raw_tx', self.tx.get_struct().hex(), '--human']
        args = self.parser.parse_args(params)

        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args)

        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        human = output[0].replace("'", '"')
        tx_data = json_loadb(human)

        self.assertTrue(isinstance(tx_data, dict))
        self.assertTrue('hash' in tx_data)
        self.assertTrue('timestamp' in tx_data)

        self.assertEqual(tx_data['parents'][0], self.tx.parents[1].hex())
        self.assertEqual(tx_data['parents'][1], self.tx.parents[0].hex())
        self.assertEqual(tx_data['weight'], self.tx.weight)

    def test_struct_error(self):
        # Struct error
        tx_hex = self.tx.get_struct().hex()
        params = ['--raw_tx', tx_hex + 'aa']
        args = self.parser.parse_args(params)

        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args)

        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        self.assertEqual('Error getting transaction from bytes', output[0])

    def test_parameter_error(self):
        # Parameter error
        args = self.parser.parse_args([])

        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args)

        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        self.assertEqual('The command expects raw_tx or hash and url as parameters', output[0])


class SyncV1TwinTxTest(unittest.SyncV1Params, BaseTwinTxTest):
    __test__ = True


class SyncV2TwinTxTest(unittest.SyncV2Params, BaseTwinTxTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeTwinTxTest(unittest.SyncBridgeParams, SyncV2TwinTxTest):
    pass
