from twisted.internet.defer import inlineCallbacks

from hathor.transaction import Transaction
from hathor.transaction.genesis import get_genesis_transactions
from hathor.transaction.resources import TransactionResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_blocks_unlock_reward, add_new_blocks, add_new_transactions, start_remote_storage


class TransactionTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(TransactionResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')

    @inlineCallbacks
    def test_get_one(self):
        genesis_tx = get_genesis_transactions(self.manager.tx_storage)[0]
        response_success = yield self.web.get("transaction", {b'id': bytes(genesis_tx.hash.hex(), 'utf-8')})
        data_success = response_success.json_value()
        self.assertTrue(data_success['success'])
        dict_test = genesis_tx.to_json(decode_script=True)
        dict_test['raw'] = genesis_tx.get_struct().hex()
        dict_test['nonce'] = str(dict_test['nonce'])
        if genesis_tx.is_block:
            dict_test['height'] = genesis_tx.calculate_height()
        self.assertEqual(data_success['tx'], dict_test)

        # Test sending hash that does not exist
        response_error1 = yield self.web.get(
            "transaction", {b'id': b'000000831cff82fa730cbdf8640fae6c130aab1681336e2f8574e314a5533848'})
        data_error1 = response_error1.json_value()
        self.assertFalse(data_error1['success'])

        # Test sending invalid hash
        response_error2 = yield self.web.get(
            "transaction", {b'id': b'000000831cff82fa730cbdf8640fae6c130aab1681336e2f8574e314a553384'})
        data_error2 = response_error2.json_value()
        self.assertFalse(data_error2['success'])

        # Adding blocks to have funds
        add_new_blocks(self.manager, 2, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        tx = add_new_transactions(self.manager, 1)[0]

        tx2 = Transaction.create_from_struct(tx.get_struct())
        tx2.parents = [tx.parents[1], tx.parents[0]]
        tx2.resolve()

        self.manager.propagate_tx(tx2)

        # Now we get a tx with conflict, voided_by and twin
        response_conflict = yield self.web.get("transaction", {b'id': bytes(tx2.hash.hex(), 'utf-8')})
        data_conflict = response_conflict.json_value()
        self.assertTrue(data_conflict['success'])

    @inlineCallbacks
    def test_get_many(self):
        # Add some blocks and txs and get them in timestamp order
        blocks = add_new_blocks(self.manager, 4, advance_clock=1)
        _blocks = add_blocks_unlock_reward(self.manager)
        txs = sorted(add_new_transactions(self.manager, 25), key=lambda x: (x.timestamp, x.hash))

        blocks.extend(_blocks)
        blocks = sorted(blocks, key=lambda x: (x.timestamp, x.hash))

        # Get last 2 blocks
        expected1 = blocks[-2:]
        expected1.reverse()

        response1 = yield self.web.get("transaction", {b'count': b'2', b'type': b'block'})
        data1 = response1.json_value()

        for expected, result in zip(expected1, data1['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertTrue(data1['has_more'])

        # Get last 8 txs
        expected2 = txs[-8:]
        expected2.reverse()

        response2 = yield self.web.get("transaction", {b'count': b'8', b'type': b'tx'})
        data2 = response2.json_value()

        for expected, result in zip(expected2, data2['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertTrue(data2['has_more'])

        # Get older blocks with hash reference
        expected3 = blocks[:2]
        expected3.reverse()

        response3 = yield self.web.get(
            "transaction", {
                b'count': b'3',
                b'type': b'block',
                b'timestamp': bytes(str(blocks[2].timestamp), 'utf-8'),
                b'hash': bytes(blocks[2].hash.hex(), 'utf-8'),
                b'page': b'next'
            })
        data3 = response3.json_value()

        for expected, result in zip(expected3, data3['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertFalse(data3['has_more'])

        # Get newer txs with hash reference
        response4 = yield self.web.get(
            "transaction", {
                b'count': b'16',
                b'type': b'tx',
                b'timestamp': bytes(str(txs[-9].timestamp), 'utf-8'),
                b'hash': bytes(txs[-9].hash.hex(), 'utf-8'),
                b'page': b'previous'
            })
        data4 = response4.json_value()

        for expected, result in zip(expected2, data4['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertFalse(data4['has_more'])

        # Get newer blocks with hash reference
        expected5 = blocks[-2:]
        expected5.reverse()

        response5 = yield self.web.get(
            "transaction", {
                b'count': b'3',
                b'type': b'block',
                b'timestamp': bytes(str(expected1[-1].timestamp), 'utf-8'),
                b'hash': bytes(expected1[-1].hash.hex(), 'utf-8'),
                b'page': b'previous'
            })
        data5 = response5.json_value()

        for expected, result in zip(expected5, data5['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertFalse(data5['has_more'])

        # Get txs with hash reference
        expected6 = txs[:8]
        expected6.reverse()

        response6 = yield self.web.get(
            "transaction", {
                b'count': b'8',
                b'type': b'tx',
                b'timestamp': bytes(str(txs[8].timestamp), 'utf-8'),
                b'hash': bytes(txs[8].hash.hex(), 'utf-8'),
                b'page': b'next'
            })
        data6 = response6.json_value()

        for expected, result in zip(expected6, data6['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertTrue(data6['has_more'])

    @inlineCallbacks
    def test_invalid_params(self):
        # Add some blocks and txs
        add_new_blocks(self.manager, 4, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        add_new_transactions(self.manager, 3)

        # invalid count
        response = yield self.web.get("transaction", {b'count': b'a', b'type': b'block'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing type
        response = yield self.web.get("transaction", {b'count': b'3'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid type
        response = yield self.web.get("transaction", {b'count': b'3', b'type': b'block1'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing timestamp
        response = yield self.web.get(
                "transaction", {
                    b'count': b'3',
                    b'type': b'block',
                    b'hash': bytes('0000000043bae7193ae512e8e6e6cd666ef3ea46db6df63bd22f201c5fd682ea', 'utf-8')
                })
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid timestamp
        response = yield self.web.get(
                "transaction", {
                    b'count': b'3',
                    b'type': b'block',
                    b'hash': bytes('0000000043bae7193ae512e8e6e6cd666ef3ea46db6df63bd22f201c5fd682ea', 'utf-8'),
                    b'timestamp': b'aa'
                })
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing page
        response = yield self.web.get(
                "transaction", {
                    b'count': b'3',
                    b'type': b'block',
                    b'hash': bytes('0000000043bae7193ae512e8e6e6cd666ef3ea46db6df63bd22f201c5fd682ea', 'utf-8'),
                    b'timestamp': b'1579716659'
                })
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid timestamp
        response = yield self.web.get(
                "transaction", {
                    b'count': b'3',
                    b'type': b'block',
                    b'hash': bytes('0000000043bae7193ae512e8e6e6cd666ef3ea46db6df63bd22f201c5fd682ea', 'utf-8'),
                    b'timestamp': b'1579716659',
                    b'page': b'next1'
                })
        data = response.json_value()
        self.assertFalse(data['success'])


class RemoteStorageTransactionTest(TransactionTest):
    def setUp(self):
        self.tx_storage, self._server = start_remote_storage()
        self.tx_storage.with_index = True
        super().setUp()

    def tearDown(self):
        self._server.stop(0).wait()
        super().tearDown()
