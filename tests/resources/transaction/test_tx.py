from hathor.transaction.resources import TransactionResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import TestSite, _BaseResourceTest
from hathor.transaction.genesis import genesis_transactions


class TransactionTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = TestSite(TransactionResource(self.manager))

    @inlineCallbacks
    def test_get_one(self):
        genesis_tx = genesis_transactions(self.manager.tx_storage)[0]
        response_success = yield self.web.get("transaction", {b'id': bytes(genesis_tx.hash.hex(), 'utf-8')})
        data_success = response_success.json_value()
        self.assertTrue(data_success['success'])
        dict_test = genesis_tx.to_json(decode_script=True)
        dict_test['raw'] = genesis_tx.get_struct().hex()
        self.assertEqual(data_success['tx'], dict_test)

        # Test sending hash that does not exist
        response_error1 = yield self.web.get(
            "transaction",
            {b'id': b'000000831cff82fa730cbdf8640fae6c130aab1681336e2f8574e314a5533848'}
        )
        data_error1 = response_error1.json_value()
        self.assertFalse(data_error1['success'])

        # Test sending invalid hash
        response_error2 = yield self.web.get(
            "transaction",
            {b'id': b'000000831cff82fa730cbdf8640fae6c130aab1681336e2f8574e314a553384'}
        )
        data_error2 = response_error2.json_value()
        self.assertFalse(data_error2['success'])

    @inlineCallbacks
    def test_get_many(self):
        genesis = genesis_transactions(self.manager.tx_storage)
        # Many blocks
        response_block = yield self.web.get("transaction", {b'count': b'10', b'type': b'block'})
        data_block = response_block.json_value()
        self.assertFalse(data_block['has_more'])
        result_block = [x.to_json() for x in genesis if x.is_block]
        self.assertEqual(data_block['transactions'], result_block)

        # Many txs
        response_tx = yield self.web.get("transaction", {b'count': b'10', b'type': b'tx'})
        data_tx = response_tx.json_value()
        self.assertFalse(data_tx['has_more'])
        result_tx = [x.to_json() for x in genesis if not x.is_block]
        # Inverse order from the timestamp
        result_tx.reverse()
        self.assertEqual(data_tx['transactions'], result_tx)
