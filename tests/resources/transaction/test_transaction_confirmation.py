from twisted.internet.defer import inlineCallbacks

from hathor.simulator.utils import add_new_blocks
from hathor.transaction.resources import TransactionAccWeightResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_blocks_unlock_reward, add_new_transactions


class BaseTransactionTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.web = StubSite(TransactionAccWeightResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')

    @inlineCallbacks
    def test_get_data(self):
        genesis_tx = next(x for x in self.manager.tx_storage.get_all_genesis() if x.is_transaction)
        response_success = yield self.web.get(
            "transaction_acc_weight",
            {b'id': bytes(genesis_tx.hash.hex(), 'utf-8')}
        )
        data_success = response_success.json_value()
        self.assertTrue(data_success['success'])
        self.assertEqual(data_success['accumulated_weight'], genesis_tx.weight)
        self.assertEqual(data_success['confirmation_level'], 0)

        # Adding blocks to have funds
        add_new_blocks(self.manager, 2, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        tx = add_new_transactions(self.manager, 5)[0]
        add_new_blocks(self.manager, 2, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        response_success2 = yield self.web.get(
            "transaction_acc_weight",
            {b'id': bytes(tx.hash.hex(), 'utf-8')}
        )
        data_success2 = response_success2.json_value()
        self.assertGreater(data_success2['accumulated_weight'], tx.weight)
        self.assertEqual(data_success2['confirmation_level'], 1)

        # Test sending hash that does not exist
        response_error1 = yield self.web.get(
            "transaction_acc_weight", {b'id': b'000000831cff82fa730cbdf8640fae6c130aab1681336e2f8574e314a5533848'})
        data_error1 = response_error1.json_value()
        self.assertFalse(data_error1['success'])

        # Test sending invalid hash
        response_error2 = yield self.web.get(
            "transaction_acc_weight", {b'id': b'000000831cff82fa730cbdf8640fae6c130aab1681336e2f8574e314a553384'})
        data_error2 = response_error2.json_value()
        self.assertFalse(data_error2['success'])

    @inlineCallbacks
    def test_blocks_are_blocked(self):
        genesis_tx = next(x for x in self.manager.tx_storage.get_all_genesis() if x.is_block)
        response_success = yield self.web.get(
            "transaction_acc_weight",
            {b'id': bytes(genesis_tx.hash.hex(), 'utf-8')}
        )
        data_success = response_success.json_value()
        self.assertFalse(data_success['success'])


class SyncV1TransactionTest(unittest.SyncV1Params, BaseTransactionTest):
    __test__ = True


class SyncV2TransactionTest(unittest.SyncV2Params, BaseTransactionTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeTransactionTest(unittest.SyncBridgeParams, SyncV2TransactionTest):
    pass
