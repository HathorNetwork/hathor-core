from twisted.internet.defer import inlineCallbacks

from hathor.transaction.resources import MempoolResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_new_blocks, add_new_transactions, add_blocks_unlock_reward


class MempoolTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(MempoolResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')
        # add block to confirm genesis txs
        add_new_blocks(self.manager, 4, advance_clock=1)
        add_blocks_unlock_reward(self.manager)

    @inlineCallbacks
    def test_get(self):

        # Success empty mempool
        # genesis_block = next(x for x in self.manager.tx_storage.get_all_genesis() if x.is_block)
        response1 = yield self.web.get("mempool")
        data1 = response1.json_value()
        self.assertTrue(data1['success'])
        self.assertEqual(data1['transactions'], [])

        # Success mempool with single TX
        tx = add_new_transactions(self.manager, 1, advance_clock=1)
        response2 = yield self.web.get("mempool")
        data2 = response2.json_value()
        self.assertTrue(data2['success'])
        self.assertEqual(data2['transactions'], [tx[0].hash.hex()])

        # Success mempool with multiple TX
        txs = add_new_transactions(self.manager, 2, advance_clock=1)
        response3 = yield self.web.get("mempool")
        data3 = response3.json_value()
        self.assertTrue(data3['success'])
        self.assertEqual(data3['transactions'], list(map(lambda t: t.hash.hex(), tx+txs)))

        # add block to confirm previous txs
        add_new_blocks(self.manager, 1, advance_clock=1)

        # and next call will not have previous mempool
        txs2 = add_new_transactions(self.manager, 2, advance_clock=1)
        response4 = yield self.web.get("mempool")
        data4 = response4.json_value()
        self.assertTrue(data4['success'])
        self.assertEqual(data4['transactions'], list(map(lambda t: t.hash.hex(), txs2)))
