from twisted.internet.defer import inlineCallbacks

from hathor.simulator.utils import add_new_blocks
from hathor.transaction.resources import MempoolResource
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest
from hathor_tests.utils import add_blocks_unlock_reward, add_new_transactions


class MempoolTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(MempoolResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')
        add_new_blocks(self.manager, 4, advance_clock=1)
        add_blocks_unlock_reward(self.manager)

    @inlineCallbacks
    def test_get(self):

        # Success empty mempool
        response1 = yield self.web.get("mempool")
        data1 = response1.json_value()
        self.assertTrue(data1['success'])
        self.assertEqual(data1['transactions'], [])

        # Success mempool with single TX
        txs2 = add_new_transactions(self.manager, 1, advance_clock=1)
        response2 = yield self.web.get("mempool")
        data2 = response2.json_value()
        self.assertTrue(data2['success'])
        self.assertEqual(data2['transactions'], list(map(lambda t: t.hash.hex(), txs2)))

        # Success mempool with multiple TX
        txs3 = add_new_transactions(self.manager, 2, advance_clock=1)
        response3 = yield self.web.get("mempool")
        data3 = response3.json_value()
        self.assertTrue(data3['success'])
        self.assertEqual(data3['transactions'], list(map(lambda t: t.hash.hex(), txs2+txs3)))

        # add block to confirm previous txs
        add_new_blocks(self.manager, 1, advance_clock=1)

        # and next call will not have previous mempool
        txs4 = add_new_transactions(self.manager, 2, advance_clock=1)
        response4 = yield self.web.get("mempool")
        data4 = response4.json_value()
        self.assertTrue(data4['success'])
        self.assertEqual(data4['transactions'], list(map(lambda t: t.hash.hex(), txs4)))

        # add block to confirm previous txs
        add_new_blocks(self.manager, 1, advance_clock=1)

        # Add more than api limit and check truncated return
        add_new_transactions(self.manager, self._settings.MEMPOOL_API_TX_LIMIT + 1, advance_clock=1)
        response5 = yield self.web.get("mempool")
        data5 = response5.json_value()
        self.assertTrue(data5['success'])
        # default limit is 100
        self.assertEqual(len(data5['transactions']), self._settings.MEMPOOL_API_TX_LIMIT)
