import time

from twisted.internet.defer import inlineCallbacks

from hathor.transaction.resources import TipsHistogramResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_blocks_unlock_reward, add_new_blocks, add_new_transactions


class TipsTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(TipsHistogramResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')
        self.manager.reactor.advance(time.time())

    @inlineCallbacks
    def test_get_tips_histogram(self):
        # Add blocks to have funds
        add_new_blocks(self.manager, 2, 2)
        add_blocks_unlock_reward(self.manager)

        txs = add_new_transactions(self.manager, 10, 2)

        response1 = yield self.web.get("tips-histogram", {
            b'begin': str(txs[0].timestamp).encode(),
            b'end': str(txs[0].timestamp).encode()
        })
        data1 = response1.json_value()
        self.assertTrue(data1['success'])
        self.assertEqual(len(data1['tips']), 1)
        self.assertEqual([txs[0].timestamp, 1], data1['tips'][0])

        response2 = yield self.web.get("tips-histogram", {
            b'begin': str(txs[0].timestamp).encode(),
            b'end': str(txs[0].timestamp + 1).encode()
        })
        data2 = response2.json_value()
        self.assertTrue(data2['success'])
        self.assertEqual(len(data2['tips']), 2)
        self.assertEqual([txs[0].timestamp, 1], data2['tips'][0])
        self.assertEqual([txs[0].timestamp + 1, 1], data2['tips'][1])

        response3 = yield self.web.get("tips-histogram", {
            b'begin': str(txs[0].timestamp).encode(),
            b'end': str(txs[-1].timestamp).encode()
        })
        data3 = response3.json_value()
        self.assertTrue(data3['success'])
        self.assertEqual(len(data3['tips']), 19)

    @inlineCallbacks
    def test_invalid_params(self):
        # missing end param
        response = yield self.web.get("tips-histogram", {b'begin': b'0'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # wrong end param
        response = yield self.web.get("tips-histogram", {b'begin': b'a', b'end': b'10'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing begin param
        response = yield self.web.get("tips-histogram", {b'end': b'0'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # wrong begin param
        response = yield self.web.get("tips-histogram", {b'begin': b'0', b'end': b'a'})
        data = response.json_value()
        self.assertFalse(data['success'])
