from hathor.transaction.resources import TipsHistogramResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import StubSite, _BaseResourceTest

from tests.utils import add_new_blocks, add_new_transactions
import time


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

        txs = add_new_transactions(self.manager, 10, 2)

        response1 = yield self.web.get("tips-histogram", {b'begin': txs[0].timestamp, b'end': txs[0].timestamp})
        data1 = response1.json_value()
        self.assertEqual(len(data1), 1)
        self.assertEqual([txs[0].timestamp, 1], data1[0])

        response2 = yield self.web.get("tips-histogram", {b'begin': txs[0].timestamp, b'end': txs[0].timestamp + 1})
        data2 = response2.json_value()
        self.assertEqual(len(data2), 2)
        self.assertEqual([txs[0].timestamp, 1], data2[0])
        self.assertEqual([txs[0].timestamp + 1, 1], data2[1])

        response3 = yield self.web.get("tips-histogram", {b'begin': txs[0].timestamp, b'end': txs[-1].timestamp})
        data3 = response3.json_value()
        self.assertEqual(len(data3), 19)


if __name__ == '__main__':
    unittest.main()
