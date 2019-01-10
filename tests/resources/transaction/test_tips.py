from twisted.internet.defer import inlineCallbacks

from hathor.transaction.genesis import genesis_transactions
from hathor.transaction.resources import TipsResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_new_blocks, add_new_transactions


class TipsTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(TipsResource(self.manager))

    @inlineCallbacks
    def test_get_tips(self):
        genesis_txs = [tx for tx in genesis_transactions(self.manager.tx_storage) if not tx.is_block]

        # Tips are only the genesis
        response1 = yield self.web.get("tips")
        data1 = response1.json_value()
        self.assertEqual(len(data1), len(genesis_txs))

        self.manager.wallet.unlock(b'MYPASS')

        # Add blocks to have funds
        add_new_blocks(self.manager, 2)

        # Add one tx, now you have only one tip
        tx = add_new_transactions(self.manager, 1)[0]

        response2 = yield self.web.get("tips")
        data2 = response2.json_value()
        self.assertEqual(len(data2), 1)

        # Getting tips sending timestamp as parameter
        response3 = yield self.web.get("tips", {b'timestamp': tx.timestamp - 1})
        data3 = response3.json_value()
        self.assertEqual(len(data3), 2)
