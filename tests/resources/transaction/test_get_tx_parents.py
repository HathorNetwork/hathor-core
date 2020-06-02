from twisted.internet.defer import inlineCallbacks

from hathor.transaction.genesis import get_genesis_transactions
from hathor.transaction.resources import TxParentsResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_blocks_unlock_reward, create_tokens


class DecodeTxTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(TxParentsResource(self.manager))

    @inlineCallbacks
    def test_get_success(self):
        resp = yield self.web.get('tx_parents')
        data = resp.json_value()

        self.assertTrue(data['success'])
        self.assertEqual(2, len(data['tx_parents']))

    @inlineCallbacks
    def test_get_syncing(self):
        self.manager._allow_mining_without_peers = False

        resp = yield self.web.get('tx_parents')
        data = resp.json_value()

        self.assertFalse(data['success'])
