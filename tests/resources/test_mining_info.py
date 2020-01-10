from twisted.internet.defer import inlineCallbacks

from hathor.p2p.resources import MiningInfoResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_new_blocks


class GetMiningInfoTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(MiningInfoResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')

    @inlineCallbacks
    def test_get_many(self):
        response1 = yield self.web.get("getmininginfo")
        data1 = response1.json_value()
        self.assertTrue(data1['success'])
        # No blocks
        self.assertEqual(data1['blocks'], 0)
        # Difficulty is 1
        self.assertEqual(data1['difficulty'], 1)

        # Add 10 blocks
        blocks = add_new_blocks(self.manager, 10, advance_clock=1)

        response2 = yield self.web.get("getmininginfo")
        data2 = response2.json_value()
        self.assertTrue(data2['success'])
        # 10 blocks
        self.assertEqual(data2['blocks'], 10)
        # Difficulty is 1
        self.assertEqual(data2['difficulty'], 1)
        # Hashrate < 1 because of low weight and many blocks added fast
        self.assertLess(data2['hashrate'], 1)