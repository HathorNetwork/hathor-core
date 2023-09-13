from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.p2p.resources import MiningInfoResource
from hathor.utils.simulator import add_new_blocks
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest

settings = HathorSettings()


class BaseGetMiningInfoTest(_BaseResourceTest._ResourceTest):
    __test__ = False

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
        add_new_blocks(self.manager, 10, advance_clock=1)

        response2 = yield self.web.get("getmininginfo")
        data2 = response2.json_value()
        self.assertTrue(data2['success'])
        # 10 blocks
        self.assertEqual(data2['blocks'], 10)
        # Difficulty is 1
        self.assertEqual(data2['difficulty'], 1)
        # Hashrate < 1 because of low weight and many blocks added fast
        self.assertLess(data2['hashrate'], 1)

    @inlineCallbacks
    def test_mined_tokens(self):
        self.manager.wallet.unlock(b'MYPASS')

        response = yield self.web.get("mined_tokens")
        data = response.json_value()
        self.assertEqual(data['blocks'], 0)
        self.assertEqual(data['mined_tokens'], 0)

        add_new_blocks(self.manager, 5, advance_clock=1)

        response = yield self.web.get("mined_tokens")
        data = response.json_value()
        self.assertEqual(data['blocks'], 5)
        self.assertEqual(data['mined_tokens'], 5*settings.INITIAL_TOKENS_PER_BLOCK)

        add_new_blocks(self.manager, settings.BLOCKS_PER_HALVING + 15, advance_clock=1)
        mined_tokens = (settings.BLOCKS_PER_HALVING * settings.INITIAL_TOKENS_PER_BLOCK +
                        20 * settings.INITIAL_TOKENS_PER_BLOCK // 2)

        response = yield self.web.get("mined_tokens")
        data = response.json_value()
        self.assertEqual(data['blocks'], settings.BLOCKS_PER_HALVING + 20)
        self.assertEqual(data['mined_tokens'], mined_tokens)


class SyncV1GetMiningInfoTest(unittest.SyncV1Params, BaseGetMiningInfoTest):
    __test__ = True


class SyncV2GetMiningInfoTest(unittest.SyncV2Params, BaseGetMiningInfoTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeGetMiningInfoTest(unittest.SyncBridgeParams, SyncV2GetMiningInfoTest):
    pass
