from twisted.internet.defer import inlineCallbacks

from hathor.p2p.resources import MiningInfoResource
from hathor.simulator.utils import add_new_blocks
from hathor.util import not_none
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest


class BaseGetMiningInfoTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.web = StubSite(MiningInfoResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')

    async def test_get_many(self) -> None:
        response1 = await self.web.get("getmininginfo")
        data1 = response1.json_value()
        self.assertTrue(data1['success'])
        # No blocks
        self.assertEqual(data1['blocks'], 0)
        # Difficulty is 1
        self.assertEqual(data1['difficulty'], 1)

        # Add 10 blocks
        await add_new_blocks(self.manager, 10, advance_clock=1)

        response2 = await self.web.get("getmininginfo")
        data2 = response2.json_value()
        self.assertTrue(data2['success'])
        # 10 blocks
        self.assertEqual(data2['blocks'], 10)
        # Difficulty is 1
        self.assertEqual(data2['difficulty'], 1)
        # Hashrate < 1 because of low weight and many blocks added fast
        self.assertLess(data2['hashrate'], 1)

    async def test_mined_tokens(self) -> None:
        self.manager.wallet.unlock(b'MYPASS')

        response = await self.web.get("mined_tokens")
        data = response.json_value()
        self.assertEqual(data['blocks'], 0)
        self.assertEqual(data['mined_tokens'], 0)

        await add_new_blocks(self.manager, 5, advance_clock=1)

        response = await self.web.get("mined_tokens")
        data = response.json_value()
        self.assertEqual(data['blocks'], 5)
        self.assertEqual(data['mined_tokens'], 5*self._settings.INITIAL_TOKENS_PER_BLOCK)

        await add_new_blocks(self.manager, not_none(self._settings.BLOCKS_PER_HALVING) + 15, advance_clock=1)
        mined_tokens = (not_none(self._settings.BLOCKS_PER_HALVING) * self._settings.INITIAL_TOKENS_PER_BLOCK +
                        20 * self._settings.INITIAL_TOKENS_PER_BLOCK // 2)

        response = await self.web.get("mined_tokens")
        data = response.json_value()
        self.assertEqual(data['blocks'], not_none(self._settings.BLOCKS_PER_HALVING) + 20)
        self.assertEqual(data['mined_tokens'], mined_tokens)


class SyncV1GetMiningInfoTest(unittest.SyncV1Params, BaseGetMiningInfoTest):
    __test__ = True


class SyncV2GetMiningInfoTest(unittest.SyncV2Params, BaseGetMiningInfoTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeGetMiningInfoTest(unittest.SyncBridgeParams, SyncV2GetMiningInfoTest):
    pass
