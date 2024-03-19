from hathor.simulator.utils import add_new_blocks
from hathor.transaction.resources import BlockAtHeightResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest


class BaseBlockAtHeightTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.web = StubSite(BlockAtHeightResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')

    async def test_get(self) -> None:
        blocks = await add_new_blocks(self.manager, 4, advance_clock=1)

        # Error1: No parameter
        response1 = await self.web.get("block_at_height")
        data1 = response1.json_value()
        self.assertFalse(data1['success'])

        # Error2: Invalid parameter
        response2 = await self.web.get("block_at_height", {b'height': b'c'})
        data2 = response2.json_value()
        self.assertFalse(data2['success'])

        # Success genesis
        genesis_block = next(x for x in self.manager.tx_storage.get_all_genesis() if x.is_block)
        response3 = await self.web.get("block_at_height", {b'height': b'0'})
        data3 = response3.json_value()
        self.assertTrue(data3['success'])
        self.assertEqual(data3['block']['tx_id'], genesis_block.hash.hex())

        # Success height 1
        response4 = await self.web.get("block_at_height", {b'height': b'1'})
        data4 = response4.json_value()
        self.assertTrue(data4['success'])
        self.assertEqual(data4['block']['tx_id'], blocks[0].hash.hex())

        # Success height 5
        response5 = await self.web.get("block_at_height", {b'height': b'4'})
        data5 = response5.json_value()
        self.assertTrue(data5['success'])
        self.assertEqual(data5['block']['tx_id'], blocks[3].hash.hex())

        # Error 3: height 5 (does not have this block)
        response6 = await self.web.get("block_at_height", {b'height': b'5'})
        data6 = response6.json_value()
        self.assertFalse(data6['success'])


class SyncV1BlockAtHeightTest(unittest.SyncV1Params, BaseBlockAtHeightTest):
    __test__ = True


class SyncV2BlockAtHeightTest(unittest.SyncV2Params, BaseBlockAtHeightTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeBlockAtHeightTest(unittest.SyncBridgeParams, SyncV2BlockAtHeightTest):
    pass
