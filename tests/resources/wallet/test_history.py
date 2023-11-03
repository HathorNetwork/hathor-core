import base64

from twisted.internet.defer import inlineCallbacks

from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.p2p.resources import MiningResource
from hathor.wallet.resources import HistoryResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import resolve_block_bytes


class BaseHistoryTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.web = StubSite(HistoryResource(self.manager))
        self.web_mining = StubSite(MiningResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        # Mining new block
        response_mining = yield self.web_mining.get("mining")
        data_mining = response_mining.json_value()
        block_bytes = resolve_block_bytes(
            block_bytes=data_mining['block_bytes'],
            cpu_mining_service=CpuMiningService()
        )
        yield self.web_mining.post("mining", {'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})

        # Getting wallet history
        response = yield self.web.get("wallet/history", {b'page': 1, b'count': 10})
        data = response.json_value()
        self.assertEqual(len(data['history']), 1)
        self.assertEqual(data['total_pages'], 1)


class SyncV1HistoryTest(unittest.SyncV1Params, BaseHistoryTest):
    __test__ = True


class SyncV2HistoryTest(unittest.SyncV2Params, BaseHistoryTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeHistoryTest(unittest.SyncBridgeParams, SyncV2HistoryTest):
    pass
