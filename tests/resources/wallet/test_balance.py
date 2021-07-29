import base64

from twisted.internet.defer import inlineCallbacks

from hathor.p2p.resources import MiningResource
from hathor.wallet.resources import BalanceResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import resolve_block_bytes


class BaseBalanceTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.web = StubSite(BalanceResource(self.manager))
        self.web_mining = StubSite(MiningResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get("wallet/balance")
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertEqual(data['balance'], {'available': 0, 'locked': 0})

        # Mining new block
        response_mining = yield self.web_mining.get("mining")
        data_mining = response_mining.json_value()
        block_bytes = resolve_block_bytes(block_bytes=data_mining['block_bytes'])
        yield self.web_mining.post("mining", {'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})

        # Get new balance after block
        response2 = yield self.web.get("wallet/balance")
        data2 = response2.json_value()
        self.assertTrue(data2['success'])
        tokens = self.manager.get_tokens_issued_per_block(1)
        self.assertEqual(data2['balance'], {'available': tokens, 'locked': 0})


class SyncV1BalanceTest(unittest.SyncV1Params, BaseBalanceTest):
    __test__ = True


class SyncV2BalanceTest(unittest.SyncV2Params, BaseBalanceTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeBalanceTest(unittest.SyncBridgeParams, SyncV2BalanceTest):
    pass
