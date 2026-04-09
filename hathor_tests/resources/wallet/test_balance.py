import base64

from twisted.internet.defer import inlineCallbacks

from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.p2p.resources import MiningResource
from hathor.wallet.resources import BalanceResource
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest
from hathor_tests.utils import resolve_block_bytes


class BalanceTest(_BaseResourceTest._ResourceTest):
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
        block_bytes = resolve_block_bytes(
            block_bytes=data_mining['block_bytes'],
            cpu_mining_service=CpuMiningService()
        )
        yield self.web_mining.post("mining", {'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})
        self.clock.advance(1)

        # Get new balance after block
        response2 = yield self.web.get("wallet/balance")
        data2 = response2.json_value()
        self.assertTrue(data2['success'])
        tokens = self.manager.get_tokens_issued_per_block(1)
        self.assertEqual(data2['balance'], {'available': tokens, 'locked': 0})
