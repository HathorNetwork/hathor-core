from hathor.wallet.resources import BalanceResource
from hathor.p2p.resources import MiningResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import TestSite, _BaseResourceTest
from tests.utils import resolve_block_bytes
import base64


class BalanceTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = TestSite(BalanceResource(self.manager))
        self.web_mining = TestSite(MiningResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get("wallet/balance")
        data = response.json_value()
        self.assertEqual(data['balance'], 0)

        # Mining new block
        response_mining = yield self.web_mining.get("mining")
        data_mining = response_mining.json_value()
        block_bytes = resolve_block_bytes(block_bytes=data_mining['block_bytes'])
        yield self.web_mining.post("mining", {b'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})

        # Get new balance after block
        response2 = yield self.web.get("wallet/balance")
        data2 = response2.json_value()
        self.assertEqual(data2['balance'], 10000)
