from hathor.p2p.resources import MiningResource
from hathor.wallet.resources import SendTokensResource, BalanceResource, AuthWalletResource, HistoryResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import TestSite, _BaseResourceTest
from tests.utils import resolve_block_bytes
import base64
import json


class SendTokensTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = TestSite(SendTokensResource(self.manager))
        self.web_mining = TestSite(MiningResource(self.manager))
        self.web_balance = TestSite(BalanceResource(self.manager))
        self.web_auth = TestSite(AuthWalletResource(self.manager))
        self.web_history = TestSite(HistoryResource(self.manager))

    @inlineCallbacks
    def test_post(self):
        # Mining new block
        response_mining = yield self.web_mining.get("mining")
        data_mining = response_mining.json_value()
        block_bytes = resolve_block_bytes(block_bytes=data_mining['block_bytes'])
        yield self.web_mining.post("mining", {b'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})

        # Unlocking wallet
        self.manager.wallet.unlock(b"MYPASS")

        # Sending token to random address without input
        data_json = {
            "outputs": [{"address": "1234", "value": 500}],
            "inputs": []
        }
        response = yield self.web.post(
            "wallet/send_tokens",
            {b'data': bytes(json.dumps(data_json), 'utf-8')}
        )
        data = response.json_value()
        self.assertTrue(data['success'])

        # Asserting new balance
        response_balance = yield self.web_balance.get("wallet/balance")
        data_balance = response_balance.json_value()
        self.assertEqual(data_balance['balance'], 9500)

        # Getting history, so we can get the input
        response_history = yield self.web_history.get("wallet/history", {b'page': 1, b'count': 10})
        data_history = response_history.json_value()
        input_hash = data_history['history'][0]['tx_id']

        # Sending token to random address with input
        data_json = {
            "outputs": [{"address": "1234", "value": 500}],
            "inputs": [{"tx_id": input_hash, "index": 0}]
        }
        response2 = yield self.web.post(
            "wallet/send_tokens",
            {b'data': bytes(json.dumps(data_json), 'utf-8')}
        )
        data2 = response2.json_value()
        self.assertTrue(data2['success'])
