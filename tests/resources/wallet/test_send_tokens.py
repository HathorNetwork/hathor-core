from hathor.p2p.resources import MiningResource
from hathor.wallet.resources import SendTokensResource, BalanceResource, HistoryResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import resolve_block_bytes, add_new_blocks
import base64


class SendTokensTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(SendTokensResource(self.manager))
        self.web_mining = StubSite(MiningResource(self.manager))
        self.web_balance = StubSite(BalanceResource(self.manager))
        self.web_history = StubSite(HistoryResource(self.manager))

    @inlineCallbacks
    def test_post(self):
        # Mining new block
        response_mining = yield self.web_mining.get("mining")
        data_mining = response_mining.json_value()
        block_bytes = resolve_block_bytes(block_bytes=data_mining['block_bytes'])
        yield self.web_mining.post("mining", {'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})
        self.reactor.advance(10)

        # Unlocking wallet
        self.manager.wallet.unlock(b"MYPASS")

        # Sending token to random address without input

        # Options
        yield self.web.options("wallet/send_tokens")

        data_json = {
            "outputs": [{"address": "2jGdawyCaFf1Zsw6bjHxPUiyMZix", "value": 505}],
            "inputs": []
        }
        response = yield self.web.post(
            "wallet/send_tokens",
            {'data': data_json}
        )
        data = response.json_value()
        self.assertTrue(data['success'])
        self.reactor.advance(10)

        # Asserting new balance
        response_balance = yield self.web_balance.get("wallet/balance")
        data_balance = response_balance.json_value()
        self.assertEqual(data_balance['balance'], 1495)

        # Getting history, so we can get the input
        response_history = yield self.web_history.get("wallet/history", {b'page': 1, b'count': 10})
        data_history = response_history.json_value()
        input_hash = data_history['history'][0]['tx_id']

        # Sending token to random address with input wrong amount
        data_json = {
            "outputs": [{"address": "2jGdawyCaFf1Zsw6bjHxPUiyMZix", "value": 500}],
            "inputs": [{"tx_id": input_hash, "index": 0}]
        }
        response2 = yield self.web.post(
            "wallet/send_tokens",
            {'data': data_json}
        )
        data2 = response2.json_value()
        self.assertFalse(data2['success'])
        self.reactor.advance(10)

        # Sending duplicate input
        data_json_duplicate = {
            "outputs": [{"address": "2jGdawyCaFf1Zsw6bjHxPUiyMZix", "value": 19000}],
            "inputs": [
                {"tx_id": input_hash, "index": 0},
                {"tx_id": input_hash, "index": 0}
            ]
        }
        response_duplicate = yield self.web.post("wallet/send_tokens", {'data': data_json_duplicate})
        data_duplicate = response_duplicate.json_value()
        self.assertFalse(data_duplicate['success'])

        # Sending token to random address with input right amount
        data_json2 = {
            "outputs": [{"address": "2jGdawyCaFf1Zsw6bjHxPUiyMZix", "value": 1495}],
            "inputs": [{"tx_id": input_hash, "index": 0}]
        }
        response3 = yield self.web.post(
            "wallet/send_tokens",
            {'data': data_json2}
        )
        data3 = response3.json_value()
        self.assertTrue(data3['success'])

        # Sending token to invalid addresses
        data_json3 = {
            "outputs": [{"address": "2jGdawyCaFf1Zsw6bjHxPUiyMZil", "value": 500}],
            "inputs": []
        }
        response_error1 = yield self.web.post(
            "wallet/send_tokens",
            {'data': data_json3}
        )
        data_error1 = response_error1.json_value()
        self.assertFalse(data_error1['success'])

        data_json4 = {
            "outputs": [{"address": "1234", "value": 500}],
            "inputs": []
        }
        response_error2 = yield self.web.post(
            "wallet/send_tokens",
            {'data': data_json4}
        )
        data_error2 = response_error2.json_value()
        self.assertFalse(data_error2['success'])

        # Error insuficient funds
        data_json5 = {
            "outputs": [{"address": "2jGdawyCaFf1Zsw6bjHxPUiyMZix", "value": 5000000}],
            "inputs": []
        }
        response_error3 = yield self.web.post("wallet/send_tokens", {'data': data_json5})
        data_error3 = response_error3.json_value()
        self.assertFalse(data_error3['success'])

    @inlineCallbacks
    def test_tx_weight(self):
        add_new_blocks(self.manager, 3)
        self.reactor.advance(3)

        # Unlocking wallet
        self.manager.wallet.unlock(b"MYPASS")
        self.manager.test_mode = False

        data_json = {
            "outputs": [{"address": "2jGdawyCaFf1Zsw6bjHxPUiyMZix", "value": 505}],
            "inputs": [],
            "weight": 1
        }
        response = yield self.web.post(
            "wallet/send_tokens",
            {'data': data_json}
        )
        data = response.json_value()
        self.assertFalse(data['success'])
