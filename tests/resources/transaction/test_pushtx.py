import base64
import unittest

from hathor.transaction.resources import PushTxResource
from hathor.p2p.resources import MiningResource
from hathor.wallet.resources import SendTokensResource, BalanceResource, HistoryResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import StubSite, _BaseResourceTest
from hathor.transaction.genesis import genesis_transactions
from tests.utils import resolve_block_bytes


class DecodeTxTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(PushTxResource(self.manager))
        self.web_tokens = StubSite(SendTokensResource(self.manager))
        self.web_mining = StubSite(MiningResource(self.manager))
        self.web_balance = StubSite(BalanceResource(self.manager))
        self.web_history = StubSite(HistoryResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        # Mining new block
        response_mining = yield self.web_mining.get('mining')
        data_mining = response_mining.json_value()
        block_bytes = resolve_block_bytes(block_bytes=data_mining['block_bytes'])
        yield self.web_mining.post('mining', {'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})

        # Unlocking wallet
        self.manager.wallet.unlock(b'MYPASS')

        # Sending token to random address without input
        data_json = {
            'outputs': [{'address': '15d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH', 'value': 5}],
            'inputs': []
        }
        yield self.web_tokens.post(
            'wallet/send_tokens',
            {'data': data_json}
        )

        # Valid
        (valid_tx, _) = self.manager.tx_storage.get_newest_txs(count=1)
        valid_tx = valid_tx[0]
        # modify tx so pushing it again will succeed
        valid_tx.weight += 0.1
        valid_tx.resolve()
        response_success = yield self.web.get('push_tx', {b'hex_tx': bytes(valid_tx.get_struct().hex(), 'utf-8')})
        data_success = response_success.json_value()
        self.assertTrue(data_success['success'])

        # Invalid tx (don't have inputs)
        genesis_tx = genesis_transactions(self.manager.tx_storage)[1]
        response_genesis = yield self.web.get('push_tx', {b'hex_tx': bytes(genesis_tx.get_struct().hex(), 'utf-8')})
        data_genesis = response_genesis.json_value()
        self.assertFalse(data_genesis['success'])

        # Invalid hex
        response_error1 = yield self.web.get('push_tx', {b'hex_tx': b'XXXX'})
        data_error1 = response_error1.json_value()

        self.assertFalse(data_error1['success'])

        # Invalid tx hex
        response_error2 = yield self.web.get('push_tx', {b'hex_tx': b'a12c'})
        data_error2 = response_error2.json_value()

        self.assertFalse(data_error2['success'])


if __name__ == '__main__':
    unittest.main()
