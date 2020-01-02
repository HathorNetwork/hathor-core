import base64

from twisted.internet.defer import inlineCallbacks

from hathor.crypto.util import decode_address
from hathor.p2p.resources import MiningResource
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.genesis import get_genesis_transactions
from hathor.transaction.resources import PushTxResource
from hathor.transaction.scripts import P2PKH, create_output_script, parse_address_script
from hathor.wallet.resources import BalanceResource, HistoryResource, SendTokensResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_blocks_unlock_reward, add_new_blocks, create_tokens, resolve_block_bytes


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

        # Creating a valid transaction to be pushed to the network
        blocks = add_new_blocks(self.manager, 3, advance_clock=2)
        add_blocks_unlock_reward(self.manager)
        tx_id = blocks[0].hash
        output = blocks[0].outputs[0]
        script_type_out = parse_address_script(output.script)
        address = script_type_out.address
        private_key = self.manager.wallet.get_private_key(address)

        output_address = decode_address(self.get_address(0))
        value = self.manager.get_tokens_issued_per_block(1)
        o = TxOutput(value, create_output_script(output_address, None))
        i = TxInput(tx_id, 0, b'')
        tx = Transaction(inputs=[i], outputs=[o])

        data_to_sign = tx.get_sighash_all()
        public_key_bytes, signature_bytes = self.manager.wallet.get_input_aux_data(data_to_sign, private_key)
        i.data = P2PKH.create_input_data(public_key_bytes, signature_bytes)
        tx.inputs = [i]
        tx.timestamp = int(self.clock.seconds())
        tx.weight = self.manager.minimum_tx_weight(tx)
        tx.parents = self.manager.get_new_tx_parents(tx.timestamp)
        tx.resolve()

        response = yield self.web.get('push_tx', {b'hex_tx': bytes(tx.get_struct().hex(), 'utf-8')})
        data = response.json_value()
        self.assertTrue(data['success'])

        # Sending token to random address without input
        data_json = {'outputs': [{'address': self.get_address(0), 'value': 5}], 'inputs': []}
        yield self.web_tokens.post('wallet/send_tokens', {'data': data_json})

        # modify tx so it will be a double spending, then rejected
        tx.weight += 0.1
        tx.resolve()
        response_success = yield self.web.get('push_tx', {b'hex_tx': bytes(tx.get_struct().hex(), 'utf-8')})
        data_success = response_success.json_value()
        self.assertFalse(data_success['success'])

        # Invalid tx (don't have inputs)
        genesis_tx = get_genesis_transactions(self.manager.tx_storage)[1]
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

        # Token creation tx
        tx2 = create_tokens(self.manager, address, mint_amount=100, propagate=False)
        response = yield self.web.get('push_tx', {b'hex_tx': bytes(tx2.get_struct().hex(), 'utf-8')})
        data = response.json_value()
        self.assertTrue(data['success'])
