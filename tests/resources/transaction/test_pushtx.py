import base64
from typing import Generator

from twisted.internet.defer import inlineCallbacks

from hathor.crypto.util import decode_address
from hathor.p2p.resources import MiningResource
from hathor.transaction import Transaction, TxInput, TxOutput
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
    def _run_push_tx_test(self, is_post: bool) -> Generator:
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
        assert script_type_out is not None
        address = script_type_out.address
        private_key = self.manager.wallet.get_private_key(address)

        script_out_addr = self.get_address(0)
        assert script_out_addr is not None
        output_address = decode_address(script_out_addr)
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

        push_tx_fn = self.web.post if is_post else self.web.get
        hex_param = 'hex_tx' if is_post else b'hex_tx'
        force_param = 'force' if is_post else b'force'

        tx_hex = tx.get_struct().hex()
        hex_data = tx_hex if is_post else bytes(tx_hex, 'utf-8')

        response = yield push_tx_fn('push_tx', {hex_param: hex_data})
        data = response.json_value()
        self.assertTrue(data['success'])

        # Sending token to random address without input
        data_json = {'outputs': [{'address': self.get_address(0), 'value': 5}], 'inputs': []}
        yield self.web_tokens.post('wallet/send_tokens', {'data': data_json})

        # modify tx so it will be a double spending, then rejected
        tx.weight += 0.1
        tx.resolve()

        tx_hex = tx.get_struct().hex()
        hex_data = tx_hex if is_post else bytes(tx_hex, 'utf-8')
        response_success = yield push_tx_fn('push_tx', {hex_param: hex_data})
        data_success = response_success.json_value()
        self.assertFalse(data_success['success'])

        # invalid transaction, without forcing
        tx.timestamp = 5
        tx.inputs = [TxInput(blocks[1].hash, 0, b'')]
        script_type_out = parse_address_script(blocks[1].outputs[0].script)
        assert script_type_out is not None
        private_key = self.manager.wallet.get_private_key(script_type_out.address)
        data_to_sign = tx.get_sighash_all()
        public_key_bytes, signature_bytes = self.manager.wallet.get_input_aux_data(data_to_sign, private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_key_bytes, signature_bytes)

        tx_hex = tx.get_struct().hex()
        hex_data = tx_hex if is_post else bytes(tx_hex, 'utf-8')
        response = yield push_tx_fn('push_tx', {hex_param: hex_data})
        data = response.json_value()
        self.assertFalse(data['success'])

        # force
        tx_hex = tx.get_struct().hex()
        hex_data = tx_hex if is_post else bytes(tx_hex, 'utf-8')
        response = yield push_tx_fn('push_tx', {hex_param: hex_data, force_param: True if is_post else b'true'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # Invalid tx (don't have inputs)
        genesis_tx = next(x for x in self.manager.tx_storage.get_all_genesis() if x.is_transaction)
        genesis_hex = genesis_tx.get_struct().hex()
        hex_data = genesis_hex if is_post else bytes(genesis_hex, 'utf-8')
        response_genesis = yield push_tx_fn('push_tx', {hex_param: hex_data})
        data_genesis = response_genesis.json_value()
        self.assertFalse(data_genesis['success'])

        # Invalid tx hex
        invalid_hex_data = 'a12c' if is_post else b'a12c'
        response_error2 = yield push_tx_fn('push_tx', {hex_param: invalid_hex_data})
        data_error2 = response_error2.json_value()
        self.assertFalse(data_error2['success'])

        # Token creation tx
        tx2 = create_tokens(self.manager, address, mint_amount=100, propagate=False)
        tx2_hex = tx2.get_struct().hex()
        hex_data = tx2_hex if is_post else bytes(tx2_hex, 'utf-8')
        response = yield push_tx_fn('push_tx', {hex_param: hex_data})
        data = response.json_value()
        self.assertTrue(data['success'])

    @inlineCallbacks
    def _run_invalid_params_test(self, is_post: bool) -> Generator:
        push_tx_fn = self.web.post if is_post else self.web.get
        hex_param = 'hex_tx' if is_post else b'hex_tx'

        # Missing hex
        response = yield push_tx_fn('push_tx')
        data = response.json_value()
        self.assertFalse(data['success'])

        # Missing hex 2
        response = yield push_tx_fn('push_tx', {})
        data = response.json_value()
        self.assertFalse(data['success'])

        # Invalid hex
        invalid_hex_data = 'XXXX' if is_post else b'XXXX'
        response = yield push_tx_fn('push_tx', {hex_param: invalid_hex_data})
        data = response.json_value()
        self.assertFalse(data['success'])

    def test_push_tx_get(self):
        self._run_push_tx_test(False)

    def test_push_tx_post(self):
        self._run_push_tx_test(True)

    def test_invalid_params_get(self):
        self._run_invalid_params_test(False)

    def test_invalid_params_post(self):
        self._run_invalid_params_test(True)
