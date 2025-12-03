from typing import Generator, Optional

from twisted.internet.defer import inlineCallbacks

from hathor.crypto.util import decode_address
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction, TxInput
from hathor.transaction.resources import PushTxResource
from hathor.transaction.scripts import P2PKH, parse_address_script
from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo
from hathor.wallet.resources import SendTokensResource
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest
from hathor_tests.utils import add_blocks_unlock_reward, add_tx_with_data_script, create_tokens


class BasePushTxTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    is_post: Optional[bool] = None

    def setUp(self):
        super().setUp()
        self.web = StubSite(PushTxResource(self.manager))
        self.web_tokens = StubSite(SendTokensResource(self.manager, self._settings))

    def get_tx(self, inputs: Optional[list[WalletInputInfo]] = None,
               outputs: Optional[list[WalletOutputInfo]] = None) -> Transaction:
        if not outputs:
            address = self.get_address(0)
            assert address is not None
            outputs = [
                WalletOutputInfo(address=decode_address(address), value=1, timelock=None),
                WalletOutputInfo(address=decode_address(address), value=1, timelock=None)
            ]
        if inputs:
            tx = self.manager.wallet.prepare_transaction(Transaction, inputs, outputs)
        else:
            tx = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)

        tx.storage = self.manager.tx_storage
        tx.weight = 1
        max_ts_spent_tx = max(tx.get_spent_tx(txin).timestamp for txin in tx.inputs)
        tx.timestamp = max(max_ts_spent_tx + 1, int(self.manager.reactor.seconds()))
        tx.parents = self.manager.get_new_tx_parents(tx.timestamp)
        self.manager.cpu_mining_service.resolve(tx)
        tx.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        return tx

    def push_tx(self, data=None):
        if self.is_post is None:
            raise Exception('You must set self.is_push before calling this method.')

        if self.is_post:
            body = data
            return self.web.post('push_tx', body)

        if data is None:
            args = None
        else:
            args = {}
            for k, v in data.items():
                nk = k.encode()
                if isinstance(v, str):
                    nv = v.encode()
                elif isinstance(v, bool):
                    nv = b'true' if v else b'false'
                else:
                    raise NotImplementedError
                args[nk] = nv
        return self.web.get('push_tx', args)

    @inlineCallbacks
    def test_push_tx(self) -> Generator:
        self.manager.wallet.unlock(b'MYPASS')
        blocks = add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)
        tx = self.get_tx()

        tx_hex = tx.get_struct().hex()
        response = yield self.push_tx({'hex_tx': tx_hex})
        data = response.json_value()
        self.assertTrue(data['success'])

        # Sending token to random address without input
        data_json = {'outputs': [{'address': self.get_address(0), 'value': 5}], 'inputs': []}
        yield self.web_tokens.post('wallet/send_tokens', {'data': data_json})

        # modify tx so it will be a double spending, then rejected
        tx.weight += 0.1
        self.manager.cpu_mining_service.resolve(tx)

        tx_hex = tx.get_struct().hex()
        response_success = yield self.push_tx({'hex_tx': tx_hex})
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
        response = yield self.push_tx({'hex_tx': tx_hex})
        data = response.json_value()
        self.assertFalse(data['success'])

        # force
        tx_hex = tx.get_struct().hex()
        response = yield self.push_tx({'hex_tx': tx_hex, 'force': True})
        data = response.json_value()
        self.assertFalse(data['success'])

        # Invalid tx (don't have inputs)
        genesis_tx = next(x for x in self.manager.tx_storage.get_all_genesis() if x.is_transaction)
        genesis_hex = genesis_tx.get_struct().hex()
        response_genesis = yield self.push_tx({'tx_hex': genesis_hex})
        data_genesis = response_genesis.json_value()
        self.assertFalse(data_genesis['success'])

        # Token creation tx
        script_type_out = parse_address_script(blocks[0].outputs[0].script)
        assert script_type_out is not None
        address = script_type_out.address
        tx2 = create_tokens(self.manager, address, mint_amount=100, propagate=False)
        tx2_hex = tx2.get_struct().hex()
        response = yield self.push_tx({'hex_tx': tx2_hex})
        data = response.json_value()
        self.assertTrue(data['success'])

    @inlineCallbacks
    def test_push_nft(self) -> Generator:
        self.manager.wallet.unlock(b'MYPASS')
        blocks = add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)
        # NFT creation tx
        script_type_out = parse_address_script(blocks[0].outputs[0].script)
        assert script_type_out is not None
        address = script_type_out.address
        tx3 = create_tokens(self.manager, address, mint_amount=100, propagate=False, nft_data='test')
        tx3_hex = tx3.get_struct().hex()
        response = yield self.push_tx({'hex_tx': tx3_hex})
        data = response.json_value()
        self.assertTrue(data['success'])

    @inlineCallbacks
    def test_invalid_params(self) -> Generator:
        # Missing hex
        response = yield self.push_tx()
        data = response.json_value()
        self.assertFalse(data['success'])

        # Missing hex 2
        response = yield self.push_tx({})
        data = response.json_value()
        self.assertFalse(data['success'])

        # Invalid hex
        response = yield self.push_tx({'hex_tx': 'XXXX'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # Invalid tx hex
        response_error2 = yield self.push_tx({'hex_tx': 'a12c'})
        data_error2 = response_error2.json_value()
        self.assertFalse(data_error2['success'])

    @inlineCallbacks
    def test_script_too_big(self) -> Generator:
        self.manager.wallet.unlock(b'MYPASS')
        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)
        tx = self.get_tx()

        # Invalid tx (output script is too long)
        tx.outputs[0].script = b'*' * (self._settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE + 1)
        self.manager.cpu_mining_service.resolve(tx)
        tx_hex = tx.get_struct().hex()
        response = yield self.push_tx({'hex_tx': tx_hex})
        data = response.json_value()
        self.assertFalse(data['success'])
        self.assertEqual('Transaction is non standard.', data['message'])

    @inlineCallbacks
    def test_non_standard_script(self) -> Generator:
        self.manager.wallet.unlock(b'MYPASS')
        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)
        tx = self.get_tx()

        # Invalid tx (output script is too long)
        tx.outputs[0].script = b'*' * 5
        self.manager.cpu_mining_service.resolve(tx)
        tx_hex = tx.get_struct().hex()
        response = yield self.push_tx({'hex_tx': tx_hex})
        data = response.json_value()
        self.assertFalse(data['success'])
        expected = 'Transaction is non standard.'
        self.assertEqual(expected, data['message'])

    @inlineCallbacks
    def test_spending_voided(self) -> Generator:
        self.manager.wallet.unlock(b'MYPASS')
        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        # Push a first tx
        tx = self.get_tx()
        tx_hex = tx.get_struct().hex()
        response = yield self.push_tx({'hex_tx': tx_hex})
        data = response.json_value()
        self.assertTrue(data['success'])

        wallet = self.manager.wallet

        # Pushing a tx that spends this first tx works
        txout = tx.outputs[0]
        p2pkh = parse_address_script(txout.script)
        assert p2pkh is not None
        private_key = wallet.get_private_key(p2pkh.address)
        inputs = [WalletInputInfo(tx_id=tx.hash, index=0, private_key=private_key)]
        outputs = [WalletOutputInfo(address=decode_address(p2pkh.address), value=txout.value, timelock=None), ]
        tx2 = self.get_tx(inputs, outputs)
        tx2_hex = tx2.get_struct().hex()
        response = yield self.push_tx({'hex_tx': tx2_hex})
        data = response.json_value()
        self.assertTrue(data['success'])

        # We have to get tx2 from the storage because the saved instance is different from the one we created here.
        tx2 = self.manager.tx_storage.get_transaction(tx2.hash)

        # Now we set this tx2 as voided and try to push a tx3 that spends tx2
        tx_meta = tx2.get_metadata()
        tx_meta.voided_by = {tx2.hash}
        self.manager.tx_storage.save_transaction(tx2, only_metadata=True)

        inputs = [WalletInputInfo(tx_id=tx2.hash, index=0, private_key=private_key)]
        outputs = [WalletOutputInfo(address=decode_address(p2pkh.address), value=txout.value, timelock=None), ]
        tx3 = self.get_tx(inputs, outputs)
        tx3_hex = tx3.get_struct().hex()
        response = yield self.push_tx({'hex_tx': tx3_hex})
        data = response.json_value()
        self.assertFalse(data['success'])

        # Now we set this tx2 as voided and try to push a tx3 that spends tx2
        tx_meta = tx2.get_metadata()
        tx_meta.voided_by = {self._settings.SOFT_VOIDED_ID}
        self.manager.tx_storage.save_transaction(tx2, only_metadata=True)

        # Try to push again with soft voided id as voided by
        response = yield self.push_tx({'hex_tx': tx3_hex})
        data = response.json_value()
        self.assertFalse(data['success'])

        # Now without voided_by the push tx must succeed
        tx_meta = tx2.get_metadata()
        tx_meta.voided_by = None
        self.manager.tx_storage.save_transaction(tx2, only_metadata=True)

        response = yield self.push_tx({'hex_tx': tx3_hex})
        data = response.json_value()
        self.assertTrue(data['success'])

    @inlineCallbacks
    def test_push_standard_script_data(self) -> Generator:
        # We accept transaction with at most 25 script data outputs
        # as standard
        self.manager.wallet.unlock(b'MYPASS')

        # First a tx with one data script output
        tx1 = add_tx_with_data_script(self.manager, ['test'], propagate=False)
        tx1_hex = tx1.get_struct().hex()

        response = yield self.push_tx({'hex_tx': tx1_hex})
        data = response.json_value()
        self.assertTrue(data['success'])

        self.manager.reactor.advance(1)

        # Now a tx with 25 data script outputs
        data25 = ['test{}'.format(i) for i in range(25)]
        tx25 = add_tx_with_data_script(self.manager, data25, propagate=False)
        tx25_hex = tx25.get_struct().hex()

        response = yield self.push_tx({'hex_tx': tx25_hex})
        data = response.json_value()
        self.assertTrue(data['success'])

        self.manager.reactor.advance(1)

        # Now a tx with 26 data script outputs and it must fail
        data26 = ['test{}'.format(i) for i in range(26)]
        tx26 = add_tx_with_data_script(self.manager, data26, propagate=False)
        tx26_hex = tx26.get_struct().hex()

        response = yield self.push_tx({'hex_tx': tx26_hex})
        data = response.json_value()
        self.assertFalse(data['success'])
        expected = 'Transaction is non standard.'
        self.assertEqual(expected, data['message'])


# GET


class PushTxGetTest(BasePushTxTest):
    is_post = False
    __test__ = True


# POST


class PushTxPostTest(BasePushTxTest):
    is_post = True
    __test__ = True
