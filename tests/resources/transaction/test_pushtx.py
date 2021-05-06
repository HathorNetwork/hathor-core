from typing import Generator, Optional

from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.transaction import Transaction, TxInput
from hathor.transaction.resources import PushTxResource
from hathor.transaction.scripts import P2PKH, parse_address_script
from hathor.wallet.base_wallet import WalletOutputInfo
from hathor.wallet.resources import SendTokensResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_blocks_unlock_reward, add_new_blocks, create_tokens

settings = HathorSettings()


class _BaseTests:
    class PushTxTest(_BaseResourceTest._ResourceTest):
        is_post: Optional[bool] = None

        def setUp(self):
            super().setUp()
            self.web = StubSite(PushTxResource(self.manager))
            self.web_tokens = StubSite(SendTokensResource(self.manager))

        def get_tx(self):
            address = self.get_address(0)
            outputs = [
                WalletOutputInfo(address=decode_address(address), value=1, timelock=None),
                WalletOutputInfo(address=decode_address(address), value=1, timelock=None)
            ]
            tx = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
            tx.weight = 1
            tx.parents = self.manager.get_new_tx_parents()
            tx.timestamp = int(self.clock.seconds())
            tx.resolve()
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
            tx.resolve()

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
            tx.outputs[0].script = b'*' * (settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE + 1)
            tx.resolve()
            tx_hex = tx.get_struct().hex()
            response = yield self.push_tx({'hex_tx': tx_hex})
            data = response.json_value()
            self.assertFalse(data['success'])
            self.assertEqual('Transaction has an output script that is too big.', data['message'])

        @inlineCallbacks
        def test_non_standard_script(self) -> Generator:
            self.manager.wallet.unlock(b'MYPASS')
            add_new_blocks(self.manager, 5, advance_clock=15)
            add_blocks_unlock_reward(self.manager)
            tx = self.get_tx()

            # Invalid tx (output script is too long)
            tx.outputs[0].script = b'*' * 5
            tx.resolve()
            tx_hex = tx.get_struct().hex()
            response = yield self.push_tx({'hex_tx': tx_hex})
            data = response.json_value()
            self.assertFalse(data['success'])
            expected = 'Transaction has a non-standard script. Only standard scripts are allowed.'
            self.assertEqual(expected, data['message'])


class PushTxGetTest(_BaseTests.PushTxTest):
    is_post = False


class PushTxPostTest(_BaseTests.PushTxTest):
    is_post = True
