import json
import time

from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import Clock

from hathor.constants import DECIMAL_PLACES, HATHOR_TOKEN_UID, TOKENS_PER_BLOCK
from hathor.transaction.resources import SignDataResource
from hathor.transaction.scripts import parse_address_script
from hathor.wallet.resources.thin_wallet import AddressHistoryResource, SendTokensResource
from tests.resources.base_resource import StubSite, TestDummyRequest, _BaseResourceTest
from tests.utils import add_new_blocks


class SendTokensTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()

        self.clock = Clock()
        self.clock.advance(time.time())
        self.network = 'testnet'
        self.manager2 = self.create_peer(self.network, unlock_wallet=True, wallet_index=True)

        self.web = StubSite(SendTokensResource(self.manager2))
        self.web_address_history = StubSite(AddressHistoryResource(self.manager2))
        self.web_sign_data = StubSite(SignDataResource())

    @inlineCallbacks
    def test_post(self):
        # Unlocking wallet
        self.manager2.wallet.unlock(b'MYPASS')

        per_block = TOKENS_PER_BLOCK * (10**DECIMAL_PLACES)
        quantity = 3

        blocks = add_new_blocks(self.manager2, quantity)

        self.assertEqual(self.manager2.wallet.balance[HATHOR_TOKEN_UID].available, quantity*per_block)

        # Options
        yield self.web.options('thin_wallet/send_tokens')

        tx_id = blocks[0].hash_hex
        output = blocks[0].outputs[0]
        script_type_out = parse_address_script(output.script)
        address = script_type_out.address
        private_key = self.manager2.wallet.get_private_key(address)

        output_address = '15d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH'
        invalid_address = '1234'
        value = per_block
        o = json.dumps({'address': output_address, 'value': value}).encode('utf-8')
        o_invalid = json.dumps({'address': invalid_address, 'value': value}).encode('utf-8')
        i = json.dumps({'tx_id': tx_id, 'index': 0}).encode('utf-8')

        # Error with invalid address
        response_error = yield self.web_sign_data.get(
            'sign_data', {
                b'outputs[]': o_invalid,
                b'inputs[]': i
            }
        )
        error_data = response_error.json_value()
        self.assertFalse(error_data['success'])

        # First get data to be signed
        response_sign_data = yield self.web_sign_data.get(
            'sign_data', {
                b'outputs[]': o,
                b'inputs[]': i
            }
        )

        # First get data to be signed
        response_sign_data = yield self.web_sign_data.get(
            'sign_data', {
                b'outputs[]': o,
                b'inputs[]': i
            }
        )

        data_to_sign = bytes.fromhex(response_sign_data.json_value()['data_to_sign'])
        public_key_bytes, signature_bytes = self.manager2.wallet.get_input_aux_data(data_to_sign, private_key)

        public_key = public_key_bytes.hex()
        signature = signature_bytes.hex()

        data_invalid_json = {
            'outputs': [
                {'address': invalid_address, 'value': value}
            ],
            'inputs': [
                {'tx_id': tx_id, 'index': 0, 'signature': signature, 'public_key': public_key}
            ]
        }
        # Error invalid address
        response_invalid = yield self.web.post('wallet/send_tokens', {'data': data_invalid_json})
        data_invalid = response_invalid.json_value()
        self.assertFalse(data_invalid['success'])

        data_wrong_amount_json = {
            'outputs': [
                {'address': output_address, 'value': value-1}
            ],
            'inputs': [
                {'tx_id': tx_id, 'index': 0, 'signature': signature, 'public_key': public_key}
            ]
        }
        # Error wrong amount
        response_wrong_amount = yield self.web.post('wallet/send_tokens', {'data': data_wrong_amount_json})
        data_wrong_amount = response_wrong_amount.json_value()
        self.assertFalse(data_wrong_amount['success'])

        data_json = {
            'outputs': [
                {'address': output_address, 'value': value}
            ],
            'inputs': [
                {'tx_id': tx_id, 'index': 0, 'signature': signature, 'public_key': public_key}
            ]
        }
        # Then send tokens
        response = yield self.web.post('wallet/send_tokens', {'data': data_json})
        data = response.json_value()
        self.assertTrue(data['success'])

        # Check if tokens were really sent
        self.assertEqual(self.manager2.wallet.balance[HATHOR_TOKEN_UID].available, (quantity-1)*per_block)

        response_history = yield self.web_address_history.get(
            'thin_wallet/address_history', {
                b'addresses[]': address.encode(),
            }
        )

        response_data = response_history.json_value()['history']
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0]['address'], address)
        self.assertEqual(len(response_data[0]['history']), 2)
        self.assertTrue(response_data[0]['history'][0]['is_output'])
        self.assertFalse(response_data[0]['history'][1]['is_output'])

    def test_error_request(self):
        resource = SendTokensResource(self.manager2)
        request = TestDummyRequest('POST', 'thin_wallet/send_tokens', {})

        self.assertIsNotNone(request._finishedDeferreds)
        resource._err_tx_resolve('Error', request)
        self.assertIsNone(request._finishedDeferreds)
