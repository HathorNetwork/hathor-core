from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH, create_output_script, parse_address_script
from hathor.wallet.resources.thin_wallet import AddressHistoryResource, SendTokensResource
from tests.resources.base_resource import StubSite, TestDummyRequest, _BaseResourceTest
from tests.utils import add_new_blocks

settings = HathorSettings()


class SendTokensTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True, wallet_index=True)

        sendtokens_resource = SendTokensResource(self.manager)
        sendtokens_resource.sleep_seconds = 0.1

        self.web = StubSite(sendtokens_resource)
        self.web_address_history = StubSite(AddressHistoryResource(self.manager))

    @inlineCallbacks
    def test_post(self):
        # Unlocking wallet
        self.manager.wallet.unlock(b'MYPASS')

        per_block = settings.TOKENS_PER_BLOCK * (10**settings.DECIMAL_PLACES)
        quantity = 3

        blocks = add_new_blocks(self.manager, quantity)

        self.assertEqual(self.manager.wallet.balance[settings.HATHOR_TOKEN_UID].available, quantity*per_block)

        # Options
        yield self.web.options('thin_wallet/send_tokens')

        tx_id = blocks[0].hash
        output = blocks[0].outputs[0]
        script_type_out = parse_address_script(output.script)
        address = script_type_out.address
        private_key = self.manager.wallet.get_private_key(address)

        output_address = decode_address(self.get_address(0))
        value = per_block
        o = TxOutput(value, create_output_script(output_address, None))
        o_invalid_amount = TxOutput(value-1, create_output_script(output_address, None))
        i = TxInput(tx_id, 0, b'')

        # wrong weight
        tx = Transaction(inputs=[i], outputs=[o])

        data_to_sign = tx.get_sighash_all()
        public_key_bytes, signature_bytes = self.manager.wallet.get_input_aux_data(data_to_sign, private_key)

        i.data = P2PKH.create_input_data(public_key_bytes, signature_bytes)
        tx.inputs = [i]
        tx.timestamp = int(self.clock.seconds())
        tx.weight = 0

        response = yield self.web.post('thin_wallet/send_tokens', {'tx_hex': tx.get_struct().hex()})
        data = response.json_value()
        self.assertFalse(data['success'])

        # Error wrong amount
        tx2 = Transaction(inputs=[i], outputs=[o_invalid_amount])

        data_to_sign = tx2.get_sighash_all()
        public_key_bytes, signature_bytes = self.manager.wallet.get_input_aux_data(data_to_sign, private_key)

        i.data = P2PKH.create_input_data(public_key_bytes, signature_bytes)
        tx2.inputs = [i]
        tx2.timestamp = int(self.clock.seconds())
        tx2.weight = self.manager.minimum_tx_weight(tx2)

        response_wrong_amount = yield self.web.post('thin_wallet/send_tokens', {'tx_hex': tx2.get_struct().hex()})
        data_wrong_amount = response_wrong_amount.json_value()
        self.assertFalse(data_wrong_amount['success'])

        # successful tx
        tx3 = Transaction(inputs=[i], outputs=[o])

        data_to_sign = tx3.get_sighash_all()
        public_key_bytes, signature_bytes = self.manager.wallet.get_input_aux_data(data_to_sign, private_key)

        i.data = P2PKH.create_input_data(public_key_bytes, signature_bytes)
        tx3.inputs = [i]
        tx3.timestamp = int(self.clock.seconds())
        tx3.weight = self.manager.minimum_tx_weight(tx3)

        # Then send tokens
        response = yield self.web.post('thin_wallet/send_tokens', {'tx_hex': tx3.get_struct().hex()})
        data = response.json_value()
        self.assertTrue(data['success'])

        # Trying to send a double spending will not have success
        self.clock.advance(5)
        tx3.timestamp = int(self.clock.seconds())
        response = yield self.web.post('thin_wallet/send_tokens', {'tx_hex': tx3.get_struct().hex()})
        data_error = response.json_value()
        self.assertFalse(data_error['success'])

        # Check if tokens were really sent
        self.assertEqual(self.manager.wallet.balance[settings.HATHOR_TOKEN_UID].available, (quantity-1)*per_block)

        response_history = yield self.web_address_history.get(
            'thin_wallet/address_history', {
                b'addresses[]': address.encode(),
            }
        )

        response_data = response_history.json_value()['history']
        self.assertIn(data['tx']['hash'], [x['tx_id'] for x in response_data])
#
#       TODO these tests were causing timeouts in CI server [yan - 01.04.2019]
#       TODO add to top imports
#       from twisted.internet.defer import CancelledError, inlineCallbacks
#       from twisted.python.failure import Failure
#        def get_new_tx_struct(weight=0):
#            tx = Transaction(inputs=[i], outputs=[o])
#            tx.inputs = tx3.inputs
#            self.clock.advance(5)
#            tx.timestamp = int(self.clock.seconds())
#            if weight == 0:
#                weight = self.manager.minimum_tx_weight(tx)
#            tx.weight = weight
#            return tx.get_struct().hex()
#
#        # Making pow threads full
#        deferreds = []
#        for x in range(settings.MAX_POW_THREADS):
#            d = self.web.post('thin_wallet/send_tokens', {'tx_hex': get_new_tx_struct(50)})
#            d.addErrback(lambda err: None)
#            deferreds.append(d)
#
#        # All threads are in use
#        response = yield self.web.post('thin_wallet/send_tokens', {'tx_hex': get_new_tx_struct(1)})
#        data = response.json_value()
#        self.assertFalse(data['success'])
#
#        # Releasing one thread
#        d = deferreds.pop()
#        d.request.processingFailed(Failure(CancelledError()))
#
#        # Waiting for thread to finish
#        yield d.request.thread_deferred
#
#        # Now you can send
#        response = yield self.web.post('thin_wallet/send_tokens', {'tx_hex': get_new_tx_struct(1)})
#        data = response.json_value()
#        self.assertTrue(data['success'])
#
#        # Releasing all other threads
#        for d in deferreds:
#            d.request.processingFailed(Failure(CancelledError()))
#
#        # Waiting for all threads to finish
#        for d in deferreds:
#            yield d.request.thread_deferred

    def test_error_request(self):
        resource = SendTokensResource(self.manager)
        request = TestDummyRequest('POST', 'thin_wallet/send_tokens', {})

        self.assertIsNotNone(request._finishedDeferreds)
        resource._err_tx_resolve('Error', request)
        self.assertIsNone(request._finishedDeferreds)
