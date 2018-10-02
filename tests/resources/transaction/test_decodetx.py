from hathor.transaction.resources import DecodeTxResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import TestSite, _BaseResourceTest
from hathor.transaction.genesis import genesis_transactions


class DecodeTxTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = TestSite(DecodeTxResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        genesis_tx = genesis_transactions(self.manager.tx_storage)[1]
        response_success = yield self.web.get("decode_tx", {b'hex_tx': bytes(genesis_tx.get_struct().hex(), 'utf-8')})
        data_success = response_success.json_value()

        self.assertTrue(data_success['success'])
        data_genesis = genesis_tx.to_json(decode_script=True)
        data_genesis['accumulated_weight'] = genesis_tx.get_metadata().accumulated_weight
        self.assertEqual(data_success['transaction'], data_genesis)

        # Invalid hex
        response_error1 = yield self.web.get("decode_tx", {b'hex_tx': b'XXXX'})
        data_error1 = response_error1.json_value()

        self.assertFalse(data_error1['success'])

        # Invalid tx hex
        response_error2 = yield self.web.get("decode_tx", {b'hex_tx': b'a12c'})
        data_error2 = response_error2.json_value()

        self.assertFalse(data_error2['success'])
