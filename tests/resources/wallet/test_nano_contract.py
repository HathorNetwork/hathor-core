from hathor.wallet.resources import SignTxResource
from hathor.transaction.resources import PushTxResource, DecodeTxResource
from hathor.wallet.resources.nano_contracts import NanoContractDecodeResource, NanoContractExecuteResource, \
                                                   NanoContractMatchValueResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_new_blocks


class NanoContractsTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.manager.wallet.unlock(b"MYPASS")

    @inlineCallbacks
    def test_match_values(self):
        decode_resource = StubSite(NanoContractDecodeResource(self.manager))
        execute_resource = StubSite(NanoContractExecuteResource(self.manager))
        match_value_resource = StubSite(NanoContractMatchValueResource(self.manager))
        pushtx_resource = StubSite(PushTxResource(self.manager))
        signtx_resource = StubSite(SignTxResource(self.manager))
        decodetx_resource = StubSite(DecodeTxResource(self.manager))
        add_new_blocks(self.manager, 3)
        self.reactor.advance(3)
        # Options
        yield match_value_resource.options("wallet/nano_contracts/match_values")

        # create nano contract
        address1 = '1Pa4MMsr5DMRAeU1PzthFXyEJeVNXsMHoz'
        data_post = {
            'oracle_pubkey_hash': '6o6ul2c+sqAariBVW+CwNaSJb9w=',
            'oracle_data_id': 'some_id',
            'total_value': 2000,
            'input_value': 2000,
            'min_timestamp': 1,
            'fallback_address': '1CBxvu6tFPTU8ygSPj9vyEadf9DsqTwy3D',
            'values': [{'address': address1, 'value': 300}]
        }
        response = yield match_value_resource.post(
            "wallet/nano_contracts/match_value",
            data_post
        )
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertIsNotNone(data['hex_tx'])
        nano_contract_hex = data['hex_tx']

        # decode
        response_decode = yield decode_resource.get(
            "wallet/nano_contracts/decode",
            {b'hex_tx': bytes(nano_contract_hex, 'utf-8')}
        )
        data = response_decode.json_value()
        self.assertTrue(data['success'])
        nano_contract = data['nano_contract']
        self.assertIsNotNone(nano_contract)
        self.assertEqual(nano_contract['type'], 'NanoContractMatchValues')
        self.assertEqual(len(data['other_inputs']), 0)
        self.assertEqual(len(data['my_inputs']), 1)
        self.assertEqual(len(data['outputs']), 0)

        # update
        address2 = '1CBxvu6tFPTU8ygSPj9vyEadf9DsqTwy3D'
        data_put = {
            'hex_tx': nano_contract_hex,
            'new_values': [{'address': address2, 'value': 500}],
            'input_value': 2000
        }
        response = yield match_value_resource.put(
            "wallet/nano_contracts/match_value",
            data_put
        )
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertIsNotNone(data['hex_tx'])

        # sign tx
        response = yield signtx_resource.get(
            "wallet/sign_tx",
            {b'hex_tx': bytes(nano_contract_hex, 'utf-8'), b'prepare_to_send': b'true'}
        )
        data = response.json_value()
        self.assertTrue(data['success'])
        nano_contract_hex = data['hex_tx']

        # propagate tx
        response = yield pushtx_resource.get("push_tx", {b'hex_tx': bytes(nano_contract_hex, 'utf-8')})
        data = response.json_value()
        self.assertTrue(data['success'])

        self.reactor.advance(3)

        # get tx hash
        response = yield decodetx_resource.get("decode_tx", {b'hex_tx': bytes(nano_contract_hex, 'utf-8')})
        data = response.json_value()
        self.assertTrue(data['success'])
        hash_hex = data['transaction']['hash']

        # execute nano contract
        data = {
            'spent_tx_id': hash_hex,
            'spent_tx_index': 0,
            'oracle_data': 'B3NvbWVfaWQEW/xjGQIBLA==',
            'oracle_signature': 'MEUCIGeqbmLRI6lrgXMy4sQEgK94F5m14oVL5Z7oLLVII7BUAiEApKTMuWlwvws574'
                                '+jtqKW5/AuH+ICD0u+HyMyHe0aric=',
            'oracle_pubkey': 'Awmloohhey8WhajdDURgvbk1z3JHX2vxDSBjz9uG9wEp',
            'address': address1,
            'value': 2000
        }
        response = yield execute_resource.post(
            "wallet/nano_contracts/execute",
            data
        )
        data = response.json_value()
        self.assertTrue(data['success'])


if __name__ == '__main__':
    unittest.main()
