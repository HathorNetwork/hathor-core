import pytest
from twisted.internet.defer import inlineCallbacks

from hathor.simulator.utils import add_new_blocks
from hathor.transaction.resources import DecodeTxResource, PushTxResource
from hathor.transaction.vertex_parser import vertex_deserializer, vertex_serializer
from hathor.util import json_loadb
from hathor.wallet.resources import SignTxResource
from hathor.wallet.resources.nano_contracts import (
    NanoContractDecodeResource,
    NanoContractExecuteResource,
    NanoContractMatchValueResource,
)
from hathor_tests.resources.base_resource import StubSite, TestDummyRequest, _BaseResourceTest
from hathor_tests.utils import add_blocks_unlock_reward


@pytest.mark.skip(reason='old feature, this will be removed')
class NanoContractsTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.manager.wallet.unlock(b"MYPASS")

    @inlineCallbacks
    def test_match_values(self):
        decode_resource = StubSite(NanoContractDecodeResource(self.manager))
        execute_resource = StubSite(NanoContractExecuteResource(self.manager))
        match_value_resource = StubSite(NanoContractMatchValueResource(self.manager))
        pushtx_resource = StubSite(PushTxResource(self.manager, allow_non_standard_script=True))
        signtx_resource = StubSite(SignTxResource(self.manager))
        decodetx_resource = StubSite(DecodeTxResource(self.manager))
        add_new_blocks(self.manager, 3)
        add_blocks_unlock_reward(self.manager)
        self.reactor.advance(3)
        # Options
        yield match_value_resource.options("wallet/nano_contracts/match_values")

        total_value = self.manager.get_tokens_issued_per_block(1)

        address1 = self.get_address(0)
        data_post = {
            'oracle_data_id': 'some_id',
            'total_value': total_value,
            'input_value': total_value,
            'min_timestamp': 1,
            'fallback_address': self.get_address(1),
            'values': [{
                'address': address1,
                'value': 300
            }]
        }
        # Error missing parameter
        response_error = yield match_value_resource.post("wallet/nano_contracts/match_value", data_post)
        data_error = response_error.json_value()
        self.assertFalse(data_error['success'])
        self.assertEqual(data_error['message'], 'Missing parameter: oracle_pubkey_hash')

        # create nano contract
        data_post['oracle_pubkey_hash'] = '6o6ul2c+sqAariBVW+CwNaSJb9w='
        response = yield match_value_resource.post("wallet/nano_contracts/match_value", data_post)
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertIsNotNone(data['hex_tx'])
        nano_contract_hex = data['hex_tx']

        # Error missing parameter
        response_error = yield decode_resource.get("wallet/nano_contracts/decode", {})
        data_error = response_error.json_value()
        self.assertFalse(data_error['success'])
        self.assertEqual(data_error['message'], 'Missing parameter: hex_tx')

        # Error invalid hex
        response_error2 = yield decode_resource.get("wallet/nano_contracts/decode", {b'hex_tx': b'123'})
        data_error2 = response_error2.json_value()
        self.assertFalse(data_error2['success'])

        # Error valid hex but invalid tx struct
        response_error3 = yield decode_resource.get("wallet/nano_contracts/decode", {b'hex_tx': b'1334'})
        data_error3 = response_error3.json_value()
        self.assertFalse(data_error3['success'])

        # decode
        genesis_output = [tx for tx in self.manager.tx_storage.get_all_genesis() if tx.is_block][0].outputs[0]
        partial_tx = vertex_deserializer.deserialize(bytes.fromhex(nano_contract_hex))
        partial_tx.outputs.append(genesis_output)
        partial_hex = vertex_serializer.serialize(partial_tx).hex().encode()
        response_decode = yield decode_resource.get(
            "wallet/nano_contracts/decode", {b'hex_tx': partial_hex})
        data = response_decode.json_value()
        self.assertTrue(data['success'])
        nano_contract = data['nano_contract']
        self.assertIsNotNone(nano_contract)
        self.assertEqual(nano_contract['type'], 'NanoContractMatchValues')
        self.assertEqual(len(data['other_inputs']), 0)
        self.assertEqual(len(data['my_inputs']), 1)
        self.assertEqual(len(data['outputs']), 1)
        self.assertEqual(data['outputs'][0], genesis_output.to_human_readable())

        address2 = self.get_address(2)
        data_put = {'new_values': [{'address': address2, 'value': 500}], 'input_value': total_value}
        # Error missing parameter
        response_error = yield match_value_resource.put("wallet/nano_contracts/match_value", data_put)
        data_error = response_error.json_value()
        self.assertFalse(data_error['success'])
        self.assertEqual(data_error['message'], 'Missing parameter: hex_tx')

        # update
        data_put['hex_tx'] = vertex_serializer.serialize(partial_tx).hex()
        response = yield match_value_resource.put("wallet/nano_contracts/match_value", data_put)
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertIsNotNone(data['hex_tx'])

        # Error nano contract not found
        new_tx = vertex_deserializer.deserialize(vertex_serializer.serialize(partial_tx))
        new_tx.outputs = []
        data_put['hex_tx'] = vertex_serializer.serialize(new_tx).hex()
        response = yield match_value_resource.put("wallet/nano_contracts/match_value", data_put)
        data = response.json_value()
        self.assertFalse(data['success'])

        # Error missing parameter
        response_error = yield signtx_resource.get("wallet/sign_tx", {})
        data_error = response_error.json_value()
        self.assertFalse(data_error['success'])
        self.assertEqual(data_error['message'], 'Missing parameter: hex_tx')

        # Error wrong parameter value
        response_error2 = yield signtx_resource.get("wallet/sign_tx", {b'hex_tx': b'123', b'prepare_to_send': b'true'})
        data_error2 = response_error2.json_value()
        self.assertFalse(data_error2['success'])

        # Error valid hex but wrong tx struct value
        response_error3 = yield signtx_resource.get("wallet/sign_tx", {
            b'hex_tx': b'1334',
            b'prepare_to_send': b'true'
        })
        data_error3 = response_error3.json_value()
        self.assertFalse(data_error3['success'])

        # sign tx
        response = yield signtx_resource.get("wallet/sign_tx", {
            b'hex_tx': bytes(nano_contract_hex, 'utf-8'),
            b'prepare_to_send': b'true'
        })
        data = response.json_value()
        self.assertTrue(data['success'])
        nano_contract_hex = data['hex_tx']

        # sign tx without preparing
        response2 = yield signtx_resource.get("wallet/sign_tx", {b'hex_tx': bytes(nano_contract_hex, 'utf-8')})
        data2 = response2.json_value()
        self.assertTrue(data2['success'])
        self.assertIsNotNone(data2['hex_tx'])

        # propagate tx
        response = yield pushtx_resource.get("push_tx", {b'hex_tx': bytes(nano_contract_hex, 'utf-8')})
        data = response.json_value()
        self.assertTrue(data['success'])

        self.reactor.advance(3)

        # get tx hash
        response = yield decodetx_resource.get("decode_tx", {b'hex_tx': bytes(nano_contract_hex, 'utf-8')})
        data = response.json_value()
        self.assertTrue(data['success'])
        hash_hex = data['tx']['hash']

        # Options
        yield execute_resource.options("wallet/nano_contracts/execute")

        # Error no data
        response_error = yield execute_resource.post("wallet/nano_contracts/execute")
        data_error = response_error.json_value()
        self.assertFalse(data_error['success'])

        # Error missing parameter
        data = {
            'spent_tx_index': 0,
            'oracle_data': 'B3NvbWVfaWQEW/xjGQIBLA==',
            'oracle_signature': 'MEUCIGeqbmLRI6lrgXMy4sQEgK94F5m14oVL5Z7oLLVII7BUAiEApKTMuWlwvws574'
                                '+jtqKW5/AuH+ICD0u+HyMyHe0aric=',
            'oracle_pubkey': 'Awmloohhey8WhajdDURgvbk1z3JHX2vxDSBjz9uG9wEp',
            'address': address1,
            'value': total_value,
        }
        response_error2 = yield execute_resource.post("wallet/nano_contracts/execute", data)
        data_error2 = response_error2.json_value()
        self.assertFalse(data_error2['success'])
        self.assertEqual(data_error2['message'], 'Missing parameter: spent_tx_id')

        # execute nano contract
        data['spent_tx_id'] = hash_hex
        response = yield execute_resource.post("wallet/nano_contracts/execute", data)
        data = response.json_value()
        self.assertTrue(data['success'])

    def test_decode_error(self):
        resource = NanoContractExecuteResource(self.manager)
        request = TestDummyRequest('POST', 'wallet/nano_contracts/execute')
        request.content.setvalue(b'abc')

        response = resource.render_POST(request)
        data_response = json_loadb(response)
        self.assertFalse(data_response['success'])

        match_resource = NanoContractMatchValueResource(self.manager)
        request_match = TestDummyRequest('POST', 'wallet/nano_contracts/match_values')
        request_match.content.setvalue(b'abc')

        response_match = match_resource.render_POST(request_match)
        data_response_match = json_loadb(response_match)
        self.assertFalse(data_response_match['success'])

        request_match_put = TestDummyRequest('PUT', 'wallet/nano_contracts/match_values')
        request_match_put.content.setvalue(b'abc')

        response_match_put = match_resource.render_PUT(request_match_put)
        data_response_match_put = json_loadb(response_match_put)
        self.assertFalse(data_response_match_put['success'])
