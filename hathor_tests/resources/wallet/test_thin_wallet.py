import math
from typing import Any, Generator

from twisted.internet.defer import Deferred, inlineCallbacks

from hathor.crypto.util import decode_address
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH, create_output_script, parse_address_script
from hathor.transaction.token_info import TokenVersion
from hathor.wallet.resources.thin_wallet import (
    AddressHistoryResource,
    SendTokensResource,
    TokenHistoryResource,
    TokenResource,
)
from hathor_tests.resources.base_resource import StubSite, TestDummyRequest, _BaseResourceTest
from hathor_tests.utils import add_blocks_unlock_reward, add_new_tx, create_fee_tokens, create_tokens


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

        blocks = add_new_blocks(self.manager, 3, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        blocks_tokens = [sum(txout.value for txout in blk.outputs) for blk in blocks]

        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID].available, sum(blocks_tokens))

        # Options
        yield self.web.options('thin_wallet/send_tokens')

        tx_id = blocks[0].hash
        output = blocks[0].outputs[0]
        script_type_out = parse_address_script(output.script)
        address = script_type_out.address
        private_key = self.manager.wallet.get_private_key(address)

        output_address = decode_address(self.get_address(0))
        value = blocks_tokens[0]
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
        tx2.weight = self.manager.daa.minimum_tx_weight(tx2)

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
        tx3.weight = self.manager.daa.minimum_tx_weight(tx3)

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
        self.clock.advance(5)

        # Check if tokens were really sent
        self.assertEqual(
            self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID].available,
            sum(blocks_tokens[:-1])
        )

        response_history = yield self.web_address_history.get(
            'thin_wallet/address_history', {
                b'addresses[]': address.encode(),
            }
        )

        response_data = response_history.json_value()['history']
        self.assertIn(data['tx']['hash'], [x['tx_id'] for x in response_data])

        # Create token tx
        tx4 = create_tokens(self.manager, address, mint_amount=100, propagate=False)
        tx4.nonce = 0
        tx4.timestamp = int(self.clock.seconds())
        response = yield self.web.post('thin_wallet/send_tokens', {'tx_hex': tx4.get_struct().hex()})
        data = response.json_value()
        self.assertTrue(data['success'])
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
#                weight = minimum_tx_weight(tx)
#            tx.weight = weight
#            return tx.get_struct().hex()
#
#        # Making pow threads full
#        deferreds = []
#        for x in range(self._settings.MAX_POW_THREADS):
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

    @inlineCallbacks
    def test_history_paginate(self):
        # Unlocking wallet
        self.manager.wallet.unlock(b'MYPASS')

        blocks = add_new_blocks(self.manager, 3, advance_clock=1)

        output = blocks[0].outputs[0]
        script_type_out = parse_address_script(output.script)
        address = script_type_out.address
        address_bytes = decode_address(address)

        # Test paginate
        response_history = yield self.web_address_history.get(
            'thin_wallet/address_history', {
                b'addresses[]': address.encode(),
            }
        )

        response_data = response_history.json_value()
        self.assertEqual(len(response_data['history']), 1)
        self.assertEqual(blocks[0].hash.hex(), response_data['history'][0]['tx_id'])
        self.assertFalse(response_data['has_more'])

        new_blocks = add_new_blocks(
            self.manager,
            self._settings.MAX_TX_ADDRESSES_HISTORY,
            advance_clock=1,
            address=address_bytes
        )

        # Test paginate with two pages
        response_history = yield self.web_address_history.get(
            'thin_wallet/address_history', {
                b'addresses[]': address.encode(),
            }
        )

        response_data = response_history.json_value()
        self.assertEqual(len(response_data['history']), self._settings.MAX_TX_ADDRESSES_HISTORY)
        self.assertTrue(response_data['has_more'])
        self.assertEqual(response_data['first_address'], address)

        # Test paginate with big txs
        tx_count = math.ceil(self._settings.MAX_INPUTS_OUTPUTS_ADDRESS_HISTORY / self._settings.MAX_NUM_INPUTS)
        blocks.extend(new_blocks)
        new_blocks = add_new_blocks(
            self.manager,
            tx_count*self._settings.MAX_NUM_INPUTS - len(blocks),
            advance_clock=1,
            address=address_bytes
        )
        blocks.extend(new_blocks)
        random_address = self.get_address(0)
        add_blocks_unlock_reward(self.manager)

        for i in range(tx_count):
            start_index = i*self._settings.MAX_NUM_INPUTS
            end_index = start_index + self._settings.MAX_NUM_INPUTS
            amount = sum([b.outputs[0].value for b in blocks[start_index:end_index]])
            add_new_tx(self.manager, random_address, amount, advance_clock=1)

        response_history = yield self.web_address_history.get(
            'thin_wallet/address_history', {
                b'addresses[]': random_address.encode(),
            }
        )

        response_data = response_history.json_value()
        self.assertTrue(response_data['has_more'])
        # 1 block + 3 big txs
        self.assertEqual(len(response_data['history']), tx_count - 1)

        response_history = yield self.web_address_history.get(
            'thin_wallet/address_history', {
                b'addresses[]': random_address.encode(),
                b'hash': response_data['first_hash'].encode(),
            }
        )

        response_data = response_history.json_value()
        self.assertFalse(response_data['has_more'])
        # The last big tx
        self.assertEqual(len(response_data['history']), 1)

    @inlineCallbacks
    def test_address_history_optimization_regression(self):
        # setup phase1: create 3 addresses with 2 transactions each in a certain order
        self.manager.wallet.unlock(b'MYPASS')
        address1 = self.get_address(0)
        address2 = self.get_address(1)
        address3 = self.get_address(2)
        baddress1 = decode_address(address1)
        baddress2 = decode_address(address2)
        baddress3 = decode_address(address3)
        [b1] = add_new_blocks(self.manager, 1, advance_clock=1, address=baddress1)
        [b2] = add_new_blocks(self.manager, 1, advance_clock=1, address=baddress3)
        [b3] = add_new_blocks(self.manager, 1, advance_clock=1, address=baddress2)
        [b4] = add_new_blocks(self.manager, 1, advance_clock=1, address=baddress1)
        [b5] = add_new_blocks(self.manager, 1, advance_clock=1, address=baddress2)
        [b6] = add_new_blocks(self.manager, 1, advance_clock=1, address=baddress3)
        add_blocks_unlock_reward(self.manager)

        # setup phase2: make the first request without a `hash` argument
        self.web_address_history.resource.max_tx_addresses_history = 3
        res = (yield self.web_address_history.get(
            'thin_wallet/address_history', [
                (b'paginate', True),  # this isn't needed, but used to ensure compatibility is not removed
                (b'addresses[]', address1.encode()),
                (b'addresses[]', address3.encode()),
                (b'addresses[]', address2.encode()),
            ]
        )).json_value()
        self.assertTrue(res['success'])
        self.assertEqual(len(res['history']), 3)
        self.assertTrue(res['has_more'])
        self.assertEqual(res['first_address'], address3)
        self.assertEqual(res['first_hash'], b6.hash_hex)
        self.assertEqual([t['tx_id'] for t in res['history']], [b1.hash_hex, b4.hash_hex, b2.hash_hex])

        # actual test, this request will miss transactions when the regression is present
        res = (yield self.web_address_history.get(
            'thin_wallet/address_history', [
                (b'paginate', True),  # this isn't needed, but used to ensure compatibility is not removed
                (b'addresses[]', address3.encode()),
                (b'addresses[]', address2.encode()),
                (b'hash', res['first_hash'].encode()),
            ]
        )).json_value()
        self.assertTrue(res['success'])
        self.assertEqual(len(res['history']), 3)
        self.assertFalse(res['has_more'])
        self.assertEqual([t['tx_id'] for t in res['history']], [b6.hash_hex, b3.hash_hex, b5.hash_hex])

    def test_error_request(self):
        from hathor.wallet.resources.thin_wallet.send_tokens import _Context

        resource = SendTokensResource(self.manager)
        request = TestDummyRequest('POST', 'thin_wallet/send_tokens', {})
        dummy_tx = Transaction()

        self.assertIsNotNone(request._finishedDeferreds)
        resource._err_tx_resolve('Error', _Context(tx=dummy_tx, request=request), 'error')
        self.assertIsNone(request._finishedDeferreds)

    @inlineCallbacks
    def test_token(self):
        self.manager.wallet.unlock(b'MYPASS')
        resource = StubSite(TokenResource(self.manager))

        # test list of tokens empty
        response_list1 = yield resource.get('thin_wallet/token')
        data_list1 = response_list1.json_value()
        self.assertTrue(data_list1['success'])
        self.assertEqual(len(data_list1['tokens']), 0)

        # test invalid token id
        response = yield resource.get('thin_wallet/token', {b'id': 'vvvv'.encode()})
        data = response.json_value()
        self.assertFalse(data['success'])

        # test invalid token id
        response = yield resource.get('thin_wallet/token', {b'id': '1234'.encode()})
        data = response.json_value()
        self.assertFalse(data['success'])

        # test unknown token id
        unknown_uid = '00000000228ed1dd74a2e1b920c1d64bf81dc63875dce4fac486001073b45a27'.encode()
        response = yield resource.get('thin_wallet/token', {b'id': unknown_uid})
        data = response.json_value()
        self.assertFalse(data['success'])

        # test success case
        add_new_blocks(self.manager, 1, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        token_name = 'MyTestToken'
        token_symbol = 'MTT'
        token_info_version = TokenVersion.DEPOSIT
        amount = 150
        tx = create_tokens(
            self.manager,
            mint_amount=amount,
            token_name=token_name,
            token_symbol=token_symbol,
            use_genesis=False
        )
        token_uid = tx.tokens[0]
        response = yield resource.get('thin_wallet/token', {b'id': token_uid.hex().encode()})
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertEqual(len(data['mint']), 1)
        self.assertEqual(len(data['melt']), 1)
        self.assertEqual(data['mint'][0]['tx_id'], tx.hash_hex)
        self.assertEqual(data['melt'][0]['tx_id'], tx.hash_hex)
        self.assertEqual(data['mint'][0]['index'], 1)
        self.assertEqual(data['melt'][0]['index'], 2)
        self.assertTrue(data['can_mint'])
        self.assertTrue(data['can_melt'])
        self.assertEqual(data['total'], amount)
        self.assertEqual(data['name'], token_name)
        self.assertEqual(data['symbol'], token_symbol)
        self.assertEqual(data['version'], token_info_version)

        # test list of tokens with one token
        response_list2 = yield resource.get('thin_wallet/token')
        data_list2 = response_list2.json_value()
        self.assertTrue(data_list2['success'])
        self.assertEqual(len(data_list2['tokens']), 1)
        self.assertEqual(data_list2['tokens'][0]['name'], token_name)
        self.assertEqual(data_list2['tokens'][0]['symbol'], token_symbol)
        self.assertEqual(data_list2['tokens'][0]['uid'], tx.hash.hex())
        self.assertEqual(data_list2['tokens'][0]['version'], token_info_version)

        token_name2 = 'New Token'
        token_symbol2 = 'NTK'
        tx2 = create_tokens(
            self.manager,
            mint_amount=amount,
            token_name=token_name2,
            token_symbol=token_symbol2,
            use_genesis=False
        )

        token_name3 = 'Wat Coin'
        token_symbol3 = 'WTC'
        tx3 = create_tokens(
            self.manager,
            mint_amount=amount,
            token_name=token_name3,
            token_symbol=token_symbol3,
            use_genesis=False
        )

        # test list of tokens with 3 tokens
        response_list3 = yield resource.get('thin_wallet/token')
        data_list3 = response_list3.json_value()
        self.assertTrue(data_list3['success'])
        self.assertEqual(len(data_list3['tokens']), 3)
        token1 = {'uid': tx.hash.hex(), 'name': token_name, 'symbol': token_symbol, 'version': token_info_version}
        token2 = {'uid': tx2.hash.hex(), 'name': token_name2, 'symbol': token_symbol2, 'version': token_info_version}
        token3 = {'uid': tx3.hash.hex(), 'name': token_name3, 'symbol': token_symbol3, 'version': token_info_version}
        self.assertIn(token1, data_list3['tokens'])
        self.assertIn(token2, data_list3['tokens'])
        self.assertIn(token3, data_list3['tokens'])

        # test no wallet index
        manager2 = self.create_peer(self.network, unlock_wallet=True)
        resource2 = StubSite(TokenResource(manager2))
        response2 = yield resource2.get('thin_wallet/token')
        data2 = response2.json_value()
        self.assertEqual(response2.responseCode, 503)
        self.assertFalse(data2['success'])

    @inlineCallbacks
    def test_fee_token(self) -> Generator[Deferred[Any], Any, None]:
        self.manager.wallet.unlock(b'MYPASS')
        resource = StubSite(TokenResource(self.manager))

        # test success case
        add_new_blocks(self.manager, 1, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        token_name = 'MyTestToken'
        token_symbol = 'MTT'
        token_info_version = TokenVersion.FEE
        amount = 150
        tx = create_fee_tokens(
            self.manager,
            mint_amount=amount,
            token_name=token_name,
            token_symbol=token_symbol,
        )
        token_uid = tx.tokens[0]
        response = yield resource.get('thin_wallet/token', {b'id': token_uid.hex().encode()})
        data = response.json_value()

        self.assertEqual(data['version'], token_info_version)

    @inlineCallbacks
    def test_token_history(self):
        self.manager.wallet.unlock(b'MYPASS')
        resource = StubSite(TokenHistoryResource(self.manager))

        add_new_blocks(self.manager, 1, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        tx = create_tokens(self.manager, mint_amount=100, token_name='Teste', token_symbol='TST')
        token_uid = tx.tokens[0]

        response = yield resource.get('thin_wallet/token_history', {b'id': token_uid.hex().encode(), b'count': b'3'})
        data = response.json_value()
        # Success returning the token creation tx
        self.assertTrue(data['success'])
        self.assertFalse(data['has_more'])
        self.assertEqual(1, len(data['transactions']))
        self.assertEqual(tx.hash.hex(), data['transactions'][0]['tx_id'])

        response = yield resource.get('thin_wallet/token_history', {b'id': b'123', b'count': b'3'})
        data = response.json_value()
        # Fail because token is unknown
        self.assertFalse(data['success'])

        # Create a tx with this token, so we can have more tx in the history
        output = tx.outputs[0]
        script_type_out = parse_address_script(output.script)
        address = script_type_out.address
        private_key = self.manager.wallet.get_private_key(address)

        output_address = decode_address(self.get_address(0))
        o = TxOutput(100, create_output_script(output_address, None), 1)
        i = TxInput(tx.hash, 0, b'')

        tx2 = Transaction(inputs=[i], outputs=[o], tokens=[token_uid])
        data_to_sign = tx2.get_sighash_all()
        public_key_bytes, signature_bytes = self.manager.wallet.get_input_aux_data(data_to_sign, private_key)
        i.data = P2PKH.create_input_data(public_key_bytes, signature_bytes)
        tx2.inputs = [i]
        tx2.timestamp = int(self.clock.seconds())
        tx2.weight = self.manager.daa.minimum_tx_weight(tx2)
        tx2.parents = self.manager.get_new_tx_parents()
        self.manager.cpu_mining_service.resolve(tx2)
        self.manager.propagate_tx(tx2)

        # Now we have 2 txs with this token
        response = yield resource.get('thin_wallet/token_history', {b'id': token_uid.hex().encode(), b'count': b'3'})
        data = response.json_value()
        # Success returning the token creation tx and newly created tx
        self.assertTrue(data['success'])
        self.assertFalse(data['has_more'])
        self.assertEqual(2, len(data['transactions']))
        self.assertEqual(tx2.hash.hex(), data['transactions'][0]['tx_id'])
        self.assertEqual(tx.hash.hex(), data['transactions'][1]['tx_id'])

        response = yield resource.get('thin_wallet/token_history', {b'id': token_uid.hex().encode(), b'count': b'1'})
        data = response.json_value()
        # Testing has_more
        self.assertTrue(data['success'])
        self.assertTrue(data['has_more'])
        self.assertEqual(1, len(data['transactions']))

        response = yield resource.get('thin_wallet/token_history', {
            b'id': token_uid.hex().encode(),
            b'count': b'10',
            b'page': b'next',
            b'hash': tx2.hash.hex().encode(),
            b'timestamp': str(tx2.timestamp).encode(),
        })
        data = response.json_value()
        # Testing next
        self.assertTrue(data['success'])
        self.assertFalse(data['has_more'])
        self.assertEqual(1, len(data['transactions']))
        self.assertEqual(tx.hash.hex(), data['transactions'][0]['tx_id'])

        response = yield resource.get('thin_wallet/token_history', {
            b'id': token_uid.hex().encode(),
            b'count': b'10',
            b'page': b'previous',
            b'hash': tx.hash.hex().encode(),
            b'timestamp': str(tx.timestamp).encode(),
        })
        data = response.json_value()
        # Testing previous
        self.assertTrue(data['success'])
        self.assertFalse(data['has_more'])
        self.assertEqual(1, len(data['transactions']))
        self.assertEqual(tx2.hash.hex(), data['transactions'][0]['tx_id'])

        response = yield resource.get('thin_wallet/token_history', {
            b'id': token_uid.hex().encode(),
            b'count': b'10',
            b'page': b'previous',
            b'hash': tx2.hash.hex().encode(),
            b'timestamp': str(tx2.timestamp).encode(),
        })
        data = response.json_value()
        # Testing previous from first
        self.assertTrue(data['success'])
        self.assertFalse(data['has_more'])
        self.assertEqual(0, len(data['transactions']))

    @inlineCallbacks
    def test_address_history_invalid_params(self):
        # missing param
        response_history = yield self.web_address_history.get('thin_wallet/address_history')
        response_data = response_history.json_value()
        self.assertFalse(response_data['success'])

        # invalid address
        response_history = yield self.web_address_history.get(
            'thin_wallet/address_history', {
                b'addresses[]': b'aaa'
            }
        )
        response_data = response_history.json_value()
        self.assertFalse(response_data['success'])

        # invalid tx_version parameter
        address = self.get_address(0)
        response_history = yield self.web_address_history.get(
            'thin_wallet/address_history', {
                b'addresses[]': address.encode('utf-8'),
                b'tx_version[]': b'INVALID'
            }
        )
        response_data = response_history.json_value()
        self.assertEqual(response_history.responseCode, 400)
        self.assertFalse(response_data['success'])
        self.assertIn('Invalid tx_version parameter', response_data['message'])

    @inlineCallbacks
    def test_address_history_invalid_params_post(self):
        # missing param
        response_history = yield self.web_address_history.post('thin_wallet/address_history')
        response_data = response_history.json_value()
        self.assertFalse(response_data['success'])

        # invalid address
        response_history = yield self.web_address_history.post(
            'thin_wallet/address_history', {
                'addresses[]': 'aaa'
            }
        )
        response_data = response_history.json_value()
        self.assertFalse(response_data['success'])

        # invalid tx_version parameter - non-integer
        address = self.get_address(0)
        response_history = yield self.web_address_history.post(
            'thin_wallet/address_history', {
                'addresses': [address],
                'tx_version': ['INVALID']
            }
        )
        response_data = response_history.json_value()
        self.assertEqual(response_history.responseCode, 400)
        self.assertFalse(response_data['success'])
        self.assertIn('Invalid tx_version parameter', response_data['message'])

        # invalid tx_version parameter - string instead of list
        response_history = yield self.web_address_history.post(
            'thin_wallet/address_history', {
                'addresses': [address],
                'tx_version': 'NOT_A_NUMBER'
            }
        )
        response_data = response_history.json_value()
        self.assertEqual(response_history.responseCode, 400)
        self.assertFalse(response_data['success'])
        self.assertIn('Invalid tx_version parameter', response_data['message'])

    @inlineCallbacks
    def test_send_tokens_invalid_params(self):
        # missing body
        response = yield self.web.post('thin_wallet/send_tokens')
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing param
        response = yield self.web.post('thin_wallet/send_tokens', {'tx_hexYYY': 'aaa'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing param
        response = yield self.web.post('thin_wallet/send_tokens', {'tx_hex': 'aaa'})
        data = response.json_value()
        self.assertFalse(data['success'])

    @inlineCallbacks
    def test_token_history_zero_count(self):
        resource = StubSite(TokenHistoryResource(self.manager))
        response = yield resource.get('thin_wallet/token_history', {
            b'id': b'000003a3b261e142d3dfd84970d3a50a93b5bc3a66a3b6ba973956148a3eb824',
            b'count': b'0'
        })
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertEqual(0, len(data['transactions']))
        self.assertFalse(data['has_more'])

    @inlineCallbacks
    def test_token_history_negative_count(self):
        resource = StubSite(TokenHistoryResource(self.manager))
        response = yield resource.get('thin_wallet/token_history', {
            b'id': b'000003a3b261e142d3dfd84970d3a50a93b5bc3a66a3b6ba973956148a3eb824',
            b'count': b'-1'
        })
        data = response.json_value()
        self.assertFalse(data['success'])

    @inlineCallbacks
    def test_token_history_negative_timestamp(self):
        resource = StubSite(TokenHistoryResource(self.manager))
        response = yield resource.get('thin_wallet/token_history', {
            b'id': b'000003a3b261e142d3dfd84970d3a50a93b5bc3a66a3b6ba973956148a3eb824',
            b'count': b'3',
            b'hash': b'0000b1448893eb7efdd3c71b97b74d934a4ecaaf8a6b52f6cb5b60fdaf21497b',
            b'timestamp': b'-1578118186',
            b'page': b'next',
        })
        data = response.json_value()
        self.assertFalse(data['success'])

    @inlineCallbacks
    def test_token_history_invalid_params(self):
        resource = StubSite(TokenHistoryResource(self.manager))

        # invalid count
        response = yield resource.get('thin_wallet/token_history', {
            b'id': b'000003a3b261e142d3dfd84970d3a50a93b5bc3a66a3b6ba973956148a3eb824',
            b'count': b'a'
        })
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing token uid
        response = yield resource.get('thin_wallet/token_history', {
            b'count': b'3'
        })
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid token uid
        response = yield resource.get('thin_wallet/token_history', {
            b'id': b'000',
            b'count': b'3'
        })
        data = response.json_value()
        self.assertFalse(data['success'])

        response = yield resource.get('thin_wallet/token_history', {
            b'id': b'0000',
            b'count': b'3'
        })
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing timestamp
        response = yield resource.get('thin_wallet/token_history', {
            b'id': b'000003a3b261e142d3dfd84970d3a50a93b5bc3a66a3b6ba973956148a3eb824',
            b'count': b'3',
            b'hash': b'0000b1448893eb7efdd3c71b97b74d934a4ecaaf8a6b52f6cb5b60fdaf21497b',
        })
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid timestamp
        response = yield resource.get('thin_wallet/token_history', {
            b'id': b'000003a3b261e142d3dfd84970d3a50a93b5bc3a66a3b6ba973956148a3eb824',
            b'count': b'3',
            b'hash': b'0000b1448893eb7efdd3c71b97b74d934a4ecaaf8a6b52f6cb5b60fdaf21497b',
            b'timestamp': b'a'
        })
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid hash
        response = yield resource.get('thin_wallet/token_history', {
            b'id': b'000003a3b261e142d3dfd84970d3a50a93b5bc3a66a3b6ba973956148a3eb824',
            b'count': b'3',
            b'timestamp': b'1578118186',
            b'page': b'next',
            b'hash': b'000',
        })
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid page
        response = yield resource.get('thin_wallet/token_history', {
            b'id': b'000003a3b261e142d3dfd84970d3a50a93b5bc3a66a3b6ba973956148a3eb824',
            b'count': b'3',
            b'timestamp': b'1578118186',
            b'page': b'nextYY',
            b'hash': b'0000b1448893eb7efdd3c71b97b74d934a4ecaaf8a6b52f6cb5b60fdaf21497b',
        })
        data = response.json_value()
        self.assertFalse(data['success'])
