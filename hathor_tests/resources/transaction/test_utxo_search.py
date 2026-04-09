from twisted.internet.defer import inlineCallbacks

from hathor.crypto.util import decode_address
from hathor.simulator.utils import add_new_blocks
from hathor.transaction.resources import UtxoSearchResource
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest
from hathor_tests.utils import add_blocks_unlock_reward


class UtxoSearchTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp(utxo_index=True)
        self.web = StubSite(UtxoSearchResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')

    @inlineCallbacks
    def test_simple_gets(self):
        address = self.get_address(0).encode('ascii')

        add_new_blocks(self.manager, 4, advance_clock=1)

        # Error1: No parameter
        response1 = yield self.web.get("utxo_search")
        data1 = response1.json_value()
        self.assertFalse(data1['success'])
        self.assertEqual(data1['message'], 'Missing parameter: address, target_amount, token_uid')

        # Error2: Invalid parameter
        response2 = yield self.web.get("utxo_search", {b'token_uid': b'c',
                                                       b'address': address, b'target_amount': b'1'})
        data2 = response2.json_value()
        self.assertFalse(data2['success'])
        self.assertEqual(
            data2['message'],
            r'''Failed to parse 'token_uid': non-hexadecimal number found in fromhex() arg at position 1''',
        )

        # Success empty address
        response3 = yield self.web.get("utxo_search", {b'token_uid': b'00',
                                                       b'address': address, b'target_amount': b'1'})
        data3 = response3.json_value()
        self.assertTrue(data3['success'])
        self.assertEqual(data3['utxos'], [])

        # Add some blocks with the address that we have, we'll have 4 outputs of 64.00 HTR each, 256.00 HTR in total
        blocks = add_new_blocks(self.manager, 4, advance_clock=1, address=decode_address(address))
        add_blocks_unlock_reward(self.manager)

        # Success non-empty address with small amount (0.01 HTR), we should get the earliest block with 64.00 HTR
        response4 = yield self.web.get("utxo_search", {b'token_uid': b'00',
                                                       b'address': address, b'target_amount': b'1'})
        data4 = response4.json_value()
        self.assertTrue(data4['success'])
        self.assertEqual(data4['utxos'], [{
            'txid': b.hash_hex,
            'index': 0,
            'amount': 6400,
            'timelock': None,
            'heightlock': b.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS,
        } for b in blocks[:1]])

        # Success non-empty address with medium amount, will require more than one output
        response5 = yield self.web.get("utxo_search", {b'token_uid': b'00',
                                                       b'address': address, b'target_amount': b'6500'})
        data5 = response5.json_value()
        self.assertTrue(data5['success'])
        self.assertEqual(data5['utxos'], [{
            'txid': b.hash_hex,
            'index': 0,
            'amount': 6400,
            'timelock': None,
            'heightlock': b.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS,
        } for b in blocks[4:1:-1]])

        # Success non-empty address with exact amount, will require all UTXOs
        response5 = yield self.web.get("utxo_search", {b'token_uid': b'00',
                                                       b'address': address, b'target_amount': b'25600'})
        data5 = response5.json_value()
        self.assertTrue(data5['success'])
        self.assertEqual(data5['utxos'], [{
            'txid': b.hash_hex,
            'index': 0,
            'amount': 6400,
            'timelock': None,
            'heightlock': b.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS,
        } for b in blocks[::-1]])

        # Success non-empty address with excessive amount, will require all UTXOs, even if it's not enough
        response5 = yield self.web.get("utxo_search", {b'token_uid': b'00',
                                                       b'address': address, b'target_amount': b'30000'})
        data5 = response5.json_value()
        self.assertTrue(data5['success'])
        self.assertEqual(data5['utxos'], [{
            'txid': b.hash_hex,
            'index': 0,
            'amount': 6400,
            'timelock': None,
            'heightlock': b.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS,
        } for b in blocks[::-1]])
