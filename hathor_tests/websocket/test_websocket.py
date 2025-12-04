from json import JSONDecodeError
from unittest.mock import Mock

from twisted.internet.defer import inlineCallbacks
from twisted.internet.testing import StringTransport

from hathor.pubsub import EventArguments, HathorEvents
from hathor.util import json_dumpb, json_dumps, json_loadb
from hathor.wallet.base_wallet import SpentTx, UnspentTx, WalletBalance
from hathor.websocket import WebsocketStatsResource
from hathor.websocket.factory import HathorAdminWebsocketFactory, HathorAdminWebsocketProtocol
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class WebsocketTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, wallet_index=True)

        self.factory = HathorAdminWebsocketFactory(self.manager, self.manager.metrics)
        self.factory.subscribe(self.manager.pubsub)
        self.factory._setup_rate_limit()
        self.factory.openHandshakeTimeout = 0
        self.protocol = self.factory.buildProtocol(None)

        self.transport = StringTransport()
        self.protocol.makeConnection(self.transport)

        self.genesis = list(self.manager.tx_storage.get_all_genesis())
        self.genesis.sort(key=lambda x: x.timestamp)
        self.assertTrue(self.genesis[0].is_block)
        for tx in self.genesis[1:]:
            self.assertTrue(tx.is_transaction)

        self.web = StubSite(WebsocketStatsResource(self.factory))

    def _decode_value(self, value):
        ret = None
        while value:
            try:
                ret = json_loadb(value)
                break
            except (UnicodeDecodeError, JSONDecodeError):
                value = value[1:]

        return ret

    def test_new_tx(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN

        tx = self.genesis[1]
        meta = tx.get_metadata()
        meta.first_block = self.genesis[0].hash
        self.manager.tx_storage.save_transaction(tx, only_metadata=True)
        self.manager.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED,
                                    tx=tx)
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['tx_id'], tx.hash.hex())
        self.assertEqual(value['type'], 'network:new_tx_accepted')

    def test_metric(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        self.factory._send_metrics()
        value = self._decode_value(self.transport.value())
        keys = ['transactions', 'blocks', 'best_block_height', 'hash_rate', 'peers', 'type', 'time']
        self.assertEqual(len(value), len(keys))
        for key in keys:
            self.assertTrue(key in value)

    def test_balance(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        self.manager.pubsub.publish(HathorEvents.WALLET_BALANCE_UPDATED,
                                    balance={self._settings.HATHOR_TOKEN_UID: WalletBalance(10, 20)})
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['balance']['locked'], 10)
        self.assertEqual(value['balance']['available'], 20)
        self.assertEqual(value['type'], 'wallet:balance_updated')

    def test_gap_limit(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        self.manager.pubsub.publish(HathorEvents.WALLET_GAP_LIMIT, limit=10)
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['limit'], 10)
        self.assertEqual(value['type'], 'wallet:gap_limit')

    def test_output_received(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        gen_tx = self.genesis[0]
        output = UnspentTx(gen_tx.hash, 0, 10, gen_tx.timestamp, '', gen_tx.outputs[0].token_data)
        self.manager.pubsub.publish(HathorEvents.WALLET_OUTPUT_RECEIVED, total=10, output=output)
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['total'], 10)
        self.assertEqual(value['type'], 'wallet:output_received')
        self.assertEqual(value['output']['tx_id'], gen_tx.hash.hex())

    def test_input_spent_received(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        gen_tx = self.genesis[0]
        gen_tx2 = self.genesis[1]
        spent = SpentTx(gen_tx2.hash, gen_tx.hash, 0, 10, gen_tx.timestamp + 1)
        self.manager.pubsub.publish(HathorEvents.WALLET_INPUT_SPENT, output_spent=spent)
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['type'], 'wallet:output_spent')
        self.assertEqual(value['output_spent']['tx_id'], gen_tx2.hash.hex())
        self.assertEqual(value['output_spent']['from_tx_id'], gen_tx.hash.hex())

    def test_invalid_publish(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        self.manager.pubsub.publish(
            HathorEvents.NETWORK_PEER_READY,
            peers_count=self.manager.connections._get_peers_count()
        )
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertIsNone(value)

        with self.assertRaises(ValueError):
            kwargs = {}
            args = EventArguments(**kwargs)
            self.factory.serialize_message_data(HathorEvents.NETWORK_PEER_READY, args)

    def test_ping_bytes(self):
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        payload = json_dumpb({'type': 'ping'})
        self.protocol.onMessage(payload, True)
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['type'], 'pong')

    def test_ping_str(self):
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        payload = json_dumps({'type': 'ping'})
        self.protocol.onMessage(payload, False)
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['type'], 'pong')

    def test_subscribe_address(self):
        self.assertEqual(len(self.factory.address_connections), 0)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        # Subscribe to address
        address = '1Q4qyTjhpUXUZXzwKs6Yvh2RNnF5J1XN9a'
        payload = json_dumpb({'type': 'subscribe_address', 'address': address})
        self.protocol.onMessage(payload, True)
        self.assertEqual(len(self.factory.address_connections), 1)

        block_genesis = self.genesis[0]

        # Test publish address history
        # First clean the transport to make sure the value comes from this execution
        self.transport.clear()
        element = block_genesis.to_json_extended()
        self.manager.pubsub.publish(HathorEvents.WALLET_ADDRESS_HISTORY, address=address, history=element)
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['type'], 'wallet:address_history')
        self.assertEqual(value['address'], address)
        self.assertEqual(value['history']['tx_id'], block_genesis.hash_hex)
        self.assertEqual(value['history']['timestamp'], block_genesis.timestamp)

        # Publishing with address that was not subscribed must not generate any value in the ws
        # First clean the transport to make sure the value comes from this execution
        self.transport.clear()
        wrong_address = '1Q4qyTjhpUXUZXzwKs6Yvh2RNnF5J1XN9b'
        self.manager.pubsub.publish(HathorEvents.WALLET_ADDRESS_HISTORY, address=wrong_address, history=element)
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertIsNone(value)

    def test_connections(self):
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        request_mock = Mock(peer=None)
        self.protocol.onConnect(request_mock)
        self.assertEqual(len(self.factory.connections), 0)
        self.protocol.onOpen()
        self.assertEqual(len(self.factory.connections), 1)
        self.protocol.onClose(True, 1, 'Closed')
        self.assertEqual(len(self.factory.connections), 0)

    def test_invalid_metric_key(self):
        kwargs = {'test': False}
        arg = EventArguments(**kwargs)
        with self.assertRaises(ValueError):
            self.manager.metrics.handle_publish('invalid_key', arg)

    @inlineCallbacks
    def test_get_stats(self):
        response = yield self.web.get('websocket_stats')
        data = response.json_value()
        self.assertEqual(data['connections'], 0)
        self.assertEqual(data['subscribed_addresses'], 0)

        # Add one connection
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        request_mock = Mock(peer=None)
        self.protocol.onConnect(request_mock)
        self.protocol.onOpen()

        # Add two addresses
        self.assertEqual(len(self.factory.address_connections), 0)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        # Subscribe to address
        address1 = '1Q4qyTjhpUXUZXzwKs6Yvh2RNnF5J1XN9a'
        payload = json_dumpb({'type': 'subscribe_address', 'address': address1})
        self.protocol.onMessage(payload, True)

        address2 = '1Q4qyTjhpUXUZXzwKs6Yvh2RNnF5J1XN9b'
        payload = json_dumpb({'type': 'subscribe_address', 'address': address2})
        self.protocol.onMessage(payload, True)

        # Test get again
        response = yield self.web.get('websocket_stats')
        data = response.json_value()
        self.assertEqual(data['connections'], 1)
        self.assertEqual(data['subscribed_addresses'], 2)
