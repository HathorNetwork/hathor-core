import json
from unittest.mock import Mock

from twisted.internet.defer import inlineCallbacks
from twisted.test import proto_helpers

from hathor.conf import HathorSettings
from hathor.metrics import Metrics
from hathor.pubsub import EventArguments, HathorEvents
from hathor.transaction.genesis import get_genesis_transactions
from hathor.wallet.base_wallet import SpentTx, UnspentTx, WalletBalance
from hathor.websocket import WebsocketStatsResource
from hathor.websocket.factory import HathorAdminWebsocketFactory, HathorAdminWebsocketProtocol
from tests.resources.base_resource import StubSite, _BaseResourceTest

settings = HathorSettings()


class TestWebsocket(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, wallet_index=True)

        self.factory = HathorAdminWebsocketFactory(self.manager.metrics)
        self.factory.subscribe(self.manager.pubsub)
        self.factory._setup_rate_limit()
        self.factory.openHandshakeTimeout = 0
        self.protocol = self.factory.buildProtocol(None)

        self.transport = proto_helpers.StringTransport()
        self.protocol.makeConnection(self.transport)

        self.web = StubSite(WebsocketStatsResource(self.factory))

    def _decode_value(self, value):
        ret = None
        while value:
            try:
                ret = json.loads(value.decode('utf-8'))
                break
            except (UnicodeDecodeError, json.decoder.JSONDecodeError):
                value = value[1:]

        return ret

    def test_new_tx(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        self.manager.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED,
                                    tx=get_genesis_transactions(self.manager.tx_storage)[1])
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['tx_id'], get_genesis_transactions(None)[1].hash.hex())
        self.assertEqual(value['type'], 'network:new_tx_accepted')

    def test_metric(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        self.factory._schedule_and_send_metric()
        value = self._decode_value(self.transport.value())
        keys = [
            'transactions', 'blocks', 'hash_rate', 'block_hash_rate', 'tx_hash_rate', 'network_hash_rate', 'peers',
            'type', 'time'
        ]
        self.assertEqual(len(value), len(keys))
        for key in keys:
            self.assertTrue(key in value)

    def test_balance(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        self.manager.pubsub.publish(HathorEvents.WALLET_BALANCE_UPDATED,
                                    balance={settings.HATHOR_TOKEN_UID: WalletBalance(10, 20)})
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
        gen_tx = get_genesis_transactions(None)[0]
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
        gen_tx = get_genesis_transactions(None)[0]
        gen_tx2 = get_genesis_transactions(None)[1]
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
        self.manager.pubsub.publish(HathorEvents.NETWORK_PEER_CONNECTED)
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertIsNone(value)

        with self.assertRaises(ValueError):
            kwargs = {}
            args = EventArguments(**kwargs)
            self.factory.serialize_message_data(HathorEvents.NETWORK_PEER_CONNECTED, args)

    def test_ping(self):
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        payload = json.dumps({'type': 'ping'}).encode('utf-8')
        self.protocol.onMessage(payload, False)
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['type'], 'pong')

    def test_subscribe_address(self):
        self.assertEqual(len(self.factory.address_connections), 0)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        # Subscribe to address
        address = '1Q4qyTjhpUXUZXzwKs6Yvh2RNnF5J1XN9a'
        payload = json.dumps({'type': 'subscribe_address', 'address': address}).encode('utf-8')
        self.protocol.onMessage(payload, False)
        self.assertEqual(len(self.factory.address_connections), 1)

        block_genesis = [tx for tx in get_genesis_transactions(self.manager.tx_storage) if tx.is_block][0]

        # Test publish address history
        element = block_genesis.to_json_extended()
        self.manager.pubsub.publish(HathorEvents.WALLET_ADDRESS_HISTORY, address=address, history=element)
        self.run_to_completion()
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['type'], 'wallet:address_history')
        self.assertEqual(value['address'], address)
        self.assertEqual(value['history']['tx_id'], block_genesis.hash_hex)
        self.assertEqual(value['history']['timestamp'], block_genesis.timestamp)

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

        metrics = Metrics(
            pubsub=self.manager.pubsub,
            avg_time_between_blocks=self.manager.avg_time_between_blocks,
            tx_storage=self.manager.tx_storage,
        )

        self.assertNotEqual(metrics.reactor, self.manager.reactor)

        hash_rate = metrics.get_current_hash_rate(metrics.weight_block_deque, metrics.total_block_weight,
                                                  metrics.set_current_block_hash_rate,
                                                  metrics.block_hash_store_interval)

        self.assertEqual(hash_rate, 0)

    @inlineCallbacks
    def test_get_stats(self):
        response = yield self.web.get('websocket_stats')
        data = response.json_value()
        self.assertEqual(data['connections'], 0)
        self.assertEqual(data['addresses'], 0)

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
        payload = json.dumps({'type': 'subscribe_address', 'address': address1}).encode('utf-8')
        self.protocol.onMessage(payload, False)

        address2 = '1Q4qyTjhpUXUZXzwKs6Yvh2RNnF5J1XN9b'
        payload = json.dumps({'type': 'subscribe_address', 'address': address2}).encode('utf-8')
        self.protocol.onMessage(payload, False)

        # Test get again
        response = yield self.web.get('websocket_stats')
        data = response.json_value()
        self.assertEqual(data['connections'], 1)
        self.assertEqual(data['addresses'], 2)
