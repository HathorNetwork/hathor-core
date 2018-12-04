from hathor.pubsub import EventArguments
from twisted.test import proto_helpers
from hathor.websocket.factory import HathorAdminWebsocketFactory, HathorAdminWebsocketProtocol
from tests import unittest
from unittest.mock import Mock
import json
from hathor.pubsub import HathorEvents
from hathor.transaction.genesis import genesis_transactions
from hathor.wallet.base_wallet import UnspentTx, SpentTx, WalletBalance


class TestWebsocket(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network)

        self.factory = HathorAdminWebsocketFactory(self.manager.metrics)
        self.factory.subscribe(self.manager.pubsub)
        self.factory._setup_rate_limit()
        self.factory.openHandshakeTimeout = 0
        self.protocol = self.factory.buildProtocol(None)

        self.transport = proto_helpers.StringTransport()
        self.protocol.makeConnection(self.transport)

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
        self.manager.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=genesis_transactions(None)[1])
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['hash'], genesis_transactions(None)[1].hash.hex())
        self.assertEqual(value['type'], 'network:new_tx_accepted')

    def test_metric(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        self.factory._schedule_and_send_metric()
        value = self._decode_value(self.transport.value())
        keys = [
            'transactions',
            'blocks',
            'hash_rate',
            'block_hash_rate',
            'tx_hash_rate',
            'network_hash_rate',
            'peers',
            'type',
            'time'
        ]
        self.assertEqual(len(value), len(keys))
        for key in keys:
            self.assertTrue(key in value)

    def test_balance(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        self.manager.pubsub.publish(HathorEvents.WALLET_BALANCE_UPDATED, balance=WalletBalance(10, 20))
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['balance']['locked'], 10)
        self.assertEqual(value['balance']['available'], 20)
        self.assertEqual(value['type'], 'wallet:balance_updated')

    def test_output_received(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        gen_tx = genesis_transactions(None)[0]
        output = UnspentTx(gen_tx.hash, 0, 10, gen_tx.timestamp)
        self.manager.pubsub.publish(HathorEvents.WALLET_OUTPUT_RECEIVED, total=10, output=output)
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['total'], 10)
        self.assertEqual(value['type'], 'wallet:output_received')
        self.assertEqual(value['output']['tx_id'], gen_tx.hash.hex())

    def test_input_spent_received(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        gen_tx = genesis_transactions(None)[0]
        gen_tx2 = genesis_transactions(None)[1]
        spent = SpentTx(gen_tx2.hash, gen_tx.hash, 0, 10, gen_tx.timestamp + 1)
        self.manager.pubsub.publish(HathorEvents.WALLET_INPUT_SPENT, output_spent=spent)
        value = self._decode_value(self.transport.value())
        self.assertEqual(value['type'], 'wallet:output_spent')
        self.assertEqual(value['output_spent']['tx_id'], gen_tx2.hash.hex())
        self.assertEqual(value['output_spent']['from_tx_id'], gen_tx.hash.hex())

    def test_invalid_publish(self):
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        self.manager.pubsub.publish(HathorEvents.NETWORK_PEER_CONNECTED)
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

    def test_connections(self):
        self.protocol.state = HathorAdminWebsocketProtocol.STATE_OPEN
        request_mock = Mock(peer=None)
        self.protocol.onConnect(request_mock)
        self.assertEqual(len(self.factory.connections), 0)
        self.protocol.onOpen()
        self.assertEqual(len(self.factory.connections), 1)
        self.protocol.onClose(True, 1, 'Closed')
        self.assertEqual(len(self.factory.connections), 0)
