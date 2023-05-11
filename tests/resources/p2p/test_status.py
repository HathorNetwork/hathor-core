from twisted.internet import endpoints
from twisted.internet.defer import inlineCallbacks

import hathor
from hathor.conf import HathorSettings
from hathor.p2p.resources import StatusResource
from hathor.simulator import FakeConnection
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest


class BaseStatusTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.web = StubSite(StatusResource(self.manager))

        self.manager2 = self.create_peer('testnet')
        self.conn1 = FakeConnection(self.manager, self.manager2)

    @inlineCallbacks
    def test_get(self):
        settings = HathorSettings()
        response = yield self.web.get("status")
        data = response.json_value()

        server_data = data.get('server')
        self.assertEqual(server_data['app_version'], 'Hathor v{}'.format(hathor.__version__))
        self.assertEqual(server_data['network'], 'testnet')
        self.assertGreater(server_data['uptime'], 0)

        dag_data = data.get('dag')
        # We have the genesis block
        self.assertEqual(len(dag_data['best_block_tips']), 1)
        self.assertIsNotNone(dag_data['best_block_tips'][0])
        # As we don't have a type, we must check if the keys are there,
        # and the types are correct
        self.assertIn('hash', dag_data['best_block_tips'][0])
        self.assertIn('height', dag_data['best_block_tips'][0])
        self.assertIsInstance(dag_data['best_block_tips'][0]['hash'], str)
        self.assertIsInstance(dag_data['best_block_tips'][0]['height'], int)
        self.assertEqual(dag_data['best_block_tips'][0]['hash'], settings.GENESIS_BLOCK_HASH.hex())
        self.assertEqual(dag_data['best_block_tips'][0]['height'], 0)
        self.assertIsNotNone(dag_data['best_block'])
        self.assertIn('hash', dag_data['best_block'])
        self.assertIn('height', dag_data['best_block'])
        self.assertIsInstance(dag_data['best_block']['hash'], str)
        self.assertIsInstance(dag_data['best_block']['height'], int)
        self.assertEqual(dag_data['best_block']['hash'], settings.GENESIS_BLOCK_HASH.hex())
        self.assertEqual(dag_data['best_block']['height'], 0)

    @inlineCallbacks
    def test_handshaking(self):
        response = yield self.web.get("status")
        data = response.json_value()
        server_data = data.get('server')
        known_peers = data.get('known_peers')
        connections = data.get('connections')
        self.assertEqual(server_data['app_version'], 'Hathor v{}'.format(hathor.__version__))
        self.assertEqual(server_data['network'], 'testnet')
        self.assertGreater(server_data['uptime'], 0)

        handshake_peer = self.conn1.proto1.transport.getPeer()
        handshake_address = '{}:{}'.format(handshake_peer.host, handshake_peer.port)

        self.assertEqual(len(known_peers), 0)
        self.assertEqual(len(connections['connected_peers']), 0)
        self.assertEqual(len(connections['handshaking_peers']), 1)
        self.assertEqual(connections['handshaking_peers'][0]['address'], handshake_address)

    @inlineCallbacks
    def test_get_with_one_peer(self):
        self.conn1.run_one_step()  # HELLO
        self.conn1.run_one_step()  # PEER-ID
        self.conn1.run_one_step()  # READY
        self.conn1.run_one_step()  # BOTH PEERS ARE READY NOW

        response = yield self.web.get("status")
        data = response.json_value()
        server_data = data.get('server')
        known_peers = data.get('known_peers')
        connections = data.get('connections')
        self.assertEqual(server_data['app_version'], 'Hathor v{}'.format(hathor.__version__))
        self.assertEqual(server_data['network'], 'testnet')
        self.assertGreater(server_data['uptime'], 0)

        self.assertEqual(len(known_peers), 1)
        self.assertEqual(known_peers[0]['id'], self.manager2.my_peer.id)

        self.assertEqual(len(connections['connected_peers']), 1)
        self.assertEqual(connections['connected_peers'][0]['id'], self.manager2.my_peer.id)

    @inlineCallbacks
    def test_connecting_peers(self):
        address = '192.168.1.1:54321'
        endpoint = endpoints.clientFromString(self.manager.reactor, 'tcp:{}'.format(address))
        deferred = endpoint.connect
        self.manager.connections.connecting_peers[endpoint] = deferred

        response = yield self.web.get("status")
        data = response.json_value()
        connecting = data['connections']['connecting_peers']
        self.assertEqual(len(connecting), 1)
        self.assertEqual(connecting[0]['address'], address)
        self.assertIsNotNone(connecting[0]['deferred'])


class SyncV1StatusTest(unittest.SyncV1Params, BaseStatusTest):
    __test__ = True


class SyncV2StatusTest(unittest.SyncV2Params, BaseStatusTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeStatusTest(unittest.SyncBridgeParams, SyncV2StatusTest):
    pass
