from twisted.internet.address import IPv4Address
from twisted.internet.defer import inlineCallbacks

import hathor
from hathor.p2p.peer_endpoint import PeerAddress
from hathor.p2p.resources import StatusResource
from hathor.simulator import FakeConnection
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class StatusTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(StatusResource(self.manager))
        address1 = IPv4Address('TCP', '192.168.1.1', 54321)
        self.manager.connections.my_peer.info.entrypoints.add(PeerAddress.from_address(address1))
        self.manager.peers_whitelist.append(self.get_random_peer_from_pool().id)
        self.manager.peers_whitelist.append(self.get_random_peer_from_pool().id)

        self.manager2 = self.create_peer('testnet')
        address2 = IPv4Address('TCP', '192.168.1.1', 54322)
        self.manager2.connections.my_peer.info.entrypoints.add(PeerAddress.from_address(address2))
        self.conn1 = FakeConnection(self.manager, self.manager2, addr1=address1, addr2=address2)

    @inlineCallbacks
    def test_get(self):
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
        self.assertEqual(dag_data['best_block_tips'][0]['hash'], self._settings.GENESIS_BLOCK_HASH.hex())
        self.assertEqual(dag_data['best_block_tips'][0]['height'], 0)
        self.assertIsNotNone(dag_data['best_block'])
        self.assertIn('hash', dag_data['best_block'])
        self.assertIn('height', dag_data['best_block'])
        self.assertIsInstance(dag_data['best_block']['hash'], str)
        self.assertIsInstance(dag_data['best_block']['height'], int)
        self.assertEqual(dag_data['best_block']['hash'], self._settings.GENESIS_BLOCK_HASH.hex())
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

        self.assertEqual(len(known_peers), 0)
        self.assertEqual(len(connections['connected_peers']), 0)
        self.assertEqual(len(connections['handshaking_peers']), 1)
        self.assertEqual(connections['handshaking_peers'][0]['address'], str(self.conn1.proto1.addr))

    @inlineCallbacks
    def test_get_with_one_peer(self):
        assert self.conn1.peek_tr1_value().startswith(b'HELLO')
        self.conn1.run_one_step()  # HELLO
        assert self.conn1.peek_tr1_value().startswith(b'PEER-ID')
        self.conn1.run_one_step()  # PEER-ID
        assert self.conn1.peek_tr1_value().startswith(b'READY')
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
        self.assertEqual(known_peers[0]['id'], str(self.manager2.my_peer.id))

        self.assertEqual(len(connections['connected_peers']), 1)
        self.assertEqual(connections['connected_peers'][0]['id'], str(self.manager2.my_peer.id))

    @inlineCallbacks
    def test_connecting_peers(self):
        peer_address = PeerAddress.parse('tcp://192.168.1.1:54321')
        self.manager.connections._connections._connecting_outbound.add(peer_address)

        response = yield self.web.get("status")
        data = response.json_value()
        connecting = data['connections']['connecting_peers']
        self.assertEqual(len(connecting), 1)
        self.assertEqual(connecting[0]['address'], str(peer_address))


class SyncV1StatusTest(unittest.SyncV1Params, BaseStatusTest):
    __test__ = True


class SyncV2StatusTest(unittest.SyncV2Params, BaseStatusTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeStatusTest(unittest.SyncBridgeParams, SyncV2StatusTest):
    pass
