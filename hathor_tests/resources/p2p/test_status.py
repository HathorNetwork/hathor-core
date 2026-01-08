from twisted.internet import endpoints
from twisted.internet.address import IPv4Address
from twisted.internet.defer import inlineCallbacks

import hathor
from hathor.p2p.peer_endpoint import PeerAddress
from hathor.p2p.resources import StatusResource
from hathor.p2p.whitelist import URLPeersWhitelist
from hathor.simulator import FakeConnection
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class StatusTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(StatusResource(self.manager))
        address1 = IPv4Address('TCP', '192.168.1.1', 54321)
        self.manager.connections.my_peer.info.entrypoints.add(PeerAddress.from_address(address1))
        url = "https://anything.com"
        reactor = self.manager.reactor
        mock_peers_whitelist = URLPeersWhitelist(reactor, url, True)
        mock_peers_whitelist.start(mock_peers_whitelist._on_remove_callback)
        self.manager.connections.peers_whitelist = mock_peers_whitelist
        self.manager.connections.peers_whitelist.add_peer(self.get_random_peer_from_pool().id)
        self.manager.connections.peers_whitelist.add_peer(self.get_random_peer_from_pool().id)
        # Simulate successful fetch to end grace period
        self.manager.connections.peers_whitelist._has_successful_fetch = True
        url_2 = "https://somethingDifferent.com"
        self.manager2 = self.create_peer('testnet', url_whitelist=url_2)
        address2 = IPv4Address('TCP', '192.168.1.1', 54322)
        self.manager2.connections.my_peer.info.entrypoints.add(PeerAddress.from_address(address2))

        # Manager's whitelist is not empty, so its mock whitelist will be followed.
        # Since manager 2 is a different instance, we need to add it to the whitelist of manager 1
        self.manager.connections.peers_whitelist.add_peer(self.manager2.my_peer.id)

        # Likewise for manager 1 in manager 2
        self.manager2.connections.peers_whitelist.add_peer(self.manager.my_peer.id)
        # Simulate successful fetch to end grace period
        self.manager2.connections.peers_whitelist._has_successful_fetch = True

        # Now, we create a fake connection between the two managers.
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

        assert self.manager.connections.peers_whitelist is not None, 'Peers whitelist should not be None'
        assert len(self.manager.connections.peers_whitelist._current) == 3, 'Should have one peer in the whitelist'

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
