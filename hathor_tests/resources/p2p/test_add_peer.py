from twisted.internet.defer import inlineCallbacks

from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_endpoint import PeerAddress
from hathor.p2p.resources import AddPeersResource
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class AddPeerTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(AddPeersResource(self.manager))

    @inlineCallbacks
    def test_connecting_peers(self):
        response = yield self.web.post('p2p/peers', ['tcp://localhost:8006'])
        data = response.json_value()
        self.assertTrue(data['success'])

        # test when we send a peer we're already connected to
        peer = PrivatePeer.auto_generated()
        peer.entrypoints = [PeerAddress.parse('tcp://localhost:8006')]
        self.manager.connections.verified_peer_storage.add(peer)
        response = yield self.web.post('p2p/peers', ['tcp://localhost:8006', 'tcp://localhost:8007'])
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertEqual(data['peers'], ['tcp://localhost:8007'])

    @inlineCallbacks
    def test_invalid_data(self):
        # no data
        response = yield self.web.post('p2p/peers')
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid type
        response = yield self.web.post('p2p/peers', {'a': 'tcp://localhost:8006'})
        data = response.json_value()
        self.assertFalse(data['success'])
