from twisted.internet.defer import inlineCallbacks

from hathor.p2p.peer_id import PeerId
from hathor.p2p.resources import AddPeersResource
from tests.resources.base_resource import StubSite, _BaseResourceTest


class AddPeerTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(AddPeersResource(self.manager))

    @inlineCallbacks
    def test_connecting_peers(self):
        response = yield self.web.post('p2p/peers', ['tcp:localhost:8006'])
        data = response.json_value()
        self.assertTrue(data['success'])

        # test when we send a peer we're already connected to
        peer = PeerId()
        peer.entrypoints = ['tcp:localhost:8006']
        self.manager.connections.peer_storage.add(peer)
        response = yield self.web.post('p2p/peers', ['tcp:localhost:8006', 'tcp:localhost:8007'])
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertEqual(data['peers'], ['tcp:localhost:8007'])
