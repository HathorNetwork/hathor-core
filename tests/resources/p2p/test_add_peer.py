from twisted.internet.defer import inlineCallbacks

from hathor.p2p.entrypoint import Entrypoint
from hathor.p2p.peer_id import PeerId
from hathor.p2p.resources import AddPeersResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest


class BaseAddPeerTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.web = StubSite(AddPeersResource(self.manager))

    @inlineCallbacks
    def test_connecting_peers(self):
        response = yield self.web.post('p2p/peers', ['tcp://localhost:8006'])
        data = response.json_value()
        self.assertTrue(data['success'])

        # test when we send a peer we're already connected to
        peer = PeerId()
        peer.entrypoints = [Entrypoint.parse('tcp://localhost:8006')]
        self.manager.connections.peer_storage.add(peer)
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


class SyncV1AddPeerTest(unittest.SyncV1Params, BaseAddPeerTest):
    __test__ = True


class SyncV2AddPeerTest(unittest.SyncV2Params, BaseAddPeerTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeAddPeerTest(unittest.SyncBridgeParams, SyncV2AddPeerTest):
    pass
