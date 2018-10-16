from hathor.p2p.resources import StatusResource
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import Clock
from tests.resources.base_resource import TestSite, _BaseResourceTest
from tests.utils import FakeConnection
import hathor
import time


class StatusTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.clock.advance(time.time())
        self.web = TestSite(StatusResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get("status")
        data = response.json_value()
        server_data = data.get('server')
        self.assertEqual(server_data['app_version'], 'Hathor v{}'.format(hathor.__version__))
        self.assertEqual(server_data['network'], 'testnet')
        self.assertGreater(server_data['uptime'], 0)

    @inlineCallbacks
    def test_get_with_one_peer(self):
        manager2 = self.create_peer('testnet')
        conn1 = FakeConnection(self.manager, manager2)
        conn1.run_one_step()  # HELLO
        conn1.run_one_step()  # PEER-ID
        conn1.run_one_step()  # GET-PEERS

        response = yield self.web.get("status")
        data = response.json_value()
        server_data = data.get('server')
        known_peers = data.get('known_peers')
        connections = data.get('connections')
        self.assertEqual(server_data['app_version'], 'Hathor v{}'.format(hathor.__version__))
        self.assertEqual(server_data['network'], 'testnet')
        self.assertGreater(server_data['uptime'], 0)

        self.assertEqual(len(known_peers), 1)
        self.assertEqual(known_peers[0]['id'], manager2.my_peer.id)

        self.assertEqual(len(connections['connected_peers']), 1)
        self.assertEqual(connections['connected_peers'][0]['id'], manager2.my_peer.id)
