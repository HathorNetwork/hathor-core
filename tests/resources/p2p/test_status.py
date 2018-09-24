from hathor.p2p.resources import StatusResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import TestSite, _BaseResourceTest
import hathor


class StatusTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = TestSite(StatusResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get("status")
        data = response.json_value()
        server_data = data.get('server')
        self.assertEqual(server_data['app_version'], 'Hathor v{}'.format(hathor.__version__))
        self.assertEqual(server_data['network'], 'testnet')
        self.assertGreater(server_data['uptime'], 0)
