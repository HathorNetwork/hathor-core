from twisted.internet.defer import inlineCallbacks

import hathor
from hathor.version_resource import VersionResource
from tests.resources.base_resource import StubSite, _BaseResourceTest


class VersionTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(VersionResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get("version")
        data = response.json_value()
        self.assertEqual(data['version'], hathor.__version__)
