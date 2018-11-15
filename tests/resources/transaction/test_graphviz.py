from hathor.transaction.resources import GraphvizResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import StubSite, _BaseResourceTest


class GraphvizTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(GraphvizResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get("graphviz", {b'format': b'pdf'})
        data = response.written[0]
        self.assertIsNotNone(data)
