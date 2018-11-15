from hathor.p2p.resources import MiningResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import StubSite, _BaseResourceTest


class MiningTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(MiningResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get('mining')
        data = response.json_value()
        self.assertGreater(len(data['parents']), 0)
        self.assertIsNotNone(data.get('block_bytes'))

    @inlineCallbacks
    def test_post(self):
        response_get = yield self.web.get('mining')
        data_get = response_get.json_value()
        block_bytes = data_get.get('block_bytes')

        response_post = yield self.web.post('mining', {'block_bytes': block_bytes})
        self.assertEqual(response_post.written[0], b'')
