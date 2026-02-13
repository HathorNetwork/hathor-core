import base64

from twisted.internet.defer import inlineCallbacks

from hathor.p2p.resources import MiningResource
from hathor.transaction.vertex_parser import vertex_deserializer, vertex_serializer
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


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
        block_bytes_str = data_get.get('block_bytes')

        block_bytes = base64.b64decode(block_bytes_str)
        block = vertex_deserializer.deserialize(block_bytes)
        block.weight = 4
        self.manager.cpu_mining_service.resolve(block)

        block_bytes = vertex_serializer.serialize(block)
        block_bytes_str = base64.b64encode(block_bytes).decode('ascii')

        response_post = yield self.web.post('mining', {'block_bytes': block_bytes_str})
        self.assertEqual(response_post.written[0], b'1')

        block.weight = 100
        block_bytes = vertex_serializer.serialize(block)
        block_bytes_str = base64.b64encode(block_bytes).decode('ascii')

        response_post = yield self.web.post('mining', {'block_bytes': block_bytes_str})
        # Probability 2^(100 - 256) of failing
        self.assertEqual(response_post.written[0], b'0')

    @inlineCallbacks
    def test_post_invalid_data(self):
        response_get = yield self.web.get('mining')
        data_get = response_get.json_value()
        block_bytes_str = data_get.get('block_bytes')

        block_bytes = base64.b64decode(block_bytes_str)
        block = vertex_deserializer.deserialize(block_bytes)
        block.weight = 4
        self.manager.cpu_mining_service.resolve(block)

        block_bytes = vertex_serializer.serialize(block)
        block_bytes_str = base64.b64encode(block_bytes).decode('ascii')

        # missing post data
        response_post = yield self.web.post('mining')
        self.assertEqual(response_post.written[0], b'0')

        # invalid block bytes
        response_post = yield self.web.post('mining', {'block_bytes': base64.b64encode(b'aaa').decode('ascii')})
        self.assertEqual(response_post.written[0], b'0')

        # invalid base64
        response_post = yield self.web.post('mining', {'block_bytes': 'YWFha'})
        self.assertEqual(response_post.written[0], b'0')
