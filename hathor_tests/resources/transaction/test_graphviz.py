from twisted.internet.defer import inlineCallbacks

from hathor.simulator.utils import add_new_blocks
from hathor.transaction.resources import GraphvizFullResource, GraphvizNeighboursResource
from hathor.transaction.vertex_parser import vertex_deserializer
from hathor_tests.resources.base_resource import StubSite, TestDummyRequest, _BaseResourceTest
from hathor_tests.utils import add_blocks_unlock_reward, add_new_transactions


class BaseGraphvizTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.resource = self.create_resource()
        self.web = StubSite(self.resource)

        # Unlocking wallet
        self.manager.wallet.unlock(b'MYPASS')

        # Creating blocks, txs and a conflict tx to test graphviz with it
        add_new_blocks(self.manager, 2, advance_clock=2)
        add_blocks_unlock_reward(self.manager)
        txs = add_new_transactions(self.manager, 2, advance_clock=2)
        tx = txs[0]

        self.tx2 = vertex_deserializer.deserialize(tx.get_struct())
        self.tx2.parents = [tx.parents[1], tx.parents[0]]
        self.manager.cpu_mining_service.resolve(self.tx2)

        self.manager.propagate_tx(self.tx2)

    def create_resource(self):
        raise NotImplementedError


class GraphvizFullTest(BaseGraphvizTest):
    __test__ = True

    def create_resource(self):
        return GraphvizFullResource(self.manager, format='dot')

    @inlineCallbacks
    def test_full_graph_no_params(self):
        response = yield self.web.get('graphviz', {})
        data = response.written[0]
        self.assertIsNotNone(data)

    @inlineCallbacks
    def test_full_graph_simple(self):
        response = yield self.web.get('graphviz', {b'weight': b'true', b'acc_weight': b'true'})
        data = response.written[0]
        self.assertIsNotNone(data)

    @inlineCallbacks
    def test_full_graph_with_funds(self):
        response = yield self.web.get('graphviz', {b'funds': b'true'})
        data = response.written[0]
        self.assertIsNotNone(data)

    @inlineCallbacks
    def test_full_graph_complete(self):
        response = yield self.web.get('graphviz', {b'funds': b'true', b'weight': b'true', b'acc_weight': b'true'})
        data = response.written[0]
        self.assertIsNotNone(data)

    def test_parse_arg(self):
        false_args = ['false', 'False', '0', None, 0, False]
        for arg in false_args:
            self.assertFalse(self.resource.parse_bool_arg(arg))

        true_args = ['true', 'True', '1', 1, True]
        for arg in true_args:
            self.assertTrue(self.resource.parse_bool_arg(arg))

    def test_error_request(self):
        request = TestDummyRequest('GET', 'graphviz', {})

        self.assertIsNotNone(request._finishedDeferreds)
        self.resource._err_tx_resolve('Error', request)
        self.assertIsNone(request._finishedDeferreds)


class GraphvizNeigboursTest(BaseGraphvizTest):
    __test__ = True

    def create_resource(self):
        return GraphvizNeighboursResource(self.manager, format='dot')

    @inlineCallbacks
    def test_neighbours_graph_simple(self):
        response = yield self.web.get(
            'graphviz',
            {b'tx': self.tx2.hash_hex.encode('utf-8'), b'graph_type': b'funds', b'max_level': b'2'}
        )
        data = response.written[0]
        self.assertIsNotNone(data)

    def test_error_request(self):
        request = TestDummyRequest('GET', 'graphviz', {})
        self.assertIsNotNone(request._finishedDeferreds)
        self.resource._err_tx_resolve('Error', request)
        self.assertIsNone(request._finishedDeferreds)
