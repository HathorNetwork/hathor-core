from hathor.transaction.resources import GraphvizResource
from hathor.transaction import Transaction
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import StubSite, _BaseResourceTest, TestDummyRequest
from tests.utils import add_new_transactions, add_new_blocks


class GraphvizTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(GraphvizResource(self.manager))

        # Unlocking wallet
        self.manager.wallet.unlock(b'MYPASS')

        # Creating blocks, txs and a conflict tx to test graphviz with it
        add_new_blocks(self.manager, 2, advance_clock=2)
        txs = add_new_transactions(self.manager, 2, advance_clock=2)
        tx = txs[0]

        tx2 = Transaction.create_from_struct(tx.get_struct())
        tx2.parents = [tx.parents[1], tx.parents[0]]
        tx2.resolve()

        self.manager.propagate_tx(tx2)

    @inlineCallbacks
    def test_get(self):
        # With parameters
        response = yield self.web.get('graphviz', {b'format': b'dot', b'weight': b'true', b'acc_weight': b'true'})
        data = response.written[0]
        self.assertIsNotNone(data)

        # Without parameters
        response2 = yield self.web.get('graphviz', {})
        data2 = response2.written[0]
        self.assertIsNotNone(data2)

        # Funds graph without parameter
        response3 = yield self.web.get('graphviz', {b'funds': b'true'})
        data3 = response3.written[0]
        self.assertIsNotNone(data3)

        # Funds graph with parameter
        response4 = yield self.web.get('graphviz', {b'funds': b'true', b'weight': b'true', b'acc_weight': b'true'})
        data4 = response4.written[0]
        self.assertIsNotNone(data4)

    def test_parse_arg(self):
        resource = GraphvizResource(self.manager)

        false_args = ['false', 'False', '0', None, 0, False]
        for arg in false_args:
            self.assertFalse(resource.parseBoolArg(arg))

        true_args = ['true', 'True', '1', 1, True]
        for arg in true_args:
            self.assertTrue(resource.parseBoolArg(arg))

    def test_error_request(self):
        resource = GraphvizResource(self.manager)
        request = TestDummyRequest('GET', 'graphviz', {})

        self.assertIsNotNone(request._finishedDeferreds)
        resource._err_tx_resolve('Error', request)
        self.assertIsNone(request._finishedDeferreds)
