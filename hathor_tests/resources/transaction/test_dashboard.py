from twisted.internet.defer import inlineCallbacks

from hathor.transaction.resources import DashboardTransactionResource
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class DashboardTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(DashboardTransactionResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        tx_count = block_count = 6
        response = yield self.web.get("dashboard_tx", {
            b'block': str(block_count).encode(),
            b'tx': str(tx_count).encode()
        })
        data = response.json_value()

        self.assertLessEqual(len(data['transactions']), tx_count)
        self.assertLessEqual(len(data['blocks']), block_count)

    @inlineCallbacks
    def test_invalid_parameters(self):
        # wrong type block
        response = yield self.web.get("dashboard_tx", {b'block': b'a', b'tx': b'6'})
        data = response.json_value()
        self.assertFalse(data['success'])
        # missing block param
        response = yield self.web.get("dashboard_tx", {b'tx': b'6'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # wrong type tx
        response = yield self.web.get("dashboard_tx", {b'block': b'6', b'tx': b'a'})
        data = response.json_value()
        self.assertFalse(data['success'])
        # missing tx param
        response = yield self.web.get("dashboard_tx", {b'block': b'6'})
        data = response.json_value()
        self.assertFalse(data['success'])

    @inlineCallbacks
    def test_zero_count(self):
        tx_count = 0
        block_count = 6
        response = yield self.web.get("dashboard_tx", {
            b'block': str(block_count).encode(),
            b'tx': str(tx_count).encode()
        })
        data = response.json_value()

        self.assertLessEqual(len(data['transactions']), tx_count)
        self.assertLessEqual(len(data['blocks']), block_count)

        tx_count = 6
        block_count = 0
        response = yield self.web.get("dashboard_tx", {
            b'block': str(block_count).encode(),
            b'tx': str(tx_count).encode()
        })
        data = response.json_value()

        self.assertLessEqual(len(data['transactions']), tx_count)
        self.assertLessEqual(len(data['blocks']), block_count)

    @inlineCallbacks
    def test_negative_count(self):
        response = yield self.web.get("dashboard_tx", {b'block': b'-1', b'tx': b'6'})
        data = response.json_value()
        self.assertFalse(data['success'])

        response = yield self.web.get("dashboard_tx", {b'block': b'6', b'tx': b'-1'})
        data = response.json_value()
        self.assertFalse(data['success'])
