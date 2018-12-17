from hathor.transaction.resources import DashboardTransactionResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import StubSite, _BaseResourceTest


class DashboardTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(DashboardTransactionResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        tx_count = block_count = 6
        response = yield self.web.get("dashboard_tx", {b'block': block_count, b'tx': tx_count})
        data = response.json_value()

        self.assertLessEqual(len(data['transactions']), tx_count)
        self.assertLessEqual(len(data['blocks']), block_count)


if __name__ == '__main__':
    unittest.main()
