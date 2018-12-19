import unittest

from hathor.wallet.resources import AddressResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import StubSite, _BaseResourceTest


class AddressTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(AddressResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get("wallet/address", {b'new': b'true'})
        data = response.json_value()
        new_address1 = data['address']

        response_same = yield self.web.get("wallet/address", {b'new': b'false'})
        data_same = response_same.json_value()
        same_address = data_same['address']

        response_new = yield self.web.get("wallet/address", {b'new': b'true'})
        data_new = response_new.json_value()
        new_address2 = data_new['address']

        self.assertEqual(new_address1, same_address)
        self.assertNotEqual(new_address1, new_address2)


if __name__ == '__main__':
    unittest.main()
