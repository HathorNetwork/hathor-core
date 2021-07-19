from twisted.internet.defer import inlineCallbacks

from hathor.wallet.resources import AddressResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest


class BaseAddressTest(_BaseResourceTest._ResourceTest):
    __test__ = False

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

        # Default has to be new: false
        response_same2 = yield self.web.get("wallet/address")
        data_same2 = response_same2.json_value()
        same_address2 = data_same2['address']

        response_new = yield self.web.get("wallet/address", {b'new': b'true'})
        data_new = response_new.json_value()
        new_address2 = data_new['address']

        self.assertEqual(new_address1, same_address)
        self.assertEqual(same_address, same_address2)
        self.assertNotEqual(new_address1, new_address2)


class SyncV1AddressTest(unittest.SyncV1Params, BaseAddressTest):
    __test__ = True


class SyncV2AddressTest(unittest.SyncV2Params, BaseAddressTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeAddressTest(unittest.SyncBridgeParams, SyncV2AddressTest):
    pass
