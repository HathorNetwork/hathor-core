from twisted.internet.defer import inlineCallbacks

from hathor.transaction.resources import TxParentsResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest


class BaseDecodeTxTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.web = StubSite(TxParentsResource(self.manager))

    @inlineCallbacks
    def test_get_success(self):
        resp = yield self.web.get('tx_parents')
        data = resp.json_value()

        self.assertTrue(data['success'])
        self.assertEqual(2, len(data['tx_parents']))

    @inlineCallbacks
    def test_get_syncing(self):
        self.manager._allow_mining_without_peers = False

        resp = yield self.web.get('tx_parents')
        data = resp.json_value()

        self.assertFalse(data['success'])


class SyncV1DecodeTxTest(unittest.SyncV1Params, BaseDecodeTxTest):
    __test__ = True


class SyncV2DecodeTxTest(unittest.SyncV2Params, BaseDecodeTxTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeDecodeTxTest(unittest.SyncBridgeParams, SyncV2DecodeTxTest):
    pass
