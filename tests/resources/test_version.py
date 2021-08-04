from twisted.internet.defer import inlineCallbacks

import hathor
from hathor.version_resource import VersionResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest


class BaseVersionTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.web = StubSite(VersionResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get("version")
        data = response.json_value()
        self.assertEqual(data['version'], hathor.__version__)


class SyncV1VersionTest(unittest.SyncV1Params, BaseVersionTest):
    __test__ = True


class SyncV2VersionTest(unittest.SyncV2Params, BaseVersionTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeVersionTest(unittest.SyncBridgeParams, SyncV2VersionTest):
    pass
