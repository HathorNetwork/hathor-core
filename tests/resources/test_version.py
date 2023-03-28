import os
from unittest.mock import patch

from twisted.internet.defer import inlineCallbacks

import hathor
from hathor.version import BASE_VERSION, DEFAULT_VERSION_SUFFIX, _get_version
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

    @patch('hathor.version.BUILD_VERSION_FILE_PATH', '/tmp/BUILD_VERSION')
    def test_local_version(self):
        """Test that we will return a version with the default prefix when the BUILD_VERSION file
            does not exist.
        """
        self.assertEqual(_get_version(), BASE_VERSION + DEFAULT_VERSION_SUFFIX)

    @patch('hathor.version.BUILD_VERSION_FILE_PATH', '/tmp/BUILD_VERSION')
    def test_build_version(self):
        """Test that we will return the version from the BUILD_VERSION file when it exists.
        """
        with open('/tmp/BUILD_VERSION', 'w') as build_version_file:
            build_version_file.write(BASE_VERSION + '-nightly')

        self.assertEqual(_get_version(), BASE_VERSION + '-nightly')

        os.remove('/tmp/BUILD_VERSION')


class SyncV1VersionTest(unittest.SyncV1Params, BaseVersionTest):
    __test__ = True


class SyncV2VersionTest(unittest.SyncV2Params, BaseVersionTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeVersionTest(unittest.SyncBridgeParams, SyncV2VersionTest):
    pass
