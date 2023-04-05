import os
import tempfile
from unittest.mock import patch

from twisted.internet.defer import inlineCallbacks

import hathor
from hathor.version import BASE_VERSION, DEFAULT_VERSION_SUFFIX, _get_version
from hathor.version_resource import VersionResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest

TMP_DIR = tempfile.gettempdir()


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

    @patch('hathor.version.BUILD_VERSION_FILE_PATH', TMP_DIR + '/BUILD_VERSION')
    def test_local_version(self):
        """Test that we will return a version with the default prefix when the BUILD_VERSION file
            does not exist.
        """
        self.assertEqual(_get_version(), BASE_VERSION + DEFAULT_VERSION_SUFFIX)

    @patch('hathor.version.BUILD_VERSION_FILE_PATH', TMP_DIR + '/BUILD_VERSION')
    def test_build_version(self):
        """Test that we will return the version from the BUILD_VERSION file if it is valid,
            or the local version if the BUILD_VERSION is invalid.
        """
        with open(TMP_DIR + '/BUILD_VERSION', 'w') as build_version_file:
            build_version_file.write(BASE_VERSION)
        self.assertEqual(_get_version(), BASE_VERSION)

        with open(TMP_DIR + '/BUILD_VERSION', 'w') as build_version_file:
            build_version_file.write(BASE_VERSION + '-rc.1')
        self.assertEqual(_get_version(), BASE_VERSION + '-rc.1')

        with open(TMP_DIR + '/BUILD_VERSION', 'w') as build_version_file:
            build_version_file.write('nightly-a4b3f9c2')
        self.assertEqual(_get_version(), 'nightly-a4b3f9c2')

        with open(TMP_DIR + '/BUILD_VERSION', 'w') as build_version_file:
            build_version_file.write('v1.2.3')
        self.assertEqual(_get_version(), BASE_VERSION + '-local')

        with open(TMP_DIR + '/BUILD_VERSION', 'w') as build_version_file:
            build_version_file.write('1.2.3-beta')
        self.assertEqual(_get_version(), BASE_VERSION + '-local')

        os.remove(TMP_DIR + '/BUILD_VERSION')


class SyncV1VersionTest(unittest.SyncV1Params, BaseVersionTest):
    __test__ = True


class SyncV2VersionTest(unittest.SyncV2Params, BaseVersionTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeVersionTest(unittest.SyncBridgeParams, SyncV2VersionTest):
    pass
