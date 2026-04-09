import shutil
import subprocess
import tempfile
from unittest.mock import Mock, patch

from twisted.internet.defer import inlineCallbacks

import hathor
from hathor.transaction.token_info import TokenVersion
from hathor.version import BASE_VERSION, DEFAULT_VERSION_SUFFIX, _get_version
from hathor.version_resource import VersionResource
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class VersionTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(VersionResource(self.manager, Mock()))
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.tmp_dir)

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get("version")
        data = response.json_value()
        self.assertEqual(data['version'], hathor.__version__)

    @inlineCallbacks
    def test_native_token(self):
        response = yield self.web.get("version")
        data = response.json_value()

        native_token = data['native_token']
        self.assertEqual(native_token['name'], self._settings.NATIVE_TOKEN_NAME)
        self.assertEqual(native_token['symbol'], self._settings.NATIVE_TOKEN_SYMBOL)
        self.assertEqual(native_token['version'], int(TokenVersion.NATIVE))

    def test_local_version(self):
        """Test that we will return a version with the default prefix when the BUILD_VERSION file
            does not exist.
        """
        with patch('hathor.version.BUILD_VERSION_FILE_PATH', self.tmp_dir + '/BUILD_VERSION'):
            git_head = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']).decode('ascii').strip()
            self.assertEqual(_get_version(), f"{BASE_VERSION}-{git_head}-{DEFAULT_VERSION_SUFFIX}")

    def test_build_version(self):
        """Test that we will return the version from the BUILD_VERSION file if it is valid,
            or the local version if the BUILD_VERSION is invalid.
        """
        file_path = self.tmp_dir + '/BUILD_VERSION'

        with patch('hathor.version.BUILD_VERSION_FILE_PATH', file_path):
            # Valid BUILD_VERSION files
            with open(file_path, 'w') as build_version_file:
                build_version_file.write(BASE_VERSION)
            self.assertEqual(_get_version(), BASE_VERSION)

            with open(file_path, 'w') as build_version_file:
                build_version_file.write(BASE_VERSION + '-rc.1')
            self.assertEqual(_get_version(), BASE_VERSION + '-rc.1')

            with open(file_path, 'w') as build_version_file:
                build_version_file.write('nightly-a4b3f9c2')
            self.assertEqual(_get_version(), 'nightly-a4b3f9c2')

            # BUILD_VERSION with white spaces
            with open(file_path, 'w') as build_version_file:
                build_version_file.write('  ' + BASE_VERSION + '-rc.1  ')
            self.assertEqual(_get_version(), BASE_VERSION + '-rc.1')

            # Invalid BUILD_VERSION files
            git_head = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']).decode('ascii').strip()

            with open(file_path, 'w') as build_version_file:
                build_version_file.write('v1.2.3')
            self.assertEqual(_get_version(), f"{BASE_VERSION}-{git_head}-{DEFAULT_VERSION_SUFFIX}")

            with open(file_path, 'w') as build_version_file:
                build_version_file.write('1.2.3-beta')
            self.assertEqual(_get_version(), f"{BASE_VERSION}-{git_head}-{DEFAULT_VERSION_SUFFIX}")
