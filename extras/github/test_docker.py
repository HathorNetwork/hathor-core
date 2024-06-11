import os
import unittest

from extras.github.docker import prep_base_version, prep_tags

class DockerWorkflowTest(unittest.TestCase):
    def setUp(self):
        os.environ.update({
            'GITHUB_REPOSITORY': 'hathornetwork/hathor-core',
        })

    def test_nightly_build_no_github_secret(self):
        os.environ.update({
            'GITHUB_REF': 'refs/heads/ci/extract-python-scripts',
            'GITHUB_EVENT_NAME': 'schedule',
            'GITHUB_SHA': '55629a7d0ae267cdd27618f452e9f1ad6764fd43',
            'GITHUB_EVENT_DEFAULT_BRANCH': 'master',
            'GITHUB_EVENT_NUMBER': '',
            'MATRIX_PYTHON_IMPL': 'python',
            'MATRIX_PYTHON_VERSION': '3.10',
            'SECRETS_DOCKERHUB_IMAGE': '',
            'SECRETS_GHCR_IMAGE': '',
        })

        output, base_version, is_release_candidate, overwrite_hathor_core_version = prep_base_version(os.environ)

        self.assertTrue(overwrite_hathor_core_version)
        self.assertFalse(is_release_candidate)
        self.assertTrue(output['disable-slack-notification'])
        self.assertEqual(base_version, 'nightly-55629a7d')

        output = prep_tags(os.environ, base_version, is_release_candidate)

        self.assertEqual(output['slack-notification-version'], base_version)
        self.assertEqual(output['version'], base_version + '-python3.10')
        self.assertEqual(output['login-dockerhub'], 'false')
        self.assertEqual(output['login-ghcr'], 'false')
        self.assertEqual(output['tags'], 'dont-push--local-only')
        self.assertEqual(output['push'], 'false')
        self.assertEqual(output['dockerfile'], 'Dockerfile')

    def test_nightly_build(self):
        os.environ.update({
            'GITHUB_REF': 'refs/heads/ci/extract-python-scripts',
            'GITHUB_EVENT_NAME': 'schedule',
            'GITHUB_SHA': '55629a7d0ae267cdd27618f452e9f1ad6764fd43',
            'GITHUB_EVENT_DEFAULT_BRANCH': 'master',
            'GITHUB_EVENT_NUMBER': '',
            'MATRIX_PYTHON_IMPL': 'python',
            'MATRIX_PYTHON_VERSION': '3.10',
            'SECRETS_DOCKERHUB_IMAGE': 'mock_image',
            'SECRETS_GHCR_IMAGE': '',
        })

        output, base_version, is_release_candidate, overwrite_hathor_core_version = prep_base_version(os.environ)

        self.assertTrue(overwrite_hathor_core_version)
        self.assertFalse(is_release_candidate)
        self.assertTrue(output['disable-slack-notification'])
        self.assertEqual(base_version, 'nightly-55629a7d')

        output = prep_tags(os.environ, base_version, is_release_candidate)

        self.assertEqual(output['slack-notification-version'], base_version)
        self.assertEqual(output['version'], base_version + '-python3.10')
        self.assertEqual(output['login-dockerhub'], 'true')
        self.assertEqual(output['login-ghcr'], 'false')
        self.assertEqual(len(output['tags'].split(',')), 2)
        self.assertIn('mock_image:nightly-55629a7d', output['tags'].split(','))
        self.assertIn('mock_image:nightly-55629a7d-python3.10', output['tags'].split(','))
        self.assertEqual(output['push'], 'true')
        self.assertEqual(output['dockerfile'], 'Dockerfile')


    def test_release_candidate_non_default_python(self):
        os.environ.update({
            'GITHUB_REF': 'refs/tags/v0.53.0-rc.1',
            'GITHUB_EVENT_NAME': 'push',
            'GITHUB_SHA': '55629a7d0ae267cdd27618f452e9f1ad6764fd43',
            'GITHUB_EVENT_DEFAULT_BRANCH': 'master',
            'GITHUB_EVENT_NUMBER': '',
            'MATRIX_PYTHON_IMPL': 'python',
            'MATRIX_PYTHON_VERSION': '3.11',
            'SECRETS_DOCKERHUB_IMAGE': 'mock_image',
            'SECRETS_GHCR_IMAGE': '',
        })

        output, base_version, is_release_candidate, overwrite_hathor_core_version = prep_base_version(os.environ)

        self.assertTrue(overwrite_hathor_core_version)
        self.assertTrue(is_release_candidate)
        self.assertFalse(output['disable-slack-notification'])
        self.assertEqual(base_version, 'v0.53.0-rc.1')

        output = prep_tags(os.environ, base_version, is_release_candidate)

        self.assertNotIn('slack-notification-version', output)
        self.assertEqual(output['version'], base_version)
        self.assertEqual(output['login-dockerhub'], 'true')
        self.assertEqual(output['login-ghcr'], 'false')
        self.assertEqual(output['tags'], 'dont-push--local-only')
        self.assertEqual(output['push'], 'false')
        self.assertEqual(output['dockerfile'], 'Dockerfile')

    def test_release_candidate_default_python(self):
        os.environ.update({
            'GITHUB_REF': 'refs/tags/v0.53.0-rc.1',
            'GITHUB_EVENT_NAME': 'push',
            'GITHUB_SHA': '55629a7d0ae267cdd27618f452e9f1ad6764fd43',
            'GITHUB_EVENT_DEFAULT_BRANCH': 'master',
            'GITHUB_EVENT_NUMBER': '',
            'MATRIX_PYTHON_IMPL': 'python',
            'MATRIX_PYTHON_VERSION': '3.10',
            'SECRETS_DOCKERHUB_IMAGE': 'mock_image',
            'SECRETS_GHCR_IMAGE': '',
        })

        output, base_version, is_release_candidate, overwrite_hathor_core_version = prep_base_version(os.environ)

        self.assertTrue(overwrite_hathor_core_version)
        self.assertTrue(is_release_candidate)
        self.assertFalse(output['disable-slack-notification'])
        self.assertEqual(base_version, 'v0.53.0-rc.1')

        output = prep_tags(os.environ, base_version, is_release_candidate)

        self.assertEqual(output['slack-notification-version'], base_version)
        self.assertEqual(output['version'], base_version)
        self.assertEqual(output['login-dockerhub'], 'true')
        self.assertEqual(output['login-ghcr'], 'false')
        self.assertEqual(output['tags'], 'mock_image:v0.53.0-rc.1')
        self.assertEqual(output['push'], 'true')
        self.assertEqual(output['dockerfile'], 'Dockerfile')

    def test_release_default_python(self):
        os.environ.update({
            'GITHUB_REF': 'refs/tags/v0.53.0',
            'GITHUB_EVENT_NAME': 'push',
            'GITHUB_SHA': '55629a7d0ae267cdd27618f452e9f1ad6764fd43',
            'GITHUB_EVENT_DEFAULT_BRANCH': 'master',
            'GITHUB_EVENT_NUMBER': '',
            'MATRIX_PYTHON_IMPL': 'python',
            'MATRIX_PYTHON_VERSION': '3.10',
            'SECRETS_DOCKERHUB_IMAGE': 'mock_image',
            'SECRETS_GHCR_IMAGE': '',
        })

        output, base_version, is_release_candidate, overwrite_hathor_core_version = prep_base_version(os.environ)

        self.assertTrue(overwrite_hathor_core_version)
        self.assertFalse(is_release_candidate)
        self.assertFalse(output['disable-slack-notification'])
        self.assertEqual(base_version, 'v0.53.0')

        output = prep_tags(os.environ, base_version, is_release_candidate)

        self.assertEqual(output['slack-notification-version'], base_version)
        self.assertEqual(output['version'], base_version + '-python3.10')
        self.assertEqual(output['login-dockerhub'], 'true')
        self.assertEqual(output['login-ghcr'], 'false')
        self.assertEqual(len(output['tags'].split(',')), 4)
        self.assertIn('mock_image:v0.53-python3.10', output['tags'].split(','))
        self.assertIn('mock_image:v0.53.0-python3.10', output['tags'].split(','))
        self.assertIn('mock_image:v0.53.0', output['tags'].split(','))
        self.assertIn('mock_image:latest', output['tags'].split(','))
        self.assertEqual(output['push'], 'true')
        self.assertEqual(output['dockerfile'], 'Dockerfile')
