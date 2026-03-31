import unittest

from hathor._openapi.register import get_registered_resources


class LegacyOpenapiRegistryTestCase(unittest.TestCase):
    def test_get_registered_resources(self):
        resources = get_registered_resources()
        for resource in resources:
            self.assertTrue(hasattr(resource, 'openapi'))
