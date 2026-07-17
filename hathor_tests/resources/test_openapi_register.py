# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import unittest

from hathor._openapi.register import get_registered_resources
from hathor.api_util import Resource


class TestOpenAPIRegister(unittest.TestCase):
    def test_get_registered_resources_imports_resource_modules(self) -> None:
        resources = get_registered_resources()

        self.assertGreater(len(resources), 0)
        self.assertTrue(all(issubclass(resource, Resource) for resource in resources))

        from hathor.event.resources.event import EventResource

        self.assertIn(EventResource, resources)
