from hathor_tests import unittest
from hathor_tests.unittest import TestBuilder


class BuilderTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.reactor = self.clock
        self.builder = TestBuilder()

    def test_multiple_calls_to_build(self):
        self.builder.build()

        with self.assertRaises(ValueError):
            self.builder.build()

    def test_check_if_can_modify(self):
        self.builder.build()

        with self.assertRaises(ValueError):
            self.builder.set_reactor(self.reactor)
