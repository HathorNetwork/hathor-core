import tempfile

from hathor_cli.shell import Shell
from hathor_tests import unittest


class ShellTest(unittest.TestCase):
    # In this case we just want to go through the code to see if it's okay

    def test_shell_execution_temp_data(self):
        shell = Shell(argv=['--temp-data', '--', '--extra-arg'])
        self.assertTrue(shell is not None)

    def test_shell_execution_default_storage(self):
        temp_data = tempfile.TemporaryDirectory()
        shell = Shell(argv=['--data', temp_data.name])
        self.assertTrue(shell is not None)
