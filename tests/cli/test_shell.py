from hathor.cli.shell import Shell
from tests import unittest


class ShellTest(unittest.TestCase):
    def test_shell_execution(self):
        # In this case we just want to go through the code to see if it's okay
        shell = Shell(argv=[])
        self.assertTrue(shell is not None)
