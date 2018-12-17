from tests import unittest
from hathor.cli.shell import create_parser, prepare


class ShellTest(unittest.TestCase):
    def test_shell_execution(self):
        # In this case we just want to go through the code to see if it's okay
        parser = create_parser()
        args = parser.parse_args([])
        prepare(args)
